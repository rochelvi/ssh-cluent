//! Import of hosts from an OpenSSH client config (~/.ssh/config).
//!
//! Follows OpenSSH semantics where it matters: for every concrete `Host` alias
//! all matching blocks (including `Host *` and options before the first `Host`)
//! are applied in file order and the first value obtained wins; forwards
//! accumulate. `Include` is followed (with `*`/`?` in the file name),
//! `Match` blocks are skipped.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::{
    local_path::{expand_home, home, require_local_path},
    store::{AuthMethod, Forward, ForwardKind, Host},
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub host: Host,
    /// The identity file referenced by the config does not exist or was rejected.
    pub key_missing: bool,
}

struct Block {
    patterns: Vec<String>,
    options: Vec<(String, String)>,
}

pub fn default_path() -> Option<PathBuf> {
    home().map(|h| h.join(".ssh").join("config"))
}

/// Splits a config line into (lowercased keyword, raw arguments).
fn tokenize(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let idx = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let key = line[..idx].to_lowercase();
    let rest = line[idx..].trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim();
    Some((key, rest.to_string()))
}

/// Splits arguments on whitespace, honouring double quotes.
fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut has = false;
    for c in s.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                has = true;
            }
            c if c.is_whitespace() && !quoted => {
                if has {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            c => {
                cur.push(c);
                has = true;
            }
        }
    }
    if has {
        out.push(cur);
    }
    out
}

/// Case-insensitive glob with `*` and `?`.
fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn matches(patterns: &[String], alias: &str) -> bool {
    let mut any = false;
    for p in patterns {
        if let Some(neg) = p.strip_prefix('!') {
            if glob(neg, alias) {
                return false;
            }
        } else if glob(p, alias) {
            any = true;
        }
    }
    any
}

fn expand_include(arg: &str) -> Vec<PathBuf> {
    let p = expand_home(arg);
    if require_local_path(&p).is_err() {
        return vec![];
    }
    let p = if p.is_absolute() {
        p
    } else {
        match home() {
            Some(h) => h.join(".ssh").join(p),
            None => p,
        }
    };
    if require_local_path(&p).is_err() {
        return vec![];
    }
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if !name.contains(['*', '?']) {
        return vec![p];
    }
    let Some(dir) = p.parent() else { return vec![] };
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| glob(&name, &e.file_name().to_string_lossy()))
                .map(|e| e.path())
                .filter(|p| require_local_path(p).is_ok() && p.is_file())
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

/// Reads a config file, inlining `Include`d files. Each file is read at most
/// once, so include cycles (e.g. `Include *` in ~/.ssh/config) cannot blow up.
fn read_lines(path: &Path, depth: u32, seen: &mut HashSet<PathBuf>, out: &mut Vec<String>) -> Result<()> {
    if depth > 16 {
        return Ok(());
    }
    require_local_path(path)?;
    let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !seen.insert(key) {
        return Ok(());
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Не удалось прочитать {}", path.display()))?;
    for line in text.lines() {
        if let Some((k, v)) = tokenize(line) {
            if k == "include" {
                for arg in split_args(&v) {
                    for p in expand_include(&arg) {
                        let _ = read_lines(&p, depth + 1, seen, out);
                    }
                }
                continue;
            }
        }
        out.push(line.to_string());
    }
    Ok(())
}

/// "[bind:]port" → (bind host, port)
fn parse_listen(s: &str, default_bind: &str) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, port) = rest.split_once("]:")?;
        return Some((addr.to_string(), port.parse().ok()?));
    }
    match s.rsplit_once(':') {
        Some((addr, port)) => {
            let addr = if addr.is_empty() || addr == "*" { "0.0.0.0" } else { addr };
            Some((addr.to_string(), port.parse().ok()?))
        }
        None => Some((default_bind.to_string(), s.parse().ok()?)),
    }
}

/// "host:port", "[v6]:port" or "host/port" → (host, port)
fn parse_target(s: &str) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, port) = rest.split_once("]:")?;
        return Some((addr.to_string(), port.parse().ok()?));
    }
    let (h, p) = s.rsplit_once(':').or_else(|| s.rsplit_once('/'))?;
    Some((h.to_string(), p.parse().ok()?))
}

fn parse_forward(kind: &str, value: &str) -> Option<Forward> {
    let args = split_args(value);
    let kind = match kind {
        "localforward" => ForwardKind::Local,
        "remoteforward" => ForwardKind::Remote,
        "dynamicforward" => ForwardKind::Dynamic,
        _ => return None,
    };
    let (bind_host, bind_port) = parse_listen(args.first()?, "127.0.0.1")?;
    let (target_host, target_port) = match kind {
        ForwardKind::Dynamic => (String::new(), 0),
        _ => parse_target(args.get(1)?)?,
    };
    Some(Forward {
        id: String::new(),
        kind,
        bind_host,
        bind_port,
        target_host,
        target_port,
    })
}

fn expand_tokens(s: &str, alias: &str, hostname: &str, user: &str) -> String {
    let home = home().map(|h| h.display().to_string()).unwrap_or_default();
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => out.push_str(hostname),
            Some('n') => out.push_str(alias),
            Some('r') | Some('u') => out.push_str(user),
            Some('d') => out.push_str(&home),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

fn default_identity() -> Option<PathBuf> {
    let ssh = home()?.join(".ssh");
    ["id_ed25519", "id_ecdsa", "id_rsa"]
        .iter()
        .map(|n| ssh.join(n))
        .find(|p| require_local_path(p).is_ok() && p.is_file())
}

pub fn parse(path: &Path, default_user: &str) -> Result<Vec<Candidate>> {
    let mut lines = Vec::new();
    read_lines(path, 0, &mut HashSet::new(), &mut lines)?;

    // Options before the first `Host` apply to every host.
    let mut blocks = vec![Block {
        patterns: vec!["*".into()],
        options: Vec::new(),
    }];
    let mut aliases: Vec<String> = Vec::new();
    let mut in_match = false;

    for line in &lines {
        let Some((key, value)) = tokenize(line) else { continue };
        match key.as_str() {
            "host" => {
                in_match = false;
                let patterns = split_args(&value);
                for p in &patterns {
                    if !p.contains(['*', '?']) && !p.starts_with('!') && !aliases.contains(p) {
                        aliases.push(p.clone());
                    }
                }
                blocks.push(Block {
                    patterns,
                    options: Vec::new(),
                });
            }
            "match" => in_match = true,
            _ if !in_match => blocks.last_mut().unwrap().options.push((key, value)),
            _ => {}
        }
    }

    let fallback_user = if default_user.trim().is_empty() {
        std::env::var("USERNAME").unwrap_or_default()
    } else {
        default_user.trim().to_string()
    };

    let mut out = Vec::new();
    for alias in aliases {
        let mut hostname: Option<String> = None;
        let mut port: Option<u16> = None;
        let mut user: Option<String> = None;
        let mut identity: Option<String> = None;
        let mut forwards = Vec::new();

        for block in blocks.iter().filter(|b| matches(&b.patterns, &alias)) {
            for (k, v) in &block.options {
                let first = || split_args(v).into_iter().next();
                match k.as_str() {
                    "hostname" if hostname.is_none() => hostname = first(),
                    "port" if port.is_none() => port = first().and_then(|p| p.parse().ok()),
                    "user" if user.is_none() => user = first(),
                    "identityfile" if identity.is_none() => identity = first(),
                    "localforward" | "remoteforward" | "dynamicforward" => {
                        if let Some(f) = parse_forward(k, v) {
                            forwards.push(f);
                        }
                    }
                    _ => {}
                }
            }
        }

        let user = user.unwrap_or_else(|| fallback_user.clone());
        let hostname = expand_tokens(&hostname.unwrap_or_else(|| alias.clone()), &alias, &alias, &user);
        let key_path = match identity {
            Some(id) => Some(expand_home(&expand_tokens(&id, &alias, &hostname, &user))),
            None => default_identity(),
        };
        let auth = if key_path.is_some() {
            AuthMethod::Key
        } else {
            AuthMethod::Password
        };
        let (key_path, key_missing) = match key_path {
            Some(p) if require_local_path(&p).is_ok() => {
                let missing = !p.is_file();
                (Some(p), missing)
            }
            Some(_) => (None, true),
            None => (None, false),
        };

        out.push(Candidate {
            key_missing,
            host: Host {
                id: String::new(),
                label: alias,
                group: String::new(),
                hostname,
                port: port.unwrap_or(22),
                username: user,
                auth,
                key_path: key_path.map(|p| p.display().to_string()),
                forwards,
            },
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_works() {
        assert!(glob("*", "anything"));
        assert!(glob("web-?", "web-1"));
        assert!(glob("*.example.com", "a.EXAMPLE.com"));
        assert!(!glob("web-?", "web-10"));
    }

    #[test]
    fn parses_config() {
        let dir = std::env::temp_dir().join(format!("cluent-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config");
        std::fs::write(
            &cfg,
            "# comment\n\
             Host prod web-*\n  HostName 10.0.0.%h\n  User deploy\n  Port=2200\n  LocalForward 8080 db:5432\n\
             Host bastion\n  HostName bastion.example.com\n  DynamicForward 1080\n  RemoteForward 0.0.0.0:9000 localhost:3000\n\
             Match host foo\n  User ignored\n\
             Host *\n  User fallback\n  Port 22\n",
        )
        .unwrap();
        let hosts = parse(&cfg, "").unwrap();
        assert_eq!(hosts.len(), 2);

        let prod = &hosts[0].host;
        assert_eq!(prod.label, "prod");
        assert_eq!(prod.hostname, "10.0.0.prod");
        assert_eq!(prod.username, "deploy");
        assert_eq!(prod.port, 2200);
        assert_eq!(prod.forwards.len(), 1);
        assert_eq!(prod.forwards[0].bind_port, 8080);
        assert_eq!(prod.forwards[0].target_host, "db");

        let b = &hosts[1].host;
        assert_eq!(b.username, "fallback");
        assert_eq!(b.port, 22);
        assert_eq!(b.forwards.len(), 2);
        assert_eq!(b.forwards[0].kind, ForwardKind::Dynamic);
        assert_eq!(b.forwards[1].bind_host, "0.0.0.0");
        assert_eq!(b.forwards[1].target_port, 3000);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn include_cycle_terminates() {
        let dir = std::env::temp_dir().join(format!("cluent-inc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a");
        let b = dir.join("b");
        std::fs::write(&a, format!("Include \"{}\"\nInclude \"{}\"\nHost one\n", b.display(), a.display())).unwrap();
        std::fs::write(&b, format!("Include \"{}\"\nHost two\n", a.display())).unwrap();
        let hosts = parse(&a, "u").unwrap();
        let names: Vec<_> = hosts.iter().map(|c| c.host.label.as_str()).collect();
        assert_eq!(names, ["two", "one"]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(windows)]
    #[test]
    fn preview_discards_blocked_identity_paths() {
        let dir = std::env::temp_dir().join(format!("cluent-paths-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let cfg = dir.join("config");
        let key = dir.join("local key");
        std::fs::write(&key, "local fixture").unwrap();
        std::fs::write(
            &cfg,
            format!(
                "Host included\nInclude \"{}/extra-*\"\nIdentityFile \"{}\"\nHost blocked\nIdentityFile {}\n",
                dir.display(),
                key.display(),
                r"\\?\C:\blocked\key"
            ),
        )
        .unwrap();
        std::fs::write(dir.join("extra-host"), "User local-user\n").unwrap();

        let hosts = parse(&cfg, "fallback").unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].host.username, "local-user");
        assert_eq!(hosts[0].host.key_path.as_deref(), key.to_str());
        assert!(!hosts[0].key_missing);
        assert_eq!(hosts[1].host.auth, AuthMethod::Key);
        assert!(hosts[1].host.key_path.is_none());
        assert!(hosts[1].key_missing);
        assert!(expand_include(r"\\?\C:\blocked\*.conf").is_empty());
        assert!(expand_include(r"\\?\C:\blocked\config").is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
