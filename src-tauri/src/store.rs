//! Local host storage. Host metadata lives in a JSON file in the app data
//! directory. Passwords and key passphrases are never stored: they are asked
//! for on every connection and kept only in memory. Nothing ever leaves the machine.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Mutex};

use crate::local_path::{expand_home, require_local_path};

/// Service name under which older versions saved secrets in Windows Credential
/// Manager. Used only to wipe those leftovers.
const LEGACY_KEYRING_SERVICE: &str = "ssh-cluent";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Password,
    Key,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ForwardKind {
    /// -L: local port -> remote target through the server
    Local,
    /// -R: server port -> local target
    Remote,
    /// -D: local SOCKS5 proxy
    Dynamic,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Forward {
    #[serde(default)]
    pub id: String,
    pub kind: ForwardKind,
    pub bind_host: String,
    pub bind_port: u16,
    #[serde(default)]
    pub target_host: String,
    #[serde(default)]
    pub target_port: u16,
}

impl Forward {
    pub fn describe(&self) -> String {
        match self.kind {
            ForwardKind::Local => format!(
                "L {}:{} → {}:{}",
                self.bind_host, self.bind_port, self.target_host, self.target_port
            ),
            ForwardKind::Remote => format!(
                "R {}:{} → {}:{}",
                self.bind_host, self.bind_port, self.target_host, self.target_port
            ),
            ForwardKind::Dynamic => format!("D SOCKS5 {}:{}", self.bind_host, self.bind_port),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    #[serde(default)]
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub group: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub forwards: Vec<Forward>,
}

pub struct Store {
    path: PathBuf,
    lock: Mutex<()>,
}

impl Store {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    fn load(&self) -> Result<Vec<Host>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let bytes = std::fs::read(&self.path).context("reading hosts file")?;
        serde_json::from_slice(&bytes).context("parsing hosts file")
    }

    fn save(&self, hosts: &[Host]) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(hosts)?).context("writing hosts file")?;
        std::fs::rename(&tmp, &self.path).context("replacing hosts file")?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<Host>> {
        let _g = self.lock.lock().unwrap();
        self.load()
    }

    /// Removes passwords/passphrases that older versions saved in Windows
    /// Credential Manager for any of the known hosts.
    pub fn purge_legacy_secrets(&self) {
        if let Ok(hosts) = self.list() {
            for h in hosts {
                purge_legacy_secret(&h.id);
            }
        }
    }

    pub fn get(&self, id: &str) -> Result<Host> {
        let _g = self.lock.lock().unwrap();
        self.load()?
            .into_iter()
            .find(|h| h.id == id)
            .context("host not found")
    }

    pub fn upsert(&self, mut host: Host) -> Result<Host> {
        host.hostname = host.hostname.trim().to_string();
        host.username = host.username.trim().to_string();
        validate_hostname(&host.hostname)?;
        if host.username.is_empty() {
            bail!("Не указано имя пользователя");
        }
        if host.username.chars().any(|c| c.is_control() || c.is_whitespace()) {
            bail!("Имя пользователя содержит недопустимые символы");
        }
        if host.label.chars().any(char::is_control) || host.group.chars().any(char::is_control) {
            bail!("Название или группа содержат управляющие символы");
        }
        if let Some(path) = &host.key_path {
            require_local_path(&expand_home(path.trim()))?;
        }
        for f in &host.forwards {
            if !f.bind_host.trim().is_empty() {
                validate_hostname(f.bind_host.trim())?;
            }
            if f.kind != ForwardKind::Dynamic {
                validate_hostname(&f.target_host)?;
            }
        }
        if host.label.trim().is_empty() {
            host.label = host.hostname.clone();
        }
        if host.id.is_empty() {
            host.id = uuid::Uuid::new_v4().to_string();
        }
        for f in &mut host.forwards {
            if f.id.is_empty() {
                f.id = uuid::Uuid::new_v4().to_string();
            }
            if f.bind_host.trim().is_empty() {
                f.bind_host = "127.0.0.1".into();
            }
        }

        let _g = self.lock.lock().unwrap();
        let mut hosts = self.load()?;
        match hosts.iter_mut().find(|h| h.id == host.id) {
            Some(existing) => *existing = host.clone(),
            None => hosts.push(host.clone()),
        }
        self.save(&hosts)?;
        Ok(host)
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let _g = self.lock.lock().unwrap();
        let mut hosts = self.load()?;
        hosts.retain(|h| h.id != id);
        self.save(&hosts)?;
        purge_legacy_secret(id);
        Ok(())
    }
}

/// A host name / IP literal: no whitespace, control characters or the
/// characters that have meaning in known_hosts patterns and ssh syntax.
pub fn validate_hostname(h: &str) -> Result<()> {
    if h.is_empty() {
        bail!("Не указан адрес хоста");
    }
    if h.len() > 253
        || h.starts_with('-')
        || h.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(c, ',' | '[' | ']' | '/' | '\\' | '@' | '#' | '*' | '?' | '!' | '"' | '\'')
        })
    {
        bail!("Недопустимый адрес хоста: {h:?}");
    }
    Ok(())
}

fn purge_legacy_secret(id: &str) {
    if let Ok(e) = keyring::Entry::new(LEGACY_KEYRING_SERVICE, id) {
        let _ = e.delete_credential();
    }
}
