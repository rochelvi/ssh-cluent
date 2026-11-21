//! Our own known_hosts file (OpenSSH-like format, plain host patterns).

use anyhow::{Context, Result};
use russh::keys::ssh_key::PublicKey;
use std::{io::Write, path::PathBuf, sync::Mutex};

pub enum KeyCheck {
    Match,
    Unknown,
    Mismatch,
}

pub struct KnownHosts {
    path: PathBuf,
    lock: Mutex<()>,
}

fn pattern(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

impl KnownHosts {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    fn read(&self) -> String {
        std::fs::read_to_string(&self.path).unwrap_or_default()
    }

    pub fn check(&self, host: &str, port: u16, key: &PublicKey) -> Result<KeyCheck> {
        let _g = self.lock.lock().unwrap();
        let pat = pattern(host, port);
        let line = key.to_openssh()?;
        let mut parts = line.split_whitespace();
        let algo = parts.next().unwrap_or_default();
        let b64 = parts.next().unwrap_or_default();

        let mut known_other_type = false;
        for l in self.read().lines() {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 3 || f[0].starts_with('#') || !f[0].split(',').any(|h| h == pat) {
                continue;
            }
            if f[1] != algo {
                known_other_type = true;
                continue;
            }
            return Ok(if f[2] == b64 {
                KeyCheck::Match
            } else {
                KeyCheck::Mismatch
            });
        }
        // We know this host, but under a different key type: a MITM could present
        // a key of a type we have no record of. Warn exactly like a changed key.
        Ok(if known_other_type {
            KeyCheck::Mismatch
        } else {
            KeyCheck::Unknown
        })
    }

    /// Store (or replace) the key for host:port.
    pub fn trust(&self, host: &str, port: u16, key_line: &str) -> Result<()> {
        // `host` arrives over IPC: never let it inject extra lines or patterns.
        crate::store::validate_hostname(host)?;
        let key =PublicKey::from_openssh(key_line.trim()).context("invalid public key")?;
        let line = key.to_openssh()?;
        let mut parts = line.split_whitespace();
        let algo = parts.next().unwrap_or_default().to_string();
        let b64 = parts.next().unwrap_or_default().to_string();

        let _g = self.lock.lock().unwrap();
        let pat = pattern(host, port);
        let kept: Vec<String> = self
            .read()
            .lines()
            .filter(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                !(f.len() >= 2 && f[0].split(',').any(|h| h == pat) && f[1] == algo)
            })
            .map(str::to_string)
            .collect();

        let mut file = std::fs::File::create(&self.path).context("writing known_hosts")?;
        for l in kept {
            writeln!(file, "{l}")?;
        }
        writeln!(file, "{pat} {algo} {b64}")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED_A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEfVu6ut/J2tfqeGGPC36Ho68cJpBOs06CeERt5g9AFW";
    const ED_B: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCnbFwtt/qKbu4ye3dlEHZKZUuZoly17WV7Mnl+wCeM";
    const ECDSA: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDfivXmS+KqW2HrK2KHDUTULqpvkexoP22A8WE8xLmyhraoFJH0v8Ha1EvnlD3fry77cO6tDCDVL/xhZZ6YJHRg=";

    fn key(line: &str) -> PublicKey {
        PublicKey::from_openssh(line).unwrap()
    }

    #[test]
    fn detects_changed_and_downgraded_keys() {
        let path = std::env::temp_dir().join(format!("cluent-kh-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let kh = KnownHosts::new(path.clone());

        assert!(matches!(kh.check("srv", 22, &key(ED_A)).unwrap(), KeyCheck::Unknown));
        kh.trust("srv", 22, ED_A).unwrap();
        assert!(matches!(kh.check("srv", 22, &key(ED_A)).unwrap(), KeyCheck::Match));
        // Same type, different key.
        assert!(matches!(kh.check("srv", 22, &key(ED_B)).unwrap(), KeyCheck::Mismatch));
        // Different key type for a host we already know: must warn, not look "new".
        assert!(matches!(kh.check("srv", 22, &key(ECDSA)).unwrap(), KeyCheck::Mismatch));
        // Other port = other host.
        assert!(matches!(kh.check("srv", 2222, &key(ECDSA)).unwrap(), KeyCheck::Unknown));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn rejects_injection_in_host() {
        let path = std::env::temp_dir().join(format!("cluent-kh-inj-{}", std::process::id()));
        let kh = KnownHosts::new(path.clone());
        assert!(kh.trust("evil\nvictim", 22, ED_A).is_err());
        assert!(kh.trust("a b", 22, ED_A).is_err());
        assert!(kh.trust("a,b", 22, ED_A).is_err());
        std::fs::remove_file(path).ok();
    }
}
