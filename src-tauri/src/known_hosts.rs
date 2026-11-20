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

        for l in self.read().lines() {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 3 || f[0].starts_with('#') {
                continue;
            }
            if !f[0].split(',').any(|h| h == pat) || f[1] != algo {
                continue;
            }
            return Ok(if f[2] == b64 {
                KeyCheck::Match
            } else {
                KeyCheck::Mismatch
            });
        }
        Ok(KeyCheck::Unknown)
    }

    /// Store (or replace) the key for host:port.
    pub fn trust(&self, host: &str, port: u16, key_line: &str) -> Result<()> {
        let key = PublicKey::from_openssh(key_line.trim()).context("invalid public key")?;
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
