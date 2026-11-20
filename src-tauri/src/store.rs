//! Local host storage. Host metadata lives in a JSON file in the app data
//! directory; passwords and key passphrases live in Windows Credential Manager.
//! Nothing ever leaves the machine.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Mutex};

const KEYRING_SERVICE: &str = "ssh-cluent";

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostView {
    #[serde(flatten)]
    pub host: Host,
    pub has_secret: bool,
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

    pub fn list(&self) -> Result<Vec<HostView>> {
        let _g = self.lock.lock().unwrap();
        Ok(self
            .load()?
            .into_iter()
            .map(|host| HostView {
                has_secret: get_secret(&host.id).is_some(),
                host,
            })
            .collect())
    }

    pub fn get(&self, id: &str) -> Result<Host> {
        let _g = self.lock.lock().unwrap();
        self.load()?
            .into_iter()
            .find(|h| h.id == id)
            .context("host not found")
    }

    /// `secret`: None = keep as is, Some("") = forget, Some(s) = store.
    pub fn upsert(&self, mut host: Host, secret: Option<String>) -> Result<Host> {
        if host.hostname.trim().is_empty() {
            bail!("Не указан адрес хоста");
        }
        if host.username.trim().is_empty() {
            bail!("Не указано имя пользователя");
        }
        host.hostname = host.hostname.trim().to_string();
        host.username = host.username.trim().to_string();
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

        match secret {
            Some(s) if s.is_empty() => delete_secret(&host.id),
            Some(s) => set_secret(&host.id, &s)?,
            None => {}
        }
        Ok(host)
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let _g = self.lock.lock().unwrap();
        let mut hosts = self.load()?;
        hosts.retain(|h| h.id != id);
        self.save(&hosts)?;
        delete_secret(id);
        Ok(())
    }
}

fn entry(id: &str) -> Option<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, id).ok()
}

pub fn get_secret(id: &str) -> Option<String> {
    entry(id)?.get_password().ok()
}

pub fn set_secret(id: &str, secret: &str) -> Result<()> {
    entry(id)
        .context("credential store unavailable")?
        .set_password(secret)
        .context("saving secret to Windows Credential Manager")
}

pub fn delete_secret(id: &str) {
    if let Some(e) = entry(id) {
        let _ = e.delete_credential();
    }
}
