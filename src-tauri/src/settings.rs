//! Application settings, stored in settings.json in the app data directory.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Mutex};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// Copy text to the clipboard as soon as it is selected; right click pastes.
    pub copy_on_select: bool,
    /// Copy shortcut, e.g. "Ctrl+C" or "Ctrl+Shift+C".
    pub key_copy: String,
    /// Paste shortcut, e.g. "Ctrl+V" or "Shift+Insert".
    pub key_paste: String,
    /// Pre-filled user for new hosts and for imported hosts without `User`.
    pub default_username: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            copy_on_select: false,
            key_copy: "Ctrl+C".into(),
            key_paste: "Ctrl+V".into(),
            default_username: String::new(),
        }
    }
}

pub struct SettingsStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl SettingsStore {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    pub fn get(&self) -> Settings {
        let _g = self.lock.lock().unwrap();
        std::fs::read(&self.path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn set(&self, settings: &Settings) -> Result<()> {
        let _g = self.lock.lock().unwrap();
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(settings)?).context("writing settings")?;
        std::fs::rename(&tmp, &self.path).context("replacing settings")?;
        Ok(())
    }
}
