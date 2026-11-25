use anyhow::{ensure, Result};
use std::path::{Path, PathBuf};

pub(crate) fn home() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
}

pub(crate) fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix('~') {
        if let Some(home) = home() {
            return home.join(rest.trim_start_matches(['/', '\\']));
        }
    }
    PathBuf::from(path)
}

/// Check path syntax before making any filesystem call on an SSH config or key path.
pub(crate) fn require_local_path(path: &Path) -> Result<()> {
    ensure!(
        has_local_path_syntax(path),
        "Укажите локальный путь. Сетевые пути и пути устройств запрещены"
    );
    Ok(())
}

fn has_local_path_syntax(path: &Path) -> bool {
    // Windows accepts slash variants of UNC paths. Check the raw spelling too,
    // before Windows or PathBuf can interpret or normalize the prefix.
    if matches!(
        path.as_os_str().as_encoded_bytes(),
        [] | [b'\\' | b'/', b'\\' | b'/', ..]
    ) {
        return false;
    }

    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};

        match path.components().next() {
            Some(Component::Prefix(prefix)) => {
                matches!(prefix.kind(), Prefix::Disk(_)) && path.is_absolute()
            }
            Some(Component::RootDir) => false,
            // Preserve relative paths when the process has an ordinary drive as its base.
            _ => std::env::current_dir()
                .is_ok_and(|cwd| cwd.is_absolute() && has_local_path_syntax(&cwd)),
        }
    }
    #[cfg(not(windows))]
    {
        true
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn accepts_local_path_syntax() {
        for path in [r"C:\Users\me\key", "C:/Users/me/key", r"keys\key"] {
            assert!(require_local_path(Path::new(path)).is_ok(), "{path:?}");
        }
    }

    #[test]
    fn rejects_network_device_and_ambiguous_drive_paths() {
        for path in [
            r"\\example.invalid\share\key",
            "//example.invalid/share/key",
            r"\/example.invalid/share/key",
            r"/\example.invalid\share\key",
            r"\\?\UNC\example.invalid\share\key",
            r"\\?\C:\keys\key",
            r"\\.\C:\keys\key",
            r"C:keys\key",
            r"\keys\key",
            "",
        ] {
            assert!(require_local_path(Path::new(path)).is_err(), "{path:?}");
        }
    }
}
