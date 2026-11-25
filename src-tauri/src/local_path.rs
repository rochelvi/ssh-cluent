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

/// Reject remote drive roots and unsafe syntax before accessing an SSH config or key path.
pub(crate) fn require_local_path(path: &Path) -> Result<()> {
    ensure!(
        is_local_path(path),
        "Укажите путь на локальном диске. Сетевые пути и пути устройств запрещены"
    );
    Ok(())
}

fn is_local_path(path: &Path) -> bool {
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
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) => path.is_absolute() && is_local_drive(drive),
                _ => false,
            },
            Some(Component::RootDir) => false,
            // Preserve relative paths when the process has an ordinary drive as its base.
            _ => std::env::current_dir()
                .is_ok_and(|cwd| cwd.is_absolute() && is_local_path(&cwd)),
        }
    }
    #[cfg(not(windows))]
    {
        true
    }
}

#[cfg(windows)]
fn is_local_drive(drive: u8) -> bool {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

    let root = [u16::from(drive), b':' as u16, b'\\' as u16, 0];
    // SAFETY: root is a null-terminated UTF-16 drive root for the duration of the call.
    let drive_type = unsafe { GetDriveTypeW(root.as_ptr()) };
    is_local_drive_type(drive_type)
}

#[cfg(windows)]
fn is_local_drive_type(drive_type: u32) -> bool {
    use windows_sys::Win32::System::WindowsProgramming::{
        DRIVE_CDROM, DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOVABLE,
    };

    matches!(drive_type, DRIVE_FIXED | DRIVE_REMOVABLE | DRIVE_CDROM | DRIVE_RAMDISK)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn accepts_paths_on_the_current_local_drive() {
        let cwd = std::env::current_dir().unwrap();
        let key = cwd.join(r"keys\key");
        let key_with_slashes = key.to_string_lossy().replace('\\', "/");
        assert!(require_local_path(&key).is_ok());
        assert!(require_local_path(Path::new(&key_with_slashes)).is_ok());
        assert!(require_local_path(Path::new(r"keys\key")).is_ok());
    }

    #[test]
    fn rejects_remote_and_unavailable_drive_types() {
        use windows_sys::Win32::System::WindowsProgramming::{
            DRIVE_FIXED, DRIVE_NO_ROOT_DIR, DRIVE_REMOTE, DRIVE_UNKNOWN,
        };

        assert!(is_local_drive_type(DRIVE_FIXED));
        assert!(!is_local_drive_type(DRIVE_REMOTE));
        assert!(!is_local_drive_type(DRIVE_NO_ROOT_DIR));
        assert!(!is_local_drive_type(DRIVE_UNKNOWN));
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
