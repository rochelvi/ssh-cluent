use anyhow::{ensure, Context, Result};
use russh_sftp::client::SftpSession;
use serde::Serialize;
use tokio::io::AsyncWriteExt;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub is_link: bool,
    pub size: u64,
    pub modified: Option<u64>,
    pub permissions: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Listing {
    pub path: String,
    pub entries: Vec<Entry>,
}

pub async fn list(s: &SftpSession, path: &str) -> Result<Listing> {
    let path = if path.is_empty() { "." } else { path };
    let canon = s.canonicalize(path).await.context("Путь не найден")?;
    let mut entries: Vec<Entry> = s
        .read_dir(canon.clone())
        .await
        .context("Не удалось прочитать каталог")?
        .filter(|e| e.file_name() != "." && e.file_name() != "..")
        .map(|e| {
            let md = e.metadata();
            let ft = e.file_type();
            Entry {
                name: e.file_name(),
                is_dir: ft.is_dir(),
                is_link: ft.is_symlink(),
                size: md.size.unwrap_or(0),
                modified: md.mtime.map(u64::from),
                permissions: md.permissions,
            }
        })
        .collect();
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(Listing {
        path: canon,
        entries,
    })
}

/// Characters Windows does not allow in a file name (plus path separators).
const FORBIDDEN: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

fn is_reserved_device(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit())
}

/// A single, harmless Windows file name: no separators, no `..`, no device names.
pub fn is_safe_file_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.ends_with(['.', ' '])
        && !name.chars().any(|c| c.is_control() || FORBIDDEN.contains(&c))
        && !is_reserved_device(name)
}

/// The local target of a download must be an absolute path without `..`
/// whose file name is safe. Remote file names are attacker-controlled
/// (on Linux they may contain `\` and `..`), so this is checked here and
/// not only in the UI.
pub fn check_local_target(local: &str) -> Result<()> {
    let p = std::path::Path::new(local);
    if !p.is_absolute() {
        anyhow::bail!("Локальный путь должен быть абсолютным");
    }
    if p.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        anyhow::bail!("Недопустимый локальный путь: {local}");
    }
    let name = p.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
    if !is_safe_file_name(&name) {
        anyhow::bail!("Недопустимое имя файла: {name}");
    }
    Ok(())
}

pub async fn download(s: &SftpSession, remote: &str, local: &str) -> Result<()> {
    check_local_target(local)?;
    let mut src = s.open(remote).await.context("Не удалось открыть удалённый файл")?;
    let mut dst = tokio::fs::File::create(local)
        .await
        .context("Не удалось создать локальный файл")?;
    tokio::io::copy(&mut src, &mut dst).await?;
    dst.flush().await?;
    Ok(())
}

pub async fn upload(s: &SftpSession, local: &str, remote: &str) -> Result<()> {
    let mut src = tokio::fs::File::open(local)
        .await
        .context("Не удалось открыть локальный файл")?;
    if src.metadata().await?.is_dir() {
        anyhow::bail!("Загрузка папок пока не поддерживается");
    }
    let mut dst = s.create(remote).await.context("Не удалось создать удалённый файл")?;
    tokio::io::copy(&mut src, &mut dst).await?;
    dst.shutdown().await?;
    Ok(())
}

const MAX_REMOVE_DEPTH: usize = 64;

fn check_remove_depth(depth: usize) -> Result<()> {
    ensure!(
        depth <= MAX_REMOVE_DEPTH,
        "Удаление SFTP остановлено: превышена допустимая глубина каталогов ({MAX_REMOVE_DEPTH})"
    );
    Ok(())
}

pub async fn remove(s: &SftpSession, path: String, is_dir: bool) -> Result<()> {
    if is_dir {
        remove_dir(s, path, 0).await?;
    } else {
        s.remove_file(path).await?;
    }
    Ok(())
}

async fn remove_dir(s: &SftpSession, path: String, depth: usize) -> Result<()> {
    check_remove_depth(depth)?;
    for e in s.read_dir(path.clone()).await? {
        let name = e.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let child = format!("{}/{}", path.trim_end_matches('/'), name);
        if e.file_type().is_dir() {
            Box::pin(remove_dir(s, child, depth + 1)).await?;
        } else {
            s.remove_file(child).await?;
        }
    }
    s.remove_dir(path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_remove_directory_depth() {
        assert!(check_remove_depth(0).is_ok());
        assert!(check_remove_depth(64).is_ok());
        assert!(check_remove_depth(65).is_err());
    }

    #[test]
    fn rejects_traversal_and_bad_names() {
        for bad in ["..", ".", "", r"a\b", r"..\..\evil.bat", "a/b", "c:x", "NUL", "con.txt", "COM1", "x.", "x ", "a\u{1}b"] {
            assert!(!is_safe_file_name(bad), "{bad:?} must be rejected");
        }
        for ok in ["readme.txt", ".bashrc", "файл.tar.gz", "COM10", "console.log"] {
            assert!(is_safe_file_name(ok), "{ok:?} must be accepted");
        }
    }

    #[test]
    fn checks_local_target() {
        assert!(check_local_target(r"C:\Users\u\Downloads\readme.txt").is_ok());
        assert!(check_local_target(r"C:\Users\u\Downloads\..\..\evil.bat").is_err());
        assert!(check_local_target(r"relative\file.txt").is_err());
        assert!(check_local_target(r"C:\Users\u\Downloads\NUL").is_err());
    }
}
