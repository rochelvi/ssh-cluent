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
const MAX_REMOVE_ENTRIES: usize = 100_000;

fn check_remove_depth(depth: usize) -> Result<()> {
    ensure!(
        depth <= MAX_REMOVE_DEPTH,
        "Удаление SFTP остановлено: превышена допустимая глубина каталогов ({MAX_REMOVE_DEPTH})"
    );
    Ok(())
}

struct Removal {
    path: String,
    directory_depth: Option<usize>,
}

pub async fn remove(s: &SftpSession, path: String, is_dir: bool) -> Result<()> {
    if !is_dir {
        s.remove_file(path).await?;
        return Ok(());
    }

    // Finish the bounded scan before sending any delete requests.
    let plan = plan_removal(s, path).await?;
    for entry in plan.into_iter().rev() {
        if entry.directory_depth.is_some() {
            s.remove_dir(entry.path).await?;
        } else {
            s.remove_file(entry.path).await?;
        }
    }
    Ok(())
}

async fn plan_removal(s: &SftpSession, path: String) -> Result<Vec<Removal>> {
    // Every parent is added before its children, so reversing the plan empties
    // each directory before removing it.
    let mut plan = vec![Removal { path, directory_depth: Some(0) }];
    let mut next = 0;
    while let Some(entry) = plan.get(next) {
        next += 1;
        let Some(depth) = entry.directory_depth else { continue };
        check_remove_depth(depth)?;
        let path = entry.path.clone();
        for child in s.read_dir(path.clone()).await? {
            let name = child.file_name();
            if name == "." || name == ".." {
                continue;
            }
            ensure!(
                plan.len() < MAX_REMOVE_ENTRIES,
                "Удаление SFTP остановлено: превышен лимит числа записей ({MAX_REMOVE_ENTRIES})"
            );
            plan.push(Removal {
                path: format!("{}/{}", path.trim_end_matches('/'), name),
                directory_depth: child.file_type().is_dir().then_some(depth + 1),
            });
        }
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::{
        protocol::{File, Handle, Name, Status, StatusCode},
        server::{self, Handler},
    };
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    struct DirectoryFixture {
        directories: HashMap<String, Vec<File>>,
        removed: Arc<Mutex<Vec<String>>>,
    }

    fn success(id: u32) -> Status {
        Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: String::new(),
        }
    }

    impl Handler for DirectoryFixture {
        type Error = StatusCode;

        fn unimplemented(&self) -> Self::Error {
            StatusCode::OpUnsupported
        }

        async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
            if self.directories.contains_key(&path) {
                Ok(Handle { id, handle: path })
            } else {
                Err(StatusCode::NoSuchFile)
            }
        }

        async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
            let files = self.directories.remove(&handle).ok_or(StatusCode::Eof)?;
            Ok(Name { id, files })
        }

        async fn close(&mut self, id: u32, _: String) -> Result<Status, Self::Error> {
            Ok(success(id))
        }

        async fn remove(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
            self.removed.lock().unwrap().push(path);
            Ok(success(id))
        }

        async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
            self.removed.lock().unwrap().push(path);
            Ok(success(id))
        }
    }

    async fn fixture_session(depth: usize) -> (SftpSession, Arc<Mutex<Vec<String>>>) {
        let mut directories = HashMap::new();
        let mut path = "/selected".to_string();
        for level in 0..=depth {
            let mut files = vec![File::dummy("notes.txt")];
            if level < depth {
                let mut child = File::dummy("child");
                child.attrs.set_dir(true);
                files.push(child);
            }
            directories.insert(path.clone(), files);
            path.push_str("/child");
        }
        let removed = Arc::new(Mutex::new(Vec::new()));
        let (client, peer) = tokio::io::duplex(4096);
        server::run(peer, DirectoryFixture { directories, removed: removed.clone() }).await;
        (SftpSession::new(client).await.unwrap(), removed)
    }

    #[tokio::test]
    async fn plans_nested_removals_before_deleting() {
        let (s, removed) = fixture_session(1).await;
        remove(&s, "/selected".into(), true).await.unwrap();
        assert_eq!(
            *removed.lock().unwrap(),
            ["/selected/child/notes.txt", "/selected/child", "/selected/notes.txt", "/selected"]
        );

        let (s, removed) = fixture_session(MAX_REMOVE_DEPTH + 1).await;
        let err = remove(&s, "/selected".into(), true).await.unwrap_err();
        assert!(err.to_string().contains("допустимая глубина"));
        assert!(removed.lock().unwrap().is_empty());
    }

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
