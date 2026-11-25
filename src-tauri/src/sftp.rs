use anyhow::{ensure, Context, Result};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use serde::Serialize;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncWriteExt};

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
        .filter(|e| is_remote_name(&e.file_name()))
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

pub async fn download(s: &SftpSession, remote: &str, local: &str, overwrite: bool) -> Result<()> {
    check_local_target(local)?;
    let mut src = s.open(remote).await.context("Не удалось открыть удалённый файл")?;
    save_download(&mut src, Path::new(local), overwrite).await
}

async fn save_download(
    src: &mut (impl AsyncRead + Unpin),
    local: &Path,
    overwrite: bool,
) -> Result<()> {
    let parent = local.parent().context("Не найдена локальная папка назначения")?;
    let (file, temporary) = tempfile::NamedTempFile::new_in(parent)
        .context("Не удалось создать временный файл в папке назначения")?
        .into_parts();
    let mut dst = tokio::fs::File::from_std(file);
    tokio::io::copy(src, &mut dst).await.context("Скачивание прервано")?;
    dst.sync_all().await.context("Не удалось сохранить скачанные данные")?;
    drop(dst);
    if overwrite {
        temporary.persist(local)
    } else {
        temporary.persist_noclobber(local)
    }
    .with_context(|| format!("Не удалось сохранить {}", local.display()))?;
    Ok(())
}

pub async fn upload(s: &SftpSession, local: &str, remote: &str) -> Result<()> {
    let mut src = tokio::fs::File::open(local)
        .await
        .context("Не удалось открыть локальный файл")?;
    if src.metadata().await?.is_dir() {
        anyhow::bail!("Загрузка папок пока не поддерживается");
    }
    save_upload(s, &mut src, remote).await
}

async fn save_upload(
    s: &SftpSession,
    src: &mut (impl AsyncRead + Unpin),
    remote: &str,
) -> Result<()> {
    let name_start = remote.rfind('/').map_or(0, |separator| separator + 1);
    let (prefix, name) = remote.split_at(name_start);
    ensure!(is_remote_name(name), "Недопустимое имя удалённого файла");
    let temporary = format!("{prefix}.cluent-{}.part", uuid::Uuid::new_v4());
    let dst = s
        .open_with_flags(&temporary, OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE)
        .await
        .context("Не удалось создать временный файл на сервере")?;
    if let Err(error) = finish_upload(s, src, dst, &temporary, remote).await {
        if let Err(cleanup) = s.remove_file(&temporary).await {
            return Err(error.context(format!(
                "Не удалось удалить временный файл {temporary}: {cleanup}"
            )));
        }
        return Err(error);
    }
    Ok(())
}

async fn finish_upload(
    s: &SftpSession,
    src: &mut (impl AsyncRead + Unpin),
    mut dst: russh_sftp::client::fs::File,
    temporary: &str,
    remote: &str,
) -> Result<()> {
    let transfer = tokio::io::copy(src, &mut dst).await;
    let closed = dst.shutdown().await;
    transfer.context("Загрузка прервана")?;
    closed.context("Не удалось закрыть файл на сервере")?;
    // The standard SFTP v3 rename refuses an existing destination.
    s.rename(temporary, remote)
        .await
        .with_context(|| format!("Не удалось сохранить {remote}. Проверьте имя и права доступа"))
}

fn is_remote_name(name: &str) -> bool {
    !matches!(name, "" | "." | "..") && !name.contains(['/', '\0'])
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
    check_removal_root(s, &path).await?;
    let plan = plan_removal(s, path.clone()).await?;
    check_removal_root(s, &path).await?;
    for entry in plan.into_iter().rev() {
        if entry.directory_depth.is_some() {
            s.remove_dir(entry.path).await?;
        } else {
            s.remove_file(entry.path).await?;
        }
    }
    Ok(())
}

async fn check_removal_root(s: &SftpSession, path: &str) -> Result<()> {
    let metadata = s
        .symlink_metadata(path)
        .await
        .context("Не удалось проверить папку для удаления")?;
    ensure!(metadata.file_type().is_dir(), "Объект больше не является папкой");
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
            ensure!(is_remote_name(&name), "Сервер вернул недопустимое имя файла");
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
        protocol::{Attrs, File, FileAttributes, Handle, Name, Status, StatusCode},
        server::{self, Handler},
    };
    use std::{
        collections::HashMap,
        io,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context as TaskContext, Poll},
    };

    struct DirectoryFixture {
        directories: HashMap<String, Vec<File>>,
        removed: Arc<Mutex<Vec<String>>>,
        root_is_dir: bool,
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

        async fn lstat(&mut self, id: u32, _: String) -> Result<Attrs, Self::Error> {
            let mut attrs = FileAttributes::default();
            if self.root_is_dir {
                attrs.set_dir(true);
            } else {
                attrs.set_regular(true);
            }
            Ok(Attrs { id, attrs })
        }
    }

    async fn fixture_session(depth: usize) -> (SftpSession, Arc<Mutex<Vec<String>>>) {
        let mut directories = HashMap::new();
        let mut path = "/selected".to_string();
        for level in 0..=depth {
            let mut attrs = FileAttributes::default();
            attrs.set_regular(true);
            let mut files = vec![File::new("notes.txt", attrs)];
            if level < depth {
                let mut child = File::dummy("child");
                child.attrs.set_dir(true);
                files.push(child);
            }
            directories.insert(path.clone(), files);
            path.push_str("/child");
        }
        directory_session(directories, true).await
    }

    async fn directory_session(
        directories: HashMap<String, Vec<File>>,
        root_is_dir: bool,
    ) -> (SftpSession, Arc<Mutex<Vec<String>>>) {
        let removed = Arc::new(Mutex::new(Vec::new()));
        let (client, peer) = tokio::io::duplex(4096);
        server::run(peer, DirectoryFixture { directories, removed: removed.clone(), root_is_dir }).await;
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

    #[tokio::test]
    async fn refuses_recursive_delete_with_invalid_listing_or_changed_root_type() {
        let directories = HashMap::from([("/selected".into(), vec![File::dummy("invalid/name")])]);
        let (s, removed) = directory_session(directories, true).await;
        let err = remove(&s, "/selected".into(), true).await.unwrap_err();
        assert!(err.to_string().contains("недопустимое имя файла"));
        assert!(removed.lock().unwrap().is_empty());

        let (s, removed) = directory_session(HashMap::new(), false).await;
        let err = remove(&s, "/selected".into(), true).await.unwrap_err();
        assert!(err.to_string().contains("не является папкой"));
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

    struct InterruptedRead(bool);

    impl AsyncRead for InterruptedRead {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if std::mem::replace(&mut self.0, true) {
                Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
            } else {
                buf.put_slice(b"partial");
                Poll::Ready(Ok(()))
            }
        }
    }

    #[tokio::test]
    async fn downloads_preserve_existing_file_on_collision_or_interruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.txt");
        std::fs::write(&path, b"original").unwrap();
        let case_variant = dir.path().join("NOTES.txt");
        if case_variant.exists() {
            assert!(save_download(&mut &b"new"[..], &case_variant, false).await.is_err());
        }
        assert!(save_download(&mut &b"new"[..], &path, false).await.is_err());
        assert!(save_download(&mut InterruptedRead(false), &path, true).await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");

        let absent = dir.path().join("other.txt");
        assert!(save_download(&mut InterruptedRead(false), &absent, false).await.is_err());
        assert!(!absent.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        save_download(&mut &b"new"[..], &path, true).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        save_download(&mut &b"second"[..], &absent, false).await.unwrap();
        assert_eq!(std::fs::read(&absent).unwrap(), b"second");
    }

    struct UploadFixture(Arc<Mutex<HashMap<String, Vec<u8>>>>);

    impl Handler for UploadFixture {
        type Error = StatusCode;

        fn unimplemented(&self) -> Self::Error {
            StatusCode::OpUnsupported
        }

        async fn open(
            &mut self, id: u32, path: String, flags: OpenFlags, _: FileAttributes,
        ) -> Result<Handle, Self::Error> {
            assert!(flags.contains(OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE));
            let mut files = self.0.lock().unwrap();
            if files.contains_key(&path) {
                return Err(StatusCode::Failure);
            }
            files.insert(path.clone(), Vec::new());
            Ok(Handle { id, handle: path })
        }

        async fn write(
            &mut self, id: u32, path: String, offset: u64, data: Vec<u8>,
        ) -> Result<Status, Self::Error> {
            let mut files = self.0.lock().unwrap();
            let file = files.get_mut(&path).ok_or(StatusCode::NoSuchFile)?;
            assert_eq!(offset, file.len() as u64);
            file.extend(data);
            Ok(success(id))
        }

        async fn close(&mut self, id: u32, _: String) -> Result<Status, Self::Error> {
            Ok(success(id))
        }

        async fn rename(&mut self, id: u32, from: String, to: String) -> Result<Status, Self::Error> {
            let mut files = self.0.lock().unwrap();
            assert_eq!(from.rsplit_once('/').unwrap().0, to.rsplit_once('/').unwrap().0);
            if files.contains_key(&to) {
                return Err(StatusCode::Failure);
            }
            let data = files.remove(&from).ok_or(StatusCode::NoSuchFile)?;
            files.insert(to, data);
            Ok(success(id))
        }

        async fn remove(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
            self.0.lock().unwrap().remove(&path).ok_or(StatusCode::NoSuchFile)?;
            Ok(success(id))
        }
    }

    #[tokio::test]
    async fn uploads_only_publish_complete_files_and_keep_conflicting_destinations() {
        let files = Arc::new(Mutex::new(HashMap::from([("/dir/notes.txt".into(), b"original".to_vec())])));
        let (client, peer) = tokio::io::duplex(4096);
        server::run(peer, UploadFixture(files.clone())).await;
        let s = SftpSession::new(client).await.unwrap();

        assert!(save_upload(&s, &mut InterruptedRead(false), "/dir/other.txt").await.is_err());
        assert!(save_upload(&s, &mut &b"new"[..], "/dir/notes.txt").await.is_err());
        assert_eq!(*files.lock().unwrap(), HashMap::from([("/dir/notes.txt".into(), b"original".to_vec())]));
        save_upload(&s, &mut &b"new"[..], "/dir/other.txt").await.unwrap();
        let files = files.lock().unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files["/dir/other.txt"], b"new");
    }
}
