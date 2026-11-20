use anyhow::{Context, Result};
use russh_sftp::client::SftpSession;
use serde::Serialize;
use std::{future::Future, pin::Pin};
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

pub async fn download(s: &SftpSession, remote: &str, local: &str) -> Result<()> {
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

pub fn remove<'a>(
    s: &'a SftpSession,
    path: String,
    is_dir: bool,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        if !is_dir {
            s.remove_file(path).await?;
            return Ok(());
        }
        for e in s.read_dir(path.clone()).await? {
            let name = e.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let child = format!("{}/{}", path.trim_end_matches('/'), name);
            remove(s, child, e.file_type().is_dir()).await?;
        }
        s.remove_dir(path).await?;
        Ok(())
    })
}
