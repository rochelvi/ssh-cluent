//! Local (-L) and dynamic SOCKS5 (-D) port forwarding.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use crate::{
    ssh::SshHandle,
    store::{Forward, ForwardKind},
};

pub async fn start(handle: Arc<SshHandle>, f: &Forward) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind((f.bind_host.as_str(), f.bind_port))
        .await
        .with_context(|| format!("Не удалось занять порт {}:{}", f.bind_host, f.bind_port))?;
    let kind = f.kind;
    let target = (f.target_host.clone(), f.target_port);

    Ok(tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let handle = handle.clone();
            let target = target.clone();
            tokio::spawn(async move {
                let _ = match kind {
                    ForwardKind::Dynamic => socks5(sock, handle).await,
                    _ => direct(sock, handle, &target.0, target.1).await,
                };
            });
        }
    }))
}

async fn direct(mut sock: TcpStream, handle: Arc<SshHandle>, host: &str, port: u16) -> Result<()> {
    let peer = sock.peer_addr()?;
    let channel = handle
        .channel_open_direct_tcpip(host, port as u32, peer.ip().to_string(), peer.port() as u32)
        .await?;
    let mut stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut sock, &mut stream).await?;
    Ok(())
}

/// Minimal SOCKS5 server: no auth, CONNECT only.
async fn socks5(mut sock: TcpStream, handle: Arc<SshHandle>) -> Result<()> {
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 5 {
        bail!("not SOCKS5");
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        sock.write_all(&[5, 0xff]).await?;
        bail!("no acceptable auth method");
    }
    sock.write_all(&[5, 0]).await?;

    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[1] != 1 {
        sock.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        bail!("only CONNECT is supported");
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            String::from_utf8(name)?
        }
        4 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        _ => bail!("bad address type"),
    };
    let mut p = [0u8; 2];
    sock.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);

    let peer = sock.peer_addr()?;
    match handle
        .channel_open_direct_tcpip(host, port as u32, peer.ip().to_string(), peer.port() as u32)
        .await
    {
        Ok(channel) => {
            sock.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            let mut stream = channel.into_stream();
            tokio::io::copy_bidirectional(&mut sock, &mut stream).await?;
            Ok(())
        }
        Err(e) => {
            sock.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            Err(e.into())
        }
    }
}
