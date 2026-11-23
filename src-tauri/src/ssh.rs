//! SSH session: connection, authentication, interactive shell, SFTP and port forwards.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use russh::{
    client::{self, KeyboardInteractiveAuthResponse},
    keys::{
        load_secret_key,
        ssh_key::{EcdsaCurve, HashAlg, PublicKey},
        Algorithm, PrivateKeyWithHashAlg, PublicKeyOrCertificate,
    },
    cipher, kex, mac, ChannelMsg, ChannelOpenFailure, Disconnect, Preferred,
};
use russh_sftp::client::SftpSession;
use serde::Serialize;
use tauri::ipc::Channel as IpcChannel;
use tokio::{
    sync::{mpsc, Mutex},
    task::JoinHandle,
};

use crate::{
    error::{AuthFailed, HostKeyProblem},
    forward,
    known_hosts::{KeyCheck, KnownHosts},
    store::{AuthMethod, ForwardKind, Host},
};

/// Algorithms offered to the server, pinned here instead of relying on russh
/// defaults: no SHA-1 (`ssh-rsa` host key signatures, hmac-sha1), no CBC,
/// no legacy DH groups; strict-kex (Terrapin) is always offered.
fn preferred_algorithms() -> Preferred {
    Preferred {
        kex: std::borrow::Cow::Borrowed(&[
            kex::MLKEM768X25519_SHA256,
            kex::CURVE25519,
            kex::CURVE25519_PRE_RFC_8731,
            kex::DH_GEX_SHA256,
            kex::DH_G18_SHA512,
            kex::DH_G17_SHA512,
            kex::DH_G16_SHA512,
            kex::DH_G15_SHA512,
            kex::DH_G14_SHA256,
            kex::EXTENSION_SUPPORT_AS_CLIENT,
            kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
        ]),
        key: std::borrow::Cow::Borrowed(&[
            Algorithm::Ed25519,
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 },
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 },
            Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
            Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
        ]),
        cipher: std::borrow::Cow::Borrowed(&[
            cipher::CHACHA20_POLY1305,
            cipher::AES_256_GCM,
            cipher::AES_256_CTR,
            cipher::AES_192_CTR,
            cipher::AES_128_CTR,
        ]),
        mac: std::borrow::Cow::Borrowed(&[
            mac::HMAC_SHA512_ETM,
            mac::HMAC_SHA256_ETM,
            mac::HMAC_SHA512,
            mac::HMAC_SHA256,
        ]),
        ..Preferred::DEFAULT
    }
}

/// Remote (-R) forwards: server-side port -> local target.
pub type RemoteMap = Arc<StdMutex<HashMap<u32, (String, u16)>>>;

pub struct Handler {
    host: String,
    port: u16,
    known: Arc<KnownHosts>,
    problem: Arc<StdMutex<Option<HostKeyProblem>>>,
    remote: RemoteMap,
}

impl client::Handler for Handler {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, server_key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let key: PublicKey = server_key.public_key();
        let check = self.known.check(&self.host, self.port, &key)?;
        if let KeyCheck::Match = check {
            return Ok(true);
        }
        *self.problem.lock().unwrap() = Some(HostKeyProblem {
            mismatch: matches!(check, KeyCheck::Mismatch),
            host: self.host.clone(),
            port: self.port,
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            key_line: key.to_openssh()?,
        });
        Ok(false)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let target = self.remote.lock().unwrap().get(&connected_port).cloned();
        let Some((host, port)) = target else {
            reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        };
        reply.accept().await;
        {
            tokio::spawn(async move {
                if let Ok(mut tcp) = tokio::net::TcpStream::connect((host.as_str(), port)).await {
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
                }
            });
        }
        Ok(())
    }

    // The server may try to open channels we never asked for. russh accepts
    // them by default; we never use them, so refuse them outright.

    async fn server_channel_open_agent_forward(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _socket_path: &str,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _socket_path: &str,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }
}

pub type SshHandle = client::Handle<Handler>;

pub enum ShellCmd {
    Input(Vec<u8>),
    Resize(u32, u32),
}

#[derive(Serialize, Clone)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ShellEvent {
    /// Base64-encoded terminal output.
    Data { data: String },
    Exit { code: u32 },
    Closed { reason: Option<String> },
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ForwardStatus {
    pub id: String,
    pub description: String,
    pub ok: bool,
    pub error: Option<String>,
}

pub struct Session {
    handle: Arc<SshHandle>,
    shell_tx: mpsc::UnboundedSender<ShellCmd>,
    sftp: Mutex<Option<Arc<SftpSession>>>,
    tasks: StdMutex<Vec<JoinHandle<()>>>,
}

impl Session {
    pub async fn connect(
        host: &Host,
        secret: Option<String>,
        known: Arc<KnownHosts>,
        cols: u32,
        rows: u32,
        events: IpcChannel<ShellEvent>,
    ) -> Result<(Arc<Session>, Vec<ForwardStatus>)> {
        let config = Arc::new(client::Config {
            inactivity_timeout: None,
            keepalive_interval: Some(Duration::from_secs(20)),
            keepalive_max: 3,
            preferred: preferred_algorithms(),
            ..Default::default()
        });
        let problem = Arc::new(StdMutex::new(None));
        let remote: RemoteMap = Default::default();
        let handler = Handler {
            host: host.hostname.clone(),
            port: host.port,
            known,
            problem: problem.clone(),
            remote: remote.clone(),
        };

        let connecting = client::connect(config, (host.hostname.as_str(), host.port), handler);
        let mut handle = match tokio::time::timeout(Duration::from_secs(15), connecting).await {
            Err(_) => bail!("Таймаут подключения к {}:{}", host.hostname, host.port),
            Ok(Err(e)) => {
                if let Some(p) = problem.lock().unwrap().take() {
                    return Err(p.into());
                }
                return Err(e.context(format!(
                    "Не удалось подключиться к {}:{}",
                    host.hostname, host.port
                )));
            }
            Ok(Ok(h)) => h,
        };

        // A stalled server must not leave the tab "connecting" forever.
        tokio::time::timeout(Duration::from_secs(60), authenticate(&mut handle, host, secret))
            .await
            .map_err(|_| anyhow!("Таймаут аутентификации"))??;

        let mut statuses = Vec::new();

        // Remote forwards need &mut handle, so set them up before sharing it.
        for f in host.forwards.iter().filter(|f| f.kind == ForwardKind::Remote) {
            let res = handle
                .tcpip_forward(f.bind_host.clone(), f.bind_port as u32)
                .await;
            match res {
                Ok(assigned) => {
                    let port = if f.bind_port == 0 { assigned } else { f.bind_port as u32 };
                    remote
                        .lock()
                        .unwrap()
                        .insert(port, (f.target_host.clone(), f.target_port));
                    statuses.push(status(f, None));
                }
                Err(e) => statuses.push(status(f, Some(e.to_string()))),
            }
        }

        let channel = tokio::time::timeout(Duration::from_secs(30), async {
            let channel = handle.channel_open_session().await?;
            channel
                .request_pty(false, "xterm-256color", cols, rows, 0, 0, &[])
                .await?;
            channel.request_shell(false).await?;
            anyhow::Ok(channel)
        })
        .await
        .map_err(|_| anyhow!("Таймаут открытия сессии"))??;

        let handle = Arc::new(handle);
        let (shell_tx, shell_rx) = mpsc::unbounded_channel();
        let mut tasks = vec![tokio::spawn(shell_loop(channel, shell_rx, events))];

        for f in host.forwards.iter().filter(|f| f.kind != ForwardKind::Remote) {
            match forward::start(handle.clone(), f).await {
                Ok(task) => {
                    tasks.push(task);
                    statuses.push(status(f, None));
                }
                Err(e) => statuses.push(status(f, Some(format!("{e:#}")))),
            }
        }

        let session = Arc::new(Session {
            handle,
            shell_tx,
            sftp: Mutex::new(None),
            tasks: StdMutex::new(tasks),
        });
        Ok((session, statuses))
    }

    pub fn write(&self, data: Vec<u8>) -> Result<()> {
        self.shell_tx
            .send(ShellCmd::Input(data))
            .map_err(|_| anyhow!("Сессия закрыта"))
    }

    pub fn resize(&self, cols: u32, rows: u32) {
        let _ = self.shell_tx.send(ShellCmd::Resize(cols, rows));
    }

    pub async fn sftp(&self) -> Result<Arc<SftpSession>> {
        let mut guard = self.sftp.lock().await;
        if let Some(s) = guard.as_ref() {
            return Ok(s.clone());
        }
        let channel = self.handle.channel_open_session().await?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .context("Сервер не поддерживает SFTP")?;
        let sftp = Arc::new(
            SftpSession::new(channel.into_stream())
                .await
                .context("Не удалось открыть SFTP")?,
        );
        *guard = Some(sftp.clone());
        Ok(sftp)
    }

    pub async fn close(&self) {
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
    }
}

fn status(f: &crate::store::Forward, error: Option<String>) -> ForwardStatus {
    ForwardStatus {
        id: f.id.clone(),
        description: f.describe(),
        ok: error.is_none(),
        error,
    }
}

fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~") {
        if let Some(home) = std::env::var_os("USERPROFILE") {
            return PathBuf::from(home).join(rest.trim_start_matches(['/', '\\']));
        }
    }
    PathBuf::from(path)
}

async fn authenticate(handle: &mut SshHandle, host: &Host, secret: Option<String>) -> Result<()> {
    let user = host.username.clone();
    match host.auth {
        AuthMethod::Password => {
            let Some(password) = secret else {
                return Err(AuthFailed("Нужен пароль".into()).into());
            };
            if handle
                .authenticate_password(user.clone(), password.clone())
                .await?
                .success()
            {
                return Ok(());
            }
            // Many servers only allow keyboard-interactive for passwords.
            let mut resp = handle
                .authenticate_keyboard_interactive_start(user.clone(), None::<String>)
                .await?;
            for _ in 0..5 {
                match resp {
                    KeyboardInteractiveAuthResponse::Success => return Ok(()),
                    KeyboardInteractiveAuthResponse::Failure { .. } => break,
                    KeyboardInteractiveAuthResponse::InfoRequest { ref prompts, .. } => {
                        // Only hidden (no-echo) prompts get the password; visible ones
                        // ("Verification code:", "Username:") must never receive it.
                        let answers = prompts
                            .iter()
                            .map(|p| if p.echo { String::new() } else { password.clone() })
                            .collect();
                        resp = handle
                            .authenticate_keyboard_interactive_respond(answers)
                            .await?;
                    }
                }
            }
            Err(AuthFailed("Неверное имя пользователя или пароль".into()).into())
        }
        AuthMethod::Key => {
            let path = host
                .key_path
                .as_deref()
                .filter(|p| !p.trim().is_empty())
                .ok_or_else(|| anyhow!("Не указан файл приватного ключа"))?;
            let path = expand_home(path.trim());
            if !path.exists() {
                bail!("Файл ключа не найден: {}", path.display());
            }
            let key = match load_secret_key(&path, secret.as_deref()) {
                Ok(k) => k,
                Err(e) => {
                    let msg = if secret.is_none() {
                        "Ключ зашифрован — нужна парольная фраза".to_string()
                    } else {
                        format!("Не удалось расшифровать ключ: {e}")
                    };
                    return Err(AuthFailed(msg).into());
                }
            };
            let hash = handle.best_supported_rsa_hash().await?.flatten();
            let ok = handle
                .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                .await?
                .success();
            if ok {
                Ok(())
            } else {
                bail!("Сервер отклонил ключ для пользователя {}", host.username)
            }
        }
    }
}

async fn shell_loop(
    mut channel: russh::Channel<client::Msg>,
    mut rx: mpsc::UnboundedReceiver<ShellCmd>,
    events: IpcChannel<ShellEvent>,
) {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut reason = None;
    loop {
        tokio::select! {
            msg = channel.wait() => match msg {
                Some(ChannelMsg::Data { ref data }) | Some(ChannelMsg::ExtendedData { ref data, .. }) => {
                    let _ = events.send(ShellEvent::Data { data: b64.encode(&data[..]) });
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    let _ = events.send(ShellEvent::Exit { code: exit_status });
                }
                Some(ChannelMsg::Close) | None => break,
                _ => {}
            },
            cmd = rx.recv() => match cmd {
                Some(ShellCmd::Input(bytes)) => {
                    if let Err(e) = channel.data(&bytes[..]).await {
                        reason = Some(e.to_string());
                        break;
                    }
                }
                Some(ShellCmd::Resize(cols, rows)) => {
                    let _ = channel.window_change(cols, rows, 0, 0).await;
                }
                None => {
                    let _ = channel.close().await;
                    break;
                }
            }
        }
    }
    let _ = events.send(ShellEvent::Closed { reason });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_weak_algorithms_offered() {
        let p = preferred_algorithms();
        for name in p.kex.iter().map(|n| n.as_ref())
            .chain(p.cipher.iter().map(|n| n.as_ref()))
            .chain(p.mac.iter().map(|n| n.as_ref()))
        {
            let n = name.to_ascii_lowercase();
            assert!(!n.contains("cbc") && !n.contains("sha1") && !n.ends_with("-sha1@openssh.com"), "{name}");
            assert!(!n.contains("group1-") && !n.contains("group-exchange-sha1"), "{name}");
        }
        assert!(p.kex.contains(&kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT));
        assert!(!p.key.contains(&Algorithm::Rsa { hash: None }), "ssh-rsa (SHA-1) must not be offered");
    }
}
