mod error;
mod forward;
mod known_hosts;
mod sftp;
mod ssh;
mod store;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use error::{CmdError, CmdResult};
use serde::Serialize;
use tauri::{ipc::Channel, Manager, State};

struct AppState {
    store: store::Store,
    known: Arc<known_hosts::KnownHosts>,
    sessions: Mutex<HashMap<String, Arc<ssh::Session>>>,
}

impl AppState {
    fn session(&self, id: &str) -> CmdResult<Arc<ssh::Session>> {
        self.sessions
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| CmdError::Message {
                message: "Сессия не найдена или уже закрыта".into(),
            })
    }
}

#[tauri::command]
fn hosts_list(state: State<'_, AppState>) -> CmdResult<Vec<store::HostView>> {
    Ok(state.store.list()?)
}

#[tauri::command]
fn host_save(
    state: State<'_, AppState>,
    host: store::Host,
    secret: Option<String>,
) -> CmdResult<store::Host> {
    Ok(state.store.upsert(host, secret)?)
}

#[tauri::command]
fn host_delete(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    Ok(state.store.delete(&id)?)
}

#[tauri::command]
fn known_hosts_trust(
    state: State<'_, AppState>,
    host: String,
    port: u16,
    key_line: String,
) -> CmdResult<()> {
    Ok(state.known.trust(&host, port, &key_line)?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectResult {
    session_id: String,
    forwards: Vec<ssh::ForwardStatus>,
}

#[tauri::command]
async fn ssh_connect(
    state: State<'_, AppState>,
    host_id: String,
    cols: u32,
    rows: u32,
    secret: Option<String>,
    on_event: Channel<ssh::ShellEvent>,
) -> CmdResult<ConnectResult> {
    let host = state.store.get(&host_id)?;
    let secret = secret.or_else(|| store::get_secret(&host.id));
    let (session, forwards) =
        ssh::Session::connect(&host, secret, state.known.clone(), cols, rows, on_event).await?;
    let session_id = uuid::Uuid::new_v4().to_string();
    state
        .sessions
        .lock()
        .unwrap()
        .insert(session_id.clone(), session);
    Ok(ConnectResult {
        session_id,
        forwards,
    })
}

/// Synchronous on purpose: runs on the main thread, so keystrokes keep their order.
#[tauri::command]
fn ssh_write(state: State<'_, AppState>, session_id: String, data: Vec<u8>) -> CmdResult<()> {
    Ok(state.session(&session_id)?.write(data)?)
}

#[tauri::command]
fn ssh_resize(state: State<'_, AppState>, session_id: String, cols: u32, rows: u32) -> CmdResult<()> {
    state.session(&session_id)?.resize(cols, rows);
    Ok(())
}

#[tauri::command]
async fn ssh_disconnect(state: State<'_, AppState>, session_id: String) -> CmdResult<()> {
    let session = state.sessions.lock().unwrap().remove(&session_id);
    if let Some(s) = session {
        s.close().await;
    }
    Ok(())
}

/// Called when the UI (re)loads: any session still alive has no tab anymore.
#[tauri::command]
async fn ssh_disconnect_all(state: State<'_, AppState>) -> CmdResult<()> {
    let sessions: Vec<_> = state.sessions.lock().unwrap().drain().map(|(_, s)| s).collect();
    for s in sessions {
        s.close().await;
    }
    Ok(())
}

#[tauri::command]
async fn sftp_list(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
) -> CmdResult<sftp::Listing> {
    let s = state.session(&session_id)?.sftp().await?;
    Ok(sftp::list(&s, &path).await?)
}

#[tauri::command]
async fn sftp_download(
    state: State<'_, AppState>,
    session_id: String,
    remote: String,
    local: String,
) -> CmdResult<()> {
    let s = state.session(&session_id)?.sftp().await?;
    Ok(sftp::download(&s, &remote, &local).await?)
}

#[tauri::command]
async fn sftp_upload(
    state: State<'_, AppState>,
    session_id: String,
    local: String,
    remote: String,
) -> CmdResult<()> {
    let s = state.session(&session_id)?.sftp().await?;
    Ok(sftp::upload(&s, &local, &remote).await?)
}

#[tauri::command]
async fn sftp_mkdir(state: State<'_, AppState>, session_id: String, path: String) -> CmdResult<()> {
    let s = state.session(&session_id)?.sftp().await?;
    s.create_dir(path).await.map_err(anyhow::Error::from)?;
    Ok(())
}

#[tauri::command]
async fn sftp_remove(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
    is_dir: bool,
) -> CmdResult<()> {
    let s = state.session(&session_id)?.sftp().await?;
    Ok(sftp::remove(&s, path, is_dir).await?)
}

#[tauri::command]
async fn sftp_rename(
    state: State<'_, AppState>,
    session_id: String,
    from: String,
    to: String,
) -> CmdResult<()> {
    let s = state.session(&session_id)?.sftp().await?;
    s.rename(from, to).await.map_err(anyhow::Error::from)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            app.manage(AppState {
                store: store::Store::new(dir.join("hosts.json")),
                known: Arc::new(known_hosts::KnownHosts::new(dir.join("known_hosts"))),
                sessions: Mutex::new(HashMap::new()),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            hosts_list,
            host_save,
            host_delete,
            known_hosts_trust,
            ssh_connect,
            ssh_write,
            ssh_resize,
            ssh_disconnect,
            ssh_disconnect_all,
            sftp_list,
            sftp_download,
            sftp_upload,
            sftp_mkdir,
            sftp_remove,
            sftp_rename,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Cluent");
}
