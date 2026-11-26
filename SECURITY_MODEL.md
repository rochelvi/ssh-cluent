# Cluent (rochelvi/ssh-cluent) threat model

Status: built from the code (release 0.1.2) and README, with the owner's answers marked "User:". Updated 2026-11-25 from the 2026-11-23 version. User: there is no infrastructure repository (desktop app), so none was used.

## System overview

Cluent is a single-user, offline SSH/SFTP client for Windows. It is a Tauri 2 desktop app with a Rust backend (`russh` 0.65, `russh-sftp` 3, tokio) and a framework-free TypeScript UI using xterm.js 5. There is no backend service, no accounts, no telemetry and no auto-update (`src-tauri/Cargo.toml`, `README.md`). The only network traffic comes from SSH connections the user starts and from the port forwards they configure. Passwords and key passphrases are never stored. They are asked for on each connect and kept in memory only. Secrets saved by older versions in Windows Credential Manager (service `ssh-cluent`) are purged at startup (`store.rs` `purge_legacy_secrets`).

## Components

| Component | Code | Role |
|---|---|---|
| UI | `src/`, `index.html` | Webview: host list, terminal (xterm.js), SFTP panel, dialogs, paste handling |
| IPC | `src-tauri/src/lib.rs`, `src-tauri/capabilities/default.json`, `src-tauri/tauri.conf.json` | 18 Tauri commands the webview can call; CSP and plugin permissions |
| SSH | `src-tauri/src/ssh.rs`, `src-tauri/src/known_hosts.rs` | Connection, algorithms, host key check (TOFU), authentication, shell channel |
| SFTP | `src-tauri/src/sftp.rs` | Remote listing, upload, download to local disk, recursive remove, rename |
| Forwarding | `src-tauri/src/forward.rs`, `server_channel_open_forwarded_tcpip` in `ssh.rs` | `-L`, `-R` and SOCKS5 `-D` listeners and tunnels |
| Storage | `src-tauri/src/store.rs`, `src-tauri/src/settings.rs`, `src-tauri/src/ssh_config.rs`, `src-tauri/src/local_path.rs` | `hosts.json`, `settings.json`, `~/.ssh/config` import, local path policy |

## Trust boundaries

1. Remote SSH server to client. Everything the server sends is untrusted: terminal output and escape sequences, SFTP names, metadata and listings, keyboard-interactive prompts, server-opened channels and protocol messages.
2. Network to client. Until the host key is verified, a network attacker can act as the server.
3. Webview to Rust. The webview renders server-controlled data. All commands in `lib.rs` take ids, paths and bytes from it. `sftp_download` and `sftp_upload` take local paths, and `ssh_config_preview` reads a local file the user chose.
4. Local machine to app. This covers files in `%APPDATA%\app.cluent.desktop\` (`hosts.json`, `settings.json`, `known_hosts`), imported ssh config files and their `Include`s, private key files, and the clipboard. It also covers local TCP listeners opened by forwards: any local process can reach them, and so can the LAN when they bind to a non-loopback address.
5. Dependencies: crates and npm packages (`Cargo.lock`, `package-lock.json`).

## Entry points and who can reach them

- SSH protocol and channels: any server the user connects to, or a MITM before key trust (`ssh.rs` `Handler`).
- Terminal output into xterm.js: the server (`shell_loop` → base64 `ShellEvent::Data` → `src/session.ts`).
- SFTP listings and file contents: the server (`sftp.rs`, `src/sftp.ts`).
- Local forward and SOCKS5 listeners: local processes, and LAN hosts when `bindHost` is not loopback (`forward.rs`). SOCKS5 has no authentication.
- Remote forwards: anyone who can reach the server-side port. Their connections land on a local target (`server_channel_open_forwarded_tcpip`).
- ssh config import: the content of a file the user picks, including `Include` globs, `IdentityFile`, `*Forward` and `%` tokens (`ssh_config.rs`).
- Clipboard paste into the terminal (`src/session.ts` `paste`).
- Tauri IPC: only the app's own webview (`capabilities/default.json`: core, dialog, clipboard read/write text).

## Assets

- Passwords and key passphrases, held in memory during connect.
- Private key files referenced by `keyPath`.
- The local machine: files the user can write, code execution in the app or webview, and the user's Windows credential (NTLM via forced SMB authentication).
- Terminal session integrity: what gets typed into remote shells and what the user sees.
- Data privacy: anything that would expose the user's data (credentials, host list, session content, local files) to another party.
- Networks reachable through forwards: the local network via `-R`, the remote network via `-L`/`-D`.
- Host key trust state (`known_hosts`) and host definitions (`hosts.json`).

User: the assets that matter most are terminal session integrity (injected input, spoofed output) and data privacy.

## Attacker profiles

User: all of these attackers matter and none is ruled out.

- Malicious or compromised SSH server.
- Network attacker (MITM) on the path to a server.
- Other software or users on the same Windows machine (local listeners, app data files), and LAN hosts that can reach a forward bound to a non-loopback address.
- Author of a file the user imports (ssh config).
- Compromised dependency.

Who can get an account: not applicable. The app has no login.

## Existing controls

- Algorithms are pinned in `ssh.rs` `preferred_algorithms`: no SHA-1, no CBC, strict-kex, and `mlkem768x25519-sha256`. The test `no_weak_algorithms_offered` checks this.
- Host keys use TOFU with a SHA256 fingerprint prompt. A changed key, or a new key type for a known host, counts as a mismatch (`known_hosts.rs` `check`). `known_hosts_trust` validates the host name (`store::validate_hostname`) and re-serializes the key, so the key line cannot inject content into the file.
- Server-opened channels (agent, X11, session, direct-tcpip, streamlocal) are rejected. Forwarded-tcpip is accepted only for ports the user configured (`ssh.rs` `Handler`).
- Keyboard-interactive sends the password only to no-echo prompts, for at most 5 rounds (`ssh.rs` `authenticate`).
- Timeouts: 15 s for connect, 60 s for auth and 30 s for session open. Keepalive is set.
- Local path policy: `local_path.rs` `require_local_path` rejects UNC, device (`\\?\`, `\\.\`), drive-relative and non-local drive types. It applies to key paths (`Store::upsert`, `authenticate`), config `Include`/`IdentityFile` (`ssh_config.rs`) and download directories.
- SFTP download: the target must be absolute, contain no `..` and have a safe Windows file name (`sftp.rs` `check_local_target`, `is_safe_file_name`). The file is written to a temp file and persisted without overwriting (`save_download`). The UI also sanitizes names (`src/sftp.ts` `safeLocalName`). Server names that are unsafe are filtered from listings (`is_remote_name`).
- SFTP recursive remove: depth is capped by `MAX_REMOVE_DEPTH` (`check_remove_depth`).
- Paste: C0/C1 control characters are stripped, and a multi-line paste needs confirmation with a preview unless bracketed paste is on (`src/session.ts`).
- The DOM is built with `createElement`, `textContent` and `append` (`src/dom.ts` `h`). The CSP is `default-src 'self'; script-src 'self'; connect-src ipc: http://ipc.localhost` (`tauri.conf.json`).
- Host, user, label and forward fields are validated on save (`store.rs` `upsert`, `validate_hostname`). Forward `bind_host` defaults to `127.0.0.1`.
- Single instance (`tauri_plugin_single_instance`). Files are replaced atomically via temp file plus rename.
- `cargo audit` and `npm audit` run monthly and whenever a lock file changes (`.github/workflows/audit.yml`).

## Security Invariants

- **Host authentication (CWE-295, CWE-322).** A session proceeds only when `KnownHosts::check` returns `Match`. Otherwise `check_server_key` returns false and the UI asks the user to confirm the fingerprint. Trust is written only through `known_hosts_trust`, after the user confirms. A key of a different type for a known host must be treated as `Mismatch`, never as `Unknown`. Anti-pattern: accepting the key in `check_server_key` before the user decides, or matching host patterns loosely (wildcards, case folding) so that one entry vouches for another host.
- **Server-initiated channels (CWE-284).** Every `server_channel_open_*` handler rejects the channel, except forwarded-tcpip for a port present in `RemoteMap`. A new russh handler method that defaults to accept is a gap. Anti-pattern: enabling agent forwarding or X11, or accepting forwarded-tcpip for an unconfigured port.
- **Credential disclosure (CWE-522, CWE-200).** The password goes only to `authenticate_password` and to no-echo keyboard-interactive prompts. It is never written to disk, logs or error strings. Anti-pattern: answering echo prompts with the password, including the secret in `CmdError` messages, or persisting it in `hosts.json`.
- **Forced authentication and local path handling (CWE-73, CWE-522 NTLM leak).** Every filesystem access to a path taken from a config file, `hosts.json` or IPC passes `require_local_path` before `canonicalize`, `is_file`, `read_to_string`, `load_secret_key` or `exists`. Anti-pattern: calling `exists()`, `is_file()` or `canonicalize()` before the check, since each of these can start SMB authentication on Windows.
- **Path traversal on download (CWE-22).** Remote names are attacker-controlled. Local targets must pass `check_local_target`, and writes use `persist_noclobber`. Anti-pattern: joining a remote name to a local directory in Rust without `is_safe_file_name`, or relying only on `safeLocalName` in the UI.
- **Server-driven resource exhaustion (CWE-400, CWE-674).** Recursion and loops driven by server data are bounded: `MAX_REMOVE_DEPTH`, the keyboard-interactive round limit and the timeouts. Gap to check: listings, file downloads and terminal output have no size limits, and SOCKS5 parsing allocates per request.
- **XSS and webview code execution (CWE-79).** Server-, file- and clipboard-controlled strings are inserted only as text through `h()` children or `textContent`. The escape hatch is that `h()` assigns any prop for which `key in el` holds, so passing `innerHTML`/`outerHTML` as a prop, or calling `insertAdjacentHTML`, breaks the invariant. The CSP forbids inline script. Weakening `script-src` or adding `unsafe-eval` breaks it too.
- **Terminal escape injection (CWE-150).** Terminal output goes only to xterm.js, which interprets it. xterm must not be given addons that act on server-controlled sequences (links, OSC 52 clipboard write, file or URL open) without user confirmation. `allowProposedApi: true` is set in `src/session.ts`. Clipboard text is stripped of control characters before `term.paste`, and multi-line text needs confirmation unless bracketed paste is on.
- **Injection into stored formats (CWE-93, CWE-116).** `hosts.json`, `settings.json` and `known_hosts` are written only via serde or validated fields. Host names pass `validate_hostname`, which rejects whitespace, control characters, `,[]/\@#*?!"'` and a leading `-`.
- **Forward exposure and open proxy (CWE-1327, CWE-306).** Forward listeners bind to `127.0.0.1` unless the user sets another address. The SOCKS5 server (`forward.rs` `socks5`) has no authentication, so any host that can reach its bind address can tunnel through the SSH server. Remote-forward connections reach only the target the user configured. User: LAN exposure from a non-loopback bind is reported, not accepted.
- **Tauri IPC surface (CWE-749).** The capability set is minimal: core, dialog and clipboard text. No shell, fs or http plugin is granted. Adding plugins or broad permissions widens what a webview compromise can reach.
- **Dependencies (CWE-1395).** Vulnerable crates and npm packages are in scope. `cargo audit` and `npm audit` are the existing control.

## Out of scope / accepted risk

User: build and release integrity is out of scope. This covers the release script `scripts/release.mjs`, code signing (builds are made locally and are unsigned) and build hardening flags (`build.rs`, `.cargo/config.toml`). Vulnerable dependencies stay in scope.

User: otherwise nothing is out of scope or accepted risk. Report everything, including LAN exposure of forward listeners.

## Finding tags

User: findings carry Component, CWE, CVE (for dependency findings) and Attacker (which attacker profile can exploit it).

## Open questions

- None outstanding.
