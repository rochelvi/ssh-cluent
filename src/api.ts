import { Channel, invoke } from "@tauri-apps/api/core";

export type AuthMethod = "password" | "key";
export type ForwardKind = "local" | "remote" | "dynamic";

export interface Forward {
  id: string;
  kind: ForwardKind;
  bindHost: string;
  bindPort: number;
  targetHost: string;
  targetPort: number;
}

export interface Host {
  id: string;
  label: string;
  group: string;
  hostname: string;
  port: number;
  username: string;
  auth: AuthMethod;
  keyPath: string | null;
  forwards: Forward[];
}

export type ShellEvent =
  | { type: "data"; data: string }
  | { type: "exit"; code: number }
  | { type: "closed"; reason: string | null };

export interface ForwardStatus {
  id: string;
  description: string;
  ok: boolean;
  error: string | null;
}

export interface ConnectResult {
  sessionId: string;
  forwards: ForwardStatus[];
}

export type HostKeyError = {
  kind: "hostKeyUnknown" | "hostKeyMismatch";
  host: string;
  port: number;
  fingerprint: string;
  keyLine: string;
};

export type CmdError =
  | { kind: "message"; message: string }
  | { kind: "authFailed"; message: string }
  | HostKeyError;

export interface SftpEntry {
  name: string;
  isDir: boolean;
  isLink: boolean;
  size: number;
  modified: number | null;
  permissions: number | null;
}

export interface SftpListing {
  path: string;
  entries: SftpEntry[];
}

export interface Settings {
  copyOnSelect: boolean;
  keyCopy: string;
  keyPaste: string;
  defaultUsername: string;
}

export interface ImportCandidate {
  host: Host;
  keyMissing: boolean;
}

export interface ImportPreview {
  path: string;
  hosts: ImportCandidate[];
}

export const api = {
  listHosts: () => invoke<Host[]>("hosts_list"),
  saveHost: (host: Host) => invoke<Host>("host_save", { host }),
  getSettings: () => invoke<Settings>("settings_get"),
  setSettings: (settings: Settings) => invoke<void>("settings_set", { settings }),
  sshConfigPreview: (path: string | null) => invoke<ImportPreview>("ssh_config_preview", { path }),
  deleteHost: (id: string) => invoke<void>("host_delete", { id }),
  trustHostKey: (host: string, port: number, keyLine: string) =>
    invoke<void>("known_hosts_trust", { host, port, keyLine }),

  connect(hostId: string, cols: number, rows: number, secret: string | null, onEvent: (e: ShellEvent) => void) {
    const ch = new Channel<ShellEvent>();
    ch.onmessage = onEvent;
    return invoke<ConnectResult>("ssh_connect", { hostId, cols, rows, secret, onEvent: ch });
  },
  write: (sessionId: string, data: number[]) => invoke<void>("ssh_write", { sessionId, data }),
  resize: (sessionId: string, cols: number, rows: number) => invoke<void>("ssh_resize", { sessionId, cols, rows }),
  disconnect: (sessionId: string) => invoke<void>("ssh_disconnect", { sessionId }),
  disconnectAll: () => invoke<void>("ssh_disconnect_all"),

  sftpList: (sessionId: string, path: string) => invoke<SftpListing>("sftp_list", { sessionId, path }),
  sftpDownload: (sessionId: string, remote: string, local: string) =>
    invoke<void>("sftp_download", { sessionId, remote, local }),
  sftpUpload: (sessionId: string, local: string, remote: string) =>
    invoke<void>("sftp_upload", { sessionId, local, remote }),
  sftpMkdir: (sessionId: string, path: string) => invoke<void>("sftp_mkdir", { sessionId, path }),
  sftpRemove: (sessionId: string, path: string, isDir: boolean) =>
    invoke<void>("sftp_remove", { sessionId, path, isDir }),
  sftpRename: (sessionId: string, from: string, to: string) => invoke<void>("sftp_rename", { sessionId, from, to }),
};

export function errorMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (e && typeof e === "object" && "kind" in e) {
    const err = e as CmdError;
    if (err.kind === "message" || err.kind === "authFailed") return err.message;
    return `Проблема с ключом хоста ${err.host}:${err.port}`;
  }
  return String(e);
}

export function isCmdError(e: unknown): e is CmdError {
  return !!e && typeof e === "object" && "kind" in e;
}
