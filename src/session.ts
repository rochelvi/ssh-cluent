import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";
import { api, errorMessage, ForwardStatus, HostKeyError, Host, isCmdError, ShellEvent } from "./api";
import { clear, h } from "./dom";
import { confirmDialog, promptText } from "./modal";
import { comboFromEvent, getSettings } from "./settings";
import { SftpPanel } from "./sftp";

export type SessionStatus = "connecting" | "connected" | "closed";

const THEME = {
  background: "#0f141b",
  foreground: "#d6dde6",
  cursor: "#5eead4",
  cursorAccent: "#0f141b",
  selectionBackground: "#2a3a4a",
  black: "#1b222c",
  red: "#f47174",
  green: "#7ee0a1",
  yellow: "#f2cc6b",
  blue: "#6cb6ff",
  magenta: "#d39bff",
  cyan: "#5eead4",
  white: "#d6dde6",
  brightBlack: "#5c6773",
  brightRed: "#ff8f91",
  brightGreen: "#9ff0bb",
  brightYellow: "#ffdd8a",
  brightBlue: "#8fcaff",
  brightMagenta: "#e2b8ff",
  brightCyan: "#8ff5e6",
  brightWhite: "#ffffff",
};

const encoder = new TextEncoder();

function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export class SessionTab {
  readonly id = crypto.randomUUID();
  readonly el: HTMLElement;
  status: SessionStatus = "closed";

  private readonly term: Terminal;
  private readonly fit = new FitAddon();
  private readonly termEl: HTMLElement;
  private readonly sftpEl: HTMLElement;
  private readonly fwdEl: HTMLElement;
  private readonly modeBtns: Record<"terminal" | "sftp", HTMLButtonElement>;
  private readonly reconnectBtn: HTMLButtonElement;
  private readonly resizeObserver: ResizeObserver;
  private sessionId: string | null = null;
  private sftp: SftpPanel | null = null;
  private mode: "terminal" | "sftp" = "terminal";
  private opened = false;
  private pending: number[] = [];
  private writing = false;
  private connecting = false;
  private selectionTimer = 0;

  constructor(
    public host: Host,
    private readonly onChange: () => void,
  ) {
    this.term = new Terminal({
      fontFamily: '"Cascadia Mono", "Cascadia Code", Consolas, "Courier New", monospace',
      fontSize: 14,
      lineHeight: 1.15,
      cursorBlink: true,
      scrollback: 10000,
      allowProposedApi: true,
      theme: THEME,
    });
    this.term.loadAddon(this.fit);

    this.termEl = h("div", { class: "term" });
    this.sftpEl = h("div", { class: "sftp-host" });
    this.sftpEl.hidden = true;
    this.fwdEl = h("div", { class: "fwd-chips" });
    this.modeBtns = {
      terminal: h("button", { class: "seg active", onclick: () => this.setMode("terminal") }, "Терминал"),
      sftp: h("button", { class: "seg", onclick: () => this.setMode("sftp") }, "SFTP"),
    };
    this.reconnectBtn = h("button", { class: "btn small", onclick: () => this.start() }, "Переподключить");
    this.reconnectBtn.hidden = true;

    this.el = h(
      "div",
      { class: "view session" },
      h(
        "div",
        { class: "session-toolbar" },
        h("div", { class: "segmented" }, this.modeBtns.terminal, this.modeBtns.sftp),
        this.fwdEl,
        h("div", { class: "spacer" }),
        h("span", { class: "muted small" }, `${host.username}@${host.hostname}:${host.port}`),
        this.reconnectBtn,
      ),
      h("div", { class: "session-body" }, this.termEl, this.sftpEl),
    );
    this.el.hidden = true;

    this.term.onData((d) => {
      if (this.status === "connected") this.send(encoder.encode(d));
      else if (this.status === "closed" && d === "\r") this.start();
    });
    this.term.onBinary((d) => {
      if (this.status !== "connected") return;
      const bytes = new Uint8Array(d.length);
      for (let i = 0; i < d.length; i++) bytes[i] = d.charCodeAt(i) & 0xff;
      this.send(bytes);
    });
    this.term.onResize(({ cols, rows }) => {
      if (this.sessionId) api.resize(this.sessionId, cols, rows).catch(() => {});
    });
    // Copy / paste shortcuts from the settings (rebindable).
    this.term.attachCustomKeyEventHandler((e) => {
      if (e.type !== "keydown") return true;
      const combo = comboFromEvent(e);
      if (!combo) return true;
      const { keyCopy, keyPaste } = getSettings();

      if (combo === keyCopy) {
        if (this.term.hasSelection()) {
          writeText(this.term.getSelection()).catch(() => {});
          this.term.clearSelection();
          e.preventDefault();
          return false;
        }
        // Nothing selected: plain Ctrl+C keeps its terminal meaning (SIGINT);
        // any other copy shortcut is swallowed so it doesn't send a stray control code.
        if (combo === "Ctrl+C") return true;
        e.preventDefault();
        return false;
      }
      if (combo === keyPaste) {
        // Stop the browser's own paste event so the text isn't inserted twice.
        e.preventDefault();
        this.paste();
        return false;
      }
      return true;
    });

    // Copy on select (debounced: the selection changes continuously while dragging).
    this.term.onSelectionChange(() => {
      if (!getSettings().copyOnSelect) return;
      window.clearTimeout(this.selectionTimer);
      this.selectionTimer = window.setTimeout(() => {
        const sel = this.term.getSelection();
        if (sel) writeText(sel).catch(() => {});
      }, 150);
    });

    // Right click pastes when "copy on select" is on; otherwise it does nothing
    // (the WebView's own context menu is never shown in the terminal).
    this.termEl.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      if (getSettings().copyOnSelect) this.paste();
    });

    this.resizeObserver = new ResizeObserver(() => this.fitNow());
    this.resizeObserver.observe(this.termEl);
  }

  get title() {
    return this.host.label || this.host.hostname;
  }

  setVisible(visible: boolean) {
    this.el.hidden = !visible;
    if (visible && this.mode === "terminal") {
      requestAnimationFrame(() => {
        this.fitNow();
        this.term.focus();
      });
    }
  }

  async handleDrop(paths: string[]) {
    if (this.mode === "sftp" && this.sftp) await this.sftp.upload(paths);
  }

  /**
   * Pastes the clipboard into the terminal, defensively:
   *  - control characters (ESC, C1 codes…) are stripped, so clipboard content
   *    can't inject escape sequences or break out of bracketed paste;
   *  - text containing a line break is confirmed first unless the remote side
   *    has bracketed paste on — otherwise it would be executed immediately
   *    (classic "copied a command from a web page" attack).
   */
  private async paste() {
    let text: string;
    try {
      text = await readText();
    } catch {
      return;
    }
    // eslint-disable-next-line no-control-regex
    text = text.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]/g, "");
    if (!text || this.status !== "connected") return;

    if (/[\r\n]/.test(text) && !this.term.modes.bracketedPasteMode) {
      const lines = text.replace(/\r\n?/g, "\n").split("\n");
      const preview = lines.slice(0, 12).join("\n") + (lines.length > 12 ? "\n…" : "");
      const ok = await confirmDialog(
        "Вставить несколько строк?",
        h(
          "div",
          { class: "form" },
          h("p", {}, "Текст содержит перевод строки — команды будут выполнены сразу после вставки. Проверьте, что именно вставляется:"),
          h("pre", { class: "paste-preview" }, preview),
        ),
        "Вставить",
      );
      this.term.focus();
      if (!ok) return;
    }
    this.term.paste(text);
  }

  private fitNow() {
    if (this.el.hidden || this.mode !== "terminal" || !this.opened) return;
    try {
      this.fit.fit();
    } catch {
      /* not laid out yet */
    }
  }

  private setStatus(s: SessionStatus) {
    this.status = s;
    this.reconnectBtn.hidden = s !== "closed";
    this.onChange();
  }

  private setMode(mode: "terminal" | "sftp") {
    this.mode = mode;
    this.modeBtns.terminal.classList.toggle("active", mode === "terminal");
    this.modeBtns.sftp.classList.toggle("active", mode === "sftp");
    this.termEl.hidden = mode !== "terminal";
    this.sftpEl.hidden = mode !== "sftp";
    if (mode === "terminal") {
      requestAnimationFrame(() => {
        this.fitNow();
        this.term.focus();
      });
      return;
    }
    if (!this.sessionId) {
      clear(this.sftpEl);
      this.sftpEl.append(h("div", { class: "empty" }, "Нет подключения. Переподключитесь, чтобы открыть SFTP."));
      this.sftp = null;
      return;
    }
    if (!this.sftp) {
      this.sftp = new SftpPanel(this.sessionId);
      clear(this.sftpEl);
      this.sftpEl.append(this.sftp.el);
      this.sftp.load("");
    }
  }

  private send(bytes: Uint8Array) {
    for (const b of bytes) this.pending.push(b);
    if (!this.writing) this.flush();
  }

  /** Writes are serialized so keystrokes never get reordered. */
  private async flush() {
    this.writing = true;
    while (this.pending.length && this.sessionId) {
      const chunk = this.pending;
      this.pending = [];
      try {
        await api.write(this.sessionId, chunk);
      } catch {
        break;
      }
    }
    this.pending = [];
    this.writing = false;
  }

  private onEvent(ev: ShellEvent) {
    switch (ev.type) {
      case "data":
        this.term.write(b64ToBytes(ev.data));
        break;
      case "exit":
        break;
      case "closed": {
        const id = this.sessionId;
        this.sessionId = null;
        this.sftp = null;
        if (id) api.disconnect(id).catch(() => {});
        this.term.write(
          `\r\n\x1b[90m── Соединение закрыто${ev.reason ? `: ${ev.reason}` : ""}. Нажмите Enter, чтобы переподключиться ──\x1b[0m\r\n`,
        );
        this.renderForwards([]);
        this.setStatus("closed");
        if (this.mode === "sftp") this.setMode("sftp");
        break;
      }
    }
  }

  private renderForwards(list: ForwardStatus[]) {
    clear(this.fwdEl);
    for (const f of list) {
      this.fwdEl.append(
        h("span", { class: "chip " + (f.ok ? "ok" : "bad"), title: f.error ?? "Туннель активен" }, `${f.ok ? "●" : "✕"} ${f.description}`),
      );
    }
  }

  private async confirmHostKey(err: HostKeyError): Promise<boolean> {
    const mismatch = err.kind === "hostKeyMismatch";
    const body = h(
      "div",
      { class: "form" },
      mismatch
        ? h(
            "p",
            { class: "warn" },
            "ВНИМАНИЕ: ключ сервера изменился! Это может означать атаку «человек посередине» — или сервер просто переустановили. Продолжайте, только если уверены.",
          )
        : h("p", {}, `Подключение к ${err.host}:${err.port} впервые. Проверьте отпечаток ключа сервера:`),
      h("code", { class: "fingerprint" }, err.fingerprint),
      h("p", { class: "muted small" }, err.keyLine.split(" ")[0]),
    );
    return confirmDialog(
      mismatch ? "Ключ хоста изменился" : "Неизвестный хост",
      body,
      mismatch ? "Заменить ключ и подключиться" : "Доверять и подключиться",
      mismatch,
    );
  }

  private async askSecret(reason: string | null): Promise<string | null> {
    const isKey = this.host.auth === "key";
    const r = await promptText(isKey ? "Парольная фраза ключа" : `Пароль для ${this.host.username}@${this.host.hostname}`, isKey ? "Парольная фраза" : "Пароль", {
      password: true,
      hint: reason ?? undefined,
    });
    return r ? r.value : null;
  }

  async start() {
    if (this.connecting || this.status === "connected") return;
    this.connecting = true;
    try {
      await this.connectLoop();
    } finally {
      this.connecting = false;
    }
  }

  private async connectLoop() {
    if (!this.opened) {
      this.term.open(this.termEl);
      this.opened = true;
    }
    this.setStatus("connecting");
    this.fitNow();
    this.term.write(`\x1b[90mПодключение к ${this.host.username}@${this.host.hostname}:${this.host.port}…\x1b[0m\r\n`);

    let secret: string | null = null;
    if (this.host.auth === "password") {
      secret = await this.askSecret(null);
      if (secret === null) return this.fail("Отменено");
    }

    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        this.fitNow();
        const res = await api.connect(this.host.id, this.term.cols, this.term.rows, secret, (ev) => this.onEvent(ev));
        this.sessionId = res.sessionId;
        this.renderForwards(res.forwards);
        this.setStatus("connected");
        if (this.mode === "sftp") this.setMode("sftp");
        else this.term.focus();
        return;
      } catch (e) {
        if (isCmdError(e) && (e.kind === "hostKeyUnknown" || e.kind === "hostKeyMismatch")) {
          if (!(await this.confirmHostKey(e))) return this.fail("Ключ хоста не принят");
          try {
            await api.trustHostKey(e.host, e.port, e.keyLine);
          } catch (err) {
            return this.fail(errorMessage(err));
          }
          continue;
        }
        if (isCmdError(e) && e.kind === "authFailed") {
          this.term.write(`\x1b[33m${e.message}\x1b[0m\r\n`);
          secret = await this.askSecret(e.message);
          if (secret === null) return this.fail("Отменено");
          continue;
        }
        return this.fail(errorMessage(e));
      }
    }
    this.fail("Слишком много попыток");
  }

  private fail(message: string) {
    this.term.write(`\x1b[31m✕ ${message}\x1b[0m\r\n\x1b[90mНажмите Enter, чтобы попробовать снова.\x1b[0m\r\n`);
    this.setStatus("closed");
  }

  async dispose() {
    this.resizeObserver.disconnect();
    if (this.sessionId) {
      const id = this.sessionId;
      this.sessionId = null;
      await api.disconnect(id).catch(() => {});
    }
    this.term.dispose();
  }
}
