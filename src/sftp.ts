import { open, save } from "@tauri-apps/plugin-dialog";
import { api, errorMessage, SftpEntry } from "./api";
import { basename, clear, formatSize, h } from "./dom";
import { alertDialog, confirmDialog, promptText } from "./modal";

function remotePath(directory: string, name: string) {
  return directory.endsWith("/") ? directory + name : `${directory}/${name}`;
}

export class SftpPanel {
  readonly el: HTMLElement;
  private path = "";
  private entries: SftpEntry[] = [];
  private selected = new Set<string>();
  private lastClicked: string | null = null;
  private readonly pathInput: HTMLInputElement;
  private readonly tbody: HTMLTableSectionElement;
  private readonly statusEl: HTMLElement;
  private readonly operationEl: HTMLElement;
  private busy = false;
  private listingRequest = 0;
  private loading = false;

  constructor(private readonly sessionId: string) {
    this.pathInput = h("input", {
      class: "path-input",
      spellcheck: false,
      onkeydown: (e: KeyboardEvent) => e.key === "Enter" && this.load(this.pathInput.value),
    });
    this.tbody = h("tbody", {});
    this.statusEl = h("span", { class: "muted" });
    this.operationEl = h("span", { class: "muted", hidden: true });
    const btn = (label: string, title: string, fn: () => void) => h("button", { class: "btn small", title, onclick: fn }, label);

    this.el = h(
      "div",
      { class: "sftp" },
      h(
        "div",
        { class: "sftp-toolbar" },
        btn("↑", "Вверх", () => this.load(this.parent())),
        btn("⟳", "Обновить", () => this.load(this.path)),
        this.pathInput,
        btn("Новая папка", "Создать папку", () => this.mkdir()),
        btn("Загрузить", "Загрузить файлы на сервер", () => this.upload()),
        btn("Скачать", "Скачать выбранные файлы", () => this.download()),
        btn("Переименовать", "Переименовать", () => this.rename()),
        h("button", { class: "btn small danger", onclick: () => this.remove() }, "Удалить"),
      ),
      h(
        "div",
        { class: "sftp-table-wrap" },
        h(
          "table",
          { class: "sftp-table" },
          h("thead", {}, h("tr", {}, h("th", {}, "Имя"), h("th", { class: "num" }, "Размер"), h("th", {}, "Изменён"), h("th", {}, "Права"))),
          this.tbody,
        ),
      ),
      h("div", { class: "sftp-status" }, h("span", {}, this.statusEl, this.operationEl), h("span", { class: "muted small" }, "Перетащите файлы из Проводника, чтобы загрузить")),
    );
  }

  private status(text: string, error = false) {
    this.statusEl.textContent = text;
    this.statusEl.classList.toggle("error", error);
  }

  private parent() {
    if (this.path === "/" || !this.path) return "/";
    const i = this.path.replace(/\/+$/, "").lastIndexOf("/");
    return i <= 0 ? "/" : this.path.slice(0, i);
  }

  async load(path: string) {
    const request = ++this.listingRequest;
    this.loading = true;
    this.status("Загрузка…");
    try {
      const r = await api.sftpList(this.sessionId, path);
      if (request !== this.listingRequest) return;
      this.path = r.path.replace(/\/{2,}/g, "/") || "/";
      this.entries = r.entries;
      this.selected.clear();
      this.lastClicked = null;
      this.pathInput.value = this.path;
      this.render();
      this.status(`${r.entries.length} элементов`);
    } catch (e) {
      if (request === this.listingRequest) this.status(errorMessage(e), true);
    } finally {
      if (request === this.listingRequest) this.loading = false;
    }
  }

  private render() {
    clear(this.tbody);
    for (const e of this.entries) {
      const row = h(
        "tr",
        {
          class: this.selected.has(e.name) ? "selected" : "",
          onclick: (ev: MouseEvent) => this.select(e.name, ev),
          ondblclick: () => (e.isDir || e.isLink ? this.load(remotePath(this.path, e.name)) : this.download([e])),
        },
        h("td", { class: "name" }, h("span", { class: "ficon " + (e.isDir ? "dir" : e.isLink ? "link" : "file") }), e.name),
        h("td", { class: "num" }, e.isDir ? "" : formatSize(e.size)),
        h("td", {}, e.modified ? new Date(e.modified * 1000).toLocaleString() : ""),
        h("td", { class: "mono" }, e.permissions != null ? perms(e.permissions) : ""),
      );
      this.tbody.append(row);
    }
    if (this.entries.length === 0) this.tbody.append(h("tr", {}, h("td", { class: "muted", colspan: 4 }, "Пустая папка")));
  }

  private select(name: string, ev: MouseEvent) {
    if (ev.shiftKey && this.lastClicked) {
      const names = this.entries.map((e) => e.name);
      const [a, b] = [names.indexOf(this.lastClicked), names.indexOf(name)].sort((x, y) => x - y);
      for (const n of names.slice(a, b + 1)) this.selected.add(n);
    } else if (ev.ctrlKey) {
      if (this.selected.has(name)) this.selected.delete(name);
      else this.selected.add(name);
      this.lastClicked = name;
    } else {
      this.selected = new Set([name]);
      this.lastClicked = name;
    }
    this.render();
  }

  private selectedEntries() {
    return this.entries.filter((e) => this.selected.has(e.name));
  }

  private async run(directory: string, label: string, fn: () => Promise<void>) {
    if (this.busy) return;
    const request = this.listingRequest;
    this.busy = true;
    this.operationEl.hidden = false;
    this.statusEl.hidden = true;
    this.operationEl.textContent = label;
    let completed = false;
    try {
      await fn();
      completed = true;
    } catch (e) {
      if (!this.loading && request === this.listingRequest && this.path === directory) {
        this.status(errorMessage(e), true);
      }
      await alertDialog("Ошибка SFTP", errorMessage(e));
    } finally {
      this.busy = false;
      this.operationEl.hidden = true;
      this.statusEl.hidden = false;
    }
    if (completed && !this.loading && request === this.listingRequest && this.path === directory) {
      await this.load(directory);
    }
  }

  async upload(paths?: string[]) {
    const directory = this.path;
    if (!paths) {
      const picked = await open({ multiple: true, directory: false, title: "Файлы для загрузки" });
      if (!picked) return;
      paths = Array.isArray(picked) ? picked : [picked];
    }
    const list = paths;
    await this.run(directory, "Загрузка…", async () => {
      for (const [i, p] of list.entries()) {
        this.operationEl.textContent = `Загрузка ${i + 1}/${list.length}: ${basename(p)}`;
        await api.sftpUpload(this.sessionId, p, remotePath(directory, basename(p)));
      }
    });
  }

  async download(entries = this.selectedEntries()) {
    const directory = this.path;
    const files = entries.filter((e) => !e.isDir);
    if (files.length === 0) {
      this.status("Выберите файлы для скачивания (папки пока не поддерживаются)", true);
      return;
    }
    if (files.length === 1) {
      const target = await save({ defaultPath: safeLocalName(files[0].name), title: "Сохранить как новый файл" });
      if (!target) return;
      await this.run(directory, `Скачивание ${files[0].name}…`, () =>
        api.sftpDownload(this.sessionId, remotePath(directory, files[0].name), target));
      return;
    }
    const names = files.map((file) => safeLocalName(file.name));
    if (new Set(names.map((name) => name.toUpperCase())).size !== names.length) {
      await alertDialog("Ошибка SFTP", "Несколько файлов получат одинаковое имя в Windows. Скачайте их по отдельности под разными именами.");
      return;
    }
    const dir = await open({ directory: true, multiple: false, title: "Папка для скачивания без перезаписи файлов" });
    if (typeof dir !== "string") return;
    await this.run(directory, "Скачивание…", async () => {
      for (const [i, f] of files.entries()) {
        this.operationEl.textContent = `Скачивание ${i + 1}/${files.length}: ${f.name}`;
        await api.sftpDownload(this.sessionId, remotePath(directory, f.name), `${dir}\\${names[i]}`);
      }
    });
  }

  private async mkdir() {
    const directory = this.path;
    const r = await promptText("Новая папка", "Имя папки");
    if (!r?.value.trim()) return;
    await this.run(directory, "Создание папки…", () => api.sftpMkdir(this.sessionId, remotePath(directory, r.value.trim())));
  }

  private async rename() {
    const directory = this.path;
    const [e] = this.selectedEntries();
    if (!e) return;
    const r = await promptText("Переименовать", "Новое имя", { initial: e.name });
    if (!r?.value.trim() || r.value === e.name) return;
    await this.run(directory, "Переименование…", () =>
      api.sftpRename(this.sessionId, remotePath(directory, e.name), remotePath(directory, r.value.trim())));
  }

  private async remove() {
    const directory = this.path;
    const items = this.selectedEntries();
    if (items.length === 0) return;
    const what = items.length === 1 ? `«${items[0].name}»` : `${items.length} элементов`;
    const hasDir = items.some((e) => e.isDir);
    const ok = await confirmDialog(
      "Удалить",
      `Удалить ${what} в ${directory}${hasDir ? " вместе со всем содержимым папок" : ""}? Это нельзя отменить.`,
      "Удалить",
      true,
    );
    if (!ok) return;
    await this.run(directory, "Удаление…", async () => {
      for (const e of items) await api.sftpRemove(this.sessionId, remotePath(directory, e.name), e.isDir);
    });
  }
}

/**
 * Turns an untrusted remote file name into a safe Windows file name.
 * On Linux names may contain `\`, `:` or be `..`, which would otherwise let a
 * malicious server write outside the chosen download folder. The backend
 * re-checks the final path.
 */
export function safeLocalName(name: string): string {
  // eslint-disable-next-line no-control-regex
  let s = name.replace(/[<>:"/\\|?*\x00-\x1f\x7f]/g, "_").replace(/[. ]+$/, "");
  if (!s || s === "." || s === "..") s = "_";
  if (/^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i.test(s)) s = `_${s}`;
  return s;
}

function perms(mode: number): string {
  const chars = "rwxrwxrwx";
  let s = "";
  for (let i = 0; i < 9; i++) s += mode & (1 << (8 - i)) ? chars[i] : "-";
  return s;
}
