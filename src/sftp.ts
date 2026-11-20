import { open, save } from "@tauri-apps/plugin-dialog";
import { api, errorMessage, SftpEntry } from "./api";
import { basename, clear, formatSize, h } from "./dom";
import { alertDialog, confirmDialog, promptText } from "./modal";

export class SftpPanel {
  readonly el: HTMLElement;
  private path = "";
  private entries: SftpEntry[] = [];
  private selected = new Set<string>();
  private lastClicked: string | null = null;
  private readonly pathInput: HTMLInputElement;
  private readonly tbody: HTMLTableSectionElement;
  private readonly statusEl: HTMLElement;
  private busy = false;

  constructor(private readonly sessionId: string) {
    this.pathInput = h("input", {
      class: "path-input",
      spellcheck: false,
      onkeydown: (e: KeyboardEvent) => e.key === "Enter" && this.load(this.pathInput.value),
    });
    this.tbody = h("tbody", {});
    this.statusEl = h("span", { class: "muted" });
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
      h("div", { class: "sftp-status" }, this.statusEl, h("span", { class: "muted small" }, "Перетащите файлы из Проводника, чтобы загрузить")),
    );
  }

  private status(text: string, error = false) {
    this.statusEl.textContent = text;
    this.statusEl.classList.toggle("error", error);
  }

  private join(name: string) {
    return this.path.endsWith("/") ? this.path + name : `${this.path}/${name}`;
  }

  private parent() {
    if (this.path === "/" || !this.path) return "/";
    const i = this.path.replace(/\/+$/, "").lastIndexOf("/");
    return i <= 0 ? "/" : this.path.slice(0, i);
  }

  async load(path: string) {
    this.status("Загрузка…");
    try {
      const r = await api.sftpList(this.sessionId, path);
      this.path = r.path.replace(/\/{2,}/g, "/") || "/";
      this.entries = r.entries;
      this.selected.clear();
      this.pathInput.value = this.path;
      this.render();
      this.status(`${r.entries.length} элементов`);
    } catch (e) {
      this.status(errorMessage(e), true);
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
          ondblclick: () => (e.isDir || e.isLink ? this.load(this.join(e.name)) : this.download([e])),
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

  private async run(label: string, fn: () => Promise<void>) {
    if (this.busy) return;
    this.busy = true;
    this.status(label);
    try {
      await fn();
    } catch (e) {
      this.busy = false;
      this.status(errorMessage(e), true);
      await alertDialog("Ошибка SFTP", errorMessage(e));
      return;
    }
    this.busy = false;
    await this.load(this.path);
  }

  async upload(paths?: string[]) {
    if (!paths) {
      const picked = await open({ multiple: true, directory: false, title: "Файлы для загрузки" });
      if (!picked) return;
      paths = Array.isArray(picked) ? picked : [picked];
    }
    const list = paths;
    await this.run("Загрузка…", async () => {
      for (const [i, p] of list.entries()) {
        this.status(`Загрузка ${i + 1}/${list.length}: ${basename(p)}`);
        await api.sftpUpload(this.sessionId, p, this.join(basename(p)));
      }
    });
  }

  async download(entries = this.selectedEntries()) {
    const files = entries.filter((e) => !e.isDir);
    if (files.length === 0) {
      this.status("Выберите файлы для скачивания (папки пока не поддерживаются)", true);
      return;
    }
    if (files.length === 1) {
      const target = await save({ defaultPath: files[0].name, title: "Сохранить как" });
      if (!target) return;
      await this.run(`Скачивание ${files[0].name}…`, () => api.sftpDownload(this.sessionId, this.join(files[0].name), target));
      return;
    }
    const dir = await open({ directory: true, multiple: false, title: "Папка для скачивания" });
    if (typeof dir !== "string") return;
    await this.run("Скачивание…", async () => {
      for (const [i, f] of files.entries()) {
        this.status(`Скачивание ${i + 1}/${files.length}: ${f.name}`);
        await api.sftpDownload(this.sessionId, this.join(f.name), `${dir}\\${f.name}`);
      }
    });
  }

  private async mkdir() {
    const r = await promptText("Новая папка", "Имя папки");
    if (!r?.value.trim()) return;
    await this.run("Создание папки…", () => api.sftpMkdir(this.sessionId, this.join(r.value.trim())));
  }

  private async rename() {
    const [e] = this.selectedEntries();
    if (!e) return;
    const r = await promptText("Переименовать", "Новое имя", { initial: e.name });
    if (!r?.value.trim() || r.value === e.name) return;
    await this.run("Переименование…", () => api.sftpRename(this.sessionId, this.join(e.name), this.join(r.value.trim())));
  }

  private async remove() {
    const items = this.selectedEntries();
    if (items.length === 0) return;
    const what = items.length === 1 ? `«${items[0].name}»` : `${items.length} элементов`;
    const hasDir = items.some((e) => e.isDir);
    const ok = await confirmDialog(
      "Удалить",
      `Удалить ${what} на сервере${hasDir ? " вместе со всем содержимым папок" : ""}? Это нельзя отменить.`,
      "Удалить",
      true,
    );
    if (!ok) return;
    await this.run("Удаление…", async () => {
      for (const e of items) await api.sftpRemove(this.sessionId, this.join(e.name), e.isDir);
    });
  }
}

function perms(mode: number): string {
  const chars = "rwxrwxrwx";
  let s = "";
  for (let i = 0; i < 9; i++) s += mode & (1 << (8 - i)) ? chars[i] : "-";
  return s;
}
