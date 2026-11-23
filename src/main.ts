import "@xterm/xterm/css/xterm.css";
import "./styles.css";
import { getVersion } from "@tauri-apps/api/app";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { api, errorMessage, Host } from "./api";
import { clear, h } from "./dom";
import { editHost } from "./hostForm";
import { importSshConfig } from "./importDialog";
import { alertDialog, confirmDialog } from "./modal";
import { SessionTab } from "./session";
import { loadSettings } from "./settings";
import { openSettings } from "./settingsDialog";

const tabbar = document.getElementById("tabbar")!;
const views = document.getElementById("views")!;
const home = document.getElementById("view-home")!;

let hosts: Host[] = [];
const tabs: SessionTab[] = [];
let active = "home";
let filter = "";
let appVersion = "";

// Disable the WebView's own context menu outside inputs (it would offer "Reload" etc.).
document.addEventListener("contextmenu", (e) => {
  const t = e.target as HTMLElement;
  if (!t.closest("input, textarea")) e.preventDefault();
});

// ---------- tabs ----------

function renderTabs() {
  clear(tabbar);
  tabbar.append(
    h("div", { class: "brand", title: appVersion ? `Cluent ${appVersion}` : "Cluent" }, h("img", { src: "/icon.svg", alt: "" }), "Cluent", appVersion ? h("span", { class: "version" }, `v${appVersion}`) : null),
    h("button", { class: "tab" + (active === "home" ? " active" : ""), onclick: () => activate("home") }, "Хосты"),
  );
  for (const t of tabs) {
    tabbar.append(
      h(
        "div",
        {
          class: "tab" + (active === t.id ? " active" : ""),
          title: `${t.host.username}@${t.host.hostname}`,
          onclick: () => activate(t.id),
          onauxclick: (e: MouseEvent) => e.button === 1 && closeTab(t),
        },
        h("span", { class: "dot " + t.status }),
        h("span", { class: "tab-title" }, t.title),
        h(
          "button",
          {
            class: "tab-close",
            title: "Закрыть",
            onclick: (e: MouseEvent) => {
              e.stopPropagation();
              closeTab(t);
            },
          },
          "×",
        ),
      ),
    );
  }
  tabbar.append(
    h("div", { class: "spacer" }),
    h("button", { class: "icon-btn gear", title: "Настройки", onclick: () => openSettings() }, "⚙"),
  );
}

function activate(id: string) {
  active = id;
  home.hidden = id !== "home";
  for (const t of tabs) t.setVisible(t.id === id);
  renderTabs();
}

async function openHost(host: Host) {
  const tab = new SessionTab({ ...host }, renderTabs);
  tabs.push(tab);
  views.append(tab.el);
  activate(tab.id);
  await tab.start();
}

async function closeTab(t: SessionTab) {
  if (t.status === "connected" && !(await confirmDialog("Закрыть сессию", `Отключиться от ${t.title}?`, "Отключить"))) return;
  await t.dispose();
  tabs.splice(tabs.indexOf(t), 1);
  t.el.remove();
  activate(active === t.id ? (tabs[tabs.length - 1]?.id ?? "home") : active);
}

// ---------- home ----------

const grid = h("div", { class: "host-groups" });
const search = h("input", {
  class: "search",
  placeholder: "Поиск хостов…",
  spellcheck: false,
  oninput: () => {
    filter = search.value;
    renderGrid();
  },
});

home.append(
  h(
    "div",
    { class: "home-toolbar" },
    search,
    h(
      "button",
      {
        class: "btn",
        title: "Импортировать хосты из ~/.ssh/config",
        onclick: async () => {
          if ((await importSshConfig(hosts)) > 0) refreshHosts();
        },
      },
      "Импорт из SSH config",
    ),
    h(
      "button",
      {
        class: "btn primary",
        onclick: async () => {
          if (await editHost()) refreshHosts();
        },
      },
      "+ Новый хост",
    ),
  ),
  grid,
);

async function refreshHosts() {
  try {
    hosts = await api.listHosts();
  } catch (e) {
    await alertDialog("Не удалось загрузить хосты", errorMessage(e));
  }
  renderGrid();
}

function renderGrid() {
  clear(grid);
  const q = filter.trim().toLowerCase();
  const list = hosts.filter((x) =>
    !q || [x.label, x.hostname, x.username, x.group].some((s) => s.toLowerCase().includes(q)),
  );

  if (hosts.length === 0) {
    grid.append(
      h(
        "div",
        { class: "empty big" },
        h("img", { src: "/icon.svg", alt: "", class: "empty-logo" }),
        h("h2", {}, "Добро пожаловать в Cluent"),
        h("p", { class: "muted" }, "Полностью офлайн SSH-клиент: данные хранятся только на этом компьютере, никакой телеметрии."),
        h("button", { class: "btn primary", onclick: async () => (await editHost()) && refreshHosts() }, "Добавить первый хост"),
      ),
    );
    return;
  }
  if (list.length === 0) {
    grid.append(h("div", { class: "empty" }, "Ничего не найдено"));
    return;
  }

  const groups = new Map<string, Host[]>();
  for (const x of list) {
    const g = x.group || "";
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g)!.push(x);
  }
  const names = [...groups.keys()].sort((a, b) => (a === "" ? 1 : b === "" ? -1 : a.localeCompare(b)));

  for (const name of names) {
    const items = groups.get(name)!.sort((a, b) => a.label.localeCompare(b.label));
    grid.append(
      h(
        "section",
        { class: "group" },
        h("h3", {}, name || "Без группы", h("span", { class: "count" }, String(items.length))),
        h("div", { class: "cards" }, ...items.map(card)),
      ),
    );
  }
}

function card(x: Host) {
  return h(
    "div",
    { class: "host-card", title: "Подключиться", onclick: () => openHost(x) },
    h("div", { class: "avatar" }, (x.label || x.hostname).charAt(0).toUpperCase()),
    h(
      "div",
      { class: "info" },
      h("div", { class: "label" }, x.label),
      h("div", { class: "sub" }, `${x.username}@${x.hostname}${x.port !== 22 ? `:${x.port}` : ""}`),
      h(
        "div",
        { class: "badges" },
        h("span", { class: "badge" }, x.auth === "key" ? "ключ" : "пароль"),
        x.forwards.length ? h("span", { class: "badge" }, `туннели: ${x.forwards.length}`) : null,
      ),
    ),
    h(
      "div",
      { class: "card-actions" },
      h(
        "button",
        {
          class: "icon-btn",
          title: "Редактировать",
          onclick: async (e: MouseEvent) => {
            e.stopPropagation();
            if (await editHost(x)) refreshHosts();
          },
        },
        "✎",
      ),
      h(
        "button",
        {
          class: "icon-btn",
          title: "Дублировать",
          onclick: async (e: MouseEvent) => {
            e.stopPropagation();
            if (await editHost(x, { duplicate: true })) refreshHosts();
          },
        },
        "⧉",
      ),
      h(
        "button",
        {
          class: "icon-btn",
          title: "Удалить",
          onclick: async (e: MouseEvent) => {
            e.stopPropagation();
            if (await confirmDialog("Удалить хост", `Удалить «${x.label}»?`, "Удалить", true)) {
              await api.deleteHost(x.id).catch((err) => alertDialog("Ошибка", errorMessage(err)));
              refreshHosts();
            }
          },
        },
        "🗑",
      ),
    ),
  );
}

// Drag files from Explorer into an SFTP view to upload them.
getCurrentWebview()
  .onDragDropEvent((e) => {
    if (e.payload.type !== "drop") return;
    tabs.find((t) => t.id === active)?.handleDrop(e.payload.paths);
  })
  .catch(() => {});

renderTabs();
// Sessions left over from a previous page load have no tab — close them (frees forwarded ports).
api.disconnectAll().catch(() => {});
getVersion()
  .then((v) => {
    appVersion = v;
    renderTabs();
  })
  .catch(() => {
    /* version is cosmetic */
  });
loadSettings().finally(refreshHosts);
