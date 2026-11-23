import { open } from "@tauri-apps/plugin-dialog";
import { api, errorMessage, Forward, Host, ImportCandidate } from "./api";
import { clear, h } from "./dom";
import { showModal } from "./modal";

const LOOPBACK = /^(localhost|127(\.\d{1,3}){3}|::1)$/i;

/** Local / dynamic forwards that listen on a non-loopback address (reachable from the network). */
function exposed(forwards: Forward[]): string[] {
  return forwards
    .filter((f) => f.kind !== "remote" && !LOOPBACK.test(f.bindHost))
    .map((f) => `${f.kind === "dynamic" ? "SOCKS" : "L"} ${f.bindHost}:${f.bindPort}`);
}

function alreadyExists(c: ImportCandidate, hosts: Host[]) {
  const x = c.host;
  return hosts.some(
    (y) =>
      y.label.toLowerCase() === x.label.toLowerCase() ||
      (y.hostname.toLowerCase() === x.hostname.toLowerCase() && y.port === x.port && y.username === x.username),
  );
}

/** Shows hosts found in ~/.ssh/config and imports the selected ones. Resolves with the number imported. */
export async function importSshConfig(existing: Host[]): Promise<number> {
  let candidates: ImportCandidate[] = [];
  let checked: boolean[] = [];

  const pathEl = h("code", { class: "path-label" });
  const listEl = h("div", { class: "import-list" });
  const group = h("input", { placeholder: "Без группы", spellcheck: false });
  const errorEl = h("p", { class: "error" });
  errorEl.hidden = true;

  const render = () => {
    clear(listEl);
    if (candidates.length === 0) {
      listEl.append(h("p", { class: "muted" }, "Хосты не найдены."));
      return;
    }
    candidates.forEach((c, i) => {
      const x = c.host;
      const exists = alreadyExists(c, existing);
      const box = h("input", { type: "checkbox", checked: checked[i] });
      box.addEventListener("change", () => (checked[i] = box.checked));
      listEl.append(
        h(
          "label",
          { class: "import-row" },
          box,
          h(
            "span",
            { class: "import-info" },
            h("span", { class: "label" }, x.label),
            h("span", { class: "sub" }, `${x.username}@${x.hostname}${x.port !== 22 ? `:${x.port}` : ""}`),
          ),
          h(
            "span",
            { class: "badges" },
            exists ? h("span", { class: "badge warn-badge" }, "уже есть") : null,
            h("span", { class: "badge", title: x.keyPath ?? "" }, x.auth === "key" ? "ключ" : "пароль"),
            c.keyMissing ? h("span", { class: "badge warn-badge", title: x.keyPath ?? "" }, "ключ не найден") : null,
            x.forwards.length ? h("span", { class: "badge" }, `туннели: ${x.forwards.length}`) : null,
            exposed(x.forwards).length
              ? h(
                  "span",
                  {
                    class: "badge warn-badge",
                    title: `Порт доступен из сети, а не только с этого компьютера:\n${exposed(x.forwards).join("\n")}`,
                  },
                  "порт открыт в сеть",
                )
              : null,
          ),
        ),
      );
    });
  };

  const load = async (path: string | null) => {
    errorEl.hidden = true;
    try {
      const preview = await api.sshConfigPreview(path);
      pathEl.textContent = preview.path;
      candidates = preview.hosts;
      // Hosts that are already in Cluent are unchecked by default.
      checked = candidates.map((c) => !alreadyExists(c, existing));
    } catch (e) {
      candidates = [];
      checked = [];
      pathEl.textContent = path ?? "~/.ssh/config";
      errorEl.textContent = errorMessage(e);
      errorEl.hidden = false;
    }
    render();
  };

  const setAll = (v: boolean) => {
    checked = checked.map(() => v);
    render();
  };

  const body = h(
    "div",
    { class: "form" },
    h(
      "div",
      { class: "row" },
      pathEl,
      h(
        "button",
        {
          class: "btn small",
          type: "button",
          onclick: async () => {
            const picked = await open({ multiple: false, directory: false, title: "Файл конфигурации SSH" });
            if (typeof picked === "string") await load(picked);
          },
        },
        "Другой файл…",
      ),
    ),
    h(
      "div",
      { class: "row tight" },
      h("button", { class: "btn small ghost", type: "button", onclick: () => setAll(true) }, "Выбрать все"),
      h("button", { class: "btn small ghost", type: "button", onclick: () => setAll(false) }, "Снять все"),
    ),
    listEl,
    h("label", { class: "field" }, h("span", {}, "Группа для импортированных хостов"), group),
    h(
      "p",
      { class: "muted small" },
      "Переносятся HostName, Port, User, IdentityFile и правила LocalForward / RemoteForward / DynamicForward. Пароли в ssh config не хранятся — их спросят при подключении.",
    ),
    errorEl,
  );

  await load(null);

  let imported = 0;
  const validate = async () => {
    if (!checked.some(Boolean)) {
      errorEl.textContent = "Не выбрано ни одного хоста";
      errorEl.hidden = false;
      return false;
    }
    for (const [i, c] of candidates.entries()) {
      if (!checked[i]) continue;
      try {
        await api.saveHost({ ...c.host, group: group.value.trim() });
        imported++;
        checked[i] = false; // never import twice if a later host fails and the user retries
      } catch (e) {
        render();
        errorEl.textContent = `${c.host.label}: ${errorMessage(e)}`;
        errorEl.hidden = false;
        return false;
      }
    }
    return true;
  };

  await showModal("Импорт из ~/.ssh/config", body, [{ label: "Импортировать", value: "import", kind: "primary" }], {
    wide: true,
    validate,
  });
  return imported;
}
