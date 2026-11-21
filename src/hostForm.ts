import { open } from "@tauri-apps/plugin-dialog";
import { homeDir } from "@tauri-apps/api/path";
import { api, errorMessage, Forward, ForwardKind, Host, HostView } from "./api";
import { clear, h } from "./dom";
import { showModal } from "./modal";
import { getSettings } from "./settings";

const KIND_LABEL: Record<ForwardKind, string> = {
  local: "Локальный (-L)",
  remote: "Удалённый (-R)",
  dynamic: "SOCKS5 (-D)",
};

/**
 * Opens the host editor. Resolves true if the host was saved.
 * With `duplicate`, the form is pre-filled from `existing` but saves a new host
 * (same name — the user renames it), and the saved password is copied over.
 */
export async function editHost(existing?: HostView, opts: { duplicate?: boolean } = {}): Promise<boolean> {
  const duplicate = !!opts.duplicate && !!existing;
  const forwards: Forward[] = structuredClone(existing?.forwards ?? []);
  if (duplicate) for (const f of forwards) f.id = "";

  const label = h("input", { value: existing?.label ?? "", placeholder: "Например: prod-web" });
  const group = h("input", { value: existing?.group ?? "", placeholder: "Без группы" });
  const hostname = h("input", { value: existing?.hostname ?? "", placeholder: "192.168.1.10 или example.com", spellcheck: false });
  const port = h("input", { type: "number", min: 1, max: 65535, value: String(existing?.port ?? 22) });
  const username = h("input", {
    value: existing?.username ?? getSettings().defaultUsername,
    placeholder: "например, root",
    spellcheck: false,
  });
  const auth = h(
    "select",
    {},
    h("option", { value: "password" }, "Пароль"),
    h("option", { value: "key" }, "Приватный ключ"),
  );
  auth.value = existing?.auth ?? "password";

  const keyPath = h("input", { value: existing?.keyPath ?? "", placeholder: "~/.ssh/id_ed25519", spellcheck: false });
  const browse = h(
    "button",
    {
      class: "btn",
      type: "button",
      onclick: async () => {
        let defaultPath: string | undefined;
        try {
          defaultPath = `${await homeDir()}\\.ssh`;
        } catch {
          /* ignore */
        }
        const picked = await open({ multiple: false, directory: false, defaultPath, title: "Приватный ключ" });
        if (typeof picked === "string") keyPath.value = picked;
      },
    },
    "Обзор…",
  );

  const secret = h("input", { type: "password", autocomplete: "off" });
  const secretLabel = h("span", {});
  const forget = h("input", { type: "checkbox" });
  const forgetRow = h("label", { class: "check" }, forget, duplicate ? "Не копировать сохранённый секрет" : "Удалить сохранённый секрет");
  forgetRow.hidden = !existing?.hasSecret;

  const keyRow = h("div", { class: "field" }, h("span", {}, "Файл ключа"), h("div", { class: "row" }, keyPath, browse));

  const syncAuth = () => {
    const isKey = auth.value === "key";
    keyRow.hidden = !isKey;
    secretLabel.textContent = isKey ? "Парольная фраза ключа (если есть)" : "Пароль";
    secret.placeholder = existing?.hasSecret
      ? duplicate
        ? "будет скопирован из исходного хоста"
        : "сохранён — оставьте пустым, чтобы не менять"
      : isKey
        ? "необязательно"
        : "спросить при подключении";
  };
  auth.addEventListener("change", syncAuth);
  syncAuth();

  const fwdList = h("div", { class: "fwd-list" });
  const renderForwards = () => {
    clear(fwdList);
    if (forwards.length === 0) {
      fwdList.append(h("p", { class: "muted small" }, "Нет правил. Туннели поднимаются автоматически при подключении."));
    }
    forwards.forEach((f, i) => {
      const kind = h("select", {}, ...(Object.keys(KIND_LABEL) as ForwardKind[]).map((k) => h("option", { value: k }, KIND_LABEL[k])));
      kind.value = f.kind;
      const bindHost = h("input", { value: f.bindHost, placeholder: "127.0.0.1", class: "w-host" });
      const bindPort = h("input", { type: "number", value: f.bindPort ? String(f.bindPort) : "", placeholder: "порт", class: "w-port" });
      const tHost = h("input", { value: f.targetHost, placeholder: f.kind === "remote" ? "localhost" : "хост за сервером", class: "w-host" });
      const tPort = h("input", { type: "number", value: f.targetPort ? String(f.targetPort) : "", placeholder: "порт", class: "w-port" });
      const target = h("span", { class: "row tight" }, h("span", { class: "arrow" }, "→"), tHost, tPort);
      target.hidden = f.kind === "dynamic";
      const sync = () => {
        f.kind = kind.value as ForwardKind;
        f.bindHost = bindHost.value.trim();
        f.bindPort = Number(bindPort.value) || 0;
        f.targetHost = tHost.value.trim();
        f.targetPort = Number(tPort.value) || 0;
        target.hidden = f.kind === "dynamic";
      };
      for (const el of [kind, bindHost, bindPort, tHost, tPort]) el.addEventListener("input", sync);
      fwdList.append(
        h(
          "div",
          { class: "fwd-row" },
          kind,
          bindHost,
          bindPort,
          target,
          h("button", { class: "icon-btn", title: "Удалить", type: "button", onclick: () => { forwards.splice(i, 1); renderForwards(); } }, "✕"),
        ),
      );
    });
  };
  renderForwards();

  const errorEl = h("p", { class: "error" });
  errorEl.hidden = true;

  const body = h(
    "div",
    { class: "form" },
    h("div", { class: "grid2" },
      h("label", { class: "field" }, h("span", {}, "Название"), label),
      h("label", { class: "field" }, h("span", {}, "Группа"), group),
    ),
    h("div", { class: "grid-host" },
      h("label", { class: "field" }, h("span", {}, "Адрес"), hostname),
      h("label", { class: "field" }, h("span", {}, "Порт"), port),
    ),
    h("div", { class: "grid2" },
      h("label", { class: "field" }, h("span", {}, "Пользователь"), username),
      h("label", { class: "field" }, h("span", {}, "Аутентификация"), auth),
    ),
    keyRow,
    h("label", { class: "field" }, secretLabel, secret),
    forgetRow,
    h("div", { class: "section-title" },
      h("span", {}, "Проброс портов"),
      h("button", {
        class: "btn small",
        type: "button",
        onclick: () => {
          forwards.push({ id: "", kind: "local", bindHost: "127.0.0.1", bindPort: 0, targetHost: "", targetPort: 0 });
          renderForwards();
        },
      }, "+ Правило"),
    ),
    fwdList,
    errorEl,
  );

  const validate = async () => {
    const showError = (msg: string) => {
      errorEl.textContent = msg;
      errorEl.hidden = false;
      return false;
    };
    const p = Number(port.value);
    if (!hostname.value.trim()) return showError("Укажите адрес хоста");
    if (!username.value.trim()) return showError("Укажите пользователя");
    if (!(p >= 1 && p <= 65535)) return showError("Порт должен быть от 1 до 65535");
    if (auth.value === "key" && !keyPath.value.trim()) return showError("Укажите файл приватного ключа");
    for (const f of forwards) {
      if (!f.bindPort && f.kind !== "remote") return showError("У правила проброса не указан локальный порт");
      if (f.kind !== "dynamic" && (!f.targetHost || !f.targetPort)) return showError("У правила проброса не указан целевой хост/порт");
    }

    const host: Host = {
      id: duplicate ? "" : (existing?.id ?? ""),
      label: label.value.trim(),
      group: group.value.trim(),
      hostname: hostname.value.trim(),
      port: p,
      username: username.value.trim(),
      auth: auth.value as Host["auth"],
      keyPath: auth.value === "key" ? keyPath.value.trim() : null,
      forwards,
    };
    let secretValue: string | null;
    let copyFrom: string | null = null;
    if (secret.value) secretValue = secret.value;
    else if (duplicate) {
      secretValue = null;
      if (existing?.hasSecret && !forget.checked) copyFrom = existing.id;
    } else secretValue = forget.checked ? "" : null;
    try {
      await api.saveHost(host, secretValue, copyFrom);
      return true;
    } catch (e) {
      return showError(errorMessage(e));
    }
  };

  const title = duplicate ? "Дублировать хост" : existing ? "Редактировать хост" : "Новый хост";
  const r = await showModal(title, body, [{ label: "Сохранить", value: "save", kind: "primary" }], {
    wide: true,
    validate,
  });
  return r === "save";
}
