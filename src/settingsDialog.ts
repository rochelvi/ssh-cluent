import { errorMessage, Settings } from "./api";
import { h } from "./dom";
import { showModal } from "./modal";
import { comboFromEvent, DEFAULT_SETTINGS, getSettings, isValidCombo, saveSettings } from "./settings";

/** Read-only input that records the next key combination pressed in it. */
function keyCapture(value: string) {
  const input = h("input", {
    class: "key-input",
    readOnly: true,
    value,
    title: "Кликните и нажмите сочетание клавиш",
    spellcheck: false,
  });
  input.dataset.keycapture = "1";
  input.addEventListener("keydown", (e) => {
    if (e.key === "Tab") return; // keep keyboard navigation
    e.preventDefault();
    e.stopPropagation();
    const combo = comboFromEvent(e);
    if (combo) input.value = combo;
  });
  return input;
}

export async function openSettings(): Promise<boolean> {
  const s = getSettings();

  const copyOnSelect = h("input", { type: "checkbox", checked: s.copyOnSelect });
  const keyCopy = keyCapture(s.keyCopy);
  const keyPaste = keyCapture(s.keyPaste);
  const defaultUser = h("input", { value: s.defaultUsername, placeholder: "например, root", spellcheck: false });
  const errorEl = h("p", { class: "error" });
  errorEl.hidden = true;

  const body = h(
    "div",
    { class: "form settings" },
    h("div", { class: "section-title first" }, h("span", {}, "Терминал")),
    h(
      "label",
      { class: "toggle-row" },
      h(
        "span",
        {},
        h("span", { class: "toggle-title" }, "Копировать при выделении, вставлять правой кнопкой"),
        h("span", { class: "muted small block" }, "Выделенный текст сразу попадает в буфер обмена, а правая кнопка мыши вставляет его."),
      ),
      h("span", { class: "switch" }, copyOnSelect, h("span", { class: "slider" })),
    ),

    h(
      "div",
      { class: "section-title" },
      h("span", {}, "Сочетания клавиш"),
      h(
        "button",
        {
          class: "btn small ghost",
          type: "button",
          onclick: () => {
            keyCopy.value = DEFAULT_SETTINGS.keyCopy;
            keyPaste.value = DEFAULT_SETTINGS.keyPaste;
          },
        },
        "По умолчанию",
      ),
    ),
    h(
      "div",
      { class: "grid2" },
      h("label", { class: "field" }, h("span", {}, "Копировать"), keyCopy),
      h("label", { class: "field" }, h("span", {}, "Вставить"), keyPaste),
    ),
    h(
      "p",
      { class: "muted small" },
      "Кликните по полю и нажмите новое сочетание. Если копирование назначено на Ctrl+C, оно срабатывает только при выделенном тексте — без выделения Ctrl+C, как обычно, прерывает процесс.",
    ),

    h("div", { class: "section-title" }, h("span", {}, "Новые хосты")),
    h("label", { class: "field" }, h("span", {}, "Пользователь по умолчанию"), defaultUser),
    h(
      "p",
      { class: "muted small" },
      "Подставляется при создании хоста и при импорте из ~/.ssh/config, если в конфиге не указан User.",
    ),
    errorEl,
  );

  const validate = async () => {
    const fail = (msg: string) => {
      errorEl.textContent = msg;
      errorEl.hidden = false;
      return false;
    };
    for (const [name, field] of [["копирования", keyCopy], ["вставки", keyPaste]] as const) {
      if (!isValidCombo(field.value)) {
        return fail(`Сочетание ${name} «${field.value}» должно включать Ctrl, Alt или Win (либо быть Insert / F1–F12).`);
      }
    }
    if (keyCopy.value === keyPaste.value) return fail("Копирование и вставка не могут использовать одно сочетание.");

    const next: Settings = {
      copyOnSelect: copyOnSelect.checked,
      keyCopy: keyCopy.value,
      keyPaste: keyPaste.value,
      defaultUsername: defaultUser.value.trim(),
    };
    try {
      await saveSettings(next);
      return true;
    } catch (e) {
      return fail(errorMessage(e));
    }
  };

  const r = await showModal("Настройки", body, [{ label: "Сохранить", value: "save", kind: "primary" }], { validate });
  return r === "save";
}
