import { h } from "./dom";

export interface ModalAction {
  label: string;
  value: string;
  kind?: "primary" | "danger" | "ghost";
}

interface ModalOptions {
  wide?: boolean;
  /** Called before closing with a non-cancel value; return false to keep the dialog open. */
  validate?: (value: string) => boolean | Promise<boolean>;
}

/** Resolves with the clicked action's value, or null if cancelled (Esc / backdrop / Cancel). */
export function showModal(
  title: string,
  body: Node,
  actions: ModalAction[],
  opts: ModalOptions = {},
): Promise<string | null> {
  const root = document.getElementById("modal-root")!;
  return new Promise((resolve) => {
    const finish = async (value: string | null) => {
      if (value !== null && opts.validate && !(await opts.validate(value))) return;
      document.removeEventListener("keydown", onKey, true);
      overlay.remove();
      resolve(value);
    };
    const onKey = (e: KeyboardEvent) => {
      // Shortcut-capture fields record every key themselves, Enter and Esc included.
      if ((e.target as HTMLElement | null)?.dataset?.keycapture) return;
      if (e.key === "Escape") {
        e.stopPropagation();
        finish(null);
      } else if (e.key === "Enter" && (e.target as HTMLElement)?.tagName === "INPUT") {
        const primary = actions.find((a) => a.kind === "primary" || a.kind === "danger");
        if (primary) {
          e.preventDefault();
          finish(primary.value);
        }
      }
    };
    const footer = h(
      "div",
      { class: "modal-footer" },
      h("button", { class: "btn ghost", onclick: () => finish(null) }, "Отмена"),
      ...actions.map((a) => h("button", { class: `btn ${a.kind ?? ""}`, onclick: () => finish(a.value) }, a.label)),
    );
    const dialog = h(
      "div",
      { class: "modal" + (opts.wide ? " wide" : ""), role: "dialog" },
      h("div", { class: "modal-header" }, title),
      h("div", { class: "modal-body" }, body),
      footer,
    );
    const overlay = h("div", { class: "modal-overlay", onmousedown: (e: MouseEvent) => e.target === overlay && finish(null) }, dialog);
    root.append(overlay);
    document.addEventListener("keydown", onKey, true);
    requestAnimationFrame(() => (dialog.querySelector("input, select, textarea") as HTMLElement | null)?.focus());
  });
}

export async function confirmDialog(title: string, message: string | Node, confirmLabel = "OK", danger = false) {
  const body = typeof message === "string" ? h("p", {}, message) : message;
  return (await showModal(title, body, [{ label: confirmLabel, value: "ok", kind: danger ? "danger" : "primary" }])) === "ok";
}

export async function alertDialog(title: string, message: string) {
  await showModal(title, h("p", { class: "pre" }, message), [{ label: "OK", value: "ok", kind: "primary" }]);
}

export async function promptText(
  title: string,
  label: string,
  opts: { initial?: string; password?: boolean; hint?: string } = {},
): Promise<{ value: string } | null> {
  const input = h("input", { type: opts.password ? "password" : "text", value: opts.initial ?? "", spellcheck: false });
  const body = h(
    "div",
    { class: "form" },
    opts.hint ? h("p", { class: "muted" }, opts.hint) : null,
    h("label", { class: "field" }, h("span", {}, label), input),
  );
  const r = await showModal(title, body, [{ label: "OK", value: "ok", kind: "primary" }]);
  if (r !== "ok") return null;
  return { value: input.value };
}
