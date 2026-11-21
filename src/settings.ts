import { api, Settings } from "./api";

export const DEFAULT_SETTINGS: Settings = {
  copyOnSelect: false,
  keyCopy: "Ctrl+C",
  keyPaste: "Ctrl+V",
  defaultUsername: "",
};

let current: Settings = { ...DEFAULT_SETTINGS };

export function getSettings(): Settings {
  return current;
}

export async function loadSettings() {
  try {
    current = { ...DEFAULT_SETTINGS, ...(await api.getSettings()) };
  } catch {
    current = { ...DEFAULT_SETTINGS };
  }
}

export async function saveSettings(next: Settings) {
  await api.setSettings(next);
  current = { ...next };
}

const MODIFIER_KEYS = new Set(["Control", "Shift", "Alt", "Meta", "AltGraph"]);

/**
 * Normalizes a keydown into "Ctrl+Shift+C". Uses the physical key (e.code) for
 * letters and digits so shortcuts work the same in any keyboard layout.
 * Returns null for a bare modifier press.
 */
export function comboFromEvent(e: KeyboardEvent): string | null {
  if (MODIFIER_KEYS.has(e.key)) return null;
  let key: string;
  if (/^Key[A-Z]$/.test(e.code)) key = e.code.slice(3);
  else if (/^Digit\d$/.test(e.code)) key = e.code.slice(5);
  else if (e.code) key = e.code;
  else key = e.key.length === 1 ? e.key.toUpperCase() : e.key;
  const parts: string[] = [];
  if (e.ctrlKey) parts.push("Ctrl");
  if (e.altKey) parts.push("Alt");
  if (e.shiftKey) parts.push("Shift");
  if (e.metaKey) parts.push("Win");
  parts.push(key);
  return parts.join("+");
}

/** A shortcut must not swallow ordinary typing: it needs Ctrl/Alt/Win, or be Insert / F1–F12. */
export function isValidCombo(combo: string): boolean {
  const parts = combo.split("+");
  const key = parts[parts.length - 1];
  const mods = parts.slice(0, -1);
  if (mods.some((m) => m === "Ctrl" || m === "Alt" || m === "Win")) return true;
  return key === "Insert" || /^F([1-9]|1[0-2])$/.test(key);
}
