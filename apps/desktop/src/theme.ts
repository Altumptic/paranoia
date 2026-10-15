import { useEffect, useState } from "react";

import { desktop } from "./engine/client";

export type ThemePref = "system" | "light" | "dark";
const KEY = "paranoia.theme";

function read(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

const media = typeof window !== "undefined" ? window.matchMedia("(prefers-color-scheme: dark)") : null;

export function resolved(pref: ThemePref): "light" | "dark" {
  return pref === "system" ? (media?.matches ? "dark" : "light") : pref;
}

/** Applies the theme to <html> and keeps the native title bar in sync. */
export function applyTheme(pref: ThemePref) {
  const root = document.documentElement;
  if (pref === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", pref);
  // Read the effective colors after the attribute change.
  const css = getComputedStyle(root);
  desktop?.setTitleBar(css.getPropertyValue("--bg-1").trim(), css.getPropertyValue("--text-2").trim());
}

export function initTheme() {
  applyTheme(read());
  media?.addEventListener("change", () => read() === "system" && applyTheme("system"));
}

export function useTheme(): [ThemePref, (p: ThemePref) => void, "light" | "dark"] {
  const [pref, setPref] = useState<ThemePref>(read);
  const [, force] = useState(0);
  useEffect(() => {
    const on = () => force((n) => n + 1);
    media?.addEventListener("change", on);
    return () => media?.removeEventListener("change", on);
  }, []);
  const set = (p: ThemePref) => {
    try {
      localStorage.setItem(KEY, p);
    } catch {
      /* storage unavailable */
    }
    setPref(p);
    applyTheme(p);
  };
  return [pref, set, resolved(pref)];
}

/** Reads a CSS custom property (for canvas drawing). */
export function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}
