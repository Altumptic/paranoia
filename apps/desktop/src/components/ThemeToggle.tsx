import { Monitor, Moon, Sun } from "lucide-react";

import { useTheme, type ThemePref } from "../theme";

const NEXT: Record<ThemePref, ThemePref> = { system: "light", light: "dark", dark: "system" };
const LABEL: Record<ThemePref, string> = { system: "Theme: system", light: "Theme: light", dark: "Theme: dark" };

export function ThemeToggle() {
  const [pref, set] = useTheme();
  const Icon = pref === "light" ? Sun : pref === "dark" ? Moon : Monitor;
  return (
    <button className="icon-btn" onClick={() => set(NEXT[pref])} title={`${LABEL[pref]} — click to change`} aria-label={LABEL[pref]}>
      <Icon size={16} />
    </button>
  );
}
