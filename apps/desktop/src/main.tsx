import React from "react";
import ReactDOM from "react-dom/client";

import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "@fontsource-variable/source-serif-4";
import "./styles/app.css";
import "./styles/layout.css";
import "./styles/views.css";

import { App } from "./App";
import { desktop, isDesktop } from "./engine/client";
import { initTheme } from "./theme";

// Desktop shell: custom title bar (drag regions + room for native window controls).
if (isDesktop) {
  document.documentElement.classList.add("desktop");
  // macOS draws its traffic lights over the page instead of the Windows title-bar overlay.
  if (desktop?.platform === "darwin") document.documentElement.classList.add("macos");
}
initTheme();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
