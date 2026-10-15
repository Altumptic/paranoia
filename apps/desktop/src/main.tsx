import React from "react";
import ReactDOM from "react-dom/client";

import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "./styles/app.css";
import "./styles/layout.css";
import "./styles/views.css";

import { App } from "./App";
import { isDesktop } from "./engine/client";

// Desktop shell: custom title bar (drag regions + room for native window controls).
if (isDesktop) document.documentElement.classList.add("desktop");

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
