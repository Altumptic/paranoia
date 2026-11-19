# Plugins

A plugin is a folder with a manifest and one script. It adds commands to the **Plugins** menu of the
desktop app. Plugins use the same APIs as the consoles (the JavaScript `pn` object or the Python
`paranoia` / `idc` / `idautils` modules), so anything you can script, you can package.

## Where they live

The app's plugins folder (**Plugins → Open plugins folder…**) — `%APPDATA%\Paranoia\plugins\<id>\` on Windows, `~/.config/Paranoia/plugins/<id>/` on Linux, `~/Library/Application Support/Paranoia/plugins/<id>/` on macOS. Two examples are in
[`examples/plugins`](../examples/plugins): copy a folder there and choose **Plugins → Reload plugins**.

```text
plugins/
  largest-functions/
    plugin.json
    main.js
```

## `plugin.json`

```json
{
  "id": "largest-functions",
  "name": "Largest functions",
  "version": "1.0.0",
  "description": "Lists the biggest functions of the open file.",
  "language": "js",
  "entry": "main.js",
  "commands": [{ "id": "top10", "title": "Show the 10 largest functions", "run": "top10" }]
}
```

| Field | Rules |
|---|---|
| `id` | lowercase letters, digits, `.` `_` `-`; must equal the folder name |
| `name`, `version` | required, short strings |
| `description` | optional, up to 300 characters |
| `language` | `"js"` or `"py"` |
| `entry` | a file in the plugin folder ending in `.js` / `.py` (matching `language`), up to 256 KB; no sub-folders, no links leaving the folder |
| `commands` | 1–32 entries with `id`, `title` and an optional `run`: a function in the script to call after the file is evaluated (leave it out to just run the file) |

A plugin that fails validation is listed in the menu with the reason instead of being loaded.

## Safety

Plugin code is somebody else's code, so:

* The first time a version runs, Paranoia asks in a **native dialog** (outside the page, so a plugin
  cannot click it) and shows the folder, script size and fingerprint. *Always run this version* remembers
  the SHA-256 of the manifest **and** the script; any edit asks again.
* The main process reads the script from disk after you agreed. The page never supplies
  code.
* **JavaScript** plugins run in the same isolated worker as the console: no DOM, no files, no network;
  they can read and change the open analysis through `pn`.
* **Python** plugins are ordinary programs in your interpreter: they run with your permissions and can read
  files and use the network. Install only plugins you have read.

## Hotkeys

A command can have a `key`: `"commands": [{ "id": "report", "title": "Print the report", "run": "report", "key": "Ctrl+Alt+R" }]`. The key needs **Ctrl or Alt** (a bare letter would steal your typing) plus one letter, digit or F-key (F1–F12), optionally with Shift, and must not be one the app uses (Ctrl+O, Ctrl+K, Ctrl+Z, F7–F9 and the other built-in shortcuts are refused, and the plugin is listed with the reason). Two commands of one plugin cannot share a key; if two plugins ask for the same key the first one in the list wins. The key is shown next to the command in the Plugins menu, and pressing it does exactly what choosing the menu item does, including the native confirmation the first time a version runs.

## Event hooks

A plugin can run a function when something happens:

```json
"hooks": [{ "event": "open", "run": "onOpen" }, { "event": "rename", "run": "onRename" }]
```

| Event | When | `event` object |
|---|---|---|
| `open` | a file was opened and analysed | `{ name, file, sha256, format, arch }` |
| `rename` | a name was changed in the app | `{ name, address, new_name }` |

The function (named by `run`; leave it out to just run the file) is called with `event`; in JavaScript it is also available as `globalThis.event`, in Python as the module variable `event`. Because a hook runs **without a click**, only a plugin version you already chose *Always run this version* for may run one; for any other version hooks are skipped silently (run one of its commands once and pick that option). Hooks never nest (a rename made by a hook does not fire the rename hook), run one after another, and a hook that fails three times in a row is switched off until the app restarts; the error appears in the console. At most 8 hooks per plugin; more events can be added later.

[`examples/plugins/open-report`](../examples/plugins/open-report) has a hotkey and both hooks.

## Not yet

Plugin-defined sidebar panels and a plugin gallery.
