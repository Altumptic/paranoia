# Plugins

A plugin is a folder with a manifest and one script. It adds commands to the **Plugins** menu of the
desktop app. Plugins use the same APIs as the consoles — the JavaScript `pn` object or the Python
`paranoia` / `idc` / `idautils` modules — so anything you can script, you can package.

## Where they live

`%APPDATA%\Paranoia\plugins\<id>\` (**Plugins → Open plugins folder…**). Two examples are in
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
| `commands` | 1–32 entries: `id`, `title` and an optional `run` — the name of a function in the script that is called after the file is evaluated (omit it to just run the file) |

A plugin that fails validation is listed in the menu with the reason instead of being loaded.

## Safety

Plugin code is somebody else's code, so:

* The first time a version runs, Paranoia asks in a **native dialog** (outside the page, so a plugin
  cannot click it) and shows the folder, script size and fingerprint. *Always run this version* remembers
  the SHA-256 of the manifest **and** the script; any edit asks again.
* The script that runs is read from disk by the main process *after* you agreed — the page never supplies
  code.
* **JavaScript** plugins run in the same isolated worker as the console: no DOM, no files, no network;
  they can read and change the open analysis through `pn`.
* **Python** plugins are ordinary programs in your interpreter: they run with your permissions and can read
  files and use the network. Install only plugins you have read.

## Not yet

Plugin-defined sidebar panels, hotkeys and event hooks; a plugin gallery. Today a plugin is a set of
commands.
