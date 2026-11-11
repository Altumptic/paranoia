# `paranoia query`

Machine-readable answers for other programs. The [REA](https://github.com/morluto/rea) provider uses it; anything that can run a command and read JSON can too. Each run analyses the file, answers one question and prints one JSON object on one line. The file is only read.

```bash
paranoia query sample.exe inventory              # functions, imports, strings, call edges
paranoia query sample.exe function 0x401c04      # pseudocode and assembly of one function
paranoia query sample.exe function main
paranoia query sample.exe xrefs CreateFileW      # references to an address or name
```

## Format `paranoia-query/1`

```json
{
  "format": "paranoia-query/1",
  "file": { "sha256": "…", "name": "sample.exe", "format": "pe", "arch": "x86_64", "bits": 64, "entry": "0x401000" },
  "result": …
}
```

- `file.sha256` is the hash of the bytes that were analysed. Check it if the file could change between runs.
- Addresses are strings: `0x` and lowercase hex without leading zeros, so 64-bit values survive JSON parsers that use doubles.
- A selector starting with `0x` is an address; anything else is a function, export or import name. A bare word is never read as hex (`add` is a name).
- A selector that matches nothing gives `"result": null`. Errors (unreadable or unsupported file) exit with a non-zero status and a message on stderr.

| Question | `result` |
| --- | --- |
| `inventory` | `functions`: `address`, `name`, `size`, `instructions`, `thunk` (jumps to an import), `library` (recognised runtime code). `imports`: `address` of the slot, `name`, `library`. `strings`: `address` (null when not mapped), `offset`, `value`, `encoding` (`ascii` or `utf16`), `xrefs` (number of code references). `calls`: `[caller, target]` pairs, the caller being a function start and the target a function start or an import slot |
| `function SEL` | `address`, `name`, `size`, `pseudocode` (null where there is no decompiler), `assembly` (the function's blocks in address order, with labels) |
| `xrefs SEL` | `address`, and `references`: `from`, `kind` (`call`, `jump` or `data`), `function` (start of the function containing `from`, or null) |

A new field can appear in a version; changing or removing one needs a new `format`.
