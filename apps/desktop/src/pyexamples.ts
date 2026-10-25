// Python console examples. Scripts run in the user's own CPython with the `paranoia`
// module; IDAPython names (idc, idautils, ida_bytes, …) work for common calls.

export const PY_EXAMPLES: { title: string; code: string }[] = [
  {
    title: "Unnamed functions (IDAPython style)",
    code: `import idautils, idc

count = 0
for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    if name.startswith("sub_"):
        count += 1
        if count <= 20:
            print(hex(ea), name)
print(count, "unnamed functions")
`,
  },
  {
    title: "Who calls an import",
    code: `import idautils

target = "CreateFileW"
for imp in info()["imports"]:
    if imp["name"] == target:
        for x in idautils.XrefsTo(imp["address"]):
            print(hex(x.frm), x.type, x.function)
`,
  },
  {
    title: "Pseudocode of the function at the cursor",
    code: `print(decompile(here()))
`,
  },
  {
    title: "Hash functions with hashlib",
    code: `import hashlib

for f in functions()[:25]:
    data = get_bytes(f["address"], f["size"]) or b""
    print(f"{f['address']:#x}  {hashlib.sha256(data).hexdigest()[:16]}  {f['name']}")
`,
  },
  {
    title: "Rename functions that reference a string",
    code: `# Names functions after the first "Error: …" string they use.
for s in strings():
    if not s["value"].startswith("Error"):
        continue
    for x in XrefsTo(s["address"]):
        f = call("functionAt", va=x.frm)
        if f and f["name"].startswith("sub_"):
            name = "err_" + "".join(c if c.isalnum() else "_" for c in s["value"][7:30])
            set_name(f["address"], name)
            print(hex(f["address"]), "->", name)
`,
  },
  {
    title: "Count instructions by mnemonic",
    code: `from collections import Counter

ea = here()
counts = Counter(text.split()[0] for _, text in disasm(ea, 300))
for m, n in counts.most_common(12):
    print(f"{m:10} {n}")
`,
  },
];
