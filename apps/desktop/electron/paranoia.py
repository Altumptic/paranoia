"""Paranoia scripting API for Python.

Scripts run in your own CPython with full access to its libraries. The module talks to
the analysis engine through the app, one JSON message per line. The common IDAPython
names are available too, so `import idc`, `idautils`, `ida_bytes`, `ida_funcs` and
`ida_name` work for everyday scripts:

    import idautils, idc
    for ea in idautils.Functions():
        if idc.get_func_name(ea).startswith("sub_"):
            print(hex(ea))
"""

import json
import os
import sys

__all__ = [
    "BADADDR", "call", "info", "functions", "Functions", "get_func_name", "get_name", "set_name",
    "set_cmt", "get_cmt", "get_bytes", "get_byte", "get_wide_dword", "get_qword", "patch_bytes",
    "XrefsTo", "CodeRefsTo", "DataRefsTo", "disasm", "generate_disasm_line", "decompile", "strings",
    "search", "find_bytes", "jumpto", "here", "get_screen_ea", "add_func", "segments", "entry", "refresh",
]

BADADDR = 0xFFFFFFFFFFFFFFFF
_seq = 0
_dirty = False


def _rpc(msg):
    global _seq
    _seq += 1
    msg["id"] = _seq
    out = sys.__stdout__
    out.write("\x1e" + json.dumps(msg) + "\n")
    out.flush()
    line = sys.stdin.readline()
    if not line:
        raise RuntimeError("Paranoia closed the scripting connection")
    reply = json.loads(line)
    if not reply.get("ok"):
        raise RuntimeError(reply.get("error") or "engine error")
    return reply.get("value")


def call(method, **args):
    """Calls any engine method (the same API the app uses), e.g. call("frame", va=ea)."""
    return _rpc({"op": "call", "method": method, "args": args or None})


def _changed():
    global _dirty
    _dirty = True


def refresh():
    """Asks the app to redraw after edits (done automatically when the script ends)."""
    global _dirty
    _rpc({"op": "refresh"})
    _dirty = False


# --- Binary --------------------------------------------------------------------------------

def info():
    """Format, architecture, sections, imports, exports, hashes."""
    return call("info")


def entry():
    return info()["entry"]


def segments():
    return info()["sections"]


def functions():
    """All functions as dicts: address, name, size, blocks, instructions, xrefs, library."""
    return call("functions")


def Functions(start=0, end=BADADDR):
    """Start addresses of functions in [start, end) — like idautils.Functions."""
    for f in functions():
        if start <= f["address"] < end:
            yield f["address"]


def get_func_name(ea):
    f = call("functionAt", va=ea)
    return f["name"] if f else None


def get_name(ea):
    return call("addressInfo", va=ea).get("name") or ""


def set_name(ea, name, flags=0):
    call("rename", va=ea, text=name or "")
    _changed()
    return True


def get_cmt(ea, repeatable=False):
    notes = call("annotations").get("comments", {})
    return notes.get(str(ea))


def set_cmt(ea, comment, repeatable=False):
    call("setComment", va=ea, text=comment or "")
    _changed()
    return True


def add_func(ea, end=BADADDR):
    call("makeFunction", va=ea)
    _changed()
    return True


# --- Bytes ---------------------------------------------------------------------------------

def get_bytes(ea, size):
    off = call("vaToOffset", va=ea)
    if off is None:
        return None
    return bytes.fromhex(call("read", offset=off, len=size))


def get_byte(ea):
    b = get_bytes(ea, 1)
    return b[0] if b else None


def get_wide_dword(ea):
    b = get_bytes(ea, 4)
    return int.from_bytes(b, "little") if b and len(b) == 4 else None


def get_qword(ea):
    b = get_bytes(ea, 8)
    return int.from_bytes(b, "little") if b and len(b) == 8 else None


def patch_bytes(ea, data):
    off = call("vaToOffset", va=ea)
    if off is None:
        raise ValueError(f"{ea:#x} is not backed by the file")
    call("patch", offset=off, hex=bytes(data).hex())
    _changed()


# --- Cross references ----------------------------------------------------------------------

class Xref:
    """An IDA-style cross reference: frm, to, type ("call", "jump" or "data")."""

    def __init__(self, d):
        self.frm = d["from"]
        self.to = d["to"]
        self.type = d["kind"]
        self.iscode = d["kind"] != "data"
        self.function = d.get("function_name")

    def __repr__(self):
        return f"Xref({self.frm:#x} -> {self.to:#x}, {self.type})"


def XrefsTo(ea, flags=0):
    return [Xref(x) for x in call("xrefs", va=ea)]


def CodeRefsTo(ea, flow=0):
    return [x.frm for x in XrefsTo(ea) if x.iscode]


def DataRefsTo(ea):
    return [x.frm for x in XrefsTo(ea) if not x.iscode]


# --- Listing and pseudocode ----------------------------------------------------------------

def _line(insn):
    ops = "".join(t["t"] for t in insn["operands"])
    return f"{insn['mnemonic']} {ops}".strip()


def disasm(ea, count=1):
    """`count` instructions from `ea` as (address, text) pairs."""
    return [(i["address"], _line(i)) for i in call("disassemble", va=ea, count=count)]


def generate_disasm_line(ea, flags=0):
    lines = disasm(ea, 1)
    return lines[0][1] if lines else ""


def decompile(ea):
    """Pseudocode of the function containing `ea`, as text."""
    p = call("pseudocode", va=ea)
    if not p:
        return None
    return "\n".join("    " * l["indent"] + "".join(t["t"] for t in l["tokens"]) for l in p["lines"])


def strings():
    return call("strings")


def search(query, limit=100):
    """Names, imports, exports and strings matching `query`."""
    return call("search", query=query, limit=limit)


def find_bytes(pattern):
    """Byte pattern with `??` wildcards, e.g. "48 8B ?? 24"."""
    return call("searchAdvanced", kind="bytes", query=pattern)


# --- UI ------------------------------------------------------------------------------------

def here():
    """The address under the cursor when the script started."""
    return int(os.environ.get("PN_CURSOR", "0") or 0)


get_screen_ea = here


def jumpto(ea):
    _rpc({"op": "goto", "va": int(ea)})
    return True


class _Pn:
    """`pn.functions()`, `pn.rename(ea, name)`, … — the same names as the JavaScript console."""

    call = staticmethod(call)
    info = staticmethod(info)
    functions = staticmethod(functions)
    names = staticmethod(lambda: call("names"))
    xrefs = staticmethod(lambda ea: call("xrefs", va=ea))
    read = staticmethod(get_bytes)
    disasm = staticmethod(disasm)
    pseudocode = staticmethod(decompile)
    rename = staticmethod(set_name)
    comment = staticmethod(set_cmt)
    patch = staticmethod(patch_bytes)
    search = staticmethod(search)
    strings = staticmethod(strings)
    goto = staticmethod(jumpto)
    here = staticmethod(here)


pn = _Pn()

# IDAPython module names resolve to this module, so common scripts run unchanged.
for _alias in ("idc", "idautils", "idaapi", "ida_bytes", "ida_funcs", "ida_name", "ida_kernwin", "ida_xref"):
    sys.modules.setdefault(_alias, sys.modules[__name__])


def _main(path):
    """Runs a user script with this module's names in scope."""
    with open(path, encoding="utf-8") as f:
        code = f.read()
    scope = {"__name__": "__main__", "__file__": path}
    scope.update({k: globals()[k] for k in __all__})
    scope["pn"] = pn
    try:
        exec(compile(code, "<script>", "exec"), scope)
    finally:
        if _dirty:
            try:
                refresh()
            except Exception:
                pass
