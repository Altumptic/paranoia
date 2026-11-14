// Name normalization shared by every metric in the benchmark.
//
// Ground truth names come from very different places (PE exports, Go pclntab,
// COFF symbols, Rust C++ Itanium mangling) and the two tools render them in
// different ways (raw, demangled, namespaced, C-sanitized). The benchmark
// compares *short names*: the last path component, canonicalized to lowercase
// [a-z0-9_] with common prefixes removed.

const KEYWORDS = new Set([
    'if', 'for', 'while', 'switch', 'do', 'else', 'return', 'sizeof', 'case', 'default',
    'break', 'continue', 'goto', 'typedef', 'struct', 'union', 'enum', 'static', 'const',
    'volatile', 'unsigned', 'signed', 'float', 'double', 'char', 'short', 'int', 'long',
    'void', 'defined', 'alignof', 'typeof', 'offsetof', 'operator', 'new', 'delete',
    'catch', 'try', 'throw', 'extern', 'register', 'auto', 'inline', 'restrict', 'asm',
    'attribute', 'unaligned', 'wchar_t', 'bool', 'size_t', 'ssize_t', 'uint', 'ulong',
    'undefined', 'undefined1', 'undefined2', 'undefined3', 'undefined4', 'undefined8',
    'byte', 'word', 'dword', 'qword', 'code', 'return', 'noreturn', 'int64_t', 'uint64_t',
    'int32_t', 'uint32_t', 'int16_t', 'uint16_t', 'int8_t', 'uint8_t', 'intptr_t',
    'uintptr_t', 'va_list', 'nullptr', 'true', 'false', 'NULL',
]);

const forRealKeyword = (s) => KEYWORDS.has(s.toLowerCase());

// Escapes inside a legacy-mangled identifier: `$LT$` is `<`, `$u20$` a space, `..` is `::`.
const LEGACY_ESCAPES = { SP: '@', BP: '*', RF: '&', LT: '<', GT: '>', LP: '(', RP: ')', C: ',' };
function decodeLegacyEscapes(raw) {
    return raw
        .replace(/\$([A-Z]+)\$/g, (m, esc) => LEGACY_ESCAPES[esc] ?? m)
        .replace(/\$u([0-9a-f]+)\$/gi, (_m, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/\.\./g, '::');
}

// Legacy Rust symbol mangling: _ZN<len><name>...E, with an optional trailing
// hash component (17h0123456789abcdef). Returns the path components, or null.
function parseRustLegacy(name) {
    if (!name.startsWith('_ZN') && !name.startsWith('__ZN')) return null;
    let i = name.startsWith('_ZN') ? 3 : 4;
    const parts = [];
    while (i < name.length) {
        if (name[i] === 'E') {
            i++;
            break;
        }
        // Escaped characters: $SP $BP $RF $LT $GT $LP $RP $C $uXX
        const m = /^(\d+)/.exec(name.slice(i));
        if (!m) return null;
        const len = parseInt(m[1], 10);
        i += m[1].length;
        // The length counts the characters as mangled, escapes included.
        if (i + len > name.length) return null;
        parts.push(decodeLegacyEscapes(name.slice(i, i + len)));
        i += len;
    }
    // The trailing component is a hash like 17h0011223344556677.
    while (parts.length && /^[0-9]+h[0-9a-f]{16}$/i.test(parts[parts.length - 1])) parts.pop();
    while (parts.length && /^h[0-9a-f]{16}$/i.test(parts[parts.length - 1])) parts.pop();
    return parts.length ? parts : null;
}

// Small Rust v0 reader: it recovers the identifiers of the path, which are
// `<length>[_]<identifier>` pieces between tag letters, skipping the crate and
// namespace disambiguators (`s<base62>_`) and back-references (`B<base62>_`).
// The short-name comparison only needs the last identifier.
function parseRustV0(name) {
    if (!name.startsWith('_R')) return null;
    const body = name.slice(2);
    const ids = [];
    let i = 0;
    while (i < body.length) {
        const c = body[i];
        if (c === 's' || c === 'B') {
            i++;
            while (i < body.length && /[0-9a-zA-Z]/.test(body[i])) i++;
            if (body[i] === '_') i++;
        } else if (c >= '0' && c <= '9') {
            let j = i;
            while (j < body.length && body[j] >= '0' && body[j] <= '9') j++;
            const len = parseInt(body.slice(i, j), 10);
            if (body[j] === '_') j++;
            const id = body.slice(j, j + len);
            if (len === 0 || j + len > body.length || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(id)) {
                i++;
                continue;
            }
            ids.push(id);
            i = j + len;
        } else {
            i++;
        }
    }
    return ids.length ? ids : null;
}

function parseMsvc(name) {
    if (!name.startsWith('?')) return null;
    const m = /^\?([^@]+)@/.exec(name);
    if (!m) return null;
    let n = m[1];
    if (n.startsWith('?0')) n = n.slice(2); // anonymous namespace
    return [n];
}

function parseItanium(name) {
    // _ZN3foo3barEv / __ZN... ; reuse the Rust legacy reader (same nesting).
    const parts = parseRustLegacy(name);
    if (!parts) return null;
    // Drop the leading 'std' style namespaces only for display; short name is last.
    return parts;
}

// Full path components of a symbol name in whatever form it arrives.
// Removes balanced generic arguments from a path component: `drop_in_place<A<B>>` becomes
// `drop_in_place`. A component that starts with `<` (`<T as Trait>`) is left alone.
function stripGenerics(part) {
    if (part.startsWith('<') || !part.includes('<')) return part;
    let depth = 0;
    let out = '';
    for (const ch of part) {
        if (ch === '<') depth++;
        else if (ch === '>' && depth > 0) depth--;
        else if (depth === 0) out += ch;
    }
    return out || part;
}

// Splits a demangled path on `::` outside any brackets, so `core::ptr::drop_in_place<a::B>` has
// three components, not four.
function splitPath(n) {
    const parts = [];
    let depth = 0;
    let cur = '';
    for (let i = 0; i < n.length; i++) {
        const ch = n[i];
        if ('<({['.includes(ch)) depth++;
        else if ('>)}]'.includes(ch) && depth > 0) depth--;
        if (depth === 0 && ch === ':' && n[i + 1] === ':') {
            if (cur) parts.push(cur);
            cur = '';
            i++;
        } else {
            cur += ch;
        }
    }
    if (cur) parts.push(cur);
    return parts;
}

const lastGenericFree = (parts) => (parts.length ? [...parts.slice(0, -1), stripGenerics(parts[parts.length - 1])] : parts);

export function symbolPath(raw) {
    if (raw == null) return [];
    let name = String(raw).trim();
    if (!name) return [];
    if (name.startsWith('EXTERNAL::')) name = name.slice('EXTERNAL::'.length);
    const rust = parseRustV0(name) ?? parseRustLegacy(name) ?? parseItanium(name);
    if (rust) return lastGenericFree(rust);
    const msvc = parseMsvc(name);
    if (msvc) return msvc;
    // Go / C++ / arbitrary dotted names: split on :: and .
    let n = name.replace(/^__imp_/, '').replace(/^imp_/, '');
    n = n.replace(/@\d+$/, '').replace(/@@.*$/, '');
    // Rust-style paths keep dots inside `{{vtable.shim}}`; Go and C++ names split on both.
    const parts = (n.includes('::') ? splitPath(n) : n.split(/\./)).filter((p) => p.length > 0);
    return parts.length ? lastGenericFree(parts) : [n];
}

// Canonical comparison key for a name in any representation.
export function canon(raw) {
    const parts = symbolPath(raw);
    if (!parts.length) return '';
    let last = parts[parts.length - 1];
    // Go filenames/type descriptors: "(0x...)" or "*T" leftovers.
    last = last.replace(/\(.*$/, '').replace(/\)$/, '');
    last = last.replace(/^(?:sub_|fun_|thunk_|j_|jmp_|loc_|lab_|unk_|data_)/i, '');
    last = last.replace(/^[_.$?*&]+/, '').replace(/[_.$?*&]+$/, '');
    last = last.replace(/@\d+$/, '');
    last = last.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
    return last;
}

// Canonical short names for a list of raw ground-truth symbols. Returns a map
// canonical -> best display name (first seen) and a set of all canonical names.
export function canonicalIndex(entries) {
    const byCanon = new Map(); // canon -> { display, raws: Set }
    for (const e of entries) {
        const c = canon(e.name);
        if (!c || c.length < 2) continue;
        if (!byCanon.has(c)) byCanon.set(c, { display: e.name, raws: new Set() });
        byCanon.get(c).raws.add(e.name);
    }
    return byCanon;
}

// Candidate canonical names for an identifier found before `(` in C output.
// Tools render the same symbol in different shapes (Ghidra C output for a Go
// function called runtime.panicIndex is `runtime::runtime_panicIndex(...)`,
// paranoia writes `runtime.panicIndex(...)`), so besides the identifier itself
// we accept trailing `_`-separated suffixes of it. The metric only counts
// candidates that occur in the ground-truth name set, so extra candidates add
// little noise.
export function canonCallCandidates(identifier) {
    const base = String(identifier)
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '');
    if (!base || base.length < 2) return [];
    const out = new Set([base]);
    const segs = base.split('_').filter(Boolean);
    for (let k = 1; k <= Math.min(3, segs.length - 1); k++) {
        const c = segs.slice(-k).join('_');
        if (c.length >= 3) out.add(c);
    }
    return [...out];
}

// Extracts identifiers used as call targets: `identifier (` with comments and
// string/char literals stripped first. Only the function body (after the first
// `{`) is scanned so the function's own signature cannot count as a call.
export function callIdentifiers(cText, selfCanon = '') {
    if (!cText) return [];
    let s = cText
        .replace(/\/\*[\s\S]*?\*\//g, ' ')
        .replace(/\/\/[^\n]*/g, ' ')
        .replace(/"(?:[^"\\]|\\.)*"/g, ' "" ')
        .replace(/'(?:[^'\\]|\\.)*'/g, " '' ");
    const brace = s.indexOf('{');
    if (brace >= 0) s = s.slice(brace + 1);
    const out = new Set();
    const re = /([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
    let m;
    while ((m = re.exec(s)) !== null) {
        const id = m[1];
        if (forRealKeyword(id)) continue;
        for (const c of canonCallCandidates(id)) {
            if (!c || c === selfCanon) continue;
            out.add(c);
        }
    }
    return [...out];
}

// Counts C output size in lines (non-empty) and characters.
export function cSize(cText) {
    if (!cText) return { lines: 0, nonEmptyLines: 0, chars: 0 };
    const lines = cText.split('\n');
    return {
        lines: lines.length,
        nonEmptyLines: lines.filter((l) => l.trim().length > 0).length,
        chars: cText.length,
    };
}

export function isFailedC(cText, error) {
    if (error) return true;
    if (cText == null) return true;
    return cText.trim().length === 0;
}
