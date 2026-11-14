// Ground truth for one benchmark binary, derived only from the file itself
// (or the compiler/linker metadata inside it), never from either tool's output.
//
// Priority:
//   Go binaries          -> Go pclntab function table (survives -s -w) + PE imports
//   GNU-linked Rust/PE   -> COFF symbol table + PE imports + PE exports
//   Microsoft system PE  -> PE export table + PE import table
//   ELF                  -> .symtab/dynsym function symbols (best effort)
import fs from 'node:fs';
import { parsePe } from './pe.mjs';
import { readGoPclntab } from './gopcln.mjs';
import { canon } from './names.mjs';

function normAddr(a) {
    if (a === null || a === undefined) return null;
    if (typeof a === 'bigint') return '0x' + a.toString(16);
    if (typeof a === 'number') return '0x' + BigInt(a).toString(16);
    const s = String(a).trim().toLowerCase();
    if (s.startsWith('0x')) return '0x' + BigInt(s).toString(16);
    return s;
}

function isExecutableSection(pe, rva) {
    for (const s of pe.sections) {
        if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) {
            return (s.characteristics & 0x20000000) !== 0;
        }
    }
    return false;
}

// Go's pclntab starts with a pseudo entry ("go:buildid") at textStart; drop it.
function isGoPseudoFunction(name) {
    return name.startsWith('go:') || name === 'runtime.text' || name === 'runtime.etext' || name === 'runtime.rodata' || name === 'runtime.erodata';
}

function parseElfSymbols(buf) {
    const out = { functions: [], exports: [], imports: [] };
    const bits = buf[4] === 2 ? 64 : 32;
    if (bits !== 64) return out; // only 64-bit ELF supported here
    const eShoff = Number(buf.readBigUInt64LE(0x28));
    const eShentsize = buf.readUInt16LE(0x3a);
    const eShnum = buf.readUInt16LE(0x3c);
    const eShstrndx = buf.readUInt16LE(0x3e);
    if (!eShoff || !eShentsize || !eShnum) return out;
    const sections = [];
    for (let i = 0; i < eShnum; i++) {
        const o = eShoff + i * eShentsize;
        if (o + 64 > buf.length) break;
        sections.push({
            nameOff: buf.readUInt32LE(o),
            type: buf.readUInt32LE(o + 4),
            addr: Number(buf.readBigUInt64LE(o + 16)),
            offset: Number(buf.readBigUInt64LE(o + 24)),
            size: Number(buf.readBigUInt64LE(o + 32)),
            link: buf.readUInt32LE(o + 40),
            entsize: Number(buf.readBigUInt64LE(o + 56)),
        });
    }
    const shstr = sections[eShstrndx];
    const shstrOff = shstr ? shstr.offset : 0;
    const readStr = (base, rel) => {
        let end = base + rel;
        while (end < buf.length && buf[end] !== 0) end++;
        return buf.toString('utf8', base + rel, end);
    };
    const symtypes = new Set([0, 1, 2, 11]); // SHT_SYMTAB, SHT_DYNSYM
    for (const s of sections) {
        if (!symtypes.has(s.type) || !s.entsize) continue;
        const strtab = sections[s.link];
        if (!strtab) continue;
        for (let off = s.offset; off + s.entsize <= s.offset + s.size && off + s.entsize <= buf.length; off += s.entsize) {
            const info = buf.readUInt8(off + 4);
            const type = info & 0xf;
            const shndx = buf.readUInt16LE(off + 6);
            const value = Number(buf.readBigUInt64LE(off + 8));
            const name = readStr(strtab.offset, buf.readUInt32LE(off));
            if (!name) continue;
            if (type === 2 && shndx !== 0) out.functions.push({ addr: normAddr(value), name });
            else if (type === 1 && shndx === 0) out.imports.push({ addr: null, name });
        }
    }
    return out;
}

export function buildGroundTruth(filePath) {
    const buf = fs.readFileSync(filePath);
    if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) return buildPeGroundTruth(filePath, buf);
    if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45) return buildElfGroundTruth(buf);
    return emptyGroundTruth('unknown');
}

function emptyGroundTruth(format) {
    return finish({ format, arch: 'unknown', bits: 0, gtSource: 'none', functionSymbols: [], imports: [], exports: [] });
}

function buildPeGroundTruth(filePath, buf) {
    const pe = parsePe(buf);
    const pcln = readGoPclntab(buf, pe.sections);
    const exports = pe.exports.filter((e) => isExecutableSection(pe, e.rva));
    const coff = pe.coffSymbols;
    let functionSymbols = [];
    let gtSource = 'none';
    if (pcln && pcln.entries.length >= 8) {
        functionSymbols = pcln.entries.filter((e) => !isGoPseudoFunction(e.name));
        gtSource = 'go-pclntab';
    } else if (coff.length >= 8) {
        functionSymbols = coff;
        gtSource = 'coff-symbols';
    } else if (exports.length) {
        functionSymbols = exports;
        gtSource = 'pe-exports';
    }
    const machine = { 0x8664: 'x86_64', 0x14c: 'x86', 0xaa64: 'aarch64' }[pe.machine] ?? 'pe-unknown';
    return finish({
        format: 'pe',
        arch: machine,
        bits: pe.bits,
        imageBase: normAddr(pe.imageBase),
        gtSource,
        functionSymbols,
        imports: pe.imports.map((i) => ({ addr: normAddr(i.iatVa), name: i.name, library: i.library })),
        exports,
    });
}

function buildElfGroundTruth(buf) {
    const elf = parseElfSymbols(buf);
    const machine = buf.readUInt16LE(18);
    const arch = { 0x3e: 'x86_64', 0x03: 'x86', 0xb7: 'aarch64' }[machine] ?? 'elf-unknown';
    const functionSymbols = [];
    const seen = new Set();
    for (const f of elf.functions) {
        if (seen.has(f.addr)) continue;
        seen.add(f.addr);
        functionSymbols.push(f);
    }
    return finish({
        format: 'elf',
        arch,
        bits: buf[4] === 2 ? 64 : 32,
        gtSource: functionSymbols.length >= 8 ? 'elf-symbols' : 'none',
        functionSymbols,
        imports: elf.imports,
        exports: [],
    });
}

function finish(gt) {
    const byAddr = new Map(); // '0x..' -> [names]
    const nameCanons = new Map(); // canon -> display name
    const canonAddrs = new Map(); // canon -> Set(addr)
    const importByAddr = new Map();

    const addName = (addr, name) => {
        const c = canon(name);
        if (!c || c.length < 2) return;
        if (!nameCanons.has(c)) nameCanons.set(c, name);
        if (!canonAddrs.has(c)) canonAddrs.set(c, new Set());
        if (addr) canonAddrs.get(c).add(addr);
    };

    for (const f of gt.functionSymbols) {
        // PE exports/pclntab entries use `va`, COFF/ELF symbols use `addr`.
        const addr = normAddr(f.addr ?? f.va);
        if (!addr || addr === '0x0') continue;
        if (!byAddr.has(addr)) byAddr.set(addr, []);
        byAddr.get(addr).push(f.name);
        addName(addr, f.name);
    }
    for (const e of gt.exports) {
        const addr = normAddr(e.addr ?? e.va);
        if (!addr) continue;
        if (!byAddr.has(addr)) byAddr.set(addr, []);
        byAddr.get(addr).push(e.name);
        addName(addr, e.name);
    }
    for (const i of gt.imports) {
        const addr = normAddr(i.addr);
        if (addr) importByAddr.set(addr, i.name);
        addName(addr ?? null, i.name);
    }

    // Names unique enough to be matched unambiguously (used only for reporting).
    const uniqueCanons = new Set([...canonAddrs.entries()].filter(([, s]) => s.size <= 1).map(([c]) => c));

    return {
        format: gt.format,
        arch: gt.arch,
        bits: gt.bits,
        imageBase: gt.imageBase ?? null,
        gtSource: gt.gtSource,
        functionSymbols: gt.functionSymbols.length,
        exportCount: gt.exports.length,
        importCount: gt.imports.length,
        byAddr,
        importByAddr,
        nameCanons, // canon -> display
        uniqueCanons,
    };
}

// GT name for a call target address, or null when the address has no symbol.
export function gtNameAt(gt, addr) {
    const a = normAddr(addr);
    if (!a) return null;
    const names = gt.byAddr.get(a);
    if (names && names.length) {
        // Prefer the name that is unique in the binary when several aliases exist.
        const uniq = names.find((n) => gt.uniqueCanons.has(canon(n)));
        return uniq ?? names[0];
    }
    const imp = gt.importByAddr.get(a);
    return imp ?? null;
}

// A stable, JSON-friendly summary of the ground truth (without Map internals).
export function gtSummary(gt) {
    return {
        gtSource: gt.gtSource,
        functionSymbols: gt.functionSymbols,
        exportCount: gt.exportCount,
        importCount: gt.importCount,
        uniqueCanonNames: gt.uniqueCanons.size,
        totalCanonNames: gt.nameCanons.size,
    };
}
