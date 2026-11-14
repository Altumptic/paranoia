// Minimal PE (32/64-bit) parser used only to derive *ground truth* for the
// benchmark: export names, import names, and the COFF symbol table that the
// GNU toolchain leaves in linked images. No third-party dependencies.
//
// Everything here is read-only and bounds-checked; a malformed file yields
// empty ground truth rather than a crash.

const IMAGE_SCN_MEM_EXECUTE = 0x20000000;

function cstr(buf, off, limit = 512) {
    if (off < 0 || off >= buf.length) return null;
    let end = off;
    const max = Math.min(buf.length, off + limit);
    while (end < max && buf[end] !== 0) end++;
    return buf.toString('utf8', off, end);
}

export function parsePe(buf) {
    const out = { ok: false, imageBase: 0n, bits: 0, machine: 0, sections: [], exports: [], imports: [], coffSymbols: [], hasCoFFSymbols: false };
    if (!buf || buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) return out;
    const peOff = buf.readUInt32LE(0x3c);
    if (peOff + 24 > buf.length || buf.readUInt32LE(peOff) !== 0x00004550) return out;
    const coff = peOff + 4;
    const machine = buf.readUInt16LE(coff);
    const numSections = buf.readUInt16LE(coff + 2);
    const symTabOff = buf.readUInt32LE(coff + 8);
    const numSymbols = buf.readUInt32LE(coff + 12);
    const optSize = buf.readUInt16LE(coff + 16);
    const optOff = coff + 20;
    if (optOff + 2 > buf.length) return out;
    const magic = buf.readUInt16LE(optOff);
    const pe32plus = magic === 0x20b;
    const bits = pe32plus ? 64 : 32;
    const imageBase = pe32plus ? buf.readBigUInt64LE(optOff + 24) : BigInt(buf.readUInt32LE(optOff + 28));
    const sizeOfHeaders = buf.readUInt32LE(optOff + 60);
    const numDirs = buf.readUInt32LE(optOff + (pe32plus ? 108 : 92));
    const dirsOff = optOff + (pe32plus ? 112 : 96);

    out.ok = true;
    out.imageBase = imageBase;
    out.bits = bits;
    out.machine = machine;

    const sections = [];
    const secOff = optOff + optSize;
    for (let i = 0; i < numSections; i++) {
        const o = secOff + i * 40;
        if (o + 40 > buf.length) break;
        const name = cstr(buf, o, 8) ?? '';
        const vsize = buf.readUInt32LE(o + 8);
        const va = buf.readUInt32LE(o + 12);
        const rawSize = buf.readUInt32LE(o + 16);
        const rawPtr = buf.readUInt32LE(o + 20);
        const characteristics = buf.readUInt32LE(o + 36);
        sections.push({ name, vsize, va, rawSize, rawPtr, characteristics });
    }
    out.sections = sections;

    out.rvaToOff = (rva) => {
        for (const s of sections) {
            const span = Math.max(s.vsize, s.rawSize);
            if (rva >= s.va && rva < s.va + span) {
                const d = rva - s.va;
                if (d >= s.rawSize) return null;
                const off = s.rawPtr + d;
                return off < buf.length ? off : null;
            }
        }
        if (rva < sizeOfHeaders && rva < buf.length) return rva;
        return null;
    };

    const dir = (i) => (i < numDirs && dirsOff + i * 8 + 8 <= buf.length ? { rva: buf.readUInt32LE(dirsOff + i * 8), size: buf.readUInt32LE(dirsOff + i * 8 + 4) } : { rva: 0, size: 0 });

    // --- Export directory -------------------------------------------------------------
    const ed = dir(0);
    if (ed.rva && ed.size) {
        const off = out.rvaToOff(ed.rva);
        if (off !== null && off + 40 <= buf.length) {
            const numFuncs = buf.readUInt32LE(off + 20);
            const numNames = buf.readUInt32LE(off + 24);
            const funcsRva = buf.readUInt32LE(off + 28);
            const namesRva = buf.readUInt32LE(off + 32);
            const ordsRva = buf.readUInt32LE(off + 36);
            const funcsOff = out.rvaToOff(funcsRva);
            const namesOff = out.rvaToOff(namesRva);
            const ordsOff = out.rvaToOff(ordsRva);
            if (funcsOff !== null && namesOff !== null && ordsOff !== null) {
                const seen = new Set();
                for (let i = 0; i < numNames; i++) {
                    if (namesOff + i * 4 + 4 > buf.length || ordsOff + i * 2 + 2 > buf.length) break;
                    const nameRva = buf.readUInt32LE(namesOff + i * 4);
                    const ord = buf.readUInt16LE(ordsOff + i * 2);
                    const nameOff = out.rvaToOff(nameRva);
                    if (nameOff === null) continue;
                    const name = cstr(buf, nameOff);
                    if (!name) continue;
                    if (ord >= numFuncs || funcsOff + ord * 4 + 4 > buf.length) continue;
                    const funcRva = buf.readUInt32LE(funcsOff + ord * 4);
                    if (!funcRva) continue;
                    // Addresses inside the export directory are forwarded exports, not code.
                    if (funcRva >= ed.rva && funcRva < ed.rva + ed.size) continue;
                    const va = imageBase + BigInt(funcRva);
                    const key = va.toString(16);
                    if (seen.has(key)) continue;
                    seen.add(key);
                    out.exports.push({ va: '0x' + va.toString(16), name, rva: funcRva });
                }
            }
        }
    }

    // --- Import directory -------------------------------------------------------------
    const idd = dir(1);
    if (idd.rva && idd.size) {
        const ptr = pe32plus ? 8 : 4;
        let descOff = out.rvaToOff(idd.rva);
        for (let d = 0; descOff !== null && d < 4096; d++, descOff += 20) {
            if (descOff + 20 > buf.length) break;
            const originalFirstThunk = buf.readUInt32LE(descOff);
            const nameRva = buf.readUInt32LE(descOff + 12);
            const firstThunk = buf.readUInt32LE(descOff + 16);
            if (!originalFirstThunk && !nameRva && !firstThunk) break;
            const dllOff = out.rvaToOff(nameRva);
            const library = dllOff === null ? '' : cstr(buf, dllOff) ?? '';
            const thunkRva = originalFirstThunk || firstThunk;
            let thunkOff = out.rvaToOff(thunkRva);
            for (let i = 0; thunkOff !== null; i++, thunkOff += ptr) {
                if (thunkOff + ptr > buf.length) break;
                const entry = ptr === 8 ? buf.readBigUInt64LE(thunkOff) : BigInt(buf.readUInt32LE(thunkOff));
                if (entry === 0n) break;
                const ordinalFlag = ptr === 8 ? 1n << 63n : 1n << 31n;
                let name = null;
                if ((entry & ordinalFlag) === 0n) {
                    const hintNameOff = out.rvaToOff(Number(entry & (ordinalFlag - 1n)));
                    if (hintNameOff !== null) name = cstr(buf, hintNameOff + 2);
                } else {
                    name = '#' + (entry & 0xffffn).toString();
                }
                if (!name) continue;
                const iatVa = imageBase + BigInt(firstThunk) + BigInt(i * ptr);
                out.imports.push({ library, name, iatVa: '0x' + iatVa.toString(16) });
            }
        }
    }

    // --- COFF symbol table (GNU toolchains keep it in linked images) -------------------
    if (symTabOff > 0 && numSymbols > 0 && symTabOff < buf.length) {
        const strTabOff = symTabOff + numSymbols * 18;
        const strTabSize = strTabOff + 4 <= buf.length ? buf.readUInt32LE(strTabOff) : 0;
        const readStr = (rel) => {
            if (rel <= 0 || rel >= strTabSize) return null;
            return cstr(buf, strTabOff + rel);
        };
        const ptr = pe32plus ? 8 : 4;
        let i = 0;
        while (i < numSymbols) {
            const o = symTabOff + i * 18;
            if (o + 18 > buf.length) break;
            const nameInline = buf.toString('latin1', o, o + 8).replace(/\0.*$/, '');
            const nameStrOff = buf.readUInt32LE(o + 4);
            let name = nameInline;
            if (buf.readUInt32LE(o) === 0) name = readStr(nameStrOff) ?? '';
            const value = buf.readUInt32LE(o + 8);
            const sectionNumber = buf.readInt16LE(o + 12);
            const type = buf.readUInt16LE(o + 14);
            const storageClass = buf.readUInt8(o + 16);
            const numAux = buf.readUInt8(o + 17);
            i += 1 + numAux;
            if (!name || name.startsWith('.') || name.startsWith('$')) continue;
            if (sectionNumber <= 0 || sectionNumber > numSections) continue;
            const sec = sections[sectionNumber - 1];
            if (!sec || (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) === 0) continue;
            const isFunction = (type & 0x20) !== 0;
            const looksLikeCode = /^[_?$A-Za-z]/.test(name) && !/^(_+_image_base__|_+header|_+section)/.test(name);
            if (!isFunction && !looksLikeCode) continue;
            // In linked images GNU ld stores RVAs in COFF symbols. A symbol value
            // far outside the image's RVA range is something else; skip it.
            const rva = value;
            if (rva > 0x10000000) continue;
            const va = imageBase + BigInt(sec.va) + BigInt(rva);
            out.coffSymbols.push({ va: '0x' + va.toString(16), name, section: sec.name, storageClass, type });
        }
        out.hasCoFFSymbols = out.coffSymbols.length > 0;
    }

    return out;
}
