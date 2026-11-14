// Go pclntab (Go 1.18+ / ver120 format) reader for benchmark ground truth.
//
// The Go runtime keeps this table in every binary, including ones built with
// -ldflags="-s -w" (the symbol table is stripped, the pclntab is not), which is
// what makes it a usable ground truth for stripped Go samples.
//
// Format (src/runtime/symtab.go, pcHeader):
//   magic uint32 = 0xFFFFFFF1, pad1, pad2, minLC uint8, ptrSize uint8,
//   nfunc, nfiles, textStart, funcnameOffset, cuOffset, filetabOffset,
//   pctabOffset, pclnOffset  -- uintptr-sized fields (8 bytes on amd64)
//
// functab: nfunc+1 entries of { entryoff uint32, funcoff uint32 } at
// pclnOffset; entry = textStart + entryoff. The _func at
// pclnOffset + funcoff starts with entryOff uint32 then nameOff int32, and the
// name lives at funcnameOffset + nameOff.

const PCLN_MAGIC = 0xfffffff1;

function readU64(buf, off) {
    return buf.readBigUInt64LE(off);
}

function readI32(buf, off) {
    return buf.readInt32LE(off);
}

function readCStr(buf, off, limit = 2048) {
    if (off < 0 || off >= buf.length) return null;
    const max = Math.min(buf.length, off + limit);
    let end = off;
    while (end < max && buf[end] !== 0) end++;
    if (end >= max) return null;
    return buf.toString('utf8', off, end);
}

function tryParseAt(buf, off, sectionVa, sectionEndOff) {
    if (off + 72 > buf.length) return null;
    if (buf.readUInt32LE(off) !== PCLN_MAGIC || buf[off + 4] !== 0 || buf[off + 5] !== 0) return null;
    const minLC = buf[off + 6];
    const ptrSize = buf[off + 7];
    if (![1, 2, 4].includes(minLC) || ![4, 8].includes(ptrSize)) return null;
    const nfunc = Number(readU64(buf, off + 8));
    const nfiles = Number(readU64(buf, off + 16));
    const textStart = readU64(buf, off + 24);
    const funcnameOffset = Number(readU64(buf, off + 32));
    const cuOffset = Number(readU64(buf, off + 40));
    const filetabOffset = Number(readU64(buf, off + 48));
    const pctabOffset = Number(readU64(buf, off + 56));
    const pclnOffset = Number(readU64(buf, off + 64));
    if (!Number.isSafeInteger(nfunc) || nfunc < 8 || nfunc > 2_000_000) return null;
    if (!Number.isSafeInteger(nfiles) || nfiles > 2_000_000) return null;
    for (const o of [funcnameOffset, cuOffset, filetabOffset, pctabOffset, pclnOffset]) {
        if (!Number.isSafeInteger(o) || o <= 0 || off + o >= buf.length) return null;
    }
    if (textStart === 0n) return null;
    const ftabOff = off + pclnOffset;
    if (ftabOff + (nfunc + 1) * 8 > buf.length) return null;
    const entries = [];
    try {
        for (let i = 0; i < nfunc; i++) {
            const e = ftabOff + i * 8;
            const entryoff = buf.readUInt32LE(e);
            const funcoff = buf.readUInt32LE(e + 4);
            if (funcoff >= buf.length - off) return null;
            const entry = textStart + BigInt(entryoff);
            const funcOff = off + pclnOffset + funcoff;
            if (funcOff + 8 > buf.length) return null;
            const nameOff = readI32(buf, funcOff + 4);
            const nameAddr = off + funcnameOffset + nameOff;
            const name = nameOff >= 0 ? readCStr(buf, nameAddr) : null;
            if (!name) continue;
            entries.push({ va: '0x' + entry.toString(16), name });
        }
    } catch {
        return null;
    }
    if (entries.length < nfunc * 0.5) return null;
    return { entries, textStart: '0x' + textStart.toString(16), nfunc };
}

// Scans the given sections (from parsePe) for a valid pclntab and returns its
// function table, or null.
export function readGoPclntab(buf, sections) {
    for (const sec of sections) {
        const start = sec.rawPtr;
        if (start >= buf.length) continue;
        const end = Math.min(buf.length, sec.rawPtr + Math.max(sec.vsize, sec.rawSize));
        const span = end - start;
        if (span <= 0) continue;
        // The magic is 8-byte aligned in practice; still scan every byte for safety.
        let off = buf.indexOf(Buffer.from([0xf1, 0xff, 0xff, 0xff, 0x00, 0x00]), start);
        while (off !== -1 && off + 72 < end) {
            const parsed = tryParseAt(buf, off, sec.va, end);
            if (parsed) return parsed;
            off = buf.indexOf(Buffer.from([0xf1, 0xff, 0xff, 0xff, 0x00, 0x00]), off + 1);
        }
    }
    return null;
}
