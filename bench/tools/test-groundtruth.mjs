// One-off sanity check for the ground-truth parsers, used while developing the
// harness. Not part of the benchmark run:
//   node bench/tools/test-groundtruth.mjs
import fs from 'node:fs';
import { parsePe } from '../lib/pe.mjs';
import { readGoPclntab } from '../lib/gopcln.mjs';
import { canon, canonicalIndex } from '../lib/names.mjs';

function load(p) {
    const buf = fs.readFileSync(p);
    const pe = parsePe(buf);
    const go = readGoPclntab(buf, pe.sections);
    return { p, buf, pe, go };
}

const cases = process.argv.slice(2);
if (!cases.length) {
    console.error('usage: node bench/tools/test-groundtruth.mjs <file>...');
    process.exit(2);
}

for (const p of cases) {
    const { pe, go } = load(p);
    console.log(`\n== ${p}`);
    console.log(`  pe ok=${pe.ok} bits=${pe.bits} imageBase=0x${pe.imageBase.toString(16)} sections=${pe.sections.map((s) => s.name).join(',')}`);
    console.log(`  exports=${pe.exports.length} imports=${pe.imports.length} coffSymbols=${pe.coffSymbols.length}`);
    if (pe.exports.length) console.log(`  export sample: ${pe.exports.slice(0, 4).map((e) => `${e.name}@${e.va}`).join(' ')}`);
    if (pe.imports.length) console.log(`  import sample: ${pe.imports.slice(0, 4).map((i) => `${i.library}!${i.name}@${i.iatVa}`).join(' ')}`);
    if (pe.coffSymbols.length) {
        console.log(`  coff sample: ${pe.coffSymbols.slice(0, 6).map((s) => `${s.name.slice(0, 40)}@${s.va}`).join(' ')}`);
        const textSec = pe.sections.find((s) => s.name === '.text');
        const inText = pe.coffSymbols.filter((s) => {
            const rva = Number(BigInt(s.va) - pe.imageBase);
            return textSec && rva >= textSec.va && rva < textSec.va + textSec.vsize;
        }).length;
        console.log(`  coff symbols in .text: ${inText}/${pe.coffSymbols.length}`);
    }
    if (go) {
        console.log(`  pclntab nfunc=${go.nfunc} parsed=${go.entries.length} textStart=${go.textStart}`);
        console.log(`  pclntab sample: ${go.entries.slice(0, 6).map((e) => `${e.name}@${e.va}`).join(' ')}`);
    }
    if (pe.exports.length) {
        const idx = canonicalIndex(pe.exports);
        const sample = [...idx.keys()].slice(0, 8);
        console.log(`  canon export sample: ${sample.join(' ')}`);
    }
}
