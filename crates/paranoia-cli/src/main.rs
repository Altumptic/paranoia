//! `paranoia` — headless access to the analysis engine, handy for scripting and CI.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use paranoia_core::{Binary, Instruction};

#[derive(Parser)]
#[command(name = "paranoia", version, about = "Open-source reverse-engineering toolkit")]
struct Cli {
    /// Emit JSON instead of human-readable tables.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// File summary: format, architecture, hashes, mitigations.
    Info { file: PathBuf },
    /// Sections with permissions and entropy.
    Sections { file: PathBuf },
    /// Imported functions.
    Imports { file: PathBuf },
    /// Exported symbols.
    Exports { file: PathBuf },
    /// Printable strings.
    Strings {
        file: PathBuf,
        /// Only strings referenced from code.
        #[arg(long)]
        referenced: bool,
    },
    /// Run auto-analysis and list discovered functions.
    Functions { file: PathBuf },
    /// Disassemble from an address (defaults to the entry point).
    Disasm {
        file: PathBuf,
        /// Start address (hex), or a function / export name.
        #[arg(short, long)]
        at: Option<String>,
        #[arg(short = 'n', long, default_value_t = 40)]
        count: usize,
    },
    /// C-like pseudocode for the function at an address or name.
    Pseudo { file: PathBuf, at: String },
    /// Cross references to an address.
    Xrefs { file: PathBuf, at: String },
}

fn open(path: &PathBuf) -> Result<Binary> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    Ok(Binary::load(&name, bytes)?)
}

fn resolve(bin: &Binary, at: &str) -> Result<u64> {
    let hex = at.trim_start_matches("0x");
    if let Ok(v) = u64::from_str_radix(hex, 16) {
        return Ok(v);
    }
    bin.functions()
        .into_iter()
        .find(|f| f.name == at)
        .map(|f| f.address)
        .or_else(|| bin.info().exports.iter().find(|e| e.name == at).map(|e| e.address))
        .with_context(|| format!("no address or symbol named `{at}`"))
}

fn print_json<T: serde::Serialize + ?Sized>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Info { file } => {
            let bin = open(&file)?;
            let i = bin.info();
            if cli.json {
                return print_json(i);
            }
            println!("{}  ({} bytes)", i.file_name, i.file_size);
            println!("  format       {} {}-bit, {}", i.format.label(), i.bits, i.kind);
            println!("  arch         {} ({:?}-endian)", i.arch.label(), i.endian);
            println!("  entry        {:#x}", i.entry);
            println!("  image base   {:#x}", i.image_base);
            println!("  entropy      {:.3}", i.entropy);
            println!("  sha256       {}", i.hashes.sha256);
            println!("  md5          {}", i.hashes.md5);
            if let Some(h) = &i.hashes.imphash {
                println!("  imphash      {h}");
            }
            println!(
                "  sections {} | imports {} | exports {} | libraries {} | symbols {}",
                i.sections.len(),
                i.imports.len(),
                i.exports.len(),
                i.libraries.len(),
                i.symbol_count
            );
            println!("\nheaders");
            for kv in &i.headers {
                println!("  {:<20} {}", kv.key, kv.value);
            }
            println!("\nmitigations");
            for m in &i.mitigations {
                println!("  [{}] {:<20} {}", if m.enabled { "x" } else { " " }, m.name, m.detail);
            }
            for w in &i.warnings {
                println!("\nwarning: {w}");
            }
        }
        Cmd::Sections { file } => {
            let bin = open(&file)?;
            let s = &bin.info().sections;
            if cli.json {
                return print_json(s);
            }
            println!("{:<18} {:>18} {:>10} {:>10} {:>10} perm entropy", "name", "vaddr", "vsize", "offset", "raw");
            for s in s {
                println!(
                    "{:<18} {:>#18x} {:>#10x} {:>#10x} {:>#10x} {}  {:.2}",
                    s.name, s.vaddr, s.vsize, s.offset, s.raw_size, s.perms, s.entropy
                );
            }
        }
        Cmd::Imports { file } => {
            let bin = open(&file)?;
            let v = &bin.info().imports;
            if cli.json {
                return print_json(v);
            }
            for i in v {
                println!("{:#018x}  {:<28} {}", i.address, i.library, i.name);
            }
        }
        Cmd::Exports { file } => {
            let bin = open(&file)?;
            let v = &bin.info().exports;
            if cli.json {
                return print_json(v);
            }
            for e in v {
                let fwd = e.forward.as_deref().map(|f| format!(" -> {f}")).unwrap_or_default();
                println!("{:#018x}  {}{}", e.address, e.name, fwd);
            }
        }
        Cmd::Strings { file, referenced } => {
            let mut bin = open(&file)?;
            bin.analyze();
            let v: Vec<_> = bin.strings().iter().filter(|s| !referenced || s.xrefs > 0).collect();
            if cli.json {
                return print_json(&v);
            }
            for s in v {
                let addr = s.address.map(|a| format!("{a:#018x}")).unwrap_or_else(|| format!("@{:#016x}", s.offset));
                println!("{addr}  {:>3}  {}", s.xrefs, s.value.escape_debug());
            }
        }
        Cmd::Functions { file } => {
            let mut bin = open(&file)?;
            let stats = bin.analyze();
            let f = bin.functions();
            if cli.json {
                return print_json(&f);
            }
            for f in &f {
                println!("{:#018x}  {:>6} insn {:>4} blk {:>4} xref  {}", f.address, f.instructions, f.blocks, f.xrefs, f.name);
            }
            eprintln!(
                "\n{} functions, {} blocks, {} instructions, {} strings, {} xrefs in {} ms",
                stats.functions, stats.blocks, stats.instructions, stats.strings, stats.xrefs, stats.millis
            );
        }
        Cmd::Disasm { file, at, count } => {
            let mut bin = open(&file)?;
            bin.analyze();
            let va = match at {
                Some(a) => resolve(&bin, &a)?,
                None => bin.info().entry,
            };
            let insns = bin.disassemble(va, count)?;
            if cli.json {
                return print_json(&insns);
            }
            for i in &insns {
                print_insn(i);
            }
        }
        Cmd::Pseudo { file, at } => {
            let mut bin = open(&file)?;
            bin.analyze();
            let va = resolve(&bin, &at)?;
            let p = bin.pseudocode(va).context("no function at that address")?;
            if cli.json {
                return print_json(&p);
            }
            if let Some(n) = &p.note {
                println!("// {n}");
            }
            for l in &p.lines {
                let text: String = l.tokens.iter().map(|t| t.t.as_str()).collect();
                println!("{}{}", "    ".repeat(l.indent as usize), text);
            }
        }
        Cmd::Xrefs { file, at } => {
            let mut bin = open(&file)?;
            bin.analyze();
            let va = resolve(&bin, &at)?;
            let x = bin.xrefs_to(va);
            if cli.json {
                return print_json(&x);
            }
            for x in x {
                println!("{:#018x}  {:<5?} {}", x.from, x.kind, x.function_name.unwrap_or_default());
            }
        }
    }
    Ok(())
}

fn print_insn(i: &Instruction) {
    if let Some(l) = &i.label {
        println!("\n{l}:");
    }
    let ops: String = i.operands.iter().map(|t| t.t.as_str()).collect();
    let comment = i.user_comment.as_ref().or(i.comment.as_ref()).map(|c| format!("  ; {c}")).unwrap_or_default();
    println!("  {:#014x}  {:<24} {:<8} {}{}", i.address, i.bytes, i.mnemonic, ops, comment);
}
