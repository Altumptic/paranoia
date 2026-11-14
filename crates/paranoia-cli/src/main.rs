//! The `paranoia` command: the engine without the app, for scripts and CI.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use paranoia_core::{Binary, Instruction};

mod disclosure;
mod mcp;
mod memory;
mod query;
mod script;

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
    Functions {
        file: PathBuf,
        /// Load symbols from this PDB first.
        #[arg(long)]
        pdb: Option<PathBuf>,
    },
    /// Disassemble from an address (defaults to the entry point).
    Disasm {
        file: PathBuf,
        /// Start address (hex), or a function / export name.
        #[arg(short, long)]
        at: Option<String>,
        #[arg(short = 'n', long, default_value_t = 40)]
        count: usize,
    },
    /// Basic blocks and edges of the function at an address or name.
    Cfg { file: PathBuf, at: String },
    /// C-like pseudocode for the function at an address or name.
    Pseudo {
        file: PathBuf,
        at: String,
        /// Generate the C text from the SSA form instead of the line-based lifter.
        #[arg(long)]
        from_ssa: bool,
    },
    /// The function in SSA form: phi nodes, one definition per value, constants and dead code.
    Ssa { file: PathBuf, at: String },
    /// Cross references to an address.
    Xrefs { file: PathBuf, at: String },
    /// Write an IDA-compatible `.pat` signature file from a binary's named functions.
    Sigmake {
        file: PathBuf,
        /// Load symbols from this PDB first.
        #[arg(long)]
        pdb: Option<PathBuf>,
        /// Only functions from the Microsoft runtime libraries (needs a PDB).
        #[arg(long)]
        library: bool,
        /// Output file (stdout when omitted).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Apply a `.pat` signature file and list the recognised functions.
    Sigapply { file: PathBuf, pat: PathBuf },
    /// Run a Python script against a binary without the app (batch mode, like IDA's -S).
    Script {
        file: PathBuf,
        script: PathBuf,
        /// Python interpreter (default: $PARANOIA_PYTHON, python, python3, py -3).
        #[arg(long)]
        python: Option<String>,
        /// Address returned by `here()` (hex).
        #[arg(long)]
        at: Option<String>,
    },
    /// Match the functions of two binaries: what changed, what was added and removed.
    Diff {
        a: PathBuf,
        b: PathBuf,
        /// Don't match functions by name, only by code.
        #[arg(long)]
        no_names: bool,
        /// Measure the matcher: match by code only, then compare with the names both files carry.
        #[arg(long)]
        check_names: bool,
        /// How many changed, added and removed functions to list.
        #[arg(short = 'n', long, default_value_t = 25)]
        limit: usize,
    },
    /// The function knowledge base: remember named functions, recognise them in other files.
    Memory {
        /// Knowledge base file (default: memory.redb next to the app's workspace).
        #[arg(long, global = true)]
        db: Option<PathBuf>,
        #[command(subcommand)]
        cmd: MemoryCmd,
    },
    /// Machine-readable answers for other tools, one JSON object per run (format paranoia-query/1).
    Query {
        file: PathBuf,
        #[command(subcommand)]
        what: QueryCmd,
    },
    /// Check a disclosure ledger written by `paranoia mcp --ledger` and summarise what was disclosed.
    Ledger { file: PathBuf },
    /// Serve the engine to AI agents over the Model Context Protocol (stdio, read-only by default).
    Mcp {
        /// Directory the agent may open files from (repeatable; default: the working directory).
        #[arg(long = "root")]
        roots: Vec<PathBuf>,
        /// Also offer rename / comment tools (changes stay in the session; export_idc keeps them).
        #[arg(long)]
        allow_writes: bool,
        /// Hide the file's string contents from the agent (placeholders like "<str#12 len=23>").
        #[arg(long)]
        redact_strings: bool,
        /// Hide numbers that look like IP addresses from the agent (placeholders like "<ip#7>").
        #[arg(long)]
        redact_ips: bool,
        /// Append every answer sent to the agent to this JSON-lines file; nothing is sent unrecorded.
        #[arg(long, value_name = "FILE")]
        ledger: Option<PathBuf>,
        /// Share names with the desktop app: read them from its workspace on open and, with
        /// --allow-writes, save changes there. Without a value, the app's own workspace.
        #[arg(long, value_name = "FILE", num_args = 0..=1, default_missing_value = "")]
        workspace: Option<PathBuf>,
        /// Offer recognize_functions from the function knowledge base. Without a value, the
        /// app's own (memory.redb next to its workspace).
        #[arg(long, value_name = "FILE", num_args = 0..=1, default_missing_value = "")]
        memory: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum QueryCmd {
    /// Functions, imports, strings and direct call edges.
    Inventory,
    /// Pseudocode and assembly of the function at `0x…` or with this name.
    Function { selector: String },
    /// References to `0x…` or to the named function, export or import.
    Xrefs { selector: String },
}

#[derive(Subcommand)]
enum MemoryCmd {
    /// Remember the named functions of these files (names from the app's workspace).
    Learn {
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Also learn names from symbols, exports and debug info.
        #[arg(long)]
        symbols: bool,
        /// Workspace to read the names from (default: the app's, if it exists).
        #[arg(long, value_name = "FILE")]
        workspace: Option<PathBuf>,
    },
    /// Find remembered functions in a file.
    Recall {
        file: PathBuf,
        /// Lowest similarity to report, 0 to 1.
        #[arg(long, default_value_t = paranoia_core::memory::RECALL_MIN_SCORE)]
        min_score: f32,
        /// Write the names and comments into the workspace (close the app first).
        #[arg(long)]
        apply: bool,
        /// Workspace for --apply (default: the app's).
        #[arg(long, value_name = "FILE")]
        workspace: Option<PathBuf>,
        /// How many results to list (0 for all).
        #[arg(short = 'n', long, default_value_t = 50)]
        limit: usize,
        /// Measure recall: hide the file's own names, recall, then compare with them.
        #[arg(long)]
        check_names: bool,
    },
    /// What the knowledge base holds.
    Stats,
    /// Write every remembered function to a JSON-lines file, to share or back up.
    Export { output: PathBuf },
    /// Add the functions from a file written by `export`.
    Import { input: PathBuf },
    /// Remove everything learned from the file with this SHA-256.
    Forget { sha256: String },
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
        Cmd::Functions { file, pdb } => {
            let mut bin = open(&file)?;
            let mut stats = bin.analyze();
            if let Some(p) = pdb {
                let r = bin.load_pdb(std::fs::read(&p)?, false).map_err(anyhow::Error::msg)?;
                eprintln!("PDB {}: {} functions, {} names", r.guid, r.functions, r.names);
                stats = bin.analyze();
            }
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
        Cmd::Sigmake { file, pdb, library, output } => {
            let mut bin = open(&file)?;
            bin.analyze();
            if let Some(p) = pdb {
                bin.load_pdb(std::fs::read(&p)?, false).map_err(anyhow::Error::msg)?;
            }
            let text = bin.make_pat(library);
            let n = text.lines().count().saturating_sub(1);
            match output {
                Some(o) => std::fs::write(&o, text)?,
                None => print!("{text}"),
            }
            eprintln!("{n} signatures");
        }
        Cmd::Script { file, script, python, at } => {
            let cursor = at.map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16)).transpose()?.unwrap_or(0);
            let code = script::run(&file, &script, python.as_deref(), cursor)?;
            std::process::exit(code);
        }
        Cmd::Diff { a, b, no_names, check_names, limit } => {
            memory::diff_command(memory::DiffArgs { a: &a, b: &b, use_names: !no_names, check: check_names, limit, json: cli.json })?;
        }
        Cmd::Memory { db, cmd } => {
            let action = match cmd {
                MemoryCmd::Learn { files, symbols, workspace } => memory::MemoryAction::Learn { files, symbols, workspace },
                MemoryCmd::Recall { file, min_score, apply, workspace, limit, check_names } => {
                    memory::MemoryAction::Recall { file, min_score, apply, workspace, limit, check: check_names }
                }
                MemoryCmd::Stats => memory::MemoryAction::Stats,
                MemoryCmd::Export { output } => memory::MemoryAction::Export { output },
                MemoryCmd::Import { input } => memory::MemoryAction::Import { input },
                MemoryCmd::Forget { sha256 } => memory::MemoryAction::Forget { sha256 },
            };
            memory::memory_command(db, action, cli.json)?;
        }
        Cmd::Query { file, what } => {
            let what = match what {
                QueryCmd::Inventory => query::What::Inventory,
                QueryCmd::Function { selector } => query::What::Function(selector),
                QueryCmd::Xrefs { selector } => query::What::Xrefs(selector),
            };
            query::run(&file, what)?;
        }
        Cmd::Ledger { file } => {
            let text = std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            let r = disclosure::verify(&text);
            if cli.json {
                print_json(&serde_json::json!({
                    "sessions": r.sessions, "answers": r.answers, "errors": r.errors, "chars": r.chars,
                    "redactions": r.redactions, "tools": r.tools, "files": r.files,
                    "bad": r.bad.iter().map(|(n, why)| serde_json::json!({ "line": n, "reason": why })).collect::<Vec<_>>(),
                }))?;
            } else {
                println!(
                    "{} sessions, {} answers ({} errors), {} characters disclosed, {} redactions",
                    r.sessions, r.answers, r.errors, r.chars, r.redactions
                );
                for (tool, n) in &r.tools {
                    println!("  {tool:<16} {n}");
                }
                for f in &r.files {
                    println!("  file sha256 {f}");
                }
                for (n, why) in &r.bad {
                    println!("line {n}: {why}");
                }
                println!("{}", if r.bad.is_empty() { "every answer matches its recorded SHA-256" } else { "THE LEDGER DOES NOT VERIFY" });
            }
            if !r.bad.is_empty() {
                std::process::exit(2);
            }
        }
        Cmd::Mcp { roots, allow_writes, redact_strings, redact_ips, ledger, workspace, memory } => {
            let workspace = match workspace {
                Some(p) if p.as_os_str().is_empty() => {
                    Some(mcp::default_workspace().context("cannot tell where the app's workspace is; pass a path")?)
                }
                other => other,
            };
            let memory = match memory {
                Some(p) if p.as_os_str().is_empty() => {
                    Some(memory::default_db().context("cannot tell where the app's knowledge base is; pass a path")?)
                }
                other => other,
            };
            mcp::run(mcp::Config { roots, allow_writes, redact_strings, redact_ips, ledger, workspace, memory })?
        }
        Cmd::Sigapply { file, pat } => {
            let mut bin = open(&file)?;
            bin.analyze();
            let is_sig = pat.extension().is_some_and(|e| e.eq_ignore_ascii_case("sig"));
            let r = if is_sig { bin.apply_sig(&std::fs::read(&pat)?) } else { bin.apply_pat(&std::fs::read_to_string(&pat)?) }
                .map_err(anyhow::Error::msg)?;
            if cli.json {
                return print_json(&r);
            }
            for (va, name) in &r.names {
                println!("{va:#018x}  {name}");
            }
            eprintln!("{} of {} signatures matched", r.matched, r.signatures);
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
        Cmd::Cfg { file, at } => {
            let mut bin = open(&file)?;
            bin.analyze();
            let va = resolve(&bin, &at)?;
            let g = bin.function_graph(va).context("no function at that address")?;
            if cli.json {
                return print_json(&g);
            }
            println!("{} ({} blocks)", g.name, g.blocks.len());
            for b in &g.blocks {
                let succ: Vec<String> = b.succs.iter().map(|e| format!("{:?}:{:#x}", e.kind, e.to)).collect();
                println!("  {:#x}..{:#x}  {}", b.start, b.end, succ.join(" "));
            }
        }
        Cmd::Ssa { file, at } => {
            let mut bin = open(&file)?;
            bin.analyze();
            let va = resolve(&bin, &at)?;
            let p = bin.ssa(va).context("no function at that address")?;
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
        Cmd::Pseudo { file, at, from_ssa } => {
            let mut bin = open(&file)?;
            bin.analyze();
            let va = resolve(&bin, &at)?;
            let p = if from_ssa { bin.pseudocode_from_ssa(va) } else { bin.pseudocode(va) }.context("no function at that address")?;
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
