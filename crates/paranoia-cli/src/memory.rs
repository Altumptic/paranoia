//! `paranoia diff` and `paranoia memory`: function matching between binaries and
//! the local knowledge base.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use paranoia_core::memory::{self, DiffOptions, DiffReport, FunctionPrint, MatchKind};

/// How well the matcher did, judged by the names both binaries carry.
#[derive(Debug, Default, serde::Serialize)]
pub struct NameCheck {
    /// Functions with the same real name in both files (each name unique per file).
    pub common: usize,
    /// Of those, matched to the function with the same name.
    pub right: usize,
    /// Matched to a function with a different real name.
    pub wrong: usize,
    /// Not matched at all.
    pub missed: usize,
}

fn unique_names(prints: &[FunctionPrint]) -> HashMap<&str, u64> {
    let mut count: HashMap<&str, usize> = HashMap::new();
    for p in prints.iter().filter(|p| p.named) {
        *count.entry(p.name.as_str()).or_default() += 1;
    }
    prints.iter().filter(|p| p.named && count[p.name.as_str()] == 1).map(|p| (p.name.as_str(), p.address)).collect()
}

/// Compares the matches with the names: run the diff with names off, then check.
pub fn check_names(a: &[FunctionPrint], b: &[FunctionPrint], report: &DiffReport, min_instructions: u32) -> NameCheck {
    let (na, nb) = (unique_names(a), unique_names(b));
    let size: HashMap<u64, u32> = a.iter().map(|p| (p.address, p.print.instructions)).collect();
    let matched: HashMap<u64, u64> = report.matches.iter().map(|m| (m.a, m.b)).collect();
    let name_b: HashMap<u64, &str> = nb.iter().map(|(n, va)| (*va, *n)).collect();
    let mut c = NameCheck::default();
    for (name, va) in &na {
        let Some(vb) = nb.get(name) else { continue };
        if size.get(va).copied().unwrap_or(0) < min_instructions {
            continue;
        }
        c.common += 1;
        match matched.get(va) {
            Some(m) if m == vb => c.right += 1,
            Some(m) if name_b.contains_key(m) => c.wrong += 1,
            // Matched to a function whose name isn't unique or isn't known: count it as missed.
            _ => c.missed += 1,
        }
    }
    c
}

fn label(k: MatchKind) -> &'static str {
    match k {
        MatchKind::Name => "name",
        MatchKind::Exact => "exact",
        MatchKind::Shape => "shape",
        MatchKind::Anchors => "anchors",
        MatchKind::CallGraph => "callgraph",
        MatchKind::Fuzzy => "fuzzy",
        MatchKind::Order => "order",
    }
}

fn load(path: &Path) -> Result<(paranoia_core::Binary, Vec<FunctionPrint>)> {
    let mut bin = super::open(&path.to_path_buf())?;
    bin.analyze();
    let prints = bin.fingerprints();
    Ok((bin, prints))
}

pub struct DiffArgs<'a> {
    pub a: &'a Path,
    pub b: &'a Path,
    pub use_names: bool,
    pub check: bool,
    pub limit: usize,
    pub json: bool,
}

pub fn diff_command(args: DiffArgs<'_>) -> Result<()> {
    let t = Instant::now();
    let (bin_a, a) = load(args.a)?;
    let (bin_b, b) = load(args.b)?;
    let t_load = t.elapsed();
    let t = Instant::now();
    // Checking against names only makes sense when the matcher didn't see them.
    let opts = DiffOptions { use_names: args.use_names && !args.check, ..DiffOptions::default() };
    let report = memory::diff(&a, &b, opts);
    let t_match = t.elapsed();
    let check = args.check.then(|| (check_names(&a, &b, &report, 0), check_names(&a, &b, &report, memory::MIN_INSTRUCTIONS * 4)));

    if args.json {
        let v = serde_json::json!({
            "a": { "file": bin_a.info().file_name, "sha256": bin_a.info().hashes.sha256, "functions": a.len() },
            "b": { "file": bin_b.info().file_name, "sha256": bin_b.info().hashes.sha256, "functions": b.len() },
            "report": report,
            "check": check.as_ref().map(|(all, big)| serde_json::json!({ "all": all, "16_or_more_instructions": big })),
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }

    let identical = report.matches.iter().filter(|m| !m.changed).count();
    let changed: Vec<_> = {
        let mut v: Vec<_> = report.matches.iter().filter(|m| m.changed).collect();
        v.sort_by(|x, y| x.score.total_cmp(&y.score).then(x.a.cmp(&y.a)));
        v
    };
    println!("{}  {} functions", bin_a.info().file_name, a.len());
    println!("{}  {} functions", bin_b.info().file_name, b.len());
    println!(
        "\nmatched {} ({} identical, {} changed), removed {}, added {}, similarity {:.1}%",
        report.matches.len(),
        identical,
        changed.len(),
        report.only_a.len(),
        report.only_b.len(),
        report.similarity * 100.0
    );
    let mut by_kind: Vec<(MatchKind, usize)> = Vec::new();
    for m in &report.matches {
        match by_kind.iter_mut().find(|(k, _)| *k == m.kind) {
            Some(e) => e.1 += 1,
            None => by_kind.push((m.kind, 1)),
        }
    }
    let kinds: Vec<String> = by_kind.iter().map(|(k, n)| format!("{} {n}", label(*k))).collect();
    println!("by pass: {}", kinds.join(", "));
    eprintln!("analysis {} ms, matching {} ms", t_load.as_millis(), t_match.as_millis());

    if let Some((all, big)) = &check {
        for (what, c) in [("all named functions", all), ("16+ instructions", big)] {
            let pct = |n: usize| if c.common == 0 { 0.0 } else { n as f64 * 100.0 / c.common as f64 };
            println!(
                "\ncheck against names, {what}: {} in both, right {} ({:.1}%), wrong {} ({:.1}%), missed {} ({:.1}%)",
                c.common,
                c.right,
                pct(c.right),
                c.wrong,
                pct(c.wrong),
                c.missed,
                pct(c.missed)
            );
        }
    }

    if args.limit > 0 {
        if !changed.is_empty() {
            println!("\nchanged (least similar first)");
            for m in changed.iter().take(args.limit) {
                let name = if m.a_name == m.b_name { m.a_name.clone() } else { format!("{} -> {}", m.a_name, m.b_name) };
                println!("  {:>5.1}%  {:#012x} {:#012x}  {:<9}  {}", m.score * 100.0, m.a, m.b, label(m.kind), name);
            }
        }
        for (title, list) in [("removed (largest first)", &report.only_a), ("added (largest first)", &report.only_b)] {
            if list.is_empty() {
                continue;
            }
            let mut v: Vec<_> = list.iter().collect();
            v.sort_by(|x, y| y.instructions.cmp(&x.instructions).then(x.address.cmp(&y.address)));
            println!("\n{title}");
            for u in v.iter().take(args.limit) {
                println!("  {:#012x}  {:>6} insn  {}", u.address, u.instructions, u.name);
            }
        }
    }
    Ok(())
}

/// Default knowledge base: `memory.redb` next to the desktop app's workspace.
pub fn default_db() -> Option<std::path::PathBuf> {
    super::mcp::default_workspace().map(|w| w.with_file_name("memory.redb"))
}

/// The workspace to read names from: the one given, or the app's own when it exists.
fn workspace_path(given: &Option<std::path::PathBuf>) -> Option<std::path::PathBuf> {
    match given {
        Some(p) if !p.as_os_str().is_empty() => Some(p.clone()),
        _ => super::mcp::default_workspace().filter(|p| p.exists()),
    }
}

/// Loads the app's names and comments for `bin` from the workspace, if there are any.
fn load_annotations(bin: &mut paranoia_core::Binary, store: Option<&paranoia_db::Store>) -> Result<usize> {
    let Some(store) = store else { return Ok(0) };
    let sha = bin.info().hashes.sha256.clone();
    let Some(v) = store.annotations(&sha)? else { return Ok(0) };
    let saved: paranoia_core::Annotations = serde_json::from_value(v)?;
    let n = saved.names.len();
    bin.set_annotations(saved);
    Ok(n)
}

fn open_store(path: Option<std::path::PathBuf>, must_exist: bool) -> Result<Option<paranoia_db::Store>> {
    let Some(p) = path else { return Ok(None) };
    if must_exist && !p.exists() {
        anyhow::bail!("no workspace at {}", p.display());
    }
    paranoia_db::Store::open(&p)
        .map(Some)
        .map_err(|e| anyhow::anyhow!("can't open the workspace {} ({e}); close the app first, it locks the file", p.display()))
}

pub enum MemoryAction {
    Learn { files: Vec<std::path::PathBuf>, symbols: bool, workspace: Option<std::path::PathBuf> },
    Recall { file: std::path::PathBuf, min_score: f32, apply: bool, workspace: Option<std::path::PathBuf>, limit: usize, check: bool },
    Stats,
    Export { output: std::path::PathBuf },
    Import { input: std::path::PathBuf },
    Forget { sha256: String },
}

pub fn memory_command(db: Option<std::path::PathBuf>, action: MemoryAction, json: bool) -> Result<()> {
    use paranoia_core::memory::LearnFrom;
    let db = db.or_else(default_db).ok_or_else(|| anyhow::anyhow!("no default location for the knowledge base; pass --db FILE"))?;
    let kb = paranoia_db::Knowledge::open(&db).map_err(|e| anyhow::anyhow!("{} ({e}); close the app if it's open", db.display()))?;
    match action {
        MemoryAction::Learn { files, symbols, workspace } => {
            // A workspace named on the command line must open; the app's own is optional
            // (the app may be holding it, or there may be nothing named yet).
            let store = match &workspace {
                Some(_) => open_store(workspace_path(&workspace), true)?,
                None => open_store(workspace_path(&None), false).unwrap_or_else(|e| {
                    eprintln!("warning: {e}; learning without the app's names");
                    None
                }),
            };
            let from = if symbols { LearnFrom::UserAndSymbols } else { LearnFrom::User };
            let mut total = paranoia_db::LearnStats::default();
            for f in &files {
                let mut bin = super::open(f)?;
                bin.analyze();
                let names = load_annotations(&mut bin, store.as_ref())?;
                let known = bin.knowledge(from);
                let s = kb.learn(&known)?;
                total.added += s.added;
                total.updated += s.updated;
                if !json {
                    println!(
                        "{}: {} functions learned ({} new, {} updated), {} names from the workspace",
                        bin.info().file_name,
                        s.added + s.updated,
                        s.added,
                        s.updated,
                        names
                    );
                    if known.is_empty() && !symbols {
                        println!("  nothing named yet; name functions in the app, or pass --symbols to learn symbol names");
                    }
                }
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&total)?);
            }
        }
        MemoryAction::Recall { file, min_score, apply, workspace, limit, check } => {
            let store = if apply { open_store(workspace_path(&workspace).or_else(super::mcp::default_workspace), false)? } else { None };
            let mut bin = super::open(&file)?;
            bin.analyze();
            load_annotations(&mut bin, store.as_ref())?;
            let sha = bin.info().hashes.sha256.clone();
            let t = Instant::now();
            let mut prints = bin.fingerprints();
            // --check-names: hide the file's own names, recall, then compare.
            let truth: HashMap<u64, String> = if check {
                let t = prints
                    .iter()
                    .filter(|p| p.named && p.print.instructions >= memory::MIN_INSTRUCTIONS)
                    .map(|p| (p.address, p.name.clone()))
                    .collect();
                for p in &mut prints {
                    p.name = format!("sub_{:X}", p.address);
                    p.named = false;
                }
                t
            } else {
                HashMap::new()
            };
            let mut recalls = kb.recall(&prints, &sha, min_score)?;
            recalls.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.address.cmp(&b.address)));
            let millis = t.elapsed().as_millis();
            if apply {
                let store = store.as_ref().ok_or_else(|| anyhow::anyhow!("--apply needs the app's workspace"))?;
                bin.checkpoint();
                let (mut renamed, mut types) = (0, 0);
                for r in &recalls {
                    let done = bin.apply_known(r.address, &r.known, r.exact);
                    renamed += done.renamed as usize;
                    types += done.types;
                }
                store.set_annotations(&sha, &serde_json::to_value(bin.annotations())?)?;
                eprintln!("applied: {renamed} functions renamed, {types} local types added in the workspace");
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&recalls)?);
                return Ok(());
            }
            println!("{}: {} functions recognised in {millis} ms", bin.info().file_name, recalls.len());
            if check {
                let right = recalls.iter().filter(|r| truth.get(&r.address) == Some(&r.known.name)).count();
                let wrong = recalls.iter().filter(|r| truth.get(&r.address).is_some_and(|n| *n != r.known.name)).count();
                let pct = |n: usize| if truth.is_empty() { 0.0 } else { n as f64 * 100.0 / truth.len() as f64 };
                println!(
                    "check against names: {} named functions, right {right} ({:.1}%), wrong {wrong} ({:.1}%), not recognised {}",
                    truth.len(),
                    pct(right),
                    pct(wrong),
                    truth.len() - right - wrong
                );
            }
            for r in recalls.iter().take(if limit == 0 { usize::MAX } else { limit }) {
                println!(
                    "  {:#012x}  {:>5.1}%{}  {} -> {}   (from {})",
                    r.address,
                    r.score * 100.0,
                    if r.exact { " =" } else { "  " },
                    r.current,
                    r.known.name,
                    r.known.source
                );
            }
        }
        MemoryAction::Stats => {
            let s = kb.stats()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&s)?);
                return Ok(());
            }
            println!("{}: {} functions from {} files", db.display(), s.functions, s.sources.len());
            for src in &s.sources {
                println!("  {}  {:>6}  {}", src.sha256, src.functions, src.file);
            }
        }
        MemoryAction::Export { output } => {
            let all = kb.all()?;
            let mut text = String::new();
            for k in &all {
                text.push_str(&serde_json::to_string(k)?);
                text.push('\n');
            }
            std::fs::write(&output, text)?;
            println!("{} functions written to {}", all.len(), output.display());
        }
        MemoryAction::Import { input } => {
            let text = std::fs::read_to_string(&input)?;
            let mut known = Vec::new();
            for (n, line) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
                known.push(serde_json::from_str(line).map_err(|e| anyhow::anyhow!("{} line {}: {e}", input.display(), n + 1))?);
            }
            let s = kb.learn(&known)?;
            println!("{} new, {} updated", s.added, s.updated);
        }
        MemoryAction::Forget { sha256 } => {
            let n = kb.forget_source(&sha256.to_ascii_lowercase())?;
            println!("{n} functions removed");
        }
    }
    Ok(())
}
