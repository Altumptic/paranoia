//! Smoke tests against binaries that ship with the host OS. Each test is a
//! no-op when its sample is missing, so they pass on every platform.

use paranoia_core::{Arch, Binary, Format};

fn sample(paths: &[&str]) -> Option<(String, Vec<u8>)> {
    paths.iter().find_map(|p| std::fs::read(p).ok().map(|b| (p.to_string(), b)))
}

fn check(path: &str, bytes: Vec<u8>, format: Format) {
    let mut bin = Binary::load(path, bytes).expect("load");
    assert_eq!(bin.info().format, format);
    let stats = bin.analyze();
    assert!(stats.functions > 10, "{path}: only {} functions", stats.functions);
    let entry = bin.info().entry;
    let insns = bin.disassemble(entry, 32).expect("disassemble entry");
    assert!(!insns.is_empty());
    assert!(insns[0].label.is_some(), "entry should be labelled");
    let graph = bin.function_graph(entry).expect("entry graph");
    assert!(!graph.blocks.is_empty());
    // Every successor edge must point at a block of the same function.
    let starts: std::collections::HashSet<u64> = graph.blocks.iter().map(|b| b.start).collect();
    for b in &graph.blocks {
        for e in &b.succs {
            assert!(starts.contains(&e.to), "{path}: dangling edge {:#x} -> {:#x}", b.start, e.to);
        }
    }
}

#[test]
fn windows_pe64() {
    if let Some((p, b)) = sample(&["C:/Windows/System32/notepad.exe"]) {
        check(&p, b, Format::Pe);
    }
}

#[test]
fn windows_pe32() {
    if let Some((p, b)) = sample(&["C:/Windows/SysWOW64/notepad.exe"]) {
        let bin = Binary::load(&p, b.clone()).unwrap();
        assert_eq!(bin.info().arch, Arch::X86);
        check(&p, b, Format::Pe);
    }
}

#[test]
fn linux_elf() {
    if let Some((p, b)) = sample(&["/bin/ls", "/usr/bin/ls"]).filter(|_| cfg!(target_os = "linux")) {
        check(&p, b, Format::Elf);
    }
}

#[test]
fn macos_macho() {
    if let Some((p, b)) = sample(&["/bin/ls", "/usr/bin/true"]).filter(|_| cfg!(target_os = "macos")) {
        check(&p, b, Format::MachO);
    }
}

#[test]
fn rejects_garbage() {
    assert!(Binary::load("x", b"definitely not an executable".to_vec()).is_err());
    assert!(Binary::load("x", vec![]).is_err());
    // Truncated headers must error, never panic.
    assert!(Binary::load("x", b"MZ\x90\x00".to_vec()).is_err());
    assert!(Binary::load("x", b"\x7fELF\x02\x01\x01".to_vec()).is_err());
}

/// Hostile-input robustness: randomly corrupted samples must never panic.
#[test]
fn corrupted_inputs_do_not_panic() {
    let custom = std::env::var("PARANOIA_FUZZ_FILE").ok();
    let paths: Vec<&str> = custom.iter().map(String::as_str).chain(["C:/Windows/System32/notepad.exe", "/bin/ls"]).collect();
    let Some((_, base)) = sample(&paths) else { return };
    let iterations = std::env::var("PARANOIA_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(25);
    let mut seed = std::env::var("PARANOIA_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x9e37_79b9_7f4a_7c15u64);
    let mut rand = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..iterations {
        let mut bytes = base.clone();
        // Hit headers hard, the rest lightly.
        for _ in 0..(rand() % 24 + 1) {
            let pos = if rand() % 2 == 0 { (rand() % 1024) as usize } else { (rand() as usize) % bytes.len() };
            bytes[pos] = rand() as u8;
        }
        if rand() % 4 == 0 {
            bytes.truncate((rand() as usize) % bytes.len());
        }
        if let Ok(mut bin) = Binary::load("fuzz", bytes) {
            bin.analyze();
            let entry = bin.info().entry;
            let _ = bin.disassemble(entry, 64);
            let _ = bin.function_graph(entry);
            let _ = bin.search("a", 50);
            // Newer passes: decompiler, signatures, debug-info lookups.
            for f in bin.functions().iter().take(12) {
                let _ = bin.pseudocode(f.address);
                let _ = bin.address_info(f.address);
                let _ = bin.frame(f.address);
            }
            let _ = bin.make_pat(false);
        }
    }
}

/// Jump tables in a large Windows DLL become `case` edges, and listings over data work.
#[test]
fn switch_tables_and_data_listing() {
    let Some((p, b)) = sample(&["C:/Windows/System32/shell32.dll"]) else { return };
    let mut bin = Binary::load(&p, b).unwrap();
    bin.analyze();
    let mut cases = 0;
    for f in bin.functions().iter().filter(|f| f.blocks > 8) {
        if cases > 20 {
            break;
        }
        if let Some(g) = bin.function_graph(f.address) {
            cases += g.blocks.iter().flat_map(|b| &b.succs).filter(|e| e.kind == paranoia_core::EdgeKind::Case).count();
        }
    }
    assert!(cases > 20, "only {cases} switch cases recovered");
    // Every section start renders without error.
    for s in bin.info().sections.clone() {
        if s.vaddr != 0 && s.raw_size > 0 {
            let l = bin.disassemble(s.vaddr, 200).unwrap();
            assert!(!l.is_empty(), "{}", s.name);
        }
    }
}

/// Local types applied to data render one line per field.
#[test]
fn structs_in_listing() {
    let Some((p, b)) = sample(&["C:/Windows/System32/notepad.exe"]) else { return };
    let mut bin = Binary::load(&p, b).unwrap();
    bin.analyze();
    bin.set_types("typedef struct { DWORD a; WORD b; BYTE c[2]; char *p; } T;").unwrap();
    let va = bin.info().sections.iter().find(|s| s.name == ".rdata").unwrap().vaddr + 0x800;
    bin.apply_struct(va, "T", 2).unwrap();
    let l = bin.disassemble(va, 10).unwrap();
    let fields: Vec<_> = l.iter().take(4).map(|i| i.comment.clone().unwrap_or_default()).collect();
    assert!(fields[0].starts_with("T[0].a"), "{fields:?}");
    assert!(fields[3].starts_with("T[0].p"), "{fields:?}");
    assert_eq!(l[4].address, va + 16);
    assert!(l[0].label.as_deref().unwrap_or("").starts_with("stru_"));
}

/// Typing a pseudocode variable (`Y`) rewrites member access and the signature.
#[test]
fn var_types_in_pseudocode() {
    let Some((p, b)) = sample(&["C:/Windows/System32/notepad.exe"]) else { return };
    let mut bin = Binary::load(&p, b).unwrap();
    bin.analyze();
    bin.set_types("typedef struct _CTX { DWORD magic; DWORD count; char *name; DWORD ids[4]; } CTX;").unwrap();
    let f = bin.functions().iter().find(|f| f.blocks > 6).map(|f| f.address).unwrap();
    let plain = bin.pseudocode(f).unwrap();
    let text = |pc: &paranoia_core::Pseudocode| {
        pc.lines.iter().map(|l| l.tokens.iter().map(|t| t.t.as_str()).collect::<String>()).collect::<Vec<_>>().join("\n")
    };
    bin.set_var_type(f, "a1", "CTX *");
    let typed = text(&bin.pseudocode(f).unwrap());
    assert!(typed.contains("CTX * a1"), "signature must carry the type:\n{typed}");
    // The same call twice is deterministic; removing the type restores the plain output.
    bin.set_var_type(f, "a1", "");
    assert_eq!(text(&bin.pseudocode(f).unwrap()), text(&plain));
}

/// Argument types flow across internal calls: when a caller passes its typed `a1`
/// to another function, the callee's signature adopts the type on its own.
#[test]
fn var_types_flow_across_calls() {
    let Some((p, b)) = sample(&["C:/Windows/System32/notepad.exe"]) else { return };
    let mut bin = Binary::load(&p, b).unwrap();
    bin.analyze();
    bin.set_types("typedef struct _CTX { DWORD magic; DWORD count; char *name; } CTX;").unwrap();
    let funcs: Vec<u64> = bin.functions().iter().map(|f| f.address).take(150).collect();
    // Render once (harvests nothing yet), type every first argument, render again:
    // forwarding callers now export `CTX *` to everyone they call with `a1`.
    for &va in &funcs {
        let _ = bin.pseudocode(va);
    }
    for &va in &funcs {
        bin.set_var_type(va, "a1", "CTX *");
    }
    for &va in &funcs {
        let _ = bin.pseudocode(va);
    }
    let signatures: Vec<String> = funcs
        .iter()
        .filter_map(|&va| bin.pseudocode(va))
        .map(|pc| pc.lines.first().map(|l| l.tokens.iter().map(|t| t.t.as_str()).collect::<String>()).unwrap_or_default())
        .collect();
    assert!(
        signatures.iter().any(|s| s.contains("CTX * a1")),
        "no callee inherited the argument type from its caller; first signatures:\n{}",
        signatures.iter().take(10).cloned().collect::<Vec<_>>().join("\n")
    );
}

/// A typed call result teaches the callee's return type, and the variable that
/// stores that call adopts the type back once its own annotation is removed.
#[test]
fn typed_returns_flow_to_callers() {
    use paranoia_core::TokenKind;
    let Some((p, b)) = sample(&["C:/Windows/System32/notepad.exe"]) else { return };
    let mut bin = Binary::load(&p, b).unwrap();
    bin.analyze();
    bin.set_types("typedef struct _CTX { DWORD magic; DWORD count; char *name; } CTX;").unwrap();
    let funcs: Vec<(u64, String)> = bin.functions().iter().map(|f| (f.address, f.name.clone())).collect();
    let internal: std::collections::HashSet<String> = funcs.iter().map(|f| f.1.clone()).collect();
    // Find `F` with a single-assignment store of an internal call: `vN = G(…);`.
    let mut hit: Option<(u64, String)> = None;
    for &(va, _) in funcs.iter().take(150) {
        let Some(pc) = bin.pseudocode(va) else { continue };
        for l in &pc.lines {
            let t = &l.tokens;
            if t.len() < 4 || t[1].t != " = " || t[0].k != TokenKind::Register || t[2].k != TokenKind::Symbol {
                continue;
            }
            if !internal.contains(&t[2].t) {
                continue;
            }
            let writes = pc
                .lines
                .iter()
                .filter(|x| x.tokens.first().is_some_and(|f| f.t == t[0].t) && x.tokens.get(1).is_some_and(|e| e.t == " = "))
                .count();
            if writes == 1 {
                hit = Some((va, t[0].t.clone()));
                break;
            }
        }
        if hit.is_some() {
            break;
        }
    }
    let Some((f, var)) = hit else { return };
    // 1. Type the stored variable: rendering records the callee's result type.
    bin.set_var_type(f, &var, "CTX *");
    let _ = bin.pseudocode(f);
    bin.set_var_type(f, &var, "");
    // 2. With the annotation gone the type comes back from the callee's return type.
    let pc = bin.pseudocode(f).unwrap();
    let text: String = pc.lines.iter().map(|l| l.tokens.iter().map(|t| t.t.as_str()).collect::<String>()).collect::<Vec<_>>().join("\n");
    assert!(text.contains("CTX *"), "the return type did not come back:\n{text}");
}

/// DWARF struct / enum definitions become debug-info types usable by `Y` and the decompiler,
/// without ever entering the saved annotations.
#[test]
fn dwarf_types_become_debug_types() {
    let Ok(path) = std::env::current_exe() else { return };
    let Ok(bytes) = std::fs::read(&path) else { return };
    let Ok(mut bin) = Binary::load("self", bytes) else { return };
    // Debug builds carry DWARF; a stripped build has no `.debug_info` and simply skips.
    let has_dwarf = bin.info().sections.iter().any(|s| s.name.ends_with("debug_info"));
    bin.set_annotations(paranoia_core::Annotations::default());
    // Debug-info types are a runtime layer: the persisted Local Types stay the user's own.
    assert!(bin.annotations().types.structs.is_empty(), "debug types leaked into the annotations");
    let types = bin.debug_types().clone();
    if !has_dwarf {
        assert!(types.structs.is_empty(), "debug types appeared without DWARF");
        return;
    }
    assert!(!types.structs.is_empty(), "DWARF is present but no struct types were recovered");
    assert!(types.structs.len() > 5, "only {} structs from DWARF", types.structs.len());
    let (name, s) = types.structs.iter().find(|(_, s)| !s.fields.is_empty()).expect("a struct with fields");
    assert!(s.size > 0, "{name} has no size");
    for f in &s.fields {
        assert!(!f.name.is_empty(), "{name} has an unnamed field");
        assert!(f.elem_size > 0, "{name}.{} has a zero element size", f.name);
        assert!(f.offset < s.size, "{name}.{} at {:#x} past the size {:#x}", f.name, f.offset, s.size);
    }
    assert!(s.fields.iter().any(|f| f.offset > 0), "{name}: every field is at offset 0");
    if let Some((n, e)) = types.enums.iter().find(|(_, e)| !e.members.is_empty()) {
        assert!(!n.is_empty());
        assert!(e.members.iter().all(|(m, _)| !m.is_empty()));
    }
    // The view finds them.
    let hits = bin.type_view().search(name, 5);
    assert!(hits.iter().any(|h| &h.name == name && h.origin == "debug"), "search did not find {name}");
    // A user declaration of the same name wins (Rust type names like `a::B` cannot be declared in C).
    if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bin.set_types(&format!("typedef struct {name} {{ DWORD a; DWORD b; }} {name};")).unwrap();
        let hits = bin.type_view().search(name, 5);
        assert!(hits.iter().any(|h| &h.name == name && h.origin == "user"), "user type does not shadow the debug one");
        assert!(!hits.iter().any(|h| &h.name == name && h.origin == "debug"), "shadowed debug type still listed");
    }
    bin.set_types("typedef struct _UserT { DWORD a; DWORD b; } UserT;").unwrap();
    assert!(bin.annotations().types.structs.contains_key("UserT"), "user type missing");
    // Debug types survive editing the Local Types.
    assert_eq!(bin.debug_types().structs.len(), types.structs.len());
}

/// A real MSVC PDB (shipped inside an npm dev dependency, so it may be absent): its type stream
/// becomes debug-info types with exact layouts, and nothing leaks into the saved annotations.
#[test]
fn pdb_types_become_debug_types() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/node_modules/electron-winstaller/vendor");
    let (Ok(exe), Ok(pdb)) = (std::fs::read(dir.join("Setup.exe")), std::fs::read(dir.join("Setup.pdb"))) else { return };
    let mut bin = Binary::load("Setup.exe", exe).unwrap();
    let report = bin.load_pdb(pdb, false).unwrap();
    assert!(report.matched && report.types > 100, "{report:?}");
    assert!(bin.annotations().types.structs.is_empty(), "PDB types leaked into the annotations");
    let dos = bin.debug_types().structs.get("_IMAGE_DOS_HEADER").expect("_IMAGE_DOS_HEADER from the PDB");
    assert_eq!(dos.size, 64);
    let f = |n: &str| dos.fields.iter().find(|f| f.name == n).unwrap_or_else(|| panic!("no field {n}"));
    assert_eq!((f("e_magic").offset, f("e_magic").elem_size), (0, 2));
    assert_eq!((f("e_res").offset, f("e_res").count), (0x1c, 4));
    assert_eq!((f("e_lfanew").offset, f("e_lfanew").elem_size), (0x3c, 4));
    // Every imported field lies inside its struct (union members overlap, so only the start is checked).
    for s in bin.debug_types().structs.values() {
        assert!(s.fields.iter().all(|f| f.offset < s.size), "{} has a field past its size", s.name);
    }
    // The type search and a Local Types declaration of the same name layer as documented.
    assert!(bin.type_view().search("IMAGE_DOS", 5).iter().any(|h| h.name == "_IMAGE_DOS_HEADER" && h.origin == "debug"));
}

/// Assembling over code: longer encodings replace whole following instructions, the rest is NOP-padded,
/// and a dry run changes nothing.
#[test]
fn assemble_over_code() {
    let Ok(bytes) = std::fs::read(std::env::current_exe().unwrap()) else { return };
    let Ok(mut bin) = Binary::load("self", bytes) else { return };
    if !matches!(bin.info().arch, paranoia_core::Arch::X86 | paranoia_core::Arch::X86_64) {
        return;
    }
    let va = bin.info().entry;
    let before = bin.listing(va, 4).unwrap();
    let first_len = before[0].size as usize;
    // Dry run: bytes come back, nothing changes.
    let bytes = bin.assemble_at(va, "int3", false).unwrap();
    assert_eq!(bytes, [0xcc]);
    assert_eq!(bin.listing(va, 1).unwrap()[0].bytes, before[0].bytes);
    // Apply: a short encoding over a longer instruction pads with NOPs.
    bin.assemble_at(va, "int3", true).unwrap();
    let after = bin.listing(va, 2).unwrap();
    assert_eq!(after[0].bytes, "cc");
    assert!(first_len == 1 || after[1].bytes.starts_with("90"), "padding is not a NOP: {:?}", after[1].bytes);
    // A long encoding takes over the instructions it overlaps.
    bin.assemble_at(va, "mov eax, 0x11223344", true).unwrap();
    let l = bin.listing(va, 1).unwrap();
    assert!(l[0].bytes.starts_with("b844332211"), "{:?}", l[0].bytes);
    assert!(bin.assemble_at(va, "bogus eax", true).is_err());
}

/// Reaching-definition variables only ever split more than the older top-level splitting, never less,
/// and the output keeps its shape: declared variables are all used, none is declared twice.
#[test]
fn ssa_variables_refine_the_old_splitting() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/node_modules/electron-winstaller/vendor");
    let mut inputs: Vec<(String, Vec<u8>)> = vec![];
    if let Ok(b) = std::fs::read(dir.join("Setup.exe")) {
        inputs.push(("Setup.exe".into(), b));
    }
    if let Ok(b) = std::env::current_exe().and_then(std::fs::read) {
        inputs.push(("self".into(), b));
    }
    let decls = |lines: &[paranoia_core::PseudoLine]| -> Vec<String> {
        lines
            .iter()
            .skip(1)
            .take_while(|l| l.address.is_none())
            .filter_map(|l| {
                let t: String = l.tokens.iter().map(|t| t.t.as_str()).collect();
                let name = t.split("; //").next()?.rsplit(' ').next()?.trim_end_matches(';').to_string();
                (t.contains("; //") && name.starts_with('v')).then_some(name)
            })
            .collect()
    };
    let (mut checked, mut old_total, mut new_total, mut grew) = (0usize, 0usize, 0usize, 0usize);
    for (name, bytes) in inputs {
        let Ok(mut bin) = Binary::load(&name, bytes) else { continue };
        bin.analyze();
        let funcs: Vec<u64> =
            bin.functions().iter().filter(|f| f.instructions > 6 && f.instructions < 500).map(|f| f.address).take(20).collect();
        for va in funcs {
            bin.set_ssa_variables(false);
            let old = bin.pseudocode(va);
            bin.set_ssa_variables(true);
            let new = bin.pseudocode(va);
            let (Some(old), Some(new)) = (old, new) else { continue };
            let (o, n) = (decls(&old.lines), decls(&new.lines));
            assert!(n.len() >= o.len(), "{name} {va:#x}: {} variables became {}", o.len(), n.len());
            let mut uniq = n.clone();
            uniq.sort();
            uniq.dedup();
            assert_eq!(uniq.len(), n.len(), "{name} {va:#x}: a variable is declared twice");
            let body: String =
                new.lines.iter().map(|l| l.tokens.iter().map(|t| t.t.as_str()).collect::<String>()).collect::<Vec<_>>().join("\n");
            for v in &n {
                assert!(body.matches(v.as_str()).count() >= 2, "{name} {va:#x}: {v} is declared but never used");
            }
            checked += 1;
            old_total += o.len();
            new_total += n.len();
            grew += usize::from(n.len() > o.len());
        }
    }
    eprintln!("ssa variables: {checked} functions, {old_total} -> {new_total} variables, {grew} functions got finer");
    if checked > 0 {
        assert!(new_total >= old_total);
    }
}
