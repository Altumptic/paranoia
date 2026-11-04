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

/// DWARF struct / enum definitions become local types usable by `Y` and the decompiler.
#[test]
fn dwarf_types_become_local_types() {
    let Ok(path) = std::env::current_exe() else { return };
    let Ok(bytes) = std::fs::read(&path) else { return };
    let Ok(mut bin) = Binary::load("self", bytes) else { return };
    // Debug builds carry DWARF; a stripped build has no `.debug_info` and simply skips.
    let has_dwarf = bin.info().sections.iter().any(|s| s.name.ends_with("debug_info"));
    // Loading annotations (what the workspace does on open) also merges the DWARF types,
    // so no analysis has to run for this test.
    bin.set_annotations(paranoia_core::Annotations::default());
    let types = bin.annotations().types.clone();
    if !has_dwarf {
        assert!(types.structs.is_empty(), "local types appeared without DWARF");
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
    // Enums, when the image has any, carry their members.
    if let Some((n, e)) = types.enums.iter().find(|(_, e)| !e.members.is_empty()) {
        assert!(!n.is_empty());
        assert!(e.members.iter().all(|(m, _)| !m.is_empty()));
    }
    // Editing Local Types must bring the DWARF types back alongside the user's declarations.
    let before = types.structs.len();
    bin.set_types("typedef struct _UserT { DWORD a; DWORD b; } UserT;").unwrap();
    let after = bin.annotations().types.clone();
    assert!(after.structs.contains_key("UserT"), "user type missing");
    assert!(after.structs.len() > before, "DWARF types did not come back after set_types");
}
