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

/// Renaming a pseudocode variable changes every use, is undone by an empty name,
/// survives a save/load of the annotations and is refused for names that are not identifiers.
#[test]
fn var_names_in_pseudocode() {
    let Some((p, b)) = sample(&["C:/Windows/System32/notepad.exe"]) else { return };
    let mut bin = Binary::load(&p, b).unwrap();
    bin.analyze();
    let text = |pc: &paranoia_core::Pseudocode| {
        pc.lines.iter().map(|l| l.tokens.iter().map(|t| t.t.as_str()).collect::<String>()).collect::<Vec<_>>().join("\n")
    };
    let word = |s: &str, w: &str| s.split(|c: char| !c.is_alphanumeric() && c != '_').any(|x| x == w);
    let f = bin.functions().iter().find(|f| f.blocks > 6).map(|f| f.address).unwrap();
    let plain = text(&bin.pseudocode(f).unwrap());
    assert!(word(&plain, "v1"), "the test needs a function with a v1:\n{plain}");
    assert!(bin.set_var_name(f, "v1", "while").is_err());
    assert!(bin.set_var_name(f, "v1", "a b").is_err());
    assert!(bin.set_var_name(f, "rax", "x").is_err());
    bin.set_var_name(f, "v1", "counter").unwrap();
    let named = text(&bin.pseudocode(f).unwrap());
    assert!(word(&named, "counter") && !word(&named, "v1"), "{named}");
    assert_eq!(named.replace("counter", "v1"), plain, "only the name may change");
    // Persisted with the annotations.
    let saved = serde_json::to_string(&bin.annotations()).unwrap();
    assert!(saved.contains("counter"));
    bin.set_var_name(f, "v1", "").unwrap();
    assert_eq!(text(&bin.pseudocode(f).unwrap()), plain);
    assert!(bin.annotations().var_names.is_empty());
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

/// A real IDA `.sig` (angr's test pair: `libc_ubuntu_2004.sig` and the stripped static-libc ELF from
/// github.com/angr/binaries, `tests/x86_64/`). Not vendored; set `PARANOIA_FLIRT_DIR` to the folder
/// holding both files to run it.
#[test]
fn real_flirt_sig_names_static_libc() {
    let Ok(dir) = std::env::var("PARANOIA_FLIRT_DIR") else { return };
    let dir = std::path::Path::new(&dir);
    let elf = std::fs::read(dir.join("elf_with_static_libc_ubuntu_2004_stripped")).expect("ELF");
    let sig = std::fs::read(dir.join("libc_ubuntu_2004.sig")).expect(".sig");
    let mut bin = Binary::load("libc-static", elf).unwrap();
    bin.analyze();
    let r = bin.apply_sig(&sig).unwrap();
    assert!(r.signatures > 1000, "{} signatures", r.signatures);
    assert!(r.matched >= 50, "only {} matched", r.matched);
    let at = |va: u64| r.names.iter().find(|(a, _)| *a == va).map(|(_, n)| n.as_str());
    // Ground truth from angr's own FLIRT tests.
    assert_eq!(at(0x4139c0), Some("__vasprintf_internal"));
    assert!(r.names.iter().all(|(_, n)| !n.is_empty() && n.chars().all(|c| c.is_ascii_graphic())), "odd names");
    // A .sig for another processor is refused with a reason.
    let mut other = sig.clone();
    other[7] = 15; // PowerPC
    assert!(bin.apply_sig(&other).unwrap_err().contains("PowerPC"));
}

/// Real PowerPC binaries (not vendored): a small Go program built with `GOOS=linux GOARCH=ppc64`
/// and `GOARCH=ppc64le`, files `hello-ppc64` / `hello-ppc64le` in `PARANOIA_PPC_DIR`.
#[test]
fn real_powerpc_binaries_decode() {
    let Ok(dir) = std::env::var("PARANOIA_PPC_DIR") else { return };
    for (file, big) in [("hello-ppc64", true), ("hello-ppc64le", false)] {
        let bytes = std::fs::read(std::path::Path::new(&dir).join(file)).expect(file);
        let mut bin = Binary::load(file, bytes).unwrap();
        assert_eq!(bin.info().arch, paranoia_core::Arch::PowerPc);
        assert_eq!(bin.info().endian == paranoia_core::Endian::Big, big, "{file}: byte order");
        let stats = bin.analyze();
        assert!(stats.functions > 1000, "{file}: {} functions", stats.functions);
        // Every non-zero word of .text decodes.
        let text = bin.info().sections.iter().find(|s| s.name == ".text").expect(".text").clone();
        let insns = bin.listing(text.vaddr, 100_000).unwrap();
        let unknown = insns.iter().filter(|i| i.mnemonic == ".word" && i.bytes != "00000000").count();
        assert!(unknown * 1000 < insns.len(), "{file}: {unknown} of {} words undecoded", insns.len());
        // main.fib: Go's stack check, a recursive call, and a return.
        let fib = bin.functions().into_iter().find(|f| f.name == "main.fib").expect("main.fib");
        let body = bin.listing(fib.address, 40).unwrap();
        let m: Vec<&str> = body.iter().map(|i| i.mnemonic.as_str()).collect();
        assert!(m.contains(&"mflr") && m.contains(&"blr") && m.contains(&"bl"), "{file}: {m:?}");
    }
}

/// A minimal ARM ELF that mixes instruction sets: `main` (ARM) calls `thumb_fn` with `blx`,
/// and `arm2` (ARM) follows the Thumb code. `symbols` picks how the modes are announced.
fn mixed_arm_elf(symbols: &str) -> Vec<u8> {
    let mut code: Vec<u8> = Vec::new();
    for w in [0xe52d_e004u32, 0xfa00_0001, 0xe49d_f004, 0xe1a0_0000] {
        code.extend(w.to_le_bytes()); // 0x8000 main: push {lr}; blx 0x8010; pop {pc}; nop
    }
    for h in [0x202au16, 0x4770, 0xbf00, 0xbf00] {
        code.extend(h.to_le_bytes()); // 0x8010 thumb_fn: movs r0, #42; bx lr; nop; nop
    }
    for w in [0xe3a0_0001u32, 0xe12f_ff1e] {
        code.extend(w.to_le_bytes()); // 0x8018 arm2: mov r0, #1; bx lr
    }
    // (name, value, type); type 2 = STT_FUNC, 0 = STT_NOTYPE
    let syms: Vec<(&str, u32, u8)> = match symbols {
        "functions" => vec![("main", 0x8000, 2), ("thumb_fn", 0x8011, 2), ("arm2", 0x8018, 2)],
        "mapping" => vec![("$a", 0x8000, 0), ("$t", 0x8010, 0), ("$a.1", 0x8018, 0)],
        _ => vec![],
    };
    let mut strtab = vec![0u8];
    let mut symtab = vec![0u8; 16];
    for (name, value, ty) in &syms {
        let off = strtab.len() as u32;
        strtab.extend(name.as_bytes());
        strtab.push(0);
        symtab.extend(off.to_le_bytes());
        symtab.extend(value.to_le_bytes());
        symtab.extend(0u32.to_le_bytes());
        symtab.push(*ty); // STB_LOCAL
        symtab.push(0);
        symtab.extend(1u16.to_le_bytes()); // .text
    }
    let shstr = b"\0.text\0.symtab\0.strtab\0.shstrtab\0".to_vec();
    let text_off = 0x100usize;
    let sym_off = text_off + code.len();
    let str_off = sym_off + symtab.len();
    let shs_off = str_off + strtab.len();
    let sh_off = (shs_off + shstr.len() + 3) & !3;
    let mut f = vec![0u8; sh_off];
    let h: Vec<u8> = [
        &[0x7f, b'E', b'L', b'F', 1, 1, 1, 0][..],
        &[0; 8],
        &2u16.to_le_bytes(),
        &40u16.to_le_bytes(),
        &1u32.to_le_bytes(),
        &0x8000u32.to_le_bytes(),
        &52u32.to_le_bytes(),
        &(sh_off as u32).to_le_bytes(),
        &0x0500_0000u32.to_le_bytes(),
        &52u16.to_le_bytes(),
        &32u16.to_le_bytes(),
        &1u16.to_le_bytes(),
        &40u16.to_le_bytes(),
        &5u16.to_le_bytes(),
        &4u16.to_le_bytes(),
    ]
    .concat();
    f[..52].copy_from_slice(&h);
    let ph: Vec<u8> = [1u32, 0, 0x7f00, 0x7f00, (text_off + code.len()) as u32, (text_off + code.len()) as u32, 5, 0x1000]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    f[52..84].copy_from_slice(&ph);
    f[text_off..sym_off].copy_from_slice(&code);
    f[sym_off..str_off].copy_from_slice(&symtab);
    f[str_off..shs_off].copy_from_slice(&strtab);
    f[shs_off..shs_off + shstr.len()].copy_from_slice(&shstr);
    let sh = |name: u32, ty: u32, flags: u32, addr: u32, off: usize, size: usize, link: u32, info: u32, align: u32, ent: u32| -> Vec<u8> {
        [name, ty, flags, addr, off as u32, size as u32, link, info, align, ent].iter().flat_map(|v| v.to_le_bytes()).collect()
    };
    f.extend(vec![0u8; 40]);
    f.extend(sh(1, 1, 6, 0x8000, text_off, code.len(), 0, 0, 4, 0));
    f.extend(sh(7, 2, 0, 0, sym_off, symtab.len(), 3, 1 + syms.len() as u32, 4, 16));
    f.extend(sh(15, 3, 0, 0, str_off, strtab.len(), 0, 0, 1, 0));
    f.extend(sh(23, 3, 0, 0, shs_off, shstr.len(), 0, 0, 1, 0));
    f
}

#[test]
fn mixed_arm_and_thumb_code() {
    let first = |bin: &Binary, va: u64, n: usize| -> Vec<(u32, String)> {
        bin.listing(va, n).unwrap().into_iter().map(|i| (i.size, i.mnemonic)).collect()
    };
    for how in ["functions", "mapping", "none"] {
        let mut bin = Binary::load("mixed", mixed_arm_elf(how)).unwrap_or_else(|e| panic!("{how}: {e}"));
        assert_eq!(bin.info().arch, paranoia_core::Arch::Arm, "{how}: an ARM entry keeps the image ARM");
        bin.analyze();
        // The Thumb function: 2-byte instructions, found through `blx` even without symbols.
        assert!(bin.is_thumb_at(0x8010), "{how}: 0x8010 is Thumb");
        let t = first(&bin, 0x8010, 2);
        assert_eq!(t[0].0, 2, "{how}: {t:?}");
        assert!(t[0].1.starts_with("mov") && t[1].1 == "bx", "{how}: {t:?}");
        assert!(bin.functions().iter().any(|f| f.address == 0x8010), "{how}: thumb_fn is a function");
        // ARM before it stays ARM.
        assert!(!bin.is_thumb_at(0x8000));
        assert_eq!(first(&bin, 0x8004, 1)[0], (4, "blx".to_string()), "{how}");
        if how != "none" {
            // With symbols, the ARM function after the Thumb code is ARM again.
            assert!(!bin.is_thumb_at(0x8018), "{how}");
            assert_eq!(first(&bin, 0x8018, 2), vec![(4, "mov".to_string()), (4, "bx".to_string())], "{how}");
        }
        // Mapping symbols are markers, not names.
        assert!(bin.symbols().iter().all(|s| !s.name.starts_with('$')), "{how}");
    }
}

/// The C view with SSA facts (dead register assignments left out, constants noted) keeps every call
/// and return, stays balanced, and never grows.
#[test]
fn ssa_facts_in_the_c_view_are_safe() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/node_modules/electron-winstaller/vendor");
    let mut inputs: Vec<(String, Vec<u8>)> = vec![];
    if let Ok(b) = std::fs::read(dir.join("Setup.exe")) {
        inputs.push(("Setup.exe".into(), b));
    }
    if let Ok(b) = std::env::current_exe().and_then(std::fs::read) {
        inputs.push(("self".into(), b));
    }
    let text = |p: &paranoia_core::Pseudocode| -> Vec<String> {
        p.lines.iter().map(|l| l.tokens.iter().map(|t| t.t.as_str()).collect()).collect()
    };
    let calls = |lines: &[String]| -> Vec<String> {
        let mut v: Vec<String> = lines
            .iter()
            .flat_map(|l| {
                l.match_indices('(')
                    .filter_map(move |(i, _)| l[..i].rsplit(|c: char| !(c.is_alphanumeric() || c == '_')).next().map(str::to_string))
            })
            .filter(|n| n.starts_with("sub_") || n.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
            .collect();
        v.sort();
        v
    };
    let (mut checked, mut removed, mut notes) = (0usize, 0usize, 0usize);
    for (name, bytes) in inputs {
        let Ok(mut bin) = Binary::load(&name, bytes) else { continue };
        bin.analyze();
        let funcs: Vec<u64> =
            bin.functions().iter().filter(|f| f.instructions > 6 && f.instructions < 500).map(|f| f.address).take(20).collect();
        for va in funcs {
            bin.set_ssa_facts(false);
            let Some(off) = bin.pseudocode(va) else { continue };
            bin.set_ssa_facts(true);
            let on = bin.pseudocode(va).unwrap();
            let (a, b) = (text(&off), text(&on));
            assert!(b.len() <= a.len(), "{name} {va:#x}: {} lines became {}", a.len(), b.len());
            assert_eq!(calls(&a), calls(&b), "{name} {va:#x}: calls changed\n{}\n----\n{}", a.join("\n"), b.join("\n"));
            let rets = |v: &[String]| v.iter().filter(|l| l.trim_start().starts_with("return")).count();
            assert_eq!(rets(&a), rets(&b), "{name} {va:#x}: returns changed");
            let depth: i64 = b.iter().map(|l| l.matches('{').count() as i64 - l.matches('}').count() as i64).sum();
            assert_eq!(depth, 0, "{name} {va:#x}: unbalanced braces");
            removed += a.len() - b.len();
            notes += b.iter().filter(|l| l.contains("  // = ")).count();
            checked += 1;
        }
    }
    eprintln!("ssa facts: {checked} functions, {removed} lines dropped, {notes} constants noted");
}

/// AArch64 pseudocode on a corpus (`PARANOIA_ARM64_DIR`: arm64 ELF / Mach-O files): no panics,
/// balanced braces, every `goto` has its label, and the direct calls in the C text are the
/// calls the disassembly shows. No-op without the variable.
#[test]
fn arm64_pseudocode_on_a_corpus() {
    let Ok(dir) = std::env::var("PARANOIA_ARM64_DIR") else { return };
    let take: usize = std::env::var("PARANOIA_ARM64_FUNCS").ok().and_then(|v| v.parse().ok()).unwrap_or(400);
    let (mut n, mut same, mut files) = (0usize, 0usize, 0usize);
    let mut differ: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let Ok(bytes) = std::fs::read(entry.path()) else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(mut bin) = Binary::load(&name, bytes) else { continue };
        if bin.info().arch != Arch::Arm64 {
            continue;
        }
        files += 1;
        bin.analyze();
        let funcs: Vec<u64> =
            bin.functions().iter().filter(|f| f.instructions > 4 && f.instructions < 800).map(|f| f.address).take(take).collect();
        for va in funcs {
            let p = bin.pseudocode(va).expect("pseudocode");
            let t: Vec<String> = p.lines.iter().map(|l| l.tokens.iter().map(|t| t.t.as_str()).collect()).collect();
            let depth: i64 = t.iter().map(|l| l.matches('{').count() as i64 - l.matches('}').count() as i64).sum();
            assert_eq!(depth, 0, "{name} {va:#x}: unbalanced\n{}", t.join("\n"));
            let labels: Vec<String> = t.iter().filter_map(|l| l.strip_suffix(':').map(str::to_string)).collect();
            for l in &t {
                if let Some(target) = l.trim_start().split("goto ").nth(1).map(|r| r.trim_end_matches(';')) {
                    assert!(
                        !target.starts_with("loc_") || labels.iter().any(|x| x == target),
                        "{name} {va:#x}: goto {target} without label"
                    );
                }
            }
            // Calls in the body (the first line is the function's own signature).
            let in_c: std::collections::BTreeSet<String> = p
                .lines
                .iter()
                .skip(1)
                .flat_map(|l| {
                    l.tokens
                        .windows(2)
                        .filter(|w| w[0].k == paranoia_core::TokenKind::Symbol && w[1].t.starts_with('('))
                        .map(|w| w[0].t.clone())
                        .collect::<Vec<_>>()
                })
                .collect();
            let in_asm: std::collections::BTreeSet<String> = bin.callees(va).into_iter().map(|c| c.name).collect();
            if in_c == in_asm {
                same += 1;
            } else if differ.len() < 5 {
                differ.push(format!("{name} {va:#x}: C {in_c:?} vs listing {in_asm:?}"));
            }
            n += 1;
        }
    }
    eprintln!("arm64 pseudocode: {files} files, {n} functions, {same} with the same direct calls as the listing");
    for d in &differ {
        eprintln!("  {d}");
    }
    if n > 0 {
        assert!(same * 100 >= n * 95, "only {same} of {n} functions call what the listing calls");
    }
}

/// C generated from the SSA form, on real code: no panics, balanced braces, every `goto` has its
/// label, and it calls the same functions as the line-based C view.
#[test]
fn c_from_ssa_on_real_code() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/node_modules/electron-winstaller/vendor");
    let mut inputs: Vec<(String, Vec<u8>)> = vec![];
    if let Ok(b) = std::fs::read(dir.join("Setup.exe")) {
        inputs.push(("Setup.exe".into(), b));
    }
    if let Ok(b) = std::env::current_exe().and_then(std::fs::read) {
        inputs.push(("self".into(), b));
    }
    let take: usize = std::env::var("PARANOIA_SSA_C_FUNCS").ok().and_then(|v| v.parse().ok()).unwrap_or(25);
    let text = |p: &paranoia_core::Pseudocode| -> Vec<String> {
        p.lines.iter().map(|l| l.tokens.iter().map(|t| t.t.as_str()).collect()).collect()
    };
    let callees = |p: &paranoia_core::Pseudocode| -> std::collections::BTreeSet<String> {
        p.lines
            .iter()
            .flat_map(|l| {
                l.tokens
                    .windows(2)
                    .filter(|w| w[0].k == paranoia_core::TokenKind::Symbol && w[1].t.starts_with('('))
                    .map(|w| w[0].t.clone())
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let (mut n, mut same_calls, mut raw_sp) = (0usize, 0usize, 0usize);
    for (name, bytes) in inputs {
        let Ok(mut bin) = Binary::load(&name, bytes) else { continue };
        bin.analyze();
        let funcs: Vec<u64> =
            bin.functions().iter().filter(|f| f.instructions > 6 && f.instructions < 800).map(|f| f.address).take(take).collect();
        for va in funcs {
            let Some(new) = bin.pseudocode_from_ssa(va) else { continue };
            let t = text(&new);
            let depth: i64 = t.iter().map(|l| l.matches('{').count() as i64 - l.matches('}').count() as i64).sum();
            assert_eq!(depth, 0, "{name} {va:#x}: unbalanced\n{}", t.join("\n"));
            let labels: Vec<String> = t.iter().filter_map(|l| l.strip_suffix(':').map(str::to_string)).collect();
            for l in &t {
                if let Some(rest) = l.trim_start().split("goto ").nth(1) {
                    let target = rest.trim_end_matches(';');
                    if target.starts_with("loc_") {
                        assert!(labels.iter().any(|x| x == target), "{name} {va:#x}: goto {target} without its label\n{}", t.join("\n"));
                    }
                }
            }
            let old = bin.pseudocode(va).unwrap();
            if callees(&old) == callees(&new) {
                same_calls += 1;
            }
            raw_sp += usize::from(t.iter().any(|l| l.contains("esp") || l.contains("rsp")));
            n += 1;
        }
    }
    eprintln!("c from ssa: {n} functions, {same_calls} call the same functions as the C view, {raw_sp} still show the stack pointer");
    if n > 0 {
        assert!(same_calls * 10 >= n * 9, "only {same_calls} of {n} functions call the same functions");
    }
}

/// A file matched against itself, and against a copy with one instruction replaced by NOPs.
#[test]
fn function_matching_finds_one_edit() {
    use paranoia_core::memory::{diff, DiffOptions};
    let Some((p, bytes)) = sample(&["C:/Windows/System32/notepad.exe", "/bin/ls", "/usr/bin/ls"]) else { return };
    let mut a = Binary::load(&p, bytes.clone()).unwrap();
    a.analyze();
    let prints_a = a.fingerprints();
    let opts = DiffOptions { use_names: false, ..DiffOptions::default() };

    let same = diff(&prints_a, &prints_a, opts);
    assert!(same.matches.iter().all(|m| m.a == m.b && !m.changed), "{p}: a file must match itself exactly");
    assert!(same.similarity > 0.999);
    assert!(same.only_a.is_empty() && same.only_b.is_empty(), "{p}: identical copies must pair up too");

    if !matches!(a.info().arch, Arch::X86 | Arch::X86_64) {
        return;
    }
    // The fifth instruction of the largest function becomes NOPs.
    let f = a.functions().into_iter().filter(|f| !f.is_import_thunk).max_by_key(|f| f.instructions).unwrap();
    let ins = &a.disassemble(f.address, 5).unwrap()[4];
    let off = a.va_to_offset(ins.address).unwrap() as usize;
    let mut edited = bytes;
    edited[off..off + ins.size as usize].fill(0x90);
    let mut b = Binary::load(&p, edited).unwrap();
    b.analyze();
    let report = diff(&prints_a, &b.fingerprints(), opts);
    let changed: Vec<_> = report.matches.iter().filter(|m| m.changed).collect();
    assert_eq!(changed.len(), 1, "{p}: exactly the edited function changes, got {changed:?}");
    assert_eq!((changed[0].a, changed[0].b), (f.address, f.address));
    assert!(changed[0].score > 0.6 && changed[0].score < 1.0);
}
