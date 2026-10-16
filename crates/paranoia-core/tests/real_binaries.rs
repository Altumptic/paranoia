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
