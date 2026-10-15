//! Symbol demangling for MSVC C++, Itanium C++ (GCC/Clang) and Rust.

/// A short, readable form of `name`, or `None` when it isn't mangled.
pub fn demangle(name: &str) -> Option<String> {
    let core = name.strip_prefix("__imp_").unwrap_or(name);
    // ELF symbol versions (`memcpy@@GLIBC_2.14`) are noise for display.
    let core = if core.starts_with('?') { core } else { core.split("@@").next().unwrap_or(core) };

    if core.starts_with('?') {
        let flags = msvc_demangler::DemangleFlags::NAME_ONLY;
        return msvc_demangler::demangle(core, flags).ok().filter(|s| !s.is_empty());
    }
    // Rust v0 (`_R`) and legacy (`_ZN...17h<hash>E`) symbols.
    if core.starts_with("_R") || (core.starts_with("_ZN") && core.ends_with('E') && core.contains("17h")) {
        if let Ok(d) = rustc_demangle::try_demangle(core) {
            return Some(format!("{d:#}"));
        }
    }
    // Itanium C++; Mach-O adds an extra leading underscore.
    let itanium = core.strip_prefix('_').filter(|s| s.starts_with("_Z")).unwrap_or(core);
    if itanium.starts_with("_Z") {
        let sym = cpp_demangle::Symbol::new(itanium).ok()?;
        let opts = cpp_demangle::DemangleOptions::new().no_params().no_return_type();
        return sym.demangle_with_options(&opts).ok();
    }
    (core != name).then(|| core.to_string())
}

#[cfg(test)]
mod tests {
    use super::demangle;

    #[test]
    fn msvc_itanium_rust() {
        assert_eq!(demangle("?foo@bar@@QEAAXH@Z").as_deref(), Some("bar::foo"));
        assert_eq!(demangle("_ZN3foo3barEv").as_deref(), Some("foo::bar"));
        assert_eq!(demangle("__ZN3foo3barEv").as_deref(), Some("foo::bar"));
        assert_eq!(demangle("_ZN4core3fmt5write17h0123456789abcdefE").as_deref(), Some("core::fmt::write"));
        assert_eq!(demangle("memcpy@@GLIBC_2.14").as_deref(), Some("memcpy"));
        assert_eq!(demangle("CreateFileW"), None);
    }
}
