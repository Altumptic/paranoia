//! Operand representation (IDA's H / R / B / M): show an instruction's numbers
//! as hex, decimal, characters, binary or symbolic constants from an enum.
//!
//! Enums come from the user's local types first, then from a small built-in
//! library of Windows / POSIX constants that is also applied automatically to
//! arguments of known APIs (`mov r9d, PAGE_EXECUTE_READWRITE ; flProtect`).

use serde::{Deserialize, Serialize};

use crate::model::{Instruction, TokenKind};
use crate::Binary;

/// How one number operand is displayed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperandFormat {
    /// Index among the instruction's number tokens; `None` applies to all of them.
    #[serde(default)]
    pub n: Option<u8>,
    /// `hex`, `dec`, `char`, `bin` or `enum`.
    pub kind: String,
    /// Enum name for `kind == "enum"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#enum: Option<String>,
}

/// An enum member: `(name, value, mask)`.
type Member = (String, i64, i64);

/// One enum: `(name, value, mask)`. A zero mask means the value is its own mask.
type Members = &'static [(&'static str, i64, i64)];

/// Built-in constants, by enum name. `true` marks bit-flag enums.
static BUILTIN: &[(&str, bool, Members)] = &[
    (
        "PAGE_PROTECTION",
        true,
        &[
            ("PAGE_NOACCESS", 0x1, 0xff),
            ("PAGE_READONLY", 0x2, 0xff),
            ("PAGE_READWRITE", 0x4, 0xff),
            ("PAGE_WRITECOPY", 0x8, 0xff),
            ("PAGE_EXECUTE", 0x10, 0xff),
            ("PAGE_EXECUTE_READ", 0x20, 0xff),
            ("PAGE_EXECUTE_READWRITE", 0x40, 0xff),
            ("PAGE_EXECUTE_WRITECOPY", 0x80, 0xff),
            ("PAGE_GUARD", 0x100, 0),
            ("PAGE_NOCACHE", 0x200, 0),
            ("PAGE_WRITECOMBINE", 0x400, 0),
        ],
    ),
    (
        "MEM_ALLOCATION",
        true,
        &[
            ("MEM_COMMIT", 0x1000, 0),
            ("MEM_RESERVE", 0x2000, 0),
            ("MEM_DECOMMIT", 0x4000, 0),
            ("MEM_RELEASE", 0x8000, 0),
            ("MEM_RESET", 0x80000, 0),
            ("MEM_TOP_DOWN", 0x100000, 0),
            ("MEM_WRITE_WATCH", 0x200000, 0),
            ("MEM_PHYSICAL", 0x400000, 0),
            ("MEM_LARGE_PAGES", 0x2000_0000, 0),
        ],
    ),
    (
        "ACCESS_MASK",
        true,
        &[
            ("PROCESS_ALL_ACCESS", 0x1f_ffff, 0x1f_ffff),
            ("KEY_ALL_ACCESS", 0xf_003f, 0x1f_ffff),
            ("KEY_READ", 0x2_0019, 0x1f_ffff),
            ("KEY_WRITE", 0x2_0006, 0x1f_ffff),
            ("GENERIC_READ", 0x8000_0000, 0),
            ("GENERIC_WRITE", 0x4000_0000, 0),
            ("GENERIC_EXECUTE", 0x2000_0000, 0),
            ("GENERIC_ALL", 0x1000_0000, 0),
            ("MAXIMUM_ALLOWED", 0x200_0000, 0),
            ("SYNCHRONIZE", 0x10_0000, 0),
            ("WRITE_OWNER", 0x8_0000, 0),
            ("WRITE_DAC", 0x4_0000, 0),
            ("READ_CONTROL", 0x2_0000, 0),
            ("DELETE", 0x1_0000, 0),
            ("KEY_WOW64_32KEY", 0x200, 0),
            ("KEY_WOW64_64KEY", 0x100, 0),
        ],
    ),
    ("FILE_SHARE", true, &[("FILE_SHARE_READ", 1, 0), ("FILE_SHARE_WRITE", 2, 0), ("FILE_SHARE_DELETE", 4, 0)]),
    (
        "CREATION_DISPOSITION",
        false,
        &[("CREATE_NEW", 1, 0), ("CREATE_ALWAYS", 2, 0), ("OPEN_EXISTING", 3, 0), ("OPEN_ALWAYS", 4, 0), ("TRUNCATE_EXISTING", 5, 0)],
    ),
    (
        "FILE_FLAGS_AND_ATTRIBUTES",
        true,
        &[
            ("FILE_ATTRIBUTE_READONLY", 0x1, 0),
            ("FILE_ATTRIBUTE_HIDDEN", 0x2, 0),
            ("FILE_ATTRIBUTE_SYSTEM", 0x4, 0),
            ("FILE_ATTRIBUTE_DIRECTORY", 0x10, 0),
            ("FILE_ATTRIBUTE_ARCHIVE", 0x20, 0),
            ("FILE_ATTRIBUTE_NORMAL", 0x80, 0),
            ("FILE_ATTRIBUTE_TEMPORARY", 0x100, 0),
            ("FILE_FLAG_WRITE_THROUGH", 0x8000_0000, 0),
            ("FILE_FLAG_OVERLAPPED", 0x4000_0000, 0),
            ("FILE_FLAG_NO_BUFFERING", 0x2000_0000, 0),
            ("FILE_FLAG_RANDOM_ACCESS", 0x1000_0000, 0),
            ("FILE_FLAG_SEQUENTIAL_SCAN", 0x800_0000, 0),
            ("FILE_FLAG_DELETE_ON_CLOSE", 0x400_0000, 0),
            ("FILE_FLAG_BACKUP_SEMANTICS", 0x200_0000, 0),
        ],
    ),
    (
        "PROCESS_CREATION_FLAGS",
        true,
        &[
            ("DEBUG_PROCESS", 0x1, 0),
            ("DEBUG_ONLY_THIS_PROCESS", 0x2, 0),
            ("CREATE_SUSPENDED", 0x4, 0),
            ("DETACHED_PROCESS", 0x8, 0),
            ("CREATE_NEW_CONSOLE", 0x10, 0),
            ("CREATE_NEW_PROCESS_GROUP", 0x200, 0),
            ("CREATE_UNICODE_ENVIRONMENT", 0x400, 0),
            ("STACK_SIZE_PARAM_IS_A_RESERVATION", 0x1_0000, 0),
            ("EXTENDED_STARTUPINFO_PRESENT", 0x8_0000, 0),
            ("CREATE_NO_WINDOW", 0x800_0000, 0),
        ],
    ),
    (
        "MESSAGEBOX_STYLE",
        true,
        &[
            ("MB_OK", 0x0, 0xf),
            ("MB_OKCANCEL", 0x1, 0xf),
            ("MB_ABORTRETRYIGNORE", 0x2, 0xf),
            ("MB_YESNOCANCEL", 0x3, 0xf),
            ("MB_YESNO", 0x4, 0xf),
            ("MB_RETRYCANCEL", 0x5, 0xf),
            ("MB_ICONERROR", 0x10, 0xf0),
            ("MB_ICONQUESTION", 0x20, 0xf0),
            ("MB_ICONWARNING", 0x30, 0xf0),
            ("MB_ICONINFORMATION", 0x40, 0xf0),
            ("MB_DEFBUTTON2", 0x100, 0xf00),
            ("MB_DEFBUTTON3", 0x200, 0xf00),
            ("MB_SYSTEMMODAL", 0x1000, 0x3000),
            ("MB_TASKMODAL", 0x2000, 0x3000),
            ("MB_SETFOREGROUND", 0x1_0000, 0),
            ("MB_TOPMOST", 0x4_0000, 0),
        ],
    ),
    (
        "SHOW_WINDOW_CMD",
        false,
        &[
            ("SW_HIDE", 0, 0),
            ("SW_SHOWNORMAL", 1, 0),
            ("SW_SHOWMINIMIZED", 2, 0),
            ("SW_SHOWMAXIMIZED", 3, 0),
            ("SW_SHOWNOACTIVATE", 4, 0),
            ("SW_SHOW", 5, 0),
            ("SW_MINIMIZE", 6, 0),
            ("SW_SHOWMINNOACTIVE", 7, 0),
            ("SW_SHOWNA", 8, 0),
            ("SW_RESTORE", 9, 0),
            ("SW_SHOWDEFAULT", 10, 0),
        ],
    ),
    (
        "HKEY",
        false,
        &[
            ("HKEY_CLASSES_ROOT", 0x8000_0000, 0),
            ("HKEY_CURRENT_USER", 0x8000_0001, 0),
            ("HKEY_LOCAL_MACHINE", 0x8000_0002, 0),
            ("HKEY_USERS", 0x8000_0003, 0),
            ("HKEY_CURRENT_CONFIG", 0x8000_0005, 0),
        ],
    ),
    ("STD_HANDLE", false, &[("STD_INPUT_HANDLE", -10, 0), ("STD_OUTPUT_HANDLE", -11, 0), ("STD_ERROR_HANDLE", -12, 0)]),
    ("WAIT_TIMEOUT", false, &[("INFINITE", 0xffff_ffff, 0)]),
    ("FILE_MOVE_METHOD", false, &[("FILE_BEGIN", 0, 0), ("FILE_CURRENT", 1, 0), ("FILE_END", 2, 0)]),
    ("SEEK_WHENCE", false, &[("SEEK_SET", 0, 0), ("SEEK_CUR", 1, 0), ("SEEK_END", 2, 0)]),
    ("CODE_PAGE", false, &[("CP_ACP", 0, 0), ("CP_OEMCP", 1, 0), ("CP_UTF7", 65000, 0), ("CP_UTF8", 65001, 0)]),
    (
        "WINDOWS_HOOK_ID",
        false,
        &[
            ("WH_KEYBOARD", 2, 0),
            ("WH_GETMESSAGE", 3, 0),
            ("WH_CALLWNDPROC", 4, 0),
            ("WH_CBT", 5, 0),
            ("WH_MOUSE", 7, 0),
            ("WH_KEYBOARD_LL", 13, 0),
            ("WH_MOUSE_LL", 14, 0),
        ],
    ),
    (
        "CSIDL",
        false,
        &[
            ("CSIDL_DESKTOP", 0x0, 0),
            ("CSIDL_STARTUP", 0x7, 0),
            ("CSIDL_APPDATA", 0x1a, 0),
            ("CSIDL_LOCAL_APPDATA", 0x1c, 0),
            ("CSIDL_COMMON_APPDATA", 0x23, 0),
            ("CSIDL_WINDOWS", 0x24, 0),
            ("CSIDL_SYSTEM", 0x25, 0),
            ("CSIDL_PROGRAM_FILES", 0x26, 0),
        ],
    ),
    (
        "WINDOW_MESSAGE",
        false,
        &[
            ("WM_CREATE", 0x1, 0),
            ("WM_DESTROY", 0x2, 0),
            ("WM_CLOSE", 0x10, 0),
            ("WM_QUIT", 0x12, 0),
            ("WM_SETTEXT", 0xc, 0),
            ("WM_GETTEXT", 0xd, 0),
            ("WM_KEYDOWN", 0x100, 0),
            ("WM_KEYUP", 0x101, 0),
            ("WM_CHAR", 0x102, 0),
            ("WM_COMMAND", 0x111, 0),
            ("WM_TIMER", 0x113, 0),
            ("WM_LBUTTONDOWN", 0x201, 0),
            ("WM_USER", 0x400, 0),
        ],
    ),
    ("ADDRESS_FAMILY", false, &[("AF_UNSPEC", 0, 0), ("AF_UNIX", 1, 0), ("AF_INET", 2, 0), ("AF_INET6", 23, 0)]),
    ("SOCKET_TYPE", false, &[("SOCK_STREAM", 1, 0), ("SOCK_DGRAM", 2, 0), ("SOCK_RAW", 3, 0)]),
    ("IPPROTO", false, &[("IPPROTO_IP", 0, 0), ("IPPROTO_ICMP", 1, 0), ("IPPROTO_TCP", 6, 0), ("IPPROTO_UDP", 17, 0)]),
    ("PROT", true, &[("PROT_NONE", 0, 0x7), ("PROT_READ", 1, 0), ("PROT_WRITE", 2, 0), ("PROT_EXEC", 4, 0)]),
    (
        "SIGNAL",
        false,
        &[
            ("SIGHUP", 1, 0),
            ("SIGINT", 2, 0),
            ("SIGQUIT", 3, 0),
            ("SIGILL", 4, 0),
            ("SIGTRAP", 5, 0),
            ("SIGABRT", 6, 0),
            ("SIGKILL", 9, 0),
            ("SIGSEGV", 11, 0),
            ("SIGPIPE", 13, 0),
            ("SIGALRM", 14, 0),
            ("SIGTERM", 15, 0),
        ],
    ),
];

/// Parameter name (and optionally the function) → built-in enum.
static PARAM_ENUMS: &[(Option<&str>, &str, &str)] = &[
    (None, "flProtect", "PAGE_PROTECTION"),
    (None, "flNewProtect", "PAGE_PROTECTION"),
    (None, "flAllocationType", "MEM_ALLOCATION"),
    (None, "dwFreeType", "MEM_ALLOCATION"),
    (None, "dwDesiredAccess", "ACCESS_MASK"),
    (None, "samDesired", "ACCESS_MASK"),
    (None, "dwShareMode", "FILE_SHARE"),
    (None, "dwCreationDisposition", "CREATION_DISPOSITION"),
    (None, "dwFlagsAndAttributes", "FILE_FLAGS_AND_ATTRIBUTES"),
    (None, "dwCreationFlags", "PROCESS_CREATION_FLAGS"),
    (None, "uType", "MESSAGEBOX_STYLE"),
    (None, "nCmdShow", "SHOW_WINDOW_CMD"),
    (None, "hKey", "HKEY"),
    (None, "nStdHandle", "STD_HANDLE"),
    (None, "dwMilliseconds", "WAIT_TIMEOUT"),
    (None, "dwMoveMethod", "FILE_MOVE_METHOD"),
    (None, "whence", "SEEK_WHENCE"),
    (None, "CodePage", "CODE_PAGE"),
    (None, "idHook", "WINDOWS_HOOK_ID"),
    (None, "csidl", "CSIDL"),
    (None, "nFolder", "CSIDL"),
    (None, "Msg", "WINDOW_MESSAGE"),
    (None, "af", "ADDRESS_FAMILY"),
    (Some("socket"), "type", "SOCKET_TYPE"),
    (Some("socket"), "protocol", "IPPROTO"),
    (None, "prot", "PROT"),
    (None, "signum", "SIGNAL"),
    (None, "sig", "SIGNAL"),
];

/// The built-in enum to use for `param` of `function`, if any.
pub(crate) fn param_enum(function: &str, param: &str) -> Option<&'static str> {
    PARAM_ENUMS.iter().find(|(f, p, _)| *p == param && f.is_none_or(|f| function.trim_start_matches('_') == f)).map(|e| e.2)
}

/// Builds a symbolic expression for `v` from `(name, value, mask)` members.
fn symbolize(members: &[(String, i64, i64)], flags: bool, v: i64, width: u32) -> Option<String> {
    let mask_w = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
    let same = |a: i64, b: i64| a == b || (a as u64 & mask_w) == (b as u64 & mask_w);
    if let Some(m) = members.iter().find(|m| same(m.1, v)) {
        return Some(m.0.clone());
    }
    if !flags || v == 0 {
        return None;
    }
    let mut rest = v as u64 & mask_w;
    let mut parts = Vec::new();
    let mut ordered: Vec<&(String, i64, i64)> = members.iter().collect();
    ordered.sort_by_key(|m| std::cmp::Reverse((if m.2 == 0 { m.1 } else { m.2 } as u64).count_ones()));
    for (name, value, mask) in ordered {
        let value = *value as u64 & mask_w;
        let mask = if *mask == 0 { value } else { *mask as u64 & mask_w };
        if value != 0 && rest & mask == value {
            parts.push(name.clone());
            rest &= !mask;
        }
    }
    if parts.is_empty() {
        return None;
    }
    if rest != 0 {
        parts.push(format!("{rest:#x}"));
    }
    Some(parts.join(" | "))
}

/// Parses a rendered number token (`0x40`, `-0x8`, `#0x10`, `12`).
fn parse_number(t: &str) -> Option<(String, i64)> {
    let (prefix, body) = match t.strip_prefix('#') {
        Some(b) => ("#", b),
        None => ("", t),
    };
    let (neg, body) = match body.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, body),
    };
    let v = if let Some(h) = body.strip_prefix("0x") {
        u64::from_str_radix(h, 16).ok()? as i64
    } else if let Some(h) = body.strip_suffix('h') {
        u64::from_str_radix(h, 16).ok()? as i64
    } else {
        body.parse::<u64>().ok()? as i64
    };
    Some((prefix.to_string(), if neg { v.wrapping_neg() } else { v }))
}

fn as_chars(v: i64) -> Option<String> {
    let bytes: Vec<u8> = (v as u64).to_be_bytes().into_iter().skip_while(|&b| b == 0).collect();
    if bytes.is_empty() || bytes.len() > 8 || !bytes.iter().all(|b| (0x20..0x7f).contains(b)) {
        return None;
    }
    Some(format!("'{}'", bytes.iter().map(|&b| if b == b'\'' { "\\'".to_string() } else { (b as char).to_string() }).collect::<String>()))
}

impl Binary {
    fn enum_members(&self, name: &str) -> Option<(Vec<Member>, bool)> {
        if let Some(e) = self.annotations.types.enums.get(name) {
            // User enums count as bit flags when every non-zero member is a single bit.
            let flags = e.members.len() > 1 && e.members.iter().all(|m| m.1 == 0 || (m.1 as u64).is_power_of_two());
            return Some((e.members.iter().map(|(n, v)| (n.clone(), *v, 0)).collect(), flags));
        }
        BUILTIN.iter().find(|b| b.0 == name).map(|(_, flags, m)| (m.iter().map(|(n, v, k)| (n.to_string(), *v, *k)).collect(), *flags))
    }

    /// Symbolic text for `v` in enum `name`.
    pub(crate) fn enum_text(&self, name: &str, v: i64, width: u32) -> Option<String> {
        let (members, flags) = self.enum_members(name)?;
        symbolize(&members, flags, v, width)
    }

    /// All enums (user + built-in) that can express `v`, for the `M` dialog.
    /// `param` (an argument name such as `dwShareMode`) puts its usual enum first.
    pub fn enum_candidates(&self, v: i64, param: Option<&str>) -> Vec<(String, String)> {
        let mut names: Vec<String> = self.annotations.types.enums.keys().cloned().collect();
        names.extend(BUILTIN.iter().map(|b| b.0.to_string()));
        if let Some(pref) = param.and_then(|p| param_enum("", p)) {
            if let Some(i) = names.iter().position(|n| n == pref) {
                let n = names.remove(i);
                names.insert(0, n);
            }
        }
        names.into_iter().filter_map(|n| self.enum_text(&n, v, 32).map(|t| (n, t))).collect()
    }

    /// Sets (or with `kind == "default"` clears) the representation of a number operand.
    pub fn set_operand_format(&mut self, va: u64, f: OperandFormat) -> Result<(), String> {
        if !matches!(f.kind.as_str(), "default" | "hex" | "dec" | "char" | "bin" | "enum") {
            return Err(format!("unknown operand format `{}`", f.kind));
        }
        if f.kind == "enum" && f.r#enum.as_deref().and_then(|e| self.enum_members(e)).is_none() {
            return Err("unknown enum".into());
        }
        let list = self.annotations.operands.entry(va).or_default();
        // A format for one operand replaces that operand's; a format for all replaces everything.
        list.retain(|x| f.n.is_some() && x.n != f.n);
        if f.kind != "default" {
            list.push(f);
        }
        if list.is_empty() {
            self.annotations.operands.remove(&va);
        }
        Ok(())
    }

    /// Applies user operand formats to rendered instructions.
    pub(crate) fn apply_operand_formats(&self, insns: &mut [Instruction]) {
        if self.annotations.operands.is_empty() {
            return;
        }
        for ins in insns.iter_mut() {
            let Some(fmts) = self.annotations.operands.get(&ins.address) else { continue };
            let width = if self.info.bits == 64 { 64 } else { 32 };
            for (n, tok) in ins.operands.iter_mut().filter(|t| t.k == TokenKind::Number).enumerate() {
                let n = n as u8;
                let Some(f) = fmts.iter().find(|f| f.n == Some(n)).or_else(|| fmts.iter().find(|f| f.n.is_none())) else { continue };
                let Some((prefix, v)) = parse_number(&tok.t) else { continue };
                let text = match f.kind.as_str() {
                    "hex" if v < 0 => Some(format!("-{:#x}", v.unsigned_abs())),
                    "hex" => Some(format!("{v:#x}")),
                    "dec" => Some(v.to_string()),
                    "bin" => Some(format!("{:#b}", v as u64)),
                    "char" => as_chars(v),
                    "enum" => f.r#enum.as_deref().and_then(|e| self.enum_text(e, v, width)),
                    _ => None,
                };
                if let Some(t) = text {
                    tok.t = format!("{prefix}{t}");
                    if f.kind == "enum" {
                        tok.k = TokenKind::Symbol;
                    }
                }
            }
        }
    }
}

/// Replaces the last immediate of an argument set-up instruction with a symbolic
/// constant (`mov r9d, 0x40` → `mov r9d, PAGE_EXECUTE_READWRITE`).
pub(crate) fn symbolize_argument(bin: &Binary, ins: &mut Instruction, function: &str, param: &str) {
    if bin.annotations.operands.contains_key(&ins.address) {
        return; // the user's choice wins
    }
    let Some(e) = param_enum(function, param) else { return };
    // Only immediates: the source operand must be a single number after the comma.
    let Some(comma) = ins.operands.iter().rposition(|t| t.k == TokenKind::Punct && t.t.contains(',')) else {
        if ins.mnemonic == "push" {
            if let [t] = ins.operands.as_mut_slice() {
                replace_number(bin, t, e);
            }
        }
        return;
    };
    let tail: Vec<usize> = (comma + 1..ins.operands.len()).filter(|&i| !ins.operands[i].t.trim().is_empty()).collect();
    if let [i] = tail[..] {
        replace_number(bin, &mut ins.operands[i], e);
    }
}

fn replace_number(bin: &Binary, t: &mut crate::model::Token, e: &str) {
    if t.k != TokenKind::Number {
        return;
    }
    if let Some((prefix, v)) = parse_number(&t.t) {
        if let Some(s) = bin.enum_text(e, v, 32) {
            t.t = format!("{prefix}{s}");
            t.k = TokenKind::Symbol;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builtin(name: &str) -> (Vec<(String, i64, i64)>, bool) {
        let (_, f, m) = BUILTIN.iter().find(|b| b.0 == name).unwrap();
        (m.iter().map(|(n, v, k)| (n.to_string(), *v, *k)).collect(), *f)
    }

    #[test]
    fn symbolic_constants() {
        let (m, f) = builtin("PAGE_PROTECTION");
        assert_eq!(symbolize(&m, f, 0x40, 32).as_deref(), Some("PAGE_EXECUTE_READWRITE"));
        assert_eq!(symbolize(&m, f, 0x104, 32).as_deref(), Some("PAGE_READWRITE | PAGE_GUARD"));
        let (m, f) = builtin("ACCESS_MASK");
        assert_eq!(symbolize(&m, f, 0xc000_0000, 32).as_deref(), Some("GENERIC_READ | GENERIC_WRITE"));
        let (m, f) = builtin("MESSAGEBOX_STYLE");
        assert_eq!(symbolize(&m, f, 0x34, 32).as_deref(), Some("MB_YESNO | MB_ICONWARNING"));
        let (m, f) = builtin("STD_HANDLE");
        assert_eq!(symbolize(&m, f, 0xffff_fff5, 32).as_deref(), Some("STD_OUTPUT_HANDLE"));
        assert_eq!(param_enum("socket", "type"), Some("SOCKET_TYPE"));
        assert_eq!(param_enum("other", "type"), None);
    }

    #[test]
    fn numbers_and_chars() {
        assert_eq!(parse_number("0x40"), Some((String::new(), 0x40)));
        assert_eq!(parse_number("#-0x8"), Some(("#".into(), -8)));
        assert_eq!(as_chars(0x41424344).as_deref(), Some("'ABCD'"));
        assert_eq!(as_chars(0x01), None);
    }
}
