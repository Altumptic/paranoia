//! Controlled disclosure for `paranoia mcp`: what an AI agent may see, and a record of
//! what it saw.
//!
//! * [`Redactor`] replaces text that came from the analysed file's strings — quoted
//!   literals in pseudocode, listings and comments, and the auto names derived from them
//!   (`aHelloWorld`) — with stable placeholders (`"<str#12 len=23>"`, `aRedacted12`). The same
//!   string always gets the same number within a session, so an agent can still say
//!   "the function that uses str#12" and a human can look it up.
//! * [`Ledger`] appends one JSON line per tool call to a file the user chose: time, tool,
//!   arguments, the analysed file's SHA-256, and the exact text returned with its SHA-256.
//!   If the line cannot be written, the result is withheld (fail closed).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Shorter strings are too common ("%s", "true") to identify anything and too short to
/// replace safely as names; they are still redacted when they appear as quoted literals.
const MIN_NAMED: usize = 4;

#[derive(Default)]
pub struct Redactor {
    /// Literal content as the engine prints it (escaped) → placeholder number.
    ids: HashMap<String, usize>,
    /// Auto names derived from strings (`aHelloWorld`) → placeholder number.
    names: HashMap<String, usize>,
    /// Last placeholder number handed out.
    next: usize,
}

impl Redactor {
    /// Numbers the file's strings in order, so numbering does not depend on what the agent
    /// asks first.
    pub fn new<'a>(strings: impl Iterator<Item = &'a str>) -> Redactor {
        let mut r = Redactor::default();
        for s in strings {
            let id = r.id_for(s.escape_debug().to_string());
            if s.chars().count() >= MIN_NAMED {
                let name = paranoia_core::string_name(s);
                // Two strings can share an auto name; the first keeps it.
                r.names.entry(name).or_insert(id);
            }
        }
        r
    }

    fn id_for(&mut self, key: String) -> usize {
        let next = &mut self.next;
        *self.ids.entry(key).or_insert_with(|| {
            *next += 1;
            *next
        })
    }

    /// Replaces quoted literals and string-derived names; returns the text and how many
    /// replacements were made.
    pub fn apply(&mut self, text: &str) -> (String, usize) {
        let mut out = String::with_capacity(text.len());
        let mut count = 0;
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '"' || c == '\'' {
                if let Some(end) = closing(&chars, i) {
                    let inner: String = chars[i + 1..end].iter().collect();
                    let len = inner.chars().count();
                    let id = self.id_for(inner);
                    out.push(c);
                    out.push_str(&format!("<str#{id} len={len}>"));
                    out.push(c);
                    count += 1;
                    i = end + 1;
                    continue;
                }
            }
            if c.is_ascii_alphabetic() || c == '_' {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                // Only whole identifiers: `aHelloWorld`, not the tail of `xaHelloWorld`.
                let whole = start == 0 || !(chars[start - 1].is_ascii_alphanumeric() || chars[start - 1] == '_');
                match self.names.get(&word) {
                    Some(id) if whole => {
                        out.push_str(&format!("aRedacted{id}"));
                        count += 1;
                    }
                    _ => out.push_str(&word),
                }
                continue;
            }
            out.push(c);
            i += 1;
        }
        (out, count)
    }
}

/// Index of the quote that closes the literal opened at `open`, on the same line; a
/// backslash escapes the next character.
fn closing(chars: &[char], open: usize) -> Option<usize> {
    let q = chars[open];
    let mut i = open + 1;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 2,
            '\n' => return None,
            c if c == q => return Some(i),
            _ => i += 1,
        }
    }
    None
}

pub struct Ledger {
    file: File,
    path: PathBuf,
}

impl Ledger {
    /// Opens `path` for appending (created if missing); earlier sessions are kept.
    pub fn open(path: &Path) -> std::io::Result<Ledger> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Ledger { file, path: path.to_path_buf() })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A ledger whose writes fail, to test that results are withheld.
    #[cfg(test)]
    pub fn read_only_for_tests(path: &Path) -> Ledger {
        Ledger { file: File::open(path).unwrap(), path: path.to_path_buf() }
    }

    /// Writes one JSON line and flushes it to disk before returning.
    pub fn record(&mut self, mut entry: Value) -> std::io::Result<()> {
        if let Some(o) = entry.as_object_mut() {
            o.insert("time".into(), Value::from(unix_time()));
        }
        writeln!(self.file, "{entry}")?;
        self.file.sync_data()
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn unix_time() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_and_derived_names_are_replaced_consistently() {
        let mut r = Redactor::new(["Hello, world!\n", "db.internal.corp", "%s"].into_iter());
        let (t, n) = r.apply("v1 = puts(\"Hello, world!\\n\"); // see aHelloWorld\nlea rax, [aDbInternalCorp]  ; \"db.internal.corp\"");
        assert_eq!(n, 4, "{t}");
        assert_eq!(t, "v1 = puts(\"<str#1 len=15>\"); // see aRedacted1\nlea rax, [aRedacted2]  ; \"<str#2 len=16>\"");
        // The same text later gets the same number; unknown literals get new ones.
        let (t, _) = r.apply("x(\"db.internal.corp\", 'k')");
        assert_eq!(t, "x(\"<str#2 len=16>\", '<str#4 len=1>')");
        // Parts of longer identifiers and unclosed quotes are left alone.
        let (t, n) = r.apply("xaHelloWorld don't");
        assert_eq!((t.as_str(), n), ("xaHelloWorld don't", 0));
    }

    #[test]
    fn escaped_quotes_stay_inside_the_literal() {
        let mut r = Redactor::default();
        let (t, n) = r.apply(r#"f("say \"hi\"", 1)"#);
        assert_eq!(n, 1);
        assert_eq!(t, r#"f("<str#1 len=10>", 1)"#);
    }

    #[test]
    fn ledger_lines_are_json_with_a_time() {
        let path = std::env::temp_dir().join(format!("paranoia-ledger-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut l = Ledger::open(&path).unwrap();
        l.record(serde_json::json!({ "tool": "decompile" })).unwrap();
        l.record(serde_json::json!({ "tool": "xrefs_to" })).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1]["tool"], "xrefs_to");
        assert!(lines[0]["time"].as_u64().unwrap() > 1_700_000_000);
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
