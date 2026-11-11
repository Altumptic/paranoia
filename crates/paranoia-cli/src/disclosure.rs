//! What `paranoia mcp` lets an agent see, and a log of what it saw.
//!
//! `Redactor` replaces the file's strings in tool output with numbered placeholders
//! (`"<str#12 len=23>"`, `aRedacted12`). `Ledger` writes every answer to a JSON-lines file
//! before it is sent; if the write fails, the answer is not sent.

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
                // A string like "1   " is named `a1`, which is also what the decompiler calls
                // the first parameter. Replacing it would rename a variable, not hide a string.
                if name.strip_prefix('a').is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())) {
                    continue;
                }
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
    /// SHA-256 of the last line written (or found when the file was opened).
    prev: Option<String>,
}

impl Ledger {
    /// Opens `path` for appending (created if missing); earlier sessions are kept.
    pub fn open(path: &Path) -> std::io::Result<Ledger> {
        // Continue the hash chain of an existing ledger.
        let prev = match std::fs::read_to_string(path) {
            Ok(t) => t.lines().rev().find(|l| !l.trim().is_empty()).map(|l| sha256_hex(l.as_bytes())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Ledger { file, path: path.to_path_buf(), prev })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A ledger whose writes fail, to test that results are withheld.
    #[cfg(test)]
    pub fn read_only_for_tests(path: &Path) -> Ledger {
        Ledger { file: File::open(path).unwrap(), path: path.to_path_buf(), prev: None }
    }

    /// Writes one JSON line and flushes it to disk before returning. Each line carries the
    /// SHA-256 of the line before it (`prev`), so removing, inserting or rewriting a line
    /// breaks the chain at that point.
    pub fn record(&mut self, mut entry: Value) -> std::io::Result<()> {
        if let Some(o) = entry.as_object_mut() {
            o.insert("time".into(), Value::from(unix_time()));
            o.insert("prev".into(), self.prev.clone().map_or(Value::Null, Value::from));
        }
        let line = entry.to_string();
        writeln!(self.file, "{line}")?;
        self.file.sync_data()?;
        self.prev = Some(sha256_hex(line.as_bytes()));
        Ok(())
    }
}

/// What `paranoia ledger` found in a ledger file.
#[derive(Default, Debug)]
pub struct Report {
    pub sessions: usize,
    pub answers: usize,
    pub errors: usize,
    pub chars: usize,
    pub redactions: u64,
    /// Answer counts per tool, sorted by name.
    pub tools: std::collections::BTreeMap<String, usize>,
    /// SHA-256 of every analysed file the agent was shown something about.
    pub files: std::collections::BTreeSet<String>,
    /// Line numbers (1-based) whose text does not match its recorded hash, or that are not
    /// valid ledger lines.
    pub bad: Vec<(usize, String)>,
}

/// Re-checks a ledger: the hash chain from the first line to the last, and each answer's
/// text against its recorded SHA-256.
pub fn verify(text: &str) -> Report {
    let mut r = Report::default();
    let mut prev: Option<String> = None;
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        if line.trim().is_empty() {
            continue;
        }
        let expected = prev.replace(sha256_hex(line.as_bytes()));
        let Ok(e) = serde_json::from_str::<Value>(line) else {
            r.bad.push((n, "not JSON".into()));
            continue;
        };
        if e.get("prev").and_then(Value::as_str).map(str::to_string) != expected {
            r.bad.push((n, "hash chain broken: a line before this one was removed, inserted or changed".into()));
        }
        match e.get("event").and_then(Value::as_str) {
            Some("session") => r.sessions += 1,
            Some("tool") => {
                let (Some(t), Some(h)) = (e.get("text").and_then(Value::as_str), e.get("sha256").and_then(Value::as_str)) else {
                    r.bad.push((n, "answer without text or sha256".into()));
                    continue;
                };
                if sha256_hex(t.as_bytes()) != h {
                    r.bad.push((n, "text does not match its sha256 (edited after it was written?)".into()));
                    continue;
                }
                r.answers += 1;
                r.chars += t.chars().count();
                r.redactions += e.get("redactions").and_then(Value::as_u64).unwrap_or(0);
                if e.get("is_error").and_then(Value::as_bool) == Some(true) {
                    r.errors += 1;
                }
                *r.tools.entry(e.get("tool").and_then(Value::as_str).unwrap_or("?").to_string()).or_default() += 1;
                if let Some(f) = e.get("file_sha256").and_then(Value::as_str) {
                    r.files.insert(f.to_string());
                }
            }
            _ => r.bad.push((n, "unknown event".into())),
        }
    }
    r
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
    fn parameter_names_are_not_mistaken_for_string_names() {
        // "1   " is auto-named `a1`, the same as the first parameter in pseudocode.
        let mut r = Redactor::new(["1   ", "ntdll.dll"].into_iter());
        let (t, n) = r.apply("f(int a1, int a2) { g(a1, aNtdllDll, \"ntdll.dll\"); }");
        assert!(t.contains("int a1,") && t.contains("g(a1,"), "{t}");
        assert!(!t.contains("aNtdllDll") && !t.contains("\"ntdll.dll\""), "{t}");
        assert_eq!(n, 2, "{t}");
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

    #[test]
    fn verify_checks_texts_and_the_chain() {
        let path = std::env::temp_dir().join(format!("paranoia-ledger-chain-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let answer = |tool: &str, text: &str| serde_json::json!({ "event": "tool", "tool": tool, "text": text, "sha256": sha256_hex(text.as_bytes()), "file_sha256": "f1", "redactions": 2, "is_error": false });
        {
            let mut l = Ledger::open(&path).unwrap();
            l.record(serde_json::json!({ "event": "session" })).unwrap();
            l.record(answer("decompile", "int main() {}")).unwrap();
        }
        // A second session continues the same chain.
        {
            let mut l = Ledger::open(&path).unwrap();
            l.record(serde_json::json!({ "event": "session" })).unwrap();
            l.record(answer("xrefs_to", "0x401000  Call")).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let r = verify(&text);
        assert!(r.bad.is_empty(), "{:?}", r.bad);
        assert_eq!((r.sessions, r.answers, r.chars, r.redactions), (2, 2, 27, 4));
        assert_eq!(r.tools.get("decompile"), Some(&1));
        assert_eq!(r.files.len(), 1);

        let lines: Vec<&str> = text.lines().collect();
        // An edited text: its own hash fails.
        let edited = lines[1].replace("int main() {}", "int main() {1}");
        let r = verify(&[lines[0], &edited, lines[2], lines[3]].join("\n"));
        assert_eq!(r.bad.iter().map(|b| b.0).collect::<Vec<_>>(), vec![2, 3], "{:?}", r.bad);
        // A removed line: the chain breaks where it was.
        let r = verify(&[lines[0], lines[2], lines[3]].join("\n"));
        assert_eq!(r.bad.iter().map(|b| b.0).collect::<Vec<_>>(), vec![2], "{:?}", r.bad);
        // Garbage is reported, not trusted.
        assert_eq!(verify("not json").bad.len(), 1);
    }
}
