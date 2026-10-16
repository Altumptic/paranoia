//! `paranoia-engine` — the native analysis process behind the desktop app.
//!
//! Protocol: one JSON object per line on stdin, one reply per line on stdout.
//!
//! ```text
//! → {"id":1,"op":"open","path":"C:/samples/a.exe"}
//! ← {"id":1,"ok":true,"value":1}
//! → {"id":2,"op":"call","handle":1,"method":"functions","args":null}
//! ← {"id":2,"ok":true,"value":[...]}
//! → {"id":3,"op":"store","method":"recent_list","args":null}
//! ```
//!
//! Running the engine out of process means a bug triggered by a hostile file can
//! never take the UI down with it, and analysis runs at full native speed.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};

#[cfg(windows)]
mod debugger;

use paranoia_core::api::Session;
use paranoia_db::Store;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Request {
    id: u64,
    op: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    handle: Option<u32>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    args: Value,
}

struct Engine {
    sessions: HashMap<u32, Session>,
    paths: HashMap<u32, String>,
    #[cfg(windows)]
    debugger: Option<debugger::Debugger>,
    next: u32,
    store: Option<Store>,
}

impl Engine {
    fn handle(&mut self, r: Request) -> Result<Value, String> {
        match r.op.as_str() {
            "open" => {
                let path = r.path.ok_or("missing path")?;
                let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
                let name = std::path::Path::new(&path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or(path.clone());
                let s = Session::open(&name, bytes)?;
                self.next += 1;
                self.sessions.insert(self.next, s);
                self.paths.insert(self.next, path);
                Ok(json!(self.next))
            }
            "call" => {
                let h = r.handle.ok_or("missing handle")?;
                let s = self.sessions.get_mut(&h).ok_or_else(|| format!("no session {h}"))?;
                s.call(r.method.as_deref().unwrap_or(""), r.args)
            }
            "close" => {
                if let Some(h) = r.handle {
                    self.sessions.remove(&h);
                }
                Ok(Value::Null)
            }
            "load_pdb" => {
                let h = r.handle.ok_or("missing handle")?;
                let path = r.path.ok_or("missing path")?;
                let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
                let force = r.args.get("force").and_then(Value::as_bool).unwrap_or(false);
                let s = self.sessions.get_mut(&h).ok_or_else(|| format!("no session {h}"))?;
                serde_json::to_value(s.binary_mut().load_pdb(bytes, force)?).map_err(|e| e.to_string())
            }
            "find_pdb" => {
                // Look next to the binary for the PDB named in its CodeView record.
                let h = r.handle.ok_or("missing handle")?;
                let path = r.path.ok_or("missing path")?;
                let s = self.sessions.get(&h).ok_or_else(|| format!("no session {h}"))?;
                let Some(recorded) = s.binary().pdb_path() else { return Ok(Value::Null) };
                let file = recorded.rsplit(['\\', '/']).next().unwrap_or(&recorded).to_string();
                let dir = std::path::Path::new(&path).parent().map(|p| p.to_path_buf()).unwrap_or_default();
                let candidates = [std::path::PathBuf::from(&recorded), dir.join(&file)];
                Ok(candidates.iter().find(|c| c.is_file()).map(|c| json!(c.to_string_lossy())).unwrap_or(Value::Null))
            }
            "export_patched" => {
                let h = r.handle.ok_or("missing handle")?;
                let path = r.path.ok_or("missing path")?;
                let s = self.sessions.get(&h).ok_or_else(|| format!("no session {h}"))?;
                std::fs::write(&path, s.binary().file_bytes()).map_err(|e| format!("cannot write {path}: {e}"))?;
                Ok(Value::Null)
            }
            "debug" => self.debug_op(r.handle, r.method.as_deref().unwrap_or(""), r.args),
            "store" => self.store_op(r.method.as_deref().unwrap_or(""), r.args),
            "ping" => Ok(json!({ "version": env!("CARGO_PKG_VERSION") })),
            other => Err(format!("unknown op `{other}`")),
        }
    }

    #[cfg(not(windows))]
    fn debug_op(&mut self, _h: Option<u32>, _m: &str, _a: Value) -> Result<Value, String> {
        Err("the debugger is available on Windows only".into())
    }

    #[cfg(windows)]
    fn debug_op(&mut self, handle: Option<u32>, method: &str, args: Value) -> Result<Value, String> {
        let va = args.get("va").and_then(Value::as_u64);
        match method {
            "start" => {
                let h = handle.ok_or("missing handle")?;
                let s = self.sessions.get(&h).ok_or_else(|| format!("no session {h}"))?;
                let info = s.binary().info();
                if info.format != paranoia_core::Format::Pe || info.arch != paranoia_core::Arch::X86_64 {
                    return Err("the debugger currently supports 64-bit Windows executables".into());
                }
                if info.kind != "Executable" {
                    return Err("only executables can be started (DLLs need a host process)".into());
                }
                let path = self.paths.get(&h).cloned().filter(|p| !p.is_empty()).ok_or("the file has no path on disk")?;
                let size = info.sections.iter().map(|x| x.vaddr + x.vsize).max().unwrap_or(0).saturating_sub(info.image_base);
                self.debugger = None;
                let bps = args
                    .get("breakpoints")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_u64).collect())
                    .unwrap_or_default();
                let d = debugger::Debugger::start(debugger::StartArgs {
                    path,
                    cmdline: args.get("cmdline").and_then(Value::as_str).unwrap_or("").to_string(),
                    image_base: info.image_base,
                    entry: info.entry,
                    breakpoints: bps,
                    break_on_entry: args.get("break_on_entry").and_then(Value::as_bool).unwrap_or(true),
                    image_size: size,
                })?;
                self.debugger = Some(d);
                Ok(json!(true))
            }
            "poll" => match &self.debugger {
                Some(d) => serde_json::to_value(d.snapshot()).map_err(|e| e.to_string()),
                None => Ok(json!({ "state": "idle" })),
            },
            "read" => {
                let d = self.debugger.as_ref().ok_or("no debug session")?;
                let len = args.get("len").and_then(Value::as_u64).unwrap_or(256) as usize;
                Ok(json!(hex_encode(&d.read(va.ok_or("missing va")?, len)?)))
            }
            "end" => {
                self.debugger = None;
                Ok(Value::Null)
            }
            cmd => {
                let d = self.debugger.as_ref().ok_or("no debug session")?;
                d.command(cmd, va)?;
                Ok(Value::Null)
            }
        }
    }

    fn store_op(&self, method: &str, args: Value) -> Result<Value, String> {
        let Some(store) = &self.store else {
            // Without a store the app still works; it just forgets annotations.
            return Ok(if method == "recent_list" { json!([]) } else { Value::Null });
        };
        let sha = || args.get("sha256").and_then(Value::as_str).map(str::to_owned).ok_or("missing sha256");
        let e = |e: paranoia_db::Error| e.to_string();
        match method {
            "annotations_get" => Ok(store.annotations(&sha()?).map_err(e)?.unwrap_or(Value::Null)),
            "annotations_set" => {
                store.set_annotations(&sha()?, args.get("annotations").unwrap_or(&Value::Null)).map_err(e)?;
                Ok(Value::Null)
            }
            "recent_list" => Ok(Value::Array(store.recent().map_err(e)?)),
            "recent_add" => {
                let entry = args.get("entry").ok_or("missing entry")?;
                let sha = entry.get("sha256").and_then(Value::as_str).ok_or("entry without sha256")?;
                store.add_recent(sha, entry).map_err(e)?;
                Ok(Value::Null)
            }
            "recent_remove" => {
                store.remove_recent(&sha()?).map_err(e)?;
                Ok(Value::Null)
            }
            _ => Err(format!("unknown store method `{method}`")),
        }
    }
}

#[cfg(windows)]
fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn panic_message(p: Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".into())
}

fn main() {
    // Panics are reported to the UI as errors; keep stderr quiet in release builds.
    std::panic::set_hook(Box::new(|info| eprintln!("engine panic: {info}")));

    let mut args = std::env::args().skip(1);
    let mut store_path = None;
    while let Some(a) = args.next() {
        if a == "--store" {
            store_path = args.next();
        } else if a == "--version" {
            println!("paranoia-engine {}", env!("CARGO_PKG_VERSION"));
            return;
        }
    }
    let store = store_path.and_then(|p| Store::open(&p).map_err(|e| eprintln!("workspace store disabled: {e}")).ok());
    let mut engine = Engine {
        sessions: HashMap::new(),
        paths: HashMap::new(),
        #[cfg(windows)]
        debugger: None,
        next: 0,
        store,
    };

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Request>(&line) {
            Ok(req) => {
                let id = req.id;
                match catch_unwind(AssertUnwindSafe(|| engine.handle(req))) {
                    Ok(Ok(value)) => json!({ "id": id, "ok": true, "value": value }),
                    Ok(Err(error)) => json!({ "id": id, "ok": false, "error": error }),
                    Err(p) => json!({
                        "id": id,
                        "ok": false,
                        "error": format!("The analysis engine hit an internal error on this input ({}). Please report the file hash.", panic_message(p)),
                    }),
                }
            }
            Err(e) => json!({ "id": null, "ok": false, "error": format!("bad request: {e}") }),
        };
        let mut out = stdout.lock();
        if serde_json::to_writer(&mut out, &reply).is_err() || out.write_all(b"\n").is_err() || out.flush().is_err() {
            break; // UI went away
        }
    }
}
