//! `paranoia script`: runs a Python script against a binary without the app
//! (like IDA's `-S` batch mode). The script gets the same `paranoia` module as the
//! desktop console; its requests are served here from an in-process session.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use paranoia_core::api::Session;
use serde_json::{json, Value};

const MODULE: &str = include_str!("../../../apps/desktop/electron/paranoia.py");
const BOOT: &str = "import paranoia, sys; paranoia._main(sys.argv[1])";

fn find_python(explicit: Option<&str>) -> Result<(String, Vec<String>)> {
    let mut candidates: Vec<(String, Vec<String>)> = Vec::new();
    if let Some(p) = explicit.map(str::to_string).or_else(|| std::env::var("PARANOIA_PYTHON").ok()) {
        candidates.push((p, vec![]));
    }
    candidates.push(("python".into(), vec![]));
    candidates.push(("python3".into(), vec![]));
    candidates.push(("py".into(), vec!["-3".into()]));
    for (exe, pre) in candidates {
        let ok = Command::new(&exe)
            .args(&pre)
            .args(["-c", "import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            return Ok((exe, pre));
        }
    }
    bail!("Python 3 was not found; pass --python or set PARANOIA_PYTHON")
}

pub fn run(binary: &Path, script: &Path, python: Option<&str>, cursor: u64) -> Result<i32> {
    let bytes = std::fs::read(binary).with_context(|| format!("reading {}", binary.display()))?;
    let name = binary.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut session = Session::open(&name, bytes).map_err(anyhow::Error::msg)?;

    let dir: PathBuf = std::env::temp_dir().join("paranoia-python");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("paranoia.py"), MODULE)?;
    let (exe, pre) = find_python(python)?;
    let mut path = dir.as_os_str().to_owned();
    if let Some(old) = std::env::var_os("PYTHONPATH") {
        path.push(if cfg!(windows) { ";" } else { ":" });
        path.push(old);
    }
    let mut child = Command::new(exe)
        .args(pre)
        .args(["-u", "-X", "utf8", "-c", BOOT])
        .arg(script)
        .env("PYTHONPATH", path)
        .env("PYTHONIOENCODING", "utf-8")
        .env("PN_CURSOR", cursor.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("starting Python")?;
    let mut stdin = child.stdin.take().context("python stdin")?;
    let stdout = BufReader::new(child.stdout.take().context("python stdout")?);
    for line in stdout.lines() {
        let line = line?;
        let Some(req) = line.strip_prefix('\u{1e}') else {
            println!("{line}");
            continue;
        };
        let msg: Value = serde_json::from_str(req).unwrap_or(Value::Null);
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let reply = match msg.get("op").and_then(Value::as_str) {
            Some("call") => {
                let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
                match session.call(method, msg.get("args").cloned().unwrap_or(Value::Null)) {
                    Ok(v) => json!({ "id": id, "ok": true, "value": v }),
                    Err(e) => json!({ "id": id, "ok": false, "error": e }),
                }
            }
            // No UI in batch mode: navigation and refresh are no-ops.
            Some("goto") | Some("refresh") => json!({ "id": id, "ok": true, "value": null }),
            _ => json!({ "id": id, "ok": false, "error": "unknown request" }),
        };
        writeln!(stdin, "{reply}")?;
        stdin.flush()?;
    }
    Ok(child.wait()?.code().unwrap_or(1))
}
