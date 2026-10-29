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
// -E ignores PYTHON* variables; the module directory is put on sys.path explicitly.
const BOOT: &str = "import sys; sys.path.insert(0, sys.argv[1]); import paranoia; paranoia._main(sys.argv[2])";

/// A new, private directory for one run (created by us, 0700 on Unix).
fn private_dir() -> Result<PathBuf> {
    let base = std::env::temp_dir();
    for attempt in 0..32u32 {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        let dir = base.join(format!("paranoia-py-{}-{nanos:x}-{attempt}", std::process::id()));
        if std::fs::create_dir(&dir).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            }
            return Ok(dir);
        }
    }
    bail!("could not create a private temporary directory")
}

fn find_python(explicit: Option<&str>, cwd: &Path) -> Result<(String, Vec<String>)> {
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
            .args(["-E", "-c", "import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)"])
            .current_dir(cwd)
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

    let dir = private_dir()?;
    let result = run_in(&dir, &mut session, script, python, cursor);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn run_in(dir: &Path, session: &mut Session, script: &Path, python: Option<&str>, cursor: u64) -> Result<i32> {
    std::fs::write(dir.join("paranoia.py"), MODULE)?;
    let script = std::fs::canonicalize(script).with_context(|| format!("reading {}", script.display()))?;
    let (exe, pre) = find_python(python, dir)?;
    let mut child = Command::new(exe)
        .args(pre)
        .args(["-E", "-u", "-X", "utf8", "-c", BOOT])
        .arg(dir)
        .arg(&script)
        .current_dir(dir)
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
