//! A client for the GDB remote serial protocol: debug a program or a firmware image that a *server*
//! runs, such as `gdbserver` (Linux, any CPU it supports) or QEMU's gdbstub (`-s -S`, bare-metal
//! firmware, Cortex-M, AArch64, …).
//!
//! The interface matches the local debuggers (`debugger.rs`, `debugger_linux.rs`): one worker thread owns
//! the connection, commands arrive over a channel, and the UI polls a shared snapshot. Addresses
//! exchanged with the UI are the *static* addresses of the analysed image; `delta` converts to the
//! target's (0 for firmware and non-PIE programs; the load base minus the image base for a PIE one).
//!
//! This is the first place the engine opens a socket. It happens only when the user asks (the desktop
//! app confirms the host and port in a native dialog first), and nothing is sent but protocol packets
//! to that one address. The code is safe Rust: no `unsafe`.
//!
//! Supported: the register layout from the server's `target.xml` (or a fixed layout for x86, x86-64,
//! AArch64 and ARM), memory reads, software breakpoints (`Z0`, falling back to `Z1`), continue, single
//! step, step over calls, interrupt, detach, and console output (`O` packets) into the log. Not
//! supported: memory or register writes from the UI, threads other than the one the server reports,
//! hardware watchpoints.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use paranoia_core::Arch;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct Snapshot {
    /// idle, running, paused, exited
    pub state: String,
    pub reason: String,
    pub pc: Option<u64>,
    pub pc_runtime: u64,
    pub base: u64,
    pub regs: Vec<(String, u64)>,
    pub stack: Vec<(u64, u64)>,
    pub breakpoints: Vec<u64>,
    pub log: Vec<String>,
    pub exit_code: Option<u32>,
}

/// What the UI asks of the connection.
enum Cmd {
    Continue,
    StepInto,
    StepOver,
    RunTo(u64),
    Pause,
    Stop,
    SetBp(u64),
    ClearBp(u64),
    Read(u64, usize, Sender<Result<Vec<u8>, String>>),
}

pub struct Remote {
    tx: Sender<Cmd>,
    shared: Arc<Mutex<Snapshot>>,
}

pub struct ConnectArgs {
    pub host: String,
    pub port: u16,
    pub arch: Arch,
    /// target address - static address
    pub delta: i64,
    pub image_base: u64,
    pub image_size: u64,
    pub entry: u64,
    pub breakpoints: Vec<u64>,
    pub break_on_entry: bool,
}

impl Remote {
    pub fn connect(args: ConnectArgs) -> Result<Remote, String> {
        let shared = Arc::new(Mutex::new(Snapshot { state: "running".into(), reason: "Connecting…".into(), ..Default::default() }));
        let (tx, rx) = channel();
        let (ready_tx, ready_rx) = channel::<Result<(), String>>();
        let sh = shared.clone();
        std::thread::Builder::new()
            .name("paranoia-gdb".into())
            .spawn(move || match Worker::connect(&args, sh) {
                Ok(mut w) => {
                    let _ = ready_tx.send(Ok(()));
                    w.run(rx);
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                }
            })
            .map_err(|e| e.to_string())?;
        ready_rx.recv_timeout(Duration::from_secs(30)).map_err(|_| "the server did not answer in time".to_string())??;
        Ok(Remote { tx, shared })
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut s = self.shared.lock().unwrap();
        let snap = s.clone();
        s.log.clear();
        snap
    }

    pub fn command(&self, name: &str, va: Option<u64>) -> Result<(), String> {
        let cmd = match name {
            "continue" => Cmd::Continue,
            "step_into" => Cmd::StepInto,
            "step_over" => Cmd::StepOver,
            "run_to" => Cmd::RunTo(va.ok_or("missing address")?),
            "pause" => Cmd::Pause,
            "stop" => Cmd::Stop,
            "set_bp" => Cmd::SetBp(va.ok_or("missing address")?),
            "clear_bp" => Cmd::ClearBp(va.ok_or("missing address")?),
            other => return Err(format!("unknown debugger command `{other}`")),
        };
        if matches!(cmd, Cmd::Continue | Cmd::StepInto | Cmd::StepOver | Cmd::RunTo(_)) {
            let mut sh = self.shared.lock().unwrap();
            if sh.state == "paused" {
                sh.state = "running".into();
                sh.reason = String::new();
            }
        }
        self.tx.send(cmd).map_err(|_| "the connection has ended".to_string())
    }

    pub fn read(&self, va: u64, len: usize) -> Result<Vec<u8>, String> {
        let (t, r) = channel();
        self.tx.send(Cmd::Read(va, len.min(1 << 20), t)).map_err(|_| "the connection has ended".to_string())?;
        r.recv_timeout(Duration::from_secs(10)).map_err(|_| "the server did not answer".to_string())?
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Stop);
    }
}

// ------------------------------------------------------------------------------------------------
// Packets
// ------------------------------------------------------------------------------------------------

fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |a, b| a.wrapping_add(*b))
}

/// Escapes `$ # } *` as the protocol requires.
fn escape(data: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for b in data.bytes() {
        if matches!(b, b'$' | b'#' | b'}' | b'*') {
            out.push(b'}');
            out.push(b ^ 0x20);
        } else {
            out.push(b);
        }
    }
    out
}

/// Undoes escaping and run-length encoding (`x*N` repeats `x` N-29 more times).
fn unescape(data: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'}' if i + 1 < data.len() => {
                out.push(data[i + 1] ^ 0x20);
                i += 2;
            }
            b'*' if i + 1 < data.len() && !out.is_empty() => {
                let n = (data[i + 1] as usize).saturating_sub(29).min(255);
                let last = *out.last().unwrap();
                out.extend(std::iter::repeat_n(last, n));
                i += 2;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fn hex_val(s: &str) -> Option<u64> {
    u64::from_str_radix(s, 16).ok()
}

fn from_hex(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() & 1 == 1 {
        return None;
    }
    s.chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok()).collect()
}

#[cfg(test)]
fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Conn {
    stream: TcpStream,
    buf: Vec<u8>,
    ack: bool,
}

impl Conn {
    fn send(&mut self, data: &str) -> Result<(), String> {
        let body = escape(data);
        let mut pkt = Vec::with_capacity(body.len() + 4);
        pkt.push(b'$');
        pkt.extend_from_slice(&body);
        pkt.extend_from_slice(format!("#{:02x}", checksum(&body)).as_bytes());
        for _ in 0..3 {
            self.stream.write_all(&pkt).map_err(|e| format!("write failed: {e}"))?;
            if !self.ack {
                return Ok(());
            }
            // Wait for the acknowledgement; a stop reply may already be arriving behind it.
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(p) =
                    self.buf.iter().position(|b| matches!(b, b'+' | b'-')).filter(|p| self.buf[..*p].iter().all(|b| *b != b'$'))
                {
                    let c = self.buf.remove(p);
                    if c == b'+' {
                        return Ok(());
                    }
                    break; // `-`: send again
                }
                if Instant::now() > deadline {
                    return Err("the server did not acknowledge a packet".into());
                }
                self.fill(Duration::from_millis(100))?;
            }
        }
        Err("the server kept rejecting a packet".into())
    }

    /// Reads whatever arrives within `wait` into the buffer. Errors when the server hangs up.
    fn fill(&mut self, wait: Duration) -> Result<(), String> {
        self.stream.set_read_timeout(Some(wait.max(Duration::from_millis(1)))).map_err(|e| e.to_string())?;
        let mut chunk = [0u8; 4096];
        match self.stream.read(&mut chunk) {
            Ok(0) => Err("the server closed the connection".into()),
            Ok(n) => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(())
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => Ok(()),
            Err(e) => Err(format!("read failed: {e}")),
        }
    }

    /// One complete packet from the buffer, if there is one (acknowledged and unescaped).
    fn take_packet(&mut self) -> Result<Option<Vec<u8>>, String> {
        loop {
            let Some(start) = self.buf.iter().position(|b| *b == b'$') else {
                // Only acknowledgements and noise so far.
                self.buf.retain(|b| *b != b'+' && *b != b'-');
                return Ok(None);
            };
            self.buf.drain(..start);
            let Some(hash) = self.buf.iter().position(|b| *b == b'#') else { return Ok(None) };
            if self.buf.len() < hash + 3 {
                return Ok(None);
            }
            let body: Vec<u8> = self.buf[1..hash].to_vec();
            let want = std::str::from_utf8(&self.buf[hash + 1..hash + 3]).ok().and_then(hex_val);
            self.buf.drain(..hash + 3);
            if want == Some(checksum(&body) as u64) {
                if self.ack {
                    self.stream.write_all(b"+").map_err(|e| e.to_string())?;
                }
                return Ok(Some(unescape(&body)));
            }
            if self.ack {
                self.stream.write_all(b"-").map_err(|e| e.to_string())?;
            }
        }
    }

    /// The next packet, waiting up to `wait` for it.
    fn recv(&mut self, wait: Duration) -> Result<Option<Vec<u8>>, String> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(p) = self.take_packet()? {
                return Ok(Some(p));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            self.fill(left.min(Duration::from_millis(100)))?;
        }
    }
}

// ------------------------------------------------------------------------------------------------
// Registers
// ------------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct RegDesc {
    name: String,
    bytes: usize,
}

/// The registers in the order of the `g` packet.
#[derive(Clone, Debug, Default)]
struct Layout {
    regs: Vec<RegDesc>,
}

impl Layout {
    fn index(&self, names: &[&str]) -> Option<usize> {
        names.iter().find_map(|n| self.regs.iter().position(|r| r.name == *n))
    }

    /// Splits a `g` reply into named values (registers wider than 8 bytes are skipped).
    fn parse(&self, reply: &[u8]) -> Vec<(String, u64)> {
        let Some(raw) = from_hex(reply) else { return Vec::new() };
        let (mut at, mut out) = (0usize, Vec::new());
        for r in &self.regs {
            let Some(b) = raw.get(at..at + r.bytes) else { break };
            at += r.bytes;
            if r.bytes <= 8 {
                out.push((r.name.clone(), b.iter().rev().fold(0u64, |a, x| a << 8 | *x as u64)));
            }
        }
        out
    }
}

fn fixed_layout(arch: Arch) -> Layout {
    let r = |names: &[&str], bytes: usize| names.iter().map(|n| RegDesc { name: (*n).to_string(), bytes }).collect::<Vec<_>>();
    let mut regs = Vec::new();
    match arch {
        Arch::X86_64 => {
            regs.extend(r(
                &["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"],
                8,
            ));
            regs.extend(r(&["eflags", "cs", "ss", "ds", "es", "fs", "gs"], 4));
        }
        Arch::X86 => regs
            .extend(r(&["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"], 4)),
        Arch::Arm64 => {
            let x: Vec<String> = (0..31).map(|i| format!("x{i}")).collect();
            regs.extend(r(&x.iter().map(String::as_str).collect::<Vec<_>>(), 8));
            regs.extend(r(&["sp", "pc"], 8));
            regs.extend(r(&["cpsr"], 4));
        }
        Arch::Arm | Arch::Thumb => {
            regs.extend(r(&["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"], 4));
            regs.extend(r(&["f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7"], 12));
            regs.extend(r(&["fps", "cpsr"], 4));
        }
        _ => {}
    }
    Layout { regs }
}

/// The `<reg>` elements of a target description, in order (`<xi:include>` already spliced in).
fn layout_from_xml(xml: &str) -> Layout {
    let mut regs: Vec<(Option<u32>, RegDesc)> = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<reg ") {
        rest = &rest[i + 5..];
        let end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..end];
        let attr = |k: &str| {
            let p = tag.find(&format!("{k}=\""))?;
            let v = &tag[p + k.len() + 2..];
            Some(&v[..v.find('"')?])
        };
        if let (Some(name), Some(bits)) = (attr("name"), attr("bitsize").and_then(|b| b.parse::<usize>().ok())) {
            regs.push((attr("regnum").and_then(|n| n.parse().ok()), RegDesc { name: name.to_string(), bytes: bits.div_ceil(8) }));
        }
    }
    // Explicit register numbers order the packet; otherwise it is document order.
    if regs.iter().all(|(n, _)| n.is_some()) {
        regs.sort_by_key(|(n, _)| *n);
    }
    Layout { regs: regs.into_iter().map(|(_, r)| r).collect() }
}

// ------------------------------------------------------------------------------------------------
// The worker
// ------------------------------------------------------------------------------------------------

/// What a stop reply says.
#[derive(Debug, PartialEq, Eq)]
enum Stop {
    Signal(u8),
    Exited(u32),
    Killed(u8),
}

fn parse_stop(p: &[u8]) -> Option<Stop> {
    let s = std::str::from_utf8(p).ok()?;
    let byte = |t: &str| u8::from_str_radix(t.get(..2)?, 16).ok();
    match s.chars().next()? {
        'T' | 'S' => Some(Stop::Signal(byte(&s[1..])?)),
        'W' => Some(Stop::Exited(byte(&s[1..])? as u32)),
        'X' => Some(Stop::Killed(byte(&s[1..])?)),
        _ => None,
    }
}

struct Worker {
    conn: Conn,
    shared: Arc<Mutex<Snapshot>>,
    arch: Arch,
    delta: i64,
    layout: Layout,
    entry: u64,
    image_size: u64,
    image_base: u64,
    /// Static addresses of the user's breakpoints, and whether the server accepted each.
    user_bps: BTreeMap<u64, bool>,
    temp_bps: BTreeMap<u64, bool>,
    running: bool,
    /// What the last command was, for naming the stop.
    stepping: bool,
    /// A signal other than SIGTRAP the program stopped with: delivered when it continues.
    pending_signal: Option<u8>,
    packet_size: usize,
}

fn log_to(shared: &Arc<Mutex<Snapshot>>, s: String) {
    let mut sh = shared.lock().unwrap();
    if sh.log.len() < 2000 {
        sh.log.push(s);
    }
}

fn signal_name(sig: u8) -> String {
    let name = match sig {
        2 => "interrupted (SIGINT)",
        4 => "illegal instruction (SIGILL)",
        6 => "abort (SIGABRT)",
        7 => "bus error (SIGBUS)",
        8 => "arithmetic error (SIGFPE)",
        11 => "segmentation fault (SIGSEGV)",
        _ => "signal",
    };
    format!("{name} {sig}")
}

impl Worker {
    fn connect(a: &ConnectArgs, shared: Arc<Mutex<Snapshot>>) -> Result<Worker, String> {
        let addrs: Vec<_> = (a.host.as_str(), a.port).to_socket_addrs().map_err(|e| format!("cannot resolve {}: {e}", a.host))?.collect();
        let mut last = String::from("no address");
        let mut stream = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last = e.to_string(),
            }
        }
        let stream = stream.ok_or_else(|| format!("cannot connect to {}:{}: {last}", a.host, a.port))?;
        let _ = stream.set_nodelay(true);
        let mut w = Worker {
            conn: Conn { stream, buf: Vec::new(), ack: true },
            shared,
            arch: a.arch,
            delta: a.delta,
            layout: fixed_layout(a.arch),
            entry: a.entry,
            image_size: a.image_size.max(0x1000),
            image_base: a.image_base,
            user_bps: a.breakpoints.iter().map(|b| (*b, false)).collect(),
            temp_bps: BTreeMap::new(),
            running: false,
            stepping: false,
            pending_signal: None,
            packet_size: 1024,
        };
        w.shared.lock().unwrap().base = (a.image_base as i64).wrapping_add(a.delta) as u64;
        w.handshake()?;
        for b in w.user_bps.keys().copied().collect::<Vec<_>>() {
            let ok = w.insert_bp(b);
            w.user_bps.insert(b, ok);
        }
        // Where is the target? Stopped, normally (gdbserver at the program's start, QEMU with -S).
        let stop = w.request("?")?;
        let first = parse_stop(&stop);
        w.log(format!("Connected to {}:{}", a.host, a.port));
        if let Some(Stop::Exited(c)) = first {
            w.finish(c);
            return Ok(w);
        }
        w.paused("Connected".into());
        // Like the local debuggers, run to the entry point unless the target is already there.
        let pc = w.shared.lock().unwrap().pc;
        if a.break_on_entry && a.entry != 0 && pc != Some(a.entry) && w.insert_bp(a.entry) {
            w.temp_bps.insert(a.entry, true);
            w.resume(false);
        }
        Ok(w)
    }

    fn log(&self, s: impl Into<String>) {
        log_to(&self.shared, s.into());
    }

    fn rt(&self, va: u64) -> u64 {
        (va as i64).wrapping_add(self.delta) as u64
    }

    fn to_static(&self, rt: u64) -> u64 {
        (rt as i64).wrapping_sub(self.delta) as u64
    }

    /// Sends a packet and returns the reply, skipping console output (`O`) on the way.
    fn request(&mut self, req: &str) -> Result<Vec<u8>, String> {
        self.conn.send(req)?;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.conn.recv(left)? {
                Some(p) if p.first() == Some(&b'O') && p.len() > 1 && !p.starts_with(b"OK") => self.console(&p[1..]),
                Some(p) => return Ok(p),
                None => return Err(format!("the server did not answer `{}`", req.split([':', ',', ';']).next().unwrap_or(req))),
            }
        }
    }

    fn console(&self, hex: &[u8]) {
        if let Some(b) = from_hex(hex) {
            for line in String::from_utf8_lossy(&b).lines() {
                self.log(format!("target: {line}"));
            }
        }
    }

    fn handshake(&mut self) -> Result<(), String> {
        let sup = self.request("qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386")?;
        let sup = String::from_utf8_lossy(&sup).into_owned();
        if let Some(n) = sup.split(';').find_map(|f| f.strip_prefix("PacketSize=")).and_then(hex_val) {
            self.packet_size = (n as usize).clamp(64, 1 << 16);
        }
        if sup.contains("QStartNoAckMode+") {
            let r = self.request("QStartNoAckMode")?;
            if r == b"OK" {
                self.conn.ack = false;
            }
        }
        if sup.contains("qXfer:features:read+") {
            match self.read_xml("target.xml", 0) {
                Ok(l) if !l.regs.is_empty() => self.layout = l,
                Ok(_) => self.log("the target description lists no registers; using the standard layout"),
                Err(e) => self.log(format!("no target description ({e}); using the standard layout")),
            }
        }
        if self.layout.regs.is_empty() {
            return Err(format!("the server gave no register layout and {} has no standard one", self.arch.label()));
        }
        Ok(())
    }

    /// Fetches `target.xml` and the files it includes, in document order.
    fn read_xml(&mut self, name: &str, depth: usize) -> Result<Layout, String> {
        let xml = self.xfer(name)?;
        if depth >= 4 {
            return Ok(layout_from_xml(&xml));
        }
        // Splice includes in place so register order stays the document's.
        let mut full = String::new();
        let mut rest = xml.as_str();
        while let Some(i) = rest.find("<xi:include") {
            full.push_str(&rest[..i]);
            let tag_end = rest[i..].find('>').map_or(rest.len(), |e| i + e + 1);
            let tag = &rest[i..tag_end];
            if let Some(h) = tag.find("href=\"").map(|p| &tag[p + 6..]).and_then(|v| v.split('"').next()) {
                match self.xfer(h) {
                    Ok(inc) => full.push_str(&inc),
                    Err(e) => self.log(format!("could not read {h}: {e}")),
                }
            }
            rest = &rest[tag_end..];
        }
        full.push_str(rest);
        Ok(layout_from_xml(&full))
    }

    fn xfer(&mut self, name: &str) -> Result<String, String> {
        let mut out = Vec::new();
        let chunk = (self.packet_size.saturating_sub(16)).clamp(64, 4000);
        loop {
            let r = self.request(&format!("qXfer:features:read:{name}:{:x},{:x}", out.len(), chunk))?;
            match r.first() {
                Some(b'm') => out.extend_from_slice(&r[1..]),
                Some(b'l') => {
                    out.extend_from_slice(&r[1..]);
                    break;
                }
                _ => return Err(format!("the server refused {name}")),
            }
            if out.len() > 4 << 20 {
                return Err("the target description is too large".into());
            }
        }
        String::from_utf8(out).map_err(|_| "the target description is not text".into())
    }

    /// Plants a software breakpoint (`Z0`, or a hardware one with `Z1` when the server has no software kind).
    fn insert_bp(&mut self, va: u64) -> bool {
        let rt = self.rt(va);
        let kind = match self.arch {
            Arch::X86 | Arch::X86_64 => 1,
            Arch::Thumb => 2,
            _ => 4,
        };
        for t in ["Z0", "Z1"] {
            if self.request(&format!("{t},{rt:x},{kind}")).is_ok_and(|r| r == b"OK") {
                return true;
            }
        }
        self.log(format!("the server would not set a breakpoint at {va:#x}"));
        false
    }

    fn remove_bp(&mut self, va: u64) {
        let rt = self.rt(va);
        let kind = match self.arch {
            Arch::X86 | Arch::X86_64 => 1,
            Arch::Thumb => 2,
            _ => 4,
        };
        for t in ["z0", "z1"] {
            if self.request(&format!("{t},{rt:x},{kind}")).is_ok_and(|r| r == b"OK") {
                return;
            }
        }
    }

    fn read_regs(&mut self) -> Vec<(String, u64)> {
        match self.request("g") {
            Ok(r) if !r.starts_with(b"E") => self.layout.parse(&r),
            _ => Vec::new(),
        }
    }

    fn read_mem(&mut self, rt: u64, len: usize) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(len);
        let step = (self.packet_size / 2).saturating_sub(16).clamp(16, 2048);
        while out.len() < len {
            let n = step.min(len - out.len());
            let r = self.request(&format!("m{:x},{:x}", rt + out.len() as u64, n))?;
            if r.first() == Some(&b'E') || r.is_empty() {
                return Err(format!("cannot read {:#x}", rt + out.len() as u64));
            }
            let b = from_hex(&r).ok_or("the server answered a memory read with something that is not hex")?;
            if b.is_empty() {
                return Err(format!("cannot read {:#x}", rt + out.len() as u64));
            }
            out.extend_from_slice(&b);
        }
        out.truncate(len);
        Ok(out)
    }

    fn pc_and_sp(&self, regs: &[(String, u64)]) -> (Option<u64>, Option<u64>) {
        let get = |names: &[&str]| {
            self.layout.index(names).and_then(|i| regs.iter().find(|(n, _)| *n == self.layout.regs[i].name)).map(|(_, v)| *v)
        };
        (get(&["pc", "rip", "eip"]), get(&["sp", "rsp", "esp"]))
    }

    /// Records a stop: registers, stack and the reason.
    fn paused(&mut self, reason: String) {
        self.running = false;
        let regs = self.read_regs();
        let (pc, sp) = self.pc_and_sp(&regs);
        let word = if matches!(self.arch, Arch::X86_64 | Arch::Arm64) { 8 } else { 4 };
        let mut stack = Vec::new();
        if let Some(sp) = sp {
            if let Ok(mem) = self.read_mem(sp, 16 * word) {
                for (i, ch) in mem.chunks_exact(word).enumerate() {
                    stack.push((sp + (i * word) as u64, ch.iter().rev().fold(0u64, |a, x| a << 8 | *x as u64)));
                }
            }
        }
        let rt = pc.unwrap_or(0);
        let static_pc = self.to_static(rt);
        let in_image = static_pc >= self.image_base && static_pc < self.image_base + self.image_size;
        let mut sh = self.shared.lock().unwrap();
        sh.state = "paused".into();
        sh.reason = reason;
        sh.pc_runtime = rt;
        sh.pc = (pc.is_some() && in_image).then_some(static_pc);
        sh.regs = regs;
        sh.stack = stack;
        sh.breakpoints = self.user_bps.keys().copied().collect();
    }

    fn finish(&mut self, code: u32) {
        self.running = false;
        let mut sh = self.shared.lock().unwrap();
        sh.state = "exited".into();
        sh.pc = None;
        sh.reason = format!("The target exited with code {code}");
        sh.exit_code = Some(code);
    }

    /// Continues or steps. The stop reply is collected by `run`, which keeps listening for commands.
    fn resume(&mut self, step: bool) {
        {
            let mut sh = self.shared.lock().unwrap();
            sh.state = "running".into();
            sh.reason = String::new();
        }
        self.stepping = step;
        let cmd = match (step, self.pending_signal.take()) {
            (true, Some(s)) => format!("S{s:02x}"),
            (true, None) => "s".to_string(),
            (false, Some(s)) => format!("C{s:02x}"),
            (false, None) => "c".to_string(),
        };
        match self.conn.send(&cmd) {
            Ok(()) => self.running = true,
            Err(e) => self.fail(&e),
        }
    }

    fn fail(&mut self, e: &str) {
        self.running = false;
        let mut sh = self.shared.lock().unwrap();
        sh.state = "exited".into();
        sh.pc = None;
        sh.reason = format!("Connection lost: {e}");
    }

    /// A stop reply arrived while running.
    fn on_stop(&mut self, p: &[u8]) {
        match parse_stop(p) {
            Some(Stop::Exited(c)) => self.finish(c),
            Some(Stop::Killed(s)) => {
                self.running = false;
                let mut sh = self.shared.lock().unwrap();
                sh.state = "exited".into();
                sh.pc = None;
                sh.reason = format!("The target was killed by signal {s}");
                sh.exit_code = Some(128 + s as u32);
            }
            Some(Stop::Signal(sig)) => {
                // A temporary breakpoint (run to cursor, step over, entry) is removed once reached.
                let hit_temp: Vec<u64> = self.temp_bps.keys().copied().collect();
                let regs = self.read_regs();
                let (pc, _) = self.pc_and_sp(&regs);
                let at = pc.map(|p| self.to_static(p));
                let was_temp = at.filter(|a| hit_temp.contains(a));
                for t in hit_temp {
                    self.temp_bps.remove(&t);
                    if Some(t) != at || !self.user_bps.contains_key(&t) {
                        self.remove_bp(t);
                    }
                }
                let reason = if sig != 5 {
                    self.pending_signal = Some(sig);
                    signal_name(sig)
                } else if at.is_some_and(|a| self.user_bps.contains_key(&a)) && !self.stepping {
                    "Breakpoint".to_string()
                } else if was_temp == Some(self.entry) && self.entry != 0 {
                    "Entry point".to_string()
                } else if was_temp.is_some() {
                    "Reached".to_string()
                } else if self.stepping {
                    "Step".to_string()
                } else {
                    "Paused".to_string()
                };
                self.paused(reason);
            }
            None => self.log(format!("unexpected reply while running: {}", String::from_utf8_lossy(p))),
        }
    }

    fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Read(va, len, reply) => {
                let r = if self.running { Err("pause the program to read its memory".into()) } else { self.read_mem(self.rt(va), len) };
                let _ = reply.send(r);
            }
            Cmd::SetBp(va) => {
                if !self.running {
                    let ok = self.insert_bp(va);
                    self.user_bps.insert(va, ok);
                } else {
                    self.user_bps.insert(va, false);
                    self.log("pause the program to set a breakpoint; it will be set on the next stop");
                }
                self.shared.lock().unwrap().breakpoints = self.user_bps.keys().copied().collect();
            }
            Cmd::ClearBp(va) => {
                if self.user_bps.remove(&va) == Some(true) && !self.running {
                    self.remove_bp(va);
                }
                self.shared.lock().unwrap().breakpoints = self.user_bps.keys().copied().collect();
            }
            Cmd::Pause => {
                if self.running {
                    if let Err(e) = self.conn.stream.write_all(&[0x03]) {
                        self.fail(&e.to_string());
                    }
                }
            }
            Cmd::Stop => {
                if !self.running {
                    let _ = self.request("D");
                } else {
                    let _ = self.conn.stream.write_all(&[0x03]);
                }
                let mut sh = self.shared.lock().unwrap();
                sh.state = "exited".into();
                sh.pc = None;
                sh.reason = "Disconnected".into();
                drop(sh);
                self.running = false;
            }
            Cmd::Continue => {
                if !self.running {
                    self.sync_user_bps();
                    self.resume(false);
                }
            }
            Cmd::StepInto => {
                if !self.running {
                    self.sync_user_bps();
                    self.resume(true);
                }
            }
            Cmd::RunTo(va) => {
                if !self.running {
                    self.sync_user_bps();
                    if self.insert_bp(va) {
                        self.temp_bps.insert(va, true);
                    }
                    self.resume(false);
                }
            }
            Cmd::StepOver => {
                if self.running {
                    return;
                }
                self.sync_user_bps();
                let regs = self.read_regs();
                let (pc, _) = self.pc_and_sp(&regs);
                let next = pc.and_then(|pc| {
                    let bytes = self.read_mem(pc, 16).ok()?;
                    call_return(self.arch, pc, &bytes)
                });
                match next {
                    Some(n) => {
                        let sva = self.to_static(n);
                        if self.insert_bp(sva) {
                            self.temp_bps.insert(sva, true);
                        }
                        self.resume(false);
                    }
                    None => self.resume(true),
                }
            }
        }
    }

    /// Breakpoints set while the program ran could not be sent then; send them now.
    fn sync_user_bps(&mut self) {
        let pending: Vec<u64> = self.user_bps.iter().filter(|(_, ok)| !**ok).map(|(k, _)| *k).collect();
        for b in pending {
            let ok = self.insert_bp(b);
            self.user_bps.insert(b, ok);
        }
    }

    fn run(&mut self, rx: Receiver<Cmd>) {
        loop {
            let ended = self.shared.lock().unwrap().state == "exited";
            if ended {
                return;
            }
            if self.running {
                while let Ok(c) = rx.try_recv() {
                    self.handle_cmd(c);
                }
                match self.conn.recv(Duration::from_millis(50)) {
                    Ok(Some(p)) if p.first() == Some(&b'O') && p.len() > 1 && !p.starts_with(b"OK") => self.console(&p[1..]),
                    Ok(Some(p)) => self.on_stop(&p),
                    Ok(None) => {}
                    Err(e) => self.fail(&e),
                }
            } else {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(c) => self.handle_cmd(c),
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        let _ = self.request("D");
                        return;
                    }
                }
            }
        }
    }
}

/// The address after the call at `pc`, from the instruction bytes, if it is a call.
fn call_return(arch: Arch, pc: u64, b: &[u8]) -> Option<u64> {
    match arch {
        Arch::X86 | Arch::X86_64 => {
            let mut d = iced_x86::Decoder::with_ip(if arch == Arch::X86 { 32 } else { 64 }, b, pc, iced_x86::DecoderOptions::NONE);
            let i = d.decode();
            matches!(i.flow_control(), iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall).then(|| pc + i.len() as u64)
        }
        Arch::Arm64 => {
            let w = u32::from_le_bytes(b.get(..4)?.try_into().ok()?);
            (w & 0xfc00_0000 == 0x9400_0000 || w & 0xffff_fc1f == 0xd63f_0000 || w & 0xfeff_f800 == 0xd63f_0800).then_some(pc + 4)
        }
        Arch::Thumb => {
            let h1 = u16::from_le_bytes(b.get(..2)?.try_into().ok()?);
            let h2 = u16::from_le_bytes(b.get(2..4)?.try_into().ok()?);
            if h1 & 0xf800 == 0xf000 && h2 & 0xd000 == 0xd000 {
                Some(pc + 4) // bl
            } else if h1 & 0xff87 == 0x4780 {
                Some(pc + 2) // blx rN
            } else {
                None
            }
        }
        Arch::Arm => {
            let w = u32::from_le_bytes(b.get(..4)?.try_into().ok()?);
            (w & 0x0f00_0000 == 0x0b00_0000 || w & 0x0fff_fff0 == 0x012f_ff30).then_some(pc + 4)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A fake gdbstub for a made-up CPU with registers r0, r1 and pc (4 bytes each), a few bytes of memory,
    /// and a program that hits a breakpoint, steps, and exits. Records the packets it received.
    fn serve(listener: TcpListener, log: Arc<Mutex<Vec<String>>>) {
        let (stream, _) = listener.accept().unwrap();
        let mut c = Conn { stream, buf: Vec::new(), ack: true };
        let mut pc = 0x1000u32;
        let mut bps: Vec<u64> = Vec::new();
        let regs = |pc: u32| to_hex(&[1u32.to_le_bytes(), 2u32.to_le_bytes(), pc.to_le_bytes()].concat());
        loop {
            let Ok(Some(p)) = c.recv(Duration::from_secs(10)) else { return };
            let req = String::from_utf8_lossy(&p).into_owned();
            log.lock().unwrap().push(req.clone());
            let reply: Option<String> = match req.as_str() {
                r if r.starts_with("qSupported") => Some("PacketSize=1000;qXfer:features:read+;swbreak+".into()),
                r if r.starts_with("qXfer:features:read:target.xml:0,") => Some(r#"l<target><xi:include href="core.xml"/></target>"#.to_string()),
                r if r.starts_with("qXfer:features:read:core.xml:0,") => Some(
                    r#"l<feature name="core"><reg name="r0" bitsize="32"/><reg name="r1" bitsize="32"/><reg name="pc" bitsize="32" type="code_ptr"/></feature>"#.to_string(),
                ),
                "?" => Some("T05thread:1;".into()),
                "g" => Some(regs(pc)),
                r if r.starts_with('m') => {
                    let (a, n) = r[1..].split_once(',').unwrap();
                    let (a, n) = (hex_val(a).unwrap(), hex_val(n).unwrap() as usize);
                    if (0x1000..0x2000).contains(&a) {
                        Some(to_hex(&(0..n).map(|i| (a as usize + i) as u8).collect::<Vec<_>>()))
                    } else {
                        Some("E01".into())
                    }
                }
                r if r.starts_with("Z0,") || r.starts_with("Z1,") => {
                    bps.push(hex_val(r[3..].split(',').next().unwrap()).unwrap());
                    Some("OK".into())
                }
                r if r.starts_with("z0,") || r.starts_with("z1,") => {
                    let a = hex_val(r[3..].split(',').next().unwrap()).unwrap();
                    bps.retain(|b| *b != a);
                    Some("OK".into())
                }
                "c" => {
                    // Run to the next breakpoint above pc; with none, exit.
                    match bps.iter().copied().filter(|b| *b > pc as u64).min() {
                        Some(b) => {
                            pc = b as u32;
                            Some("T05thread:1;swbreak:;".into())
                        }
                        None => Some("W00".into()),
                    }
                }
                "s" => {
                    pc += 2;
                    Some("T05thread:1;".into())
                }
                "D" => {
                    c.send("OK").unwrap();
                    return;
                }
                _ => Some(String::new()),
            };
            if let Some(r) = reply {
                c.send(&r).unwrap();
            }
        }
    }

    fn wait_for(r: &Remote, want: &[&str]) -> Snapshot {
        for _ in 0..300 {
            let s = r.snapshot();
            if want.contains(&s.state.as_str()) {
                return s;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("never reached {want:?}");
    }

    #[test]
    fn framing_escapes_and_run_length() {
        assert_eq!(escape("a$b#c}d*"), b"a}\x04b}\x03c}]d}\x0a");
        assert_eq!(unescape(&escape("a$b#c}d*")), b"a$b#c}d*");
        // `0* ` = '0' plus (0x20 - 29) = 3 more.
        assert_eq!(unescape(b"0* x"), b"0000x");
        assert_eq!(checksum(b"OK"), 0x9a);
        assert_eq!(parse_stop(b"T05thread:1;"), Some(Stop::Signal(5)));
        assert_eq!(parse_stop(b"S0b"), Some(Stop::Signal(11)));
        assert_eq!(parse_stop(b"W2a"), Some(Stop::Exited(42)));
        assert_eq!(parse_stop(b"X09"), Some(Stop::Killed(9)));
        assert_eq!(parse_stop(b"OK"), None);
    }

    #[test]
    fn registers_come_from_the_target_description_or_a_standard_layout() {
        let xml = r#"<target><feature name="a"><reg name="r0" bitsize="32" regnum="0"/><reg name="r1" bitsize="32" regnum="1"/></feature>
                     <feature name="b"><reg name="d0" bitsize="64"/><reg name="pc" bitsize="32" regnum="15"/></feature></target>"#;
        let l = layout_from_xml(xml);
        assert_eq!(
            l.regs.iter().map(|r| (r.name.as_str(), r.bytes)).collect::<Vec<_>>(),
            vec![("r0", 4), ("r1", 4), ("d0", 8), ("pc", 4)].into_iter().collect::<Vec<_>>()
        );
        let regs = l.parse(
            to_hex(
                &[7u32.to_le_bytes().to_vec(), 8u32.to_le_bytes().to_vec(), 9u64.to_le_bytes().to_vec(), 0x1234u32.to_le_bytes().to_vec()]
                    .concat(),
            )
            .as_bytes(),
        );
        assert_eq!(regs, vec![("r0".into(), 7), ("r1".into(), 8), ("d0".into(), 9), ("pc".into(), 0x1234)]);
        assert_eq!(fixed_layout(Arch::X86_64).regs.len(), 24);
        assert_eq!(fixed_layout(Arch::Arm64).regs.iter().map(|r| r.bytes).sum::<usize>(), 31 * 8 + 16 + 4);
        assert!(fixed_layout(Arch::Mips).regs.is_empty());
    }

    #[test]
    fn calls_are_recognised_per_cpu() {
        assert_eq!(call_return(Arch::X86_64, 0x1000, &[0xe8, 0, 0, 0, 0]), Some(0x1005));
        assert_eq!(call_return(Arch::X86_64, 0x1000, &[0xc3]), None);
        assert_eq!(call_return(Arch::Arm64, 0x1000, &0x9400_0010u32.to_le_bytes()), Some(0x1004));
        assert_eq!(call_return(Arch::Arm64, 0x1000, &0xd65f_03c0u32.to_le_bytes()), None);
        assert_eq!(call_return(Arch::Thumb, 0x1000, &[0x00, 0xf0, 0x00, 0xf8]), Some(0x1004));
        assert_eq!(call_return(Arch::Thumb, 0x1000, &[0x80, 0x47, 0, 0]), Some(0x1002));
        assert_eq!(call_return(Arch::Thumb, 0x1000, &[0x70, 0x47, 0, 0]), None);
        assert_eq!(call_return(Arch::Arm, 0x1000, &0xeb00_0010u32.to_le_bytes()), Some(0x1004));
    }

    #[test]
    fn debugging_a_fake_gdbstub() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        let server = std::thread::spawn(move || serve(listener, s2));
        // The target runs at 0x1000 + delta 0x100: the UI sees static addresses.
        let r = Remote::connect(ConnectArgs {
            host: "127.0.0.1".into(),
            port,
            arch: Arch::Arm,
            delta: 0x100,
            image_base: 0x0f00,
            image_size: 0x1000,
            entry: 0,
            breakpoints: vec![0x1010 - 0x100],
            break_on_entry: false,
        })
        .unwrap();
        let s = wait_for(&r, &["paused", "exited"]);
        assert_eq!((s.state.as_str(), s.reason.as_str()), ("paused", "Connected"), "{s:?}");
        assert_eq!(s.pc_runtime, 0x1000);
        assert_eq!(s.pc, Some(0x0f00), "static = runtime - delta");
        // The register names came from target.xml (with its <xi:include> spliced in).
        assert_eq!(s.regs.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), vec!["r0", "r1", "pc"]);
        assert_eq!(s.regs[1].1, 2);
        assert!(s.breakpoints.contains(&0x0f10));
        // Memory is read at the target's address; an unreadable one is an error, not zeros.
        assert_eq!(r.read(0x0f00, 4).unwrap(), vec![0x00, 0x01, 0x02, 0x03]);
        assert!(r.read(0x9000, 4).unwrap_err().contains("cannot read"));
        // Step: the server moves pc by 2.
        r.command("step_into", None).unwrap();
        let s = wait_for(&r, &["paused", "exited"]);
        assert_eq!((s.reason.as_str(), s.pc_runtime), ("Step", 0x1002));
        // Continue runs to the breakpoint set at connect.
        r.command("continue", None).unwrap();
        let s = wait_for(&r, &["paused", "exited"]);
        assert_eq!((s.reason.as_str(), s.pc_runtime, s.pc), ("Breakpoint", 0x1010, Some(0x0f10)), "{s:?}");
        // Clear it, continue again: the program exits.
        r.command("clear_bp", Some(0x0f10)).unwrap();
        r.command("continue", None).unwrap();
        let s = wait_for(&r, &["exited"]);
        assert_eq!(s.exit_code, Some(0), "{s:?}");
        drop(r);
        server.join().unwrap();
        let packets = seen.lock().unwrap().clone();
        assert!(packets.iter().any(|p| p.starts_with("Z0,1010,4")), "{packets:?}");
        assert!(packets.iter().any(|p| p == "s") && packets.iter().any(|p| p == "c"));
    }

    #[test]
    fn a_refused_connection_says_so() {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let e = Remote::connect(ConnectArgs {
            host: "127.0.0.1".into(),
            port,
            arch: Arch::X86_64,
            delta: 0,
            image_base: 0,
            image_size: 0,
            entry: 0,
            breakpoints: vec![],
            break_on_entry: false,
        })
        .err()
        .unwrap();
        assert!(e.contains("cannot connect"), "{e}");
    }
}
