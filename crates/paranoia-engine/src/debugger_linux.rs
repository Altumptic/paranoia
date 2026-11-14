//! A small Linux user-mode debugger for x86-64 and ARM64 ELF programs, on `ptrace`.
//!
//! Same interface as the Windows debugger (`debugger.rs`): one worker thread owns the debuggee
//! (ptrace requests must come from the tracer thread), commands arrive over a channel, and the UI
//! polls a shared snapshot. Addresses exchanged with the UI are *static* virtual addresses of the
//! analysed image; position-independent executables are translated with the runtime base read
//! from `/proc/<pid>/maps`.
//!
//! The program's stdout / stderr are captured into the debugger log, never mixed with the engine's
//! own stdout (which carries the JSON protocol).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

/// What differs between CPUs: the register file, the breakpoint instruction, and how to tell a call
/// (for "step over"). Everything else in this file is the same on x86-64 and AArch64.
#[cfg(target_arch = "x86_64")]
mod arch {
    pub const NAME: &str = "x86-64";
    /// Program counter register name in the register list.
    #[cfg(test)]
    pub const PC_NAME: &str = "rip";
    /// The breakpoint instruction (`int3`), little-endian, and its length.
    pub const BREAK: [u8; 4] = [0xcc, 0, 0, 0];
    pub const BREAK_LEN: usize = 1;
    /// How far past the breakpoint the program counter is when the trap arrives.
    pub const PC_AFTER_BREAK: u64 = 1;

    #[derive(Clone, Copy)]
    pub struct Regs(libc::user_regs_struct);

    impl Regs {
        pub fn get(pid: libc::pid_t) -> Option<Regs> {
            // SAFETY: user_regs_struct is plain data; zero is a valid value.
            let mut r: libc::user_regs_struct = unsafe { std::mem::zeroed() };
            // SAFETY: `r` is a valid user_regs_struct for the kernel to fill in.
            let ok = unsafe {
                libc::ptrace(libc::PTRACE_GETREGS, pid, std::ptr::null_mut::<libc::c_void>(), &mut r as *mut _ as *mut libc::c_void)
            };
            (ok == 0).then_some(Regs(r))
        }
        pub fn set(&self, pid: libc::pid_t) -> bool {
            // SAFETY: the pointer is to a valid user_regs_struct that the kernel only reads.
            unsafe {
                libc::ptrace(libc::PTRACE_SETREGS, pid, std::ptr::null_mut::<libc::c_void>(), &self.0 as *const _ as *mut libc::c_void) == 0
            }
        }
        pub fn pc(&self) -> u64 {
            self.0.rip
        }
        pub fn set_pc(&mut self, pc: u64) {
            self.0.rip = pc;
        }
        pub fn sp(&self) -> u64 {
            self.0.rsp
        }
        pub fn list(&self) -> Vec<(String, u64)> {
            let r = &self.0;
            [
                ("rax", r.rax),
                ("rbx", r.rbx),
                ("rcx", r.rcx),
                ("rdx", r.rdx),
                ("rsi", r.rsi),
                ("rdi", r.rdi),
                ("rbp", r.rbp),
                ("rsp", r.rsp),
                ("r8", r.r8),
                ("r9", r.r9),
                ("r10", r.r10),
                ("r11", r.r11),
                ("r12", r.r12),
                ("r13", r.r13),
                ("r14", r.r14),
                ("r15", r.r15),
                ("rip", r.rip),
                ("rflags", r.eflags),
            ]
            .into_iter()
            .map(|(n, v)| (n.to_string(), v))
            .collect()
        }
    }

    /// The address after the call at `pc`, if the instruction in `bytes` is a call.
    pub fn call_return(pc: u64, bytes: &[u8]) -> Option<u64> {
        let mut d = iced_x86::Decoder::with_ip(64, bytes, pc, iced_x86::DecoderOptions::NONE);
        let i = d.decode();
        matches!(i.flow_control(), iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall).then(|| pc + i.len() as u64)
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;
        #[test]
        pub fn calls_are_recognised() {
            // call rel32, call rax, ret, jmp rel8
            assert_eq!(call_return(0x1000, &[0xe8, 0, 0, 0, 0]), Some(0x1005));
            assert_eq!(call_return(0x1000, &[0xff, 0xd0]), Some(0x1002));
            assert_eq!(call_return(0x1000, &[0xc3]), None);
            assert_eq!(call_return(0x1000, &[0xeb, 0x05]), None);
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arch {
    pub const NAME: &str = "ARM64";
    #[cfg(test)]
    pub const PC_NAME: &str = "pc";
    /// `brk #0`, little-endian (0xD4200000), and its length.
    pub const BREAK: [u8; 4] = [0x00, 0x00, 0x20, 0xd4];
    pub const BREAK_LEN: usize = 4;
    /// `brk` traps with the program counter on the instruction itself.
    pub const PC_AFTER_BREAK: u64 = 0;

    /// `struct user_pt_regs` from the kernel's ptrace ABI.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Regs {
        x: [u64; 31],
        sp: u64,
        pc: u64,
        pstate: u64,
    }

    impl Regs {
        pub fn get(pid: libc::pid_t) -> Option<Regs> {
            let mut r = Regs { x: [0; 31], sp: 0, pc: 0, pstate: 0 };
            let mut iov = libc::iovec { iov_base: &mut r as *mut Regs as *mut libc::c_void, iov_len: std::mem::size_of::<Regs>() };
            // SAFETY: GETREGSET fills the buffer the iovec describes (a valid, writable Regs).
            let ok = unsafe {
                libc::ptrace(
                    libc::PTRACE_GETREGSET,
                    pid,
                    libc::NT_PRSTATUS as usize as *mut libc::c_void,
                    &mut iov as *mut libc::iovec as *mut libc::c_void,
                )
            };
            (ok == 0 && iov.iov_len == std::mem::size_of::<Regs>()).then_some(r)
        }
        pub fn set(&self, pid: libc::pid_t) -> bool {
            let mut copy = *self;
            let mut iov = libc::iovec { iov_base: &mut copy as *mut Regs as *mut libc::c_void, iov_len: std::mem::size_of::<Regs>() };
            // SAFETY: SETREGSET reads the buffer the iovec describes (a valid Regs).
            unsafe {
                libc::ptrace(
                    libc::PTRACE_SETREGSET,
                    pid,
                    libc::NT_PRSTATUS as usize as *mut libc::c_void,
                    &mut iov as *mut libc::iovec as *mut libc::c_void,
                ) == 0
            }
        }
        pub fn pc(&self) -> u64 {
            self.pc
        }
        pub fn set_pc(&mut self, pc: u64) {
            self.pc = pc;
        }
        pub fn sp(&self) -> u64 {
            self.sp
        }
        pub fn list(&self) -> Vec<(String, u64)> {
            let mut out: Vec<(String, u64)> = self.x.iter().enumerate().map(|(i, v)| (format!("x{i}"), *v)).collect();
            out.push(("sp".into(), self.sp));
            out.push(("pc".into(), self.pc));
            out.push(("pstate".into(), self.pstate));
            out
        }
    }

    /// The address after the call at `pc`, if the instruction in `bytes` is a call
    /// (`bl`, `blr`, or the pointer-authenticated `blraa`/`blrab` forms).
    pub fn call_return(pc: u64, bytes: &[u8]) -> Option<u64> {
        let w = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
        let bl = w & 0xfc00_0000 == 0x9400_0000;
        let blr = w & 0xffff_fc1f == 0xd63f_0000;
        let blra = w & 0xfeff_f800 == 0xd63f_0800;
        (bl || blr || blra).then(|| pc + 4)
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;
        #[test]
        pub fn calls_are_recognised() {
            let w = |v: u32| v.to_le_bytes();
            assert_eq!(call_return(0x1000, &w(0x9400_0010)), Some(0x1004)); // bl .+0x40
            assert_eq!(call_return(0x1000, &w(0xd63f_0100)), Some(0x1004)); // blr x8
            assert_eq!(call_return(0x1000, &w(0xd73f_0be8)), Some(0x1004)); // blrab x31, x8
            assert_eq!(call_return(0x1000, &w(0xd65f_03c0)), None); // ret
            assert_eq!(call_return(0x1000, &w(0x1400_0010)), None); // b .+0x40
            assert_eq!(call_return(0x1000, &w(0xd61f_0100)), None); // br x8
            assert_eq!(call_return(0x1000, &[0, 0]), None);
        }
        #[test]
        pub fn register_file_layout_is_the_kernels() {
            assert_eq!(std::mem::size_of::<Regs>(), 34 * 8);
        }
    }
}

/// The CPU this debugger runs programs for: the one it runs on.
#[cfg(target_arch = "x86_64")]
pub const HOST_ARCH: paranoia_core::Arch = paranoia_core::Arch::X86_64;
#[cfg(target_arch = "aarch64")]
pub const HOST_ARCH: paranoia_core::Arch = paranoia_core::Arch::Arm64;
/// Its name for messages.
pub use arch::NAME as HOST_NAME;

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

pub struct Debugger {
    tx: Sender<Cmd>,
    shared: Arc<Mutex<Snapshot>>,
}

pub struct StartArgs {
    pub path: String,
    pub cmdline: String,
    pub image_base: u64,
    pub entry: u64,
    pub breakpoints: Vec<u64>,
    pub break_on_entry: bool,
    pub image_size: u64,
}

impl Debugger {
    pub fn start(args: StartArgs) -> Result<Debugger, String> {
        let shared = Arc::new(Mutex::new(Snapshot { state: "running".into(), reason: "Starting…".into(), ..Default::default() }));
        let (tx, rx) = channel();
        let (ready_tx, ready_rx) = channel::<Result<(), String>>();
        let sh = shared.clone();
        std::thread::Builder::new()
            .name("paranoia-debugger".into())
            .spawn(move || {
                let mut w = match Worker::launch(&args, sh) {
                    Ok(w) => {
                        let _ = ready_tx.send(Ok(()));
                        w
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                w.run(rx, &args);
            })
            .map_err(|e| e.to_string())?;
        ready_rx.recv().map_err(|e| e.to_string())??;
        Ok(Debugger { tx, shared })
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
        self.tx.send(cmd).map_err(|_| "the debug session has ended".to_string())
    }

    pub fn read(&self, va: u64, len: usize) -> Result<Vec<u8>, String> {
        let (t, r) = channel();
        self.tx.send(Cmd::Read(va, len.min(1 << 20), t)).map_err(|_| "the debug session has ended".to_string())?;
        r.recv_timeout(Duration::from_secs(5)).map_err(|_| "debugger did not answer".to_string())?
    }
}

impl Drop for Debugger {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Stop);
    }
}

struct Worker {
    shared: Arc<Mutex<Snapshot>>,
    pid: libc::pid_t,
    /// runtime - static
    delta: i64,
    image_size: u64,
    /// Breakpoints by static VA with the original instruction bytes (little-endian) once armed.
    user_bps: BTreeMap<u64, Option<u32>>,
    temp_bps: BTreeMap<u64, u32>,
    /// Breakpoint (static VA) to re-arm after stepping off it.
    rearm: Option<u64>,
    /// Stopped, with the signal to deliver when it continues (0 = none).
    stopped: Option<i32>,
    entry: u64,
}

fn log_to(shared: &Arc<Mutex<Snapshot>>, s: String) {
    let mut sh = shared.lock().unwrap();
    if sh.log.len() < 2000 {
        sh.log.push(s);
    }
}

/// Waits for the debuggee; `None` when nothing happened (non-blocking) or on error.
fn wait(pid: libc::pid_t, block: bool) -> Option<i32> {
    let mut status = 0;
    // SAFETY: `status` is a valid out-pointer for the call.
    let r = unsafe { libc::waitpid(pid, &mut status, if block { libc::__WALL } else { libc::WNOHANG | libc::__WALL }) };
    (r == pid).then_some(status)
}

impl Worker {
    fn launch(args: &StartArgs, shared: Arc<Mutex<Snapshot>>) -> Result<Worker, String> {
        let dir = std::path::Path::new(&args.path).parent().map(|p| p.to_path_buf());
        let mut cmd = Command::new(&args.path);
        cmd.args(args.cmdline.split_whitespace()).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(d) = dir.filter(|d| d.is_dir()) {
            cmd.current_dir(d);
        }
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().map_err(|e| format!("cannot start {}: {e}", args.path))?;
        let pid = child.id() as libc::pid_t;
        for (name, pipe) in [
            ("stdout", child.stdout.take().map(|p| Box::new(p) as Box<dyn std::io::Read + Send>)),
            ("stderr", child.stderr.take().map(|p| Box::new(p) as Box<dyn std::io::Read + Send>)),
        ] {
            if let Some(p) = pipe {
                let sh = shared.clone();
                std::thread::spawn(move || {
                    for line in BufReader::new(p).lines().map_while(Result::ok) {
                        log_to(&sh, format!("{name}: {line}"));
                    }
                });
            }
        }
        // The child stops with SIGTRAP right after exec.
        let status = wait(pid, true).ok_or("the program did not start under the debugger")?;
        if !libc::WIFSTOPPED(status) {
            return Err("the program exited before the debugger could attach".into());
        }
        // SAFETY: ptrace on our own stopped child; the data argument is an integer flag, not a pointer.
        unsafe {
            libc::ptrace(libc::PTRACE_SETOPTIONS, pid, std::ptr::null_mut::<libc::c_void>(), libc::PTRACE_O_EXITKILL as *mut libc::c_void);
        }
        // Runtime base of the image: the mapping of the executable at file offset 0.
        let exe = std::fs::canonicalize(&args.path).ok();
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_default();
        let base = maps
            .lines()
            .filter_map(|l| {
                let mut f = l.split_whitespace();
                let range = f.next()?;
                let _perms = f.next()?;
                let off = u64::from_str_radix(f.next()?, 16).ok()?;
                let _dev = f.next()?;
                let _inode = f.next()?;
                let path = f.next()?;
                let same = exe.as_ref().is_some_and(|e| std::path::Path::new(path) == e.as_path());
                (same && off == 0).then(|| u64::from_str_radix(range.split('-').next()?, 16).ok()).flatten()
            })
            .min()
            .unwrap_or(args.image_base);
        let delta = base as i64 - (args.image_base & !0xfff) as i64;
        let mut user_bps = BTreeMap::new();
        for b in &args.breakpoints {
            user_bps.insert(*b, None);
        }
        let mut w = Worker {
            shared,
            pid,
            delta,
            image_size: args.image_size.max(0x1000),
            user_bps,
            temp_bps: BTreeMap::new(),
            rearm: None,
            stopped: Some(0),
            entry: args.entry,
        };
        w.shared.lock().unwrap().base = base;
        w.log(format!("Process {pid} started, image at {base:#x}"));
        w.arm_all();
        if args.break_on_entry && args.entry != 0 {
            if let Some(b) = w.arm(args.entry) {
                w.temp_bps.insert(args.entry, b);
            }
        }
        // Run to the entry point (or the first breakpoint) right away, like the Windows debugger.
        w.stopped = Some(0);
        w.resume(false);
        Ok(w)
    }

    fn log(&self, s: impl Into<String>) {
        log_to(&self.shared, s.into());
    }

    fn rt(&self, va: u64) -> u64 {
        (va as i64).wrapping_add(self.delta) as u64
    }

    fn to_static(&self, rt: u64) -> Option<u64> {
        let base = self.shared.lock().unwrap().base;
        (rt >= base && rt < base.saturating_add(self.image_size)).then(|| (rt as i64).wrapping_sub(self.delta) as u64)
    }

    fn peek(&self, addr: u64) -> Option<u64> {
        // SAFETY: __errno_location returns this thread's errno slot, which is always valid.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: PEEKDATA reads the tracee's memory through the kernel; no local memory is passed.
        let v = unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, self.pid, addr as *mut libc::c_void, std::ptr::null_mut::<libc::c_void>()) };
        // SAFETY: __errno_location returns this thread's errno slot, which is always valid.
        (v != -1 || unsafe { *libc::__errno_location() } == 0).then_some(v as u64)
    }

    fn poke(&self, addr: u64, v: u64) -> bool {
        // SAFETY: POKEDATA writes the tracee's memory through the kernel; the value goes as an integer.
        unsafe { libc::ptrace(libc::PTRACE_POKEDATA, self.pid, addr as *mut libc::c_void, v as *mut libc::c_void) == 0 }
    }

    fn read_mem(&self, rt: u64, len: usize) -> Option<Vec<u8>> {
        let end = rt.checked_add(len as u64)?;
        let mut out = Vec::with_capacity(len + 8);
        let start = rt & !7;
        let mut a = start;
        while a < end {
            out.extend_from_slice(&self.peek(a)?.to_le_bytes());
            a += 8;
        }
        let skip = (rt - start) as usize;
        Some(out[skip..skip + len].to_vec())
    }

    fn write_byte(&self, rt: u64, b: u8) -> bool {
        let word = rt & !7;
        let Some(v) = self.peek(word) else { return false };
        let shift = (rt - word) * 8;
        self.poke(word, (v & !(0xff << shift)) | ((b as u64) << shift))
    }

    /// Writes the original instruction bytes back over a breakpoint.
    fn restore(&self, rt: u64, orig: u32) {
        for i in 0..arch::BREAK_LEN {
            self.write_byte(rt + i as u64, (orig >> (8 * i)) as u8);
        }
    }

    /// Plants the breakpoint instruction and returns what it replaced.
    fn arm(&self, va: u64) -> Option<u32> {
        let rt = self.rt(va);
        let bytes = self.read_mem(rt, arch::BREAK_LEN)?;
        let orig = bytes.iter().enumerate().fold(0u32, |a, (i, b)| a | (*b as u32) << (8 * i));
        if bytes == arch::BREAK[..arch::BREAK_LEN] {
            return Some(orig);
        }
        arch::BREAK[..arch::BREAK_LEN].iter().enumerate().all(|(i, b)| self.write_byte(rt + i as u64, *b)).then_some(orig)
    }

    fn arm_all(&mut self) {
        let keys: Vec<u64> = self.user_bps.iter().filter(|(_, o)| o.is_none()).map(|(k, _)| *k).collect();
        for k in keys {
            match self.arm(k) {
                Some(b) => {
                    self.user_bps.insert(k, Some(b));
                }
                None => self.log(format!("could not set breakpoint at {k:#x}")),
            }
        }
    }

    fn regs(&self) -> Option<arch::Regs> {
        arch::Regs::get(self.pid)
    }

    fn set_regs(&self, r: &arch::Regs) -> bool {
        r.set(self.pid)
    }

    fn pause(&mut self, reason: String, signal: i32) {
        self.stopped = Some(signal);
        let mut regs_out = Vec::new();
        let mut stack = Vec::new();
        let mut pc = 0;
        if let Some(r) = self.regs() {
            pc = r.pc();
            regs_out = r.list();
            if let Some(mem) = self.read_mem(r.sp(), 16 * 8) {
                for (i, ch) in mem.as_chunks::<8>().0.iter().enumerate() {
                    stack.push((r.sp() + i as u64 * 8, u64::from_le_bytes(*ch)));
                }
            }
        }
        let st = self.to_static(pc);
        let mut sh = self.shared.lock().unwrap();
        sh.state = "paused".into();
        sh.reason = reason;
        sh.pc_runtime = pc;
        sh.pc = st;
        sh.regs = regs_out;
        sh.stack = stack;
        sh.breakpoints = self.user_bps.keys().copied().collect();
    }

    /// Continues (or single-steps). A breakpoint the program is sitting on is stepped over first.
    fn resume(&mut self, step: bool) {
        let Some(sig) = self.stopped.take() else { return };
        {
            let mut sh = self.shared.lock().unwrap();
            sh.state = "running".into();
            sh.reason = String::new();
        }
        let null = std::ptr::null_mut::<libc::c_void>();
        if let Some(va) = self.rearm.take() {
            // SAFETY: Resumes our stopped tracee; the signal number goes as an integer.
            unsafe { libc::ptrace(libc::PTRACE_SINGLESTEP, self.pid, null, sig as usize as *mut libc::c_void) };
            match wait(self.pid, true) {
                Some(s) if libc::WIFSTOPPED(s) => {
                    if self.user_bps.contains_key(&va) {
                        if let Some(b) = self.arm(va) {
                            self.user_bps.insert(va, Some(b));
                        }
                    }
                    if step {
                        self.pause("Step".into(), 0);
                        return;
                    }
                    // SAFETY: Resumes our stopped tracee; no pointers.
                    unsafe { libc::ptrace(libc::PTRACE_CONT, self.pid, null, std::ptr::null_mut::<libc::c_void>()) };
                }
                Some(s) => self.exited(s),
                None => {}
            }
            return;
        }
        let req = if step { libc::PTRACE_SINGLESTEP } else { libc::PTRACE_CONT };
        // SAFETY: Resumes our stopped tracee; the signal number goes as an integer.
        unsafe { libc::ptrace(req, self.pid, null, sig as usize as *mut libc::c_void) };
        if step {
            match wait(self.pid, true) {
                Some(s) if libc::WIFSTOPPED(s) => self.pause("Step".into(), 0),
                Some(s) => self.exited(s),
                None => {}
            }
        }
    }

    fn exited(&mut self, status: i32) {
        let mut sh = self.shared.lock().unwrap();
        sh.state = "exited".into();
        sh.pc = None;
        if libc::WIFEXITED(status) {
            let code = libc::WEXITSTATUS(status) as u32;
            sh.reason = format!("Process exited with code {code}");
            sh.exit_code = Some(code);
        } else if libc::WIFSIGNALED(status) {
            let sig = libc::WTERMSIG(status);
            sh.reason = format!("Process killed by signal {sig}");
            sh.exit_code = Some(128 + sig as u32);
        }
    }

    fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Read(va, len, reply) => {
                let r = if self.stopped.is_some() {
                    self.read_mem(self.rt(va), len).ok_or_else(|| format!("cannot read {va:#x}"))
                } else {
                    Err("pause the program to read its memory".into())
                };
                let _ = reply.send(r);
            }
            Cmd::SetBp(va) => {
                let orig = if self.stopped.is_some() { self.arm(va) } else { None };
                self.user_bps.insert(va, orig);
                self.shared.lock().unwrap().breakpoints = self.user_bps.keys().copied().collect();
            }
            Cmd::ClearBp(va) => {
                if let Some(Some(orig)) = self.user_bps.remove(&va) {
                    if self.stopped.is_some() {
                        self.restore(self.rt(va), orig);
                    }
                }
                if self.rearm == Some(va) {
                    self.rearm = None;
                }
                self.shared.lock().unwrap().breakpoints = self.user_bps.keys().copied().collect();
            }
            Cmd::Pause => {
                if self.stopped.is_none() {
                    // SAFETY: Sends a signal to our own child process.
                    unsafe { libc::kill(self.pid, libc::SIGSTOP) };
                }
            }
            Cmd::Stop => {
                // SAFETY: Sends a signal to our own child process.
                unsafe { libc::kill(self.pid, libc::SIGKILL) };
                if self.stopped.is_some() {
                    self.stopped = None;
                    // SAFETY: Lets the killed tracee run so the kernel can reap it; no pointers.
                    unsafe {
                        libc::ptrace(
                            libc::PTRACE_CONT,
                            self.pid,
                            std::ptr::null_mut::<libc::c_void>(),
                            std::ptr::null_mut::<libc::c_void>(),
                        )
                    };
                }
            }
            Cmd::Continue => self.resume(false),
            Cmd::StepInto => self.resume(true),
            Cmd::RunTo(va) => {
                if let Some(b) = self.arm(va) {
                    self.temp_bps.insert(va, b);
                }
                self.resume(false);
            }
            Cmd::StepOver => {
                let pc = self.regs().map(|r| r.pc());
                let next = pc.and_then(|pc| arch::call_return(pc, &self.read_mem(pc, 16)?));
                match next.map(|n| (n as i64).wrapping_sub(self.delta) as u64) {
                    Some(sva) => {
                        if let Some(b) = self.arm(sva) {
                            self.temp_bps.insert(sva, b);
                        }
                        self.resume(false);
                    }
                    None => self.resume(true),
                }
            }
        }
    }

    fn on_stop(&mut self, status: i32) {
        let sig = libc::WSTOPSIG(status);
        if sig == libc::SIGTRAP {
            let Some(mut r) = self.regs() else { return };
            let at = r.pc().wrapping_sub(arch::PC_AFTER_BREAK);
            let sva = (at as i64).wrapping_sub(self.delta) as u64;
            let temp = self.temp_bps.remove(&sva);
            let user = self.user_bps.get(&sva).copied().flatten();
            if let Some(orig) = temp.or(user) {
                // Our breakpoint: put the instruction back and execute the real one next.
                self.restore(at, orig);
                r.set_pc(at);
                self.set_regs(&r);
                if user.is_some() {
                    self.rearm = Some(sva);
                }
                let why = if user.is_some() {
                    "Breakpoint"
                } else if sva == self.entry {
                    "Entry point"
                } else {
                    "Reached"
                };
                self.pause(why.into(), 0);
                return;
            }
            self.pause("Trap".into(), 0);
            return;
        }
        if sig == libc::SIGSTOP {
            self.pause("Paused".into(), 0);
            return;
        }
        let name = match sig {
            libc::SIGSEGV => "segmentation fault (SIGSEGV)",
            libc::SIGILL => "illegal instruction (SIGILL)",
            libc::SIGFPE => "arithmetic error (SIGFPE)",
            libc::SIGBUS => "bus error (SIGBUS)",
            libc::SIGABRT => "abort (SIGABRT)",
            _ => "signal",
        };
        // The signal is delivered to the program when it continues.
        self.pause(format!("{name} {sig}"), sig);
    }

    fn run(&mut self, rx: Receiver<Cmd>, _args: &StartArgs) {
        loop {
            if self.stopped.is_some() {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(cmd) => self.handle_cmd(cmd),
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        // SAFETY: Sends a signal to our own child process.
                        unsafe { libc::kill(self.pid, libc::SIGKILL) };
                        self.stopped = None;
                        // SAFETY: Lets the killed tracee run so the kernel can reap it; no pointers.
                        unsafe {
                            libc::ptrace(
                                libc::PTRACE_CONT,
                                self.pid,
                                std::ptr::null_mut::<libc::c_void>(),
                                std::ptr::null_mut::<libc::c_void>(),
                            )
                        };
                    }
                }
                if self.shared.lock().unwrap().state == "exited" {
                    return;
                }
                continue;
            }
            while let Ok(cmd) = rx.try_recv() {
                self.handle_cmd(cmd);
            }
            if self.shared.lock().unwrap().state == "exited" {
                return;
            }
            match wait(self.pid, false) {
                Some(s) if libc::WIFSTOPPED(s) => self.on_stop(s),
                Some(s) => {
                    self.exited(s);
                    return;
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait_state(d: &Debugger, want: &[&str]) -> Snapshot {
        for _ in 0..300 {
            let s = d.snapshot();
            if want.contains(&s.state.as_str()) {
                return s;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the debuggee never reached {want:?}");
    }

    /// Debugs a system program: stops at its entry point (PIE base resolved), steps, reads memory,
    /// sets a breakpoint, runs to exit with its real exit code.
    #[test]
    fn debugs_a_linux_program() {
        let path = ["/bin/true", "/usr/bin/true"].into_iter().find(|p| std::path::Path::new(p).exists());
        let Some(path) = path else { return };
        let bytes = std::fs::read(path).unwrap();
        let bin = paranoia_core::Binary::load("true", bytes).unwrap();
        let info = bin.info();
        if info.arch != HOST_ARCH {
            return;
        }
        let size = info.sections.iter().map(|x| x.vaddr + x.vsize).max().unwrap_or(0).saturating_sub(info.image_base);
        let d = Debugger::start(StartArgs {
            path: path.into(),
            cmdline: String::new(),
            image_base: info.image_base,
            entry: info.entry,
            breakpoints: vec![],
            break_on_entry: true,
            image_size: size,
        })
        .unwrap();
        let s = wait_state(&d, &["paused", "exited"]);
        assert_eq!(s.state, "paused", "{s:?}");
        assert_eq!(s.reason, "Entry point");
        assert_eq!(s.pc, Some(info.entry), "runtime {:#x} base {:#x}", s.pc_runtime, s.base);
        assert!(s.regs.iter().any(|(n, v)| n == arch::PC_NAME && *v == s.pc_runtime));
        assert_eq!(s.stack.len(), 16);
        // Memory at the entry point reads back the original bytes (no breakpoint left behind).
        let mem = d.read(info.entry, 4).unwrap();
        assert_ne!(mem[..arch::BREAK_LEN], arch::BREAK[..arch::BREAK_LEN]);
        d.command("step_into", None).unwrap();
        let s2 = wait_state(&d, &["paused", "exited"]);
        assert_eq!(s2.reason, "Step", "{s2:?}");
        assert_ne!(s2.pc_runtime, s.pc_runtime);
        d.command("continue", None).unwrap();
        let s3 = wait_state(&d, &["exited"]);
        assert_eq!(s3.exit_code, Some(0), "{s3:?}");
    }

    /// A breakpoint planted on an instruction the program is about to run stops it there, is
    /// stepped off without re-triggering, and leaves the program able to finish normally.
    #[test]
    fn a_breakpoint_stops_steps_off_and_lets_the_program_finish() {
        let path = ["/bin/true", "/usr/bin/true"].into_iter().find(|p| std::path::Path::new(p).exists());
        let Some(path) = path else { return };
        let bin = paranoia_core::Binary::load("true", std::fs::read(path).unwrap()).unwrap();
        let info = bin.info();
        if info.arch != HOST_ARCH {
            return;
        }
        let size = info.sections.iter().map(|x| x.vaddr + x.vsize).max().unwrap_or(0).saturating_sub(info.image_base);
        let start = |breakpoints: Vec<u64>, break_on_entry: bool| {
            Debugger::start(StartArgs {
                path: path.into(),
                cmdline: String::new(),
                image_base: info.image_base,
                entry: info.entry,
                breakpoints,
                break_on_entry,
                image_size: size,
            })
            .unwrap()
        };
        // Walk the first instructions after the entry point to find an address that is executed.
        let d = start(vec![], true);
        let s0 = wait_state(&d, &["paused", "exited"]);
        assert_eq!(s0.reason, "Entry point", "{s0:?}");
        let mut target = s0.pc.unwrap();
        for _ in 0..3 {
            d.command("step_into", None).unwrap();
            let s = wait_state(&d, &["paused", "exited"]);
            assert_eq!(s.reason, "Step", "{s:?}");
            target = s.pc.expect("still in the image");
        }
        assert_ne!(target, info.entry, "three steps moved on");
        d.command("stop", None).unwrap();
        wait_state(&d, &["exited"]);
        // A fresh run with a breakpoint there stops at it (nothing else is armed).
        let d = start(vec![target], false);
        let s = wait_state(&d, &["paused", "exited"]);
        assert_eq!(s.state, "paused", "{s:?}");
        assert_eq!(s.reason, "Breakpoint", "{s:?}");
        assert_eq!(s.pc, Some(target));
        assert!(s.breakpoints.contains(&target));
        // The instruction the breakpoint replaced is back in memory while stopped.
        let mem = d.read(target, arch::BREAK_LEN).unwrap();
        assert_ne!(mem[..], arch::BREAK[..arch::BREAK_LEN]);
        // Stepping leaves it, and it is armed again for later (it is not reached again here).
        d.command("step_into", None).unwrap();
        let s2 = wait_state(&d, &["paused", "exited"]);
        assert_eq!(s2.reason, "Step", "{s2:?}");
        assert_ne!(s2.pc, Some(target));
        d.command("continue", None).unwrap();
        let end = wait_state(&d, &["exited"]);
        assert_eq!(end.exit_code, Some(0), "{end:?}");
    }

    #[test]
    fn a_missing_program_is_reported() {
        let e = Debugger::start(StartArgs {
            path: "/nonexistent/paranoia-test".into(),
            cmdline: String::new(),
            image_base: 0,
            entry: 0,
            breakpoints: vec![],
            break_on_entry: false,
            image_size: 0,
        });
        assert!(e.err().unwrap().contains("cannot start"));
    }
}
