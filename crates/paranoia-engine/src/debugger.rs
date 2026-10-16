//! A small Windows user-mode debugger for x64 programs (IDA's local debugger).
//!
//! The Win32 debug API requires `WaitForDebugEvent` to be called from the thread
//! that created the debuggee, so the whole session lives on one worker thread
//! that receives commands over a channel. All addresses exchanged with the UI
//! are *static* virtual addresses of the analyzed image; the worker translates
//! them using the runtime image base (ASLR).

use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use windows_sys::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, HANDLE, NTSTATUS,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugBreakProcess, FlushInstructionCache, GetThreadContext, ReadProcessMemory, SetThreadContext, WaitForDebugEvent,
    WriteProcessMemory, CONTEXT, CONTEXT_ALL_AMD64, CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT,
    EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, TerminateProcess, CREATE_NEW_CONSOLE, DEBUG_ONLY_THIS_PROCESS, PROCESS_INFORMATION, STARTUPINFOW,
};

const TRAP_FLAG: u32 = 0x100;

#[derive(Debug, Clone, Serialize, Default)]
pub struct Snapshot {
    /// idle, running, paused, exited
    pub state: String,
    pub reason: String,
    /// Static VA of the instruction pointer when it lies in the main image.
    pub pc: Option<u64>,
    pub pc_runtime: u64,
    pub base: u64,
    pub regs: Vec<(String, u64)>,
    /// (static or runtime address, value) for 16 stack slots.
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
        s.log.clear(); // the log is delivered once
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
            // Report "running" right away so a poll racing the worker never sees the old stop.
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
    process: HANDLE,
    pid: u32,
    main_tid: u32,
    threads: HashMap<u32, HANDLE>,
    /// runtime - static
    delta: i64,
    image_size_hint: u64,
    /// Static VA -> original byte, for armed user breakpoints.
    user_bps: BTreeMap<u64, Option<u8>>,
    /// One-shot breakpoints (entry, run-to, step-over), static VA -> original byte.
    temp_bps: BTreeMap<u64, u8>,
    /// Breakpoint to re-arm after single-stepping off it.
    rearm: Option<u64>,
    stepping: bool,
    seen_system_bp: bool,
    /// Where the debuggee is stopped: (thread, continue status).
    stopped: Option<(u32, NTSTATUS)>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl Worker {
    fn launch(args: &StartArgs, shared: Arc<Mutex<Snapshot>>) -> Result<Worker, String> {
        let app = wide(&args.path);
        let mut cmd = wide(&format!("\"{}\" {}", args.path, args.cmdline));
        let dir = std::path::Path::new(&args.path).parent().map(|p| wide(&p.to_string_lossy()));
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            CreateProcessW(
                app.as_ptr(),
                cmd.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                std::ptr::null(),
                dir.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
                &si,
                &mut pi,
            )
        };
        if ok == 0 {
            return Err(format!("CreateProcess failed: {}", std::io::Error::last_os_error()));
        }
        let mut user_bps = BTreeMap::new();
        for b in &args.breakpoints {
            user_bps.insert(*b, None);
        }
        Ok(Worker {
            shared,
            process: pi.hProcess,
            pid: pi.dwProcessId,
            main_tid: pi.dwThreadId,
            threads: HashMap::from([(pi.dwThreadId, pi.hThread)]),
            delta: 0,
            image_size_hint: args.image_size.max(0x1000),
            user_bps,
            temp_bps: BTreeMap::new(),
            rearm: None,
            stepping: false,
            seen_system_bp: false,
            stopped: None,
        })
    }

    fn log(&self, s: impl Into<String>) {
        let mut sh = self.shared.lock().unwrap();
        if sh.log.len() < 2000 {
            sh.log.push(s.into());
        }
    }

    fn rt(&self, va: u64) -> u64 {
        (va as i64 + self.delta) as u64
    }

    fn to_static(&self, rt: u64) -> Option<u64> {
        let s = (rt as i64 - self.delta) as u64;
        let base = self.shared.lock().unwrap().base;
        (rt >= base && rt < base + self.image_size_hint).then_some(s)
    }

    fn read_mem(&self, rt: u64, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut n = 0usize;
        let ok = unsafe { ReadProcessMemory(self.process, rt as *const _, buf.as_mut_ptr() as *mut _, len, &mut n) };
        (ok != 0).then(|| {
            buf.truncate(n);
            buf
        })
    }

    fn write_byte(&self, rt: u64, b: u8) -> bool {
        let mut n = 0usize;
        let ok = unsafe { WriteProcessMemory(self.process, rt as *const _, &b as *const u8 as *const _, 1, &mut n) };
        unsafe { FlushInstructionCache(self.process, rt as *const _, 1) };
        ok != 0
    }

    /// Writes int3 at a static VA; returns the byte it replaced.
    fn arm(&self, va: u64) -> Option<u8> {
        let rt = self.rt(va);
        let orig = *self.read_mem(rt, 1)?.first()?;
        if orig == 0xcc {
            return Some(orig);
        }
        self.write_byte(rt, 0xcc).then_some(orig)
    }

    fn arm_all(&mut self) {
        let keys: Vec<u64> = self.user_bps.iter().filter(|(_, o)| o.is_none()).map(|(k, _)| *k).collect();
        for k in keys {
            if let Some(b) = self.arm(k) {
                self.user_bps.insert(k, Some(b));
            } else {
                self.log(format!("could not set breakpoint at {k:#x}"));
            }
        }
    }

    fn context(&self, tid: u32) -> Option<Box<CONTEXT>> {
        let h = *self.threads.get(&tid)?;
        let mut ctx: Box<CONTEXT> = Box::new(unsafe { std::mem::zeroed() });
        ctx.ContextFlags = CONTEXT_ALL_AMD64;
        (unsafe { GetThreadContext(h, &mut *ctx) } != 0).then_some(ctx)
    }

    fn set_context(&self, tid: u32, ctx: &CONTEXT) -> bool {
        self.threads.get(&tid).is_some_and(|h| unsafe { SetThreadContext(*h, ctx) } != 0)
    }

    fn pause(&mut self, tid: u32, reason: String, status: NTSTATUS) {
        self.stopped = Some((tid, status));
        let ctx = self.context(tid);
        let mut sh_regs = Vec::new();
        let mut stack = Vec::new();
        let mut pc_rt = 0;
        if let Some(c) = &ctx {
            pc_rt = c.Rip;
            for (n, v) in [
                ("rax", c.Rax),
                ("rbx", c.Rbx),
                ("rcx", c.Rcx),
                ("rdx", c.Rdx),
                ("rsi", c.Rsi),
                ("rdi", c.Rdi),
                ("rbp", c.Rbp),
                ("rsp", c.Rsp),
                ("r8", c.R8),
                ("r9", c.R9),
                ("r10", c.R10),
                ("r11", c.R11),
                ("r12", c.R12),
                ("r13", c.R13),
                ("r14", c.R14),
                ("r15", c.R15),
                ("rip", c.Rip),
                ("rflags", c.EFlags as u64),
            ] {
                sh_regs.push((n.to_string(), v));
            }
            if let Some(mem) = self.read_mem(c.Rsp, 16 * 8) {
                for (i, ch) in mem.chunks_exact(8).enumerate() {
                    stack.push((c.Rsp + i as u64 * 8, u64::from_le_bytes(ch.try_into().unwrap())));
                }
            }
        }
        let pc = self.to_static(pc_rt);
        let mut sh = self.shared.lock().unwrap();
        sh.state = "paused".into();
        sh.reason = reason;
        sh.pc_runtime = pc_rt;
        sh.pc = pc;
        sh.regs = sh_regs;
        sh.stack = stack;
        sh.breakpoints = self.user_bps.keys().copied().collect();
    }

    fn resume(&mut self, step: bool) {
        let Some((tid, status)) = self.stopped.take() else { return };
        let need_tf = step || self.rearm.is_some();
        if need_tf {
            if let Some(mut c) = self.context(tid) {
                c.EFlags |= TRAP_FLAG;
                self.set_context(tid, &c);
            }
        }
        self.stepping = step;
        {
            let mut sh = self.shared.lock().unwrap();
            sh.state = "running".into();
            sh.reason = String::new();
        }
        unsafe { ContinueDebugEvent(self.pid, tid, status) };
    }

    fn handle_cmd(&mut self, cmd: Cmd) -> bool {
        match cmd {
            Cmd::Read(va, len, reply) => {
                let r = self.read_mem(self.rt(va), len).ok_or_else(|| format!("cannot read {va:#x}"));
                let _ = reply.send(r);
            }
            Cmd::SetBp(va) => {
                let orig = if self.stopped.is_some() || self.delta != 0 { self.arm(va) } else { None };
                self.user_bps.insert(va, orig);
                self.shared.lock().unwrap().breakpoints = self.user_bps.keys().copied().collect();
            }
            Cmd::ClearBp(va) => {
                if let Some(Some(orig)) = self.user_bps.remove(&va) {
                    self.write_byte(self.rt(va), orig);
                }
                if self.rearm == Some(va) {
                    self.rearm = None;
                }
                self.shared.lock().unwrap().breakpoints = self.user_bps.keys().copied().collect();
            }
            Cmd::Pause => {
                if self.stopped.is_none() {
                    unsafe { DebugBreakProcess(self.process) };
                }
            }
            Cmd::Stop => {
                unsafe { TerminateProcess(self.process, 1) };
                if self.stopped.is_some() {
                    self.resume(false);
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
                // Over a call: one-shot breakpoint after it; otherwise a single step.
                let pc = self.stopped.and_then(|(t, _)| self.context(t)).map(|c| c.Rip);
                let call_next = pc.and_then(|pc| {
                    let bytes = self.read_mem(pc, 16)?;
                    let mut d = iced_x86::Decoder::with_ip(64, &bytes, pc, iced_x86::DecoderOptions::NONE);
                    let i = d.decode();
                    matches!(i.flow_control(), iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall)
                        .then(|| pc + i.len() as u64)
                });
                match call_next.and_then(|n| self.to_static(n).or(Some((n as i64 - self.delta) as u64))) {
                    Some(next) => {
                        if let Some(b) = self.arm(next) {
                            self.temp_bps.insert(next, b);
                        }
                        self.resume(false);
                    }
                    None => self.resume(true),
                }
            }
        }
        true
    }

    fn run(&mut self, rx: Receiver<Cmd>, args: &StartArgs) {
        let mut ev: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        loop {
            if self.stopped.is_some() {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(cmd) => {
                        self.handle_cmd(cmd);
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        unsafe { TerminateProcess(self.process, 1) };
                        self.resume(false);
                    }
                }
                continue;
            }
            while let Ok(cmd) = rx.try_recv() {
                self.handle_cmd(cmd);
            }
            if unsafe { WaitForDebugEvent(&mut ev, 50) } == 0 {
                continue;
            }
            let tid = ev.dwThreadId;
            let mut status = DBG_CONTINUE;
            match ev.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let info = unsafe { ev.u.CreateProcessInfo };
                    let base = info.lpBaseOfImage as u64;
                    self.delta = base as i64 - args.image_base as i64;
                    if !info.hFile.is_null() {
                        unsafe { CloseHandle(info.hFile) };
                    }
                    self.shared.lock().unwrap().base = base;
                    self.log(format!("Process {} started, image at {base:#x}", self.pid));
                    self.arm_all();
                    if args.break_on_entry && args.entry != 0 {
                        if let Some(b) = self.arm(args.entry) {
                            self.temp_bps.insert(args.entry, b);
                        }
                    }
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    let info = unsafe { ev.u.CreateThread };
                    self.threads.insert(tid, info.hThread);
                }
                EXIT_THREAD_DEBUG_EVENT => {
                    self.threads.remove(&tid);
                }
                LOAD_DLL_DEBUG_EVENT => {
                    let info = unsafe { ev.u.LoadDll };
                    if !info.hFile.is_null() {
                        unsafe { CloseHandle(info.hFile) };
                    }
                    self.log(format!("DLL loaded at {:#x}", info.lpBaseOfDll as u64));
                }
                OUTPUT_DEBUG_STRING_EVENT => {
                    let info = unsafe { ev.u.DebugString };
                    let len = (info.nDebugStringLength as usize).min(4096);
                    if let Some(b) = self.read_mem(info.lpDebugStringData as u64, if info.fUnicode != 0 { len * 2 } else { len }) {
                        let s = if info.fUnicode != 0 {
                            String::from_utf16_lossy(&b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>())
                        } else {
                            String::from_utf8_lossy(&b).into_owned()
                        };
                        self.log(format!("debug: {}", s.trim_end_matches(['\0', '\n', '\r'])));
                    }
                }
                EXCEPTION_DEBUG_EVENT => {
                    let info = unsafe { ev.u.Exception };
                    let code = info.ExceptionRecord.ExceptionCode;
                    let addr = info.ExceptionRecord.ExceptionAddress as u64;
                    let first = info.dwFirstChance != 0;
                    if code == EXCEPTION_BREAKPOINT {
                        let sva = (addr as i64 - self.delta) as u64;
                        let temp = self.temp_bps.remove(&sva);
                        let user = self.user_bps.get(&sva).copied().flatten();
                        if let Some(orig) = temp.or(user) {
                            // Our int3: put the byte back and re-execute the instruction.
                            self.write_byte(addr, orig);
                            if let Some(mut c) = self.context(tid) {
                                c.Rip = addr;
                                self.set_context(tid, &c);
                            }
                            if user.is_some() {
                                self.rearm = Some(sva);
                            }
                            // A one-shot hit on a user breakpoint address must keep it armed.
                            if temp.is_some() && self.user_bps.contains_key(&sva) {
                                self.rearm = Some(sva);
                            }
                            let why = if user.is_some() {
                                "Breakpoint"
                            } else if sva == args.entry {
                                "Entry point"
                            } else {
                                "Reached"
                            };
                            self.pause(tid, why.into(), DBG_CONTINUE);
                            continue;
                        }
                        if !self.seen_system_bp {
                            // The loader's initial breakpoint: keep going to the entry point.
                            self.seen_system_bp = true;
                        } else {
                            let t = if self.threads.contains_key(&self.main_tid) { self.main_tid } else { tid };
                            self.pause(t, "Paused".into(), DBG_CONTINUE);
                            continue;
                        }
                    } else if code == EXCEPTION_SINGLE_STEP {
                        if let Some(va) = self.rearm.take() {
                            if self.user_bps.contains_key(&va) {
                                if let Some(b) = self.arm(va) {
                                    self.user_bps.insert(va, Some(b));
                                }
                            }
                        }
                        if self.stepping {
                            self.stepping = false;
                            self.pause(tid, "Step".into(), DBG_CONTINUE);
                            continue;
                        }
                    } else {
                        let name = match code as u32 {
                            0xC000_0005 => "access violation",
                            0xC000_0094 => "integer divide by zero",
                            0xC000_001D => "illegal instruction",
                            0xC000_00FD => "stack overflow",
                            0xE06D_7363 => "C++ exception",
                            _ => "exception",
                        };
                        status = DBG_EXCEPTION_NOT_HANDLED;
                        if first {
                            self.pause(tid, format!("{name} {:#010x} at {addr:#x} (first chance)", code as u32), DBG_EXCEPTION_NOT_HANDLED);
                            continue;
                        }
                        self.log(format!("{name} {:#010x} at {addr:#x} (second chance)", code as u32));
                    }
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    let code = unsafe { ev.u.ExitProcess.dwExitCode };
                    unsafe { ContinueDebugEvent(self.pid, tid, DBG_CONTINUE) };
                    let mut sh = self.shared.lock().unwrap();
                    sh.state = "exited".into();
                    sh.reason = format!("Process exited with code {code:#x}");
                    sh.exit_code = Some(code);
                    sh.pc = None;
                    drop(sh);
                    unsafe { CloseHandle(self.process) };
                    return;
                }
                _ => {}
            }
            unsafe { ContinueDebugEvent(self.pid, tid, status) };
        }
    }
}
