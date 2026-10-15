//! WebAssembly build of the engine with a plain C ABI — no wasm-bindgen, no
//! generated glue, no extra toolchain. The JavaScript side
//! (`apps/desktop/src/engine/wasm.worker.ts`) copies bytes in with `pn_alloc`,
//! calls `pn_open` / `pn_call`, and reads the JSON reply via `pn_result_*`.
//!
//! Protocol: every `pn_*` call that can fail returns 1 on success and 0 on
//! failure; either way the reply (JSON value or error message) is left in the
//! result buffer until the next call.

// The initializers below are already `const`; clippy misreports them through the macro.
#![allow(clippy::missing_const_for_thread_local)]

use std::cell::RefCell;

use paranoia_core::api::Session;

thread_local! {
    static SESSIONS: RefCell<Vec<Option<Session>>> = const { RefCell::new(Vec::new()) };
    static RESULT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn set_result(bytes: Vec<u8>) {
    RESULT.with(|r| *r.borrow_mut() = bytes);
}

/// # Safety
/// `ptr..ptr+len` must be memory previously obtained from [`pn_alloc`].
unsafe fn slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

/// Allocates `len` bytes for the host to fill. Exact-size boxed slices keep
/// alloc/free symmetric regardless of allocator rounding.
#[no_mangle]
pub extern "C" fn pn_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()) as *mut u8
}

/// # Safety
/// `ptr`/`len` must come from a matching [`pn_alloc`] call.
unsafe fn take(ptr: *mut u8, len: usize) -> Vec<u8> {
    Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)).into_vec()
}

/// # Safety
/// `ptr`/`len` must come from a matching [`pn_alloc`] call.
#[no_mangle]
pub unsafe extern "C" fn pn_free(ptr: *mut u8, len: usize) {
    drop(take(ptr, len));
}

#[no_mangle]
pub extern "C" fn pn_result_ptr() -> *const u8 {
    RESULT.with(|r| r.borrow().as_ptr())
}

#[no_mangle]
pub extern "C" fn pn_result_len() -> usize {
    RESULT.with(|r| r.borrow().len())
}

/// Opens a file. On success the result buffer holds the session handle (JSON number).
///
/// # Safety
/// Pointers must reference valid UTF-8 / byte buffers allocated with [`pn_alloc`].
/// Ownership of the data buffer moves into the engine.
#[no_mangle]
pub unsafe extern "C" fn pn_open(name_ptr: *const u8, name_len: usize, data_ptr: *mut u8, data_len: usize) -> u32 {
    let name = String::from_utf8_lossy(slice(name_ptr, name_len)).into_owned();
    let data = take(data_ptr, data_len);
    match Session::open(&name, data) {
        Ok(s) => {
            let handle = SESSIONS.with(|ss| {
                let mut ss = ss.borrow_mut();
                ss.push(Some(s));
                ss.len()
            });
            set_result(handle.to_string().into_bytes());
            1
        }
        Err(e) => {
            set_result(e.into_bytes());
            0
        }
    }
}

/// Invokes `method` with JSON `args` on session `handle`.
///
/// # Safety
/// Pointers must reference valid UTF-8 buffers allocated with [`pn_alloc`].
#[no_mangle]
pub unsafe extern "C" fn pn_call(handle: u32, method_ptr: *const u8, method_len: usize, args_ptr: *const u8, args_len: usize) -> u32 {
    let method = String::from_utf8_lossy(slice(method_ptr, method_len)).into_owned();
    let args = match serde_json::from_slice(slice(args_ptr, args_len)) {
        Ok(v) => v,
        Err(_) if args_len == 0 => serde_json::Value::Null,
        Err(e) => {
            set_result(format!("invalid JSON arguments: {e}").into_bytes());
            return 0;
        }
    };
    let out = SESSIONS.with(|ss| {
        let mut ss = ss.borrow_mut();
        match ss.get_mut((handle as usize).wrapping_sub(1)).and_then(Option::as_mut) {
            Some(s) => s.call(&method, args),
            None => Err(format!("no session {handle}")),
        }
    });
    match out {
        Ok(v) => {
            set_result(serde_json::to_vec(&v).unwrap_or_default());
            1
        }
        Err(e) => {
            set_result(e.into_bytes());
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn pn_close(handle: u32) {
    SESSIONS.with(|ss| {
        if let Some(slot) = ss.borrow_mut().get_mut((handle as usize).wrapping_sub(1)) {
            *slot = None;
        }
    });
}
