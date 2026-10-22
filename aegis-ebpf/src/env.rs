// SPDX-License-Identifier: GPL-2.0-only
//! The environment an exec started with. At `sched_process_exec` the new
//! image is in place and `current->mm->env_start..env_end` holds its
//! environment as the kernel copied it in, before any of the image's own
//! code (or a library preloaded into it) has run. So a library can't
//! scrub its `LD_PRELOAD` entry before this reads it.
//!
//! The region is read in 256-byte chunks with `bpf_loop`, up to 32 KiB.
//! A loader variable is found at its `=`: the bytes before it must be the
//! name, and the byte before the name a NUL (or the start of the region).
//! The last 16 bytes of each chunk are kept in front of the next, so a
//! variable split across two chunks still matches.

use aegis_common::{EventKind, ENV_LOADER_VAR, ENV_TRUNCATED, ENV_UNREADABLE};
use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_task,
        generated::{bpf_loop, bpf_probe_read_user},
    },
    macros::{btf_tracepoint, map},
    maps::PerCpuArray,
    programs::BtfTracePointContext,
};

use crate::{current, emit, off, read};

const CHUNK: usize = 256;
const CHUNKS: u32 = 128;
/// The longest name with its `=` ("LD_LIBRARY_PATH=", 16 bytes) minus
/// the `=`, plus the NUL in front of it.
const CARRY: usize = 16;

const NAMES: [&[u8]; 3] = [b"LD_PRELOAD", b"LD_AUDIT", b"LD_LIBRARY_PATH"];

#[repr(C)]
struct Scan {
    /// `CARRY` bytes of the previous chunk, then the current one.
    buf: [u8; CARRY + CHUNK],
    /// Next user address to read, and where the environment ends.
    pos: u64,
    end: u64,
    flags: u32,
    _pad: u32,
}

#[map]
static ENV_SCAN: PerCpuArray<Scan> = PerCpuArray::with_max_entries(1, 0);

#[btf_tracepoint(function = "sched_process_exec")]
pub fn aegis_exec_env(_ctx: BtfTracePointContext) -> i32 {
    let flags = scan();
    emit(EventKind::ExecEnv, |ev| {
        current(ev);
        ev.flags |= flags;
    });
    0
}

fn scan() -> u32 {
    let Some(s) = ENV_SCAN.get_ptr_mut(0) else {
        return ENV_UNREADABLE;
    };
    let s = unsafe { &mut *s };
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let mm: u64 = read(task, off!(task_mm));
    if mm == 0 {
        return ENV_UNREADABLE;
    }
    let start: u64 = read(mm as *const u8, off!(mm_env_start));
    let end: u64 = read(mm as *const u8, off!(mm_env_end));
    if start == 0 || end < start {
        return ENV_UNREADABLE;
    }
    s.pos = start;
    s.end = end;
    s.flags = 0;
    let max = (CHUNK as u64) * CHUNKS as u64;
    if end - start > max {
        s.flags = ENV_TRUNCATED;
        s.end = start + max;
    }
    // The region starts a string, as if a NUL came before it.
    unsafe { core::ptr::write_bytes(s.buf.as_mut_ptr(), 0, CARRY) };
    let cb: extern "C" fn(u32, *mut c_void) -> i64 = chunk;
    unsafe { bpf_loop(CHUNKS, cb as *mut c_void, core::ptr::null_mut(), 0) };
    s.flags
}

/// One chunk: read, look for a loader variable, keep the tail. Returns 1
/// to stop the loop.
extern "C" fn chunk(_i: u32, _ctx: *mut c_void) -> i64 {
    let Some(s) = ENV_SCAN.get_ptr_mut(0) else {
        return 1;
    };
    let s = unsafe { &mut *s };
    if s.pos >= s.end {
        return 1;
    }
    let left = s.end - s.pos;
    let n = if left < CHUNK as u64 {
        left as usize
    } else {
        CHUNK
    };
    let dst = unsafe { s.buf.as_mut_ptr().add(CARRY) } as *mut c_void;
    if unsafe { bpf_probe_read_user(dst, n as u32, s.pos as *const c_void) } != 0 {
        s.flags |= ENV_UNREADABLE;
        return 1;
    }
    if found(&s.buf, CARRY + n) {
        s.flags |= ENV_LOADER_VAR;
        return 1;
    }
    // The last CARRY bytes read go in front of the next chunk.
    let mut k = 0;
    while k < CARRY {
        s.buf[k] = s.buf[n + k];
        k += 1;
    }
    s.pos += n as u64;
    0
}

/// Whether a loader variable's `=` is in `buf[CARRY..last]`.
#[inline(always)]
fn found(buf: &[u8; CARRY + CHUNK], last: usize) -> bool {
    let mut j = CARRY;
    while j < last && j < CARRY + CHUNK {
        if buf[j] == b'=' {
            for name in NAMES {
                if is(buf, j, name) {
                    return true;
                }
            }
        }
        j += 1;
    }
    false
}

/// Whether `name` ends just before `buf[j]` and starts a string. `j` is
/// at least `CARRY`, so every index here is in bounds.
#[inline(always)]
fn is(buf: &[u8; CARRY + CHUNK], j: usize, name: &[u8]) -> bool {
    let start = j - name.len();
    if buf[start - 1] != 0 {
        return false;
    }
    let mut k = 0;
    while k < name.len() {
        if buf[start + k] != name[k] {
            return false;
        }
        k += 1;
    }
    true
}
