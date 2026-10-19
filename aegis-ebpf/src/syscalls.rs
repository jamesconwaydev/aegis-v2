// SPDX-License-Identifier: GPL-2.0-only
//! ptrace and memfd_create, from their syscall-entry tracepoints. The
//! arguments sit at 16 + 8n, past the common header and `__syscall_nr`.
//!
//! `target_tgid` is the raw pid argument, a pid in the tracer's pid
//! namespace; userspace translates it to the host namespace (Task 7).
//!
//! A ptrace event is emitted only for an attach that worked: entry
//! stashes the arguments per thread, and exit emits when the syscall
//! returned 0. A refused attach (another user's process, a container
//! naming a pid it can't reach) says nothing about the target.

use aegis_common::EventKind;
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::LruHashMap,
    programs::TracePointContext,
};

use crate::{current, emit};

const PTRACE_ATTACH: u64 = 16;
const PTRACE_SEIZE: u64 = 0x4206;

/// (request, pid) of an attach in flight, by pid_tgid.
#[map]
static PTRACE_ARGS: LruHashMap<u64, [u32; 2]> = LruHashMap::with_max_entries(1024, 0);

#[tracepoint(category = "syscalls", name = "sys_enter_ptrace")]
pub fn aegis_ptrace(ctx: TracePointContext) -> u32 {
    let request: u64 = unsafe { ctx.read_at(16) }.unwrap_or_default();
    if request != PTRACE_ATTACH && request != PTRACE_SEIZE {
        return 0;
    }
    let pid: u64 = unsafe { ctx.read_at(24) }.unwrap_or_default();
    let key = bpf_get_current_pid_tgid();
    let _ = PTRACE_ARGS.insert(&key, &[request as u32, pid as u32], 0);
    0
}

/// `ret` sits at 16, past the common header and `__syscall_nr`.
#[tracepoint(category = "syscalls", name = "sys_exit_ptrace")]
pub fn aegis_ptrace_exit(ctx: TracePointContext) -> u32 {
    let key = bpf_get_current_pid_tgid();
    let Some(args) = (unsafe { PTRACE_ARGS.get(&key) }).copied() else {
        return 0;
    };
    let _ = PTRACE_ARGS.remove(&key);
    let ret: i64 = unsafe { ctx.read_at(16) }.unwrap_or(-1);
    if ret != 0 {
        return 0;
    }
    emit(EventKind::Ptrace, |ev| {
        current(ev);
        ev.ptrace_request = args[0];
        ev.target_tgid = args[1];
    });
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_memfd_create")]
pub fn aegis_memfd(ctx: TracePointContext) -> u32 {
    let uname: u64 = unsafe { ctx.read_at(16) }.unwrap_or_default();
    emit(EventKind::MemfdCreate, |ev| {
        current(ev);
        let n = unsafe { bpf_probe_read_user_str_bytes(uname as *const u8, &mut ev.path) }
            .map_or(0, |s| s.len());
        ev.path_len = n as u32;
    });
    0
}
