// SPDX-License-Identifier: GPL-2.0-only
//! ptrace and memfd_create, from their syscall-entry tracepoints. The
//! arguments sit at 16 + 8n, past the common header and `__syscall_nr`.
//!
//! `target_tgid` is the raw pid argument, a pid in the tracer's pid
//! namespace; userspace translates it to the host namespace (Task 7).

use aegis_common::EventKind;
use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes, macros::tracepoint, programs::TracePointContext,
};

use crate::{current, emit};

const PTRACE_ATTACH: u64 = 16;
const PTRACE_SEIZE: u64 = 0x4206;

#[tracepoint(category = "syscalls", name = "sys_enter_ptrace")]
pub fn aegis_ptrace(ctx: TracePointContext) -> u32 {
    let request: u64 = unsafe { ctx.read_at(16) }.unwrap_or_default();
    if request != PTRACE_ATTACH && request != PTRACE_SEIZE {
        return 0;
    }
    let pid: u64 = unsafe { ctx.read_at(24) }.unwrap_or_default();
    emit(EventKind::Ptrace, |ev| {
        current(ev);
        ev.target_tgid = pid as u32;
        ev.ptrace_request = request as u32;
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
