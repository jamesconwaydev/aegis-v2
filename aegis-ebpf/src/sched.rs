// SPDX-License-Identifier: GPL-2.0-only
//! Fork and exit. Fork uses the BTF tracepoint because the classic one
//! only carries the child's thread id, not its thread-group id.

use aegis_common::EventKind;
use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{btf_tracepoint, tracepoint},
    programs::{BtfTracePointContext, TracePointContext},
};

use crate::{current, emit, off, read};

#[btf_tracepoint(function = "sched_process_fork")]
pub fn aegis_fork(ctx: BtfTracePointContext) -> i32 {
    let child: *const u8 = ctx.arg(1);
    let child_tgid: u32 = read(child, off!(task_tgid));
    // A new thread joins our thread group; only new processes count.
    if child_tgid == (bpf_get_current_pid_tgid() >> 32) as u32 {
        return 0;
    }
    emit(EventKind::Fork, |ev| {
        current(ev);
        ev.child_tgid = child_tgid;
        // The child is its own group leader, so its own start time is the
        // one that pairs with child_tgid to identify the new process.
        ev.child_start_time_ns = read(child, off!(task_start_time));
    });
    0
}

#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn aegis_exit(_ctx: TracePointContext) -> u32 {
    // Emit once per process, when the last thread goes. signal->live is
    // already decremented by the time this tracepoint fires, so it reads
    // zero on the final thread's exit.
    let task = unsafe { aya_ebpf::helpers::bpf_get_current_task() } as *const u8;
    let signal: u64 = read(task, off!(task_signal));
    let live: i32 = read(signal as *const u8, off!(signal_live));
    if live == 0 {
        emit(EventKind::Exit, current);
    }
    0
}
