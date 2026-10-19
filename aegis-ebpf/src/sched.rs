// SPDX-License-Identifier: GPL-2.0-only
//! Fork and exit. Fork uses the BTF tracepoint because the classic one
//! only carries the child's thread id, not its thread-group id.

use aegis_common::EventKind;
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task},
    macros::{btf_tracepoint, map, tracepoint},
    maps::LruHashMap,
    programs::{BtfTracePointContext, TracePointContext},
};

use crate::{current, emit, off, read};

/// Leader start times we've already emitted an Exit for, so a race
/// between the last threads can't double-report one process. The key is
/// the leader's start_time_ns, not a pointer: a freed signal_struct or
/// task_struct is slab-reused by the next short-lived process, which
/// would collide and suppress a real exit. A monotonic start time is
/// effectively unique and never reused.
#[map]
static EXITED: LruHashMap<u64, u8> = LruHashMap::with_max_entries(4096, 0);

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
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let signal: u64 = read(task, off!(task_signal));
    let live: i32 = read(signal as *const u8, off!(signal_live));
    if live != 0 {
        return 0;
    }
    // Dedupe by the leader's start time, in case two threads race to zero.
    let leader: u64 = read(task, off!(task_group_leader));
    let key: u64 = read(leader as *const u8, off!(task_start_time));
    if unsafe { EXITED.get(&key) }.is_some() {
        return 0;
    }
    let _ = EXITED.insert(&key, &0, 0);
    emit(EventKind::Exit, current);
    0
}
