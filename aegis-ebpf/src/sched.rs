// SPDX-License-Identifier: GPL-2.0-only
//! Fork and exit. Fork uses the BTF tracepoint because the classic one
//! only carries the child's thread id, not its thread-group id.

use aegis_common::EventKind;
use aya_ebpf::{
    bindings::BPF_NOEXIST,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task},
    macros::{btf_tracepoint, map, tracepoint},
    maps::LruHashMap,
    programs::{BtfTracePointContext, TracePointContext},
};

use crate::{current, emit, hold::HELD, off, read};

/// Processes we've already emitted an Exit for, so a race between the
/// last threads can't double-report one. Keyed by (tgid, leader
/// start_time_ns), not a pointer: a freed signal_struct is slab-reused by
/// the next short-lived process and would suppress its real exit.
#[map]
static EXITED: LruHashMap<[u64; 2], u8> = LruHashMap::with_max_entries(4096, 0);

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
    let tgid = bpf_get_current_pid_tgid() >> 32;
    // The process is gone, so its hold is too; a later process reusing
    // the tgid must start unheld.
    let _ = HELD.remove(&(tgid as u32));
    // BPF_NOEXIST makes the check-and-claim atomic: only the first thread
    // to insert this process's key emits.
    let leader: u64 = read(task, off!(task_group_leader));
    let start: u64 = read(leader as *const u8, off!(task_start_time));
    let key = [tgid, start];
    if EXITED.insert(&key, &0, BPF_NOEXIST as u64).is_ok() {
        emit(EventKind::Exit, current);
    }
    0
}
