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
    });
    0
}

#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn aegis_exit(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    if pid_tgid >> 32 == pid_tgid & 0xffff_ffff {
        emit(EventKind::Exit, current);
    }
    0
}
