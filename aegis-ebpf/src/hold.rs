// SPDX-License-Identifier: GPL-2.0-only
//! The hold: once userspace puts a process in `HELD`, these hooks refuse
//! it anything that could do harm before it is moved and frozen. Every
//! hook allows (returns 0) for a task that isn't held, after one map
//! lookup; `file_permission` and `socket_sendmsg` sit on hot paths.
//!
//! An entry is keyed by tgid and carries the leader's start time, so a
//! recycled tgid is never held by mistake. `sched.rs` deletes the entry
//! when the process exits.
//!
//! Separately, `ptrace_access_check` keeps everyone but aegisd itself
//! from attaching to aegisd (`AEGISD[0]`), held or not.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task},
    macros::{lsm, map},
    maps::{Array, HashMap},
    programs::LsmContext,
};

use crate::{off, read};

const EPERM: i32 = 1;
const EAGAIN: i32 = 11;
/// `PTRACE_MODE_ATTACH`; `PTRACE_MODE_READ` (plain /proc reads by ps and
/// systemd) stays allowed against aegisd.
const PTRACE_MODE_ATTACH: u32 = 0x02;
const MAY_WRITE: i32 = 0x02;
/// `READING_MODULE` / `LOADING_MODULE`, and the `_COMPRESSED` pair that
/// RHEL 10's 6.12 carries (upstream kernels without it never pass 7).
const MODULE_ID: u32 = 2;
const MODULE_COMPRESSED_ID: u32 = 7;

#[inline(always)]
fn is_module(id: u32) -> bool {
    id == MODULE_ID || id == MODULE_COMPRESSED_ID
}

/// tgid -> group leader's start_time_ns.
#[map]
pub(crate) static HELD: HashMap<u32, u64> = HashMap::with_max_entries(16384, 0);

/// aegisd's own tgid, written by aegisd at load.
#[map]
static AEGISD: Array<u32> = Array::with_max_entries(1, 0);

#[inline(always)]
fn current_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

#[inline(always)]
fn held() -> bool {
    let Some(&start) = (unsafe { HELD.get(&current_tgid()) }) else {
        return false;
    };
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let leader: u64 = read(task, off!(task_group_leader));
    start == read::<u64>(leader as *const u8, off!(task_start_time))
}

#[inline(always)]
fn deny(errno: i32) -> i32 {
    if held() {
        -errno
    } else {
        0
    }
}

#[lsm(hook = "task_alloc")]
pub fn aegis_hold_fork(_ctx: LsmContext) -> i32 {
    deny(EAGAIN)
}

#[lsm(hook = "socket_connect")]
pub fn aegis_hold_connect(_ctx: LsmContext) -> i32 {
    deny(EPERM)
}

#[lsm(hook = "socket_sendmsg")]
pub fn aegis_hold_sendmsg(_ctx: LsmContext) -> i32 {
    deny(EPERM)
}

#[lsm(hook = "sb_mount")]
pub fn aegis_hold_mount(_ctx: LsmContext) -> i32 {
    deny(EPERM)
}

#[lsm(hook = "move_mount")]
pub fn aegis_hold_move_mount(_ctx: LsmContext) -> i32 {
    deny(EPERM)
}

#[lsm(hook = "bpf")]
pub fn aegis_hold_bpf(_ctx: LsmContext) -> i32 {
    deny(EPERM)
}

#[lsm(hook = "kernel_module_request")]
pub fn aegis_hold_modreq(_ctx: LsmContext) -> i32 {
    deny(EPERM)
}

/// finit_module.
#[lsm(hook = "kernel_read_file")]
pub fn aegis_hold_modread(ctx: LsmContext) -> i32 {
    if !is_module(ctx.arg(1)) {
        return 0;
    }
    deny(EPERM)
}

/// init_module, which hands the image over from memory and so never
/// reaches kernel_read_file.
#[lsm(hook = "kernel_load_data")]
pub fn aegis_hold_modload(ctx: LsmContext) -> i32 {
    if !is_module(ctx.arg(0)) {
        return 0;
    }
    deny(EPERM)
}

#[lsm(hook = "ptrace_access_check")]
pub fn aegis_hold_ptrace(ctx: LsmContext) -> i32 {
    let mode: u32 = ctx.arg(1);
    if mode & PTRACE_MODE_ATTACH != 0 {
        if let Some(&me) = AEGISD.get(0) {
            let child: *const u8 = ctx.arg(0);
            let target: u32 = read(child, off!(task_tgid));
            if me != 0 && target == me && current_tgid() != me {
                return -EPERM;
            }
        }
    }
    deny(EPERM)
}

/// Writes through any fd, including ones opened before the hold.
#[lsm(hook = "file_permission")]
pub fn aegis_hold_write(ctx: LsmContext) -> i32 {
    let mask: i32 = ctx.arg(1);
    if mask & MAY_WRITE == 0 {
        return 0;
    }
    deny(EPERM)
}

#[lsm(hook = "userns_create")]
pub fn aegis_hold_userns(_ctx: LsmContext) -> i32 {
    deny(EPERM)
}

/// Only a held sender is refused: systemd and root must still be able
/// to stop and reload aegisd.
#[lsm(hook = "task_kill")]
pub fn aegis_hold_kill(ctx: LsmContext) -> i32 {
    if !held() {
        return 0;
    }
    let p: *const u8 = ctx.arg(0);
    let target: u32 = read(p, off!(task_tgid));
    match AEGISD.get(0) {
        Some(&me) if me != 0 && target == me => -EPERM,
        _ => 0,
    }
}
