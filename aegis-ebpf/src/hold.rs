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
//! An entry with a `net_cgroup` is an open hold (honeypot): the process
//! may connect and send, but only on an IPv4 or IPv6 socket in
//! `init_net` that was created in that cgroup, so sockets from before the
//! move stay refused. It may fork. Everything else stays refused.
//!
//! `inherit` copies whatever hold the parent has to each new process
//! before it first runs. A fork that passed `task_alloc` just before its
//! parent was held, or before an open hold was closed, still yields a
//! held child.
//!
//! `aegis_guard` sits on the quarantine slice's egress and drops whatever
//! isn't IPv4 to the honeypot, in case the nft redirect is ever missing.
//!
//! Separately, `ptrace_access_check` keeps everyone but aegisd itself
//! from attaching to aegisd (`AEGISD[0]`), held or not.

use aegis_common::Hold;
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task},
    macros::{cgroup_skb, lsm, map},
    maps::{Array, HashMap},
    programs::{LsmContext, SkBuffContext},
};

use crate::{off, read};

const EPERM: i32 = 1;
const EAGAIN: i32 = 11;
/// `PTRACE_MODE_ATTACH`; `PTRACE_MODE_READ` (plain /proc reads by ps and
/// systemd) stays allowed against aegisd.
const PTRACE_MODE_ATTACH: u32 = 0x02;
const MAY_WRITE: i32 = 0x02;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const S_IFMT: u16 = 0o170000;
const S_IFSOCK: u16 = 0o140000;
/// `READING_MODULE` / `LOADING_MODULE`, and the `_COMPRESSED` pair that
/// RHEL 10's 6.12 carries (upstream kernels without it never pass 7).
const MODULE_ID: u32 = 2;
const MODULE_COMPRESSED_ID: u32 = 7;

#[inline(always)]
fn is_module(id: u32) -> bool {
    id == MODULE_ID || id == MODULE_COMPRESSED_ID
}

#[map]
pub(crate) static HELD: HashMap<u32, Hold> = HashMap::with_max_entries(16384, 0);

/// The honeypot's TCP and DNS ports, host order; 0 allows nothing.
#[map]
static GUARD_PORTS: Array<u16> = Array::with_max_entries(2, 0);

/// aegisd's own tgid, written by aegisd at load.
#[map]
static AEGISD: Array<u32> = Array::with_max_entries(1, 0);

#[inline(always)]
fn current_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

/// The current process's hold, if it has one.
#[inline(always)]
fn held() -> Option<Hold> {
    let h = *(unsafe { HELD.get(&current_tgid()) })?;
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let leader: u64 = read(task, off!(task_group_leader));
    (h.start_time_ns == read::<u64>(leader as *const u8, off!(task_start_time))).then_some(h)
}

#[inline(always)]
fn deny(errno: i32) -> i32 {
    if held().is_some() {
        -errno
    } else {
        0
    }
}

/// Called from `sched_process_fork`, after the child is set up and
/// before it is first woken. The child gets the parent's hold as it
/// stands now, open or not, so nothing it runs ever goes unheld.
#[inline(always)]
pub(crate) fn inherit(child_tgid: u32, child_start_time_ns: u64) {
    if let Some(h) = held() {
        let hold = Hold {
            start_time_ns: child_start_time_ns,
            net_cgroup: h.net_cgroup,
        };
        let _ = HELD.insert(&child_tgid, &hold, 0);
    }
}

/// A plain hold refuses every fork. An open one allows them (threads
/// need nothing; `inherit` holds new processes), but not into another
/// cgroup, which would carry a child out of the scope's rules.
#[lsm(hook = "task_alloc")]
pub fn aegis_hold_fork(ctx: LsmContext) -> i32 {
    let Some(h) = held() else {
        return 0;
    };
    if h.net_cgroup == 0 {
        return -EAGAIN;
    }
    let flags: u64 = ctx.arg(1);
    if flags & CLONE_INTO_CGROUP != 0 {
        return -EPERM;
    }
    0
}

/// Whether an open hold may use `sock` (a `struct socket *`).
#[inline(always)]
fn sock_net(sock: *const u8) -> i32 {
    let Some(h) = held() else {
        return 0;
    };
    if h.net_cgroup == 0 {
        return -EPERM;
    }
    let sk: u64 = read(sock, off!(sock_sk));
    let sk = sk as *const u8;
    let family: u16 = read(sk, off!(sk_family));
    if family != AF_INET && family != AF_INET6 {
        return -EPERM;
    }
    let net: u64 = read(sk, off!(sk_net));
    let inum: u32 = read(net as *const u8, off!(net_inum));
    if inum == 0 || inum != off!(init_net_inum) as u32 {
        return -EPERM;
    }
    let cgrp: u64 = read(sk, off!(sk_cgrp_data));
    let kn: u64 = read(cgrp as *const u8, off!(cgroup_kn));
    if read::<u64>(kn as *const u8, off!(kn_id)) != h.net_cgroup {
        return -EPERM;
    }
    0
}

#[lsm(hook = "socket_connect")]
pub fn aegis_hold_connect(ctx: LsmContext) -> i32 {
    sock_net(ctx.arg(0))
}

#[lsm(hook = "socket_sendmsg")]
pub fn aegis_hold_sendmsg(ctx: LsmContext) -> i32 {
    sock_net(ctx.arg(0))
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

/// Writes through any fd, including ones opened before the hold. An
/// open hold may write to a socket; `socket_sendmsg` then decides.
#[lsm(hook = "file_permission")]
pub fn aegis_hold_write(ctx: LsmContext) -> i32 {
    let mask: i32 = ctx.arg(1);
    if mask & MAY_WRITE == 0 {
        return 0;
    }
    let Some(h) = held() else {
        return 0;
    };
    if h.net_cgroup != 0 {
        let file: *const u8 = ctx.arg(0);
        let inode: u64 = read(file, off!(file_f_inode));
        let mode: u16 = read(inode as *const u8, off!(inode_i_mode));
        if mode & S_IFMT == S_IFSOCK {
            return 0;
        }
    }
    -EPERM
}

#[lsm(hook = "userns_create")]
pub fn aegis_hold_userns(_ctx: LsmContext) -> i32 {
    deny(EPERM)
}

/// Only a held sender is refused: systemd and root must still be able
/// to stop and reload aegisd.
#[lsm(hook = "task_kill")]
pub fn aegis_hold_kill(ctx: LsmContext) -> i32 {
    if held().is_none() {
        return 0;
    }
    let p: *const u8 = ctx.arg(0);
    let target: u32 = read(p, off!(task_tgid));
    match AEGISD.get(0) {
        Some(&me) if me != 0 && target == me => -EPERM,
        _ => 0,
    }
}

/// Egress from the quarantine slice: only IPv4 TCP or UDP to
/// 127.77.0.0/16 on a `GUARD_PORTS` port gets out; 1 passes, 0 drops.
#[cgroup_skb(egress)]
pub fn aegis_guard(ctx: SkBuffContext) -> i32 {
    guard(&ctx).unwrap_or(0)
}

#[inline(always)]
fn guard(ctx: &SkBuffContext) -> Result<i32, i64> {
    const ETH_P_IP: u16 = 0x0800;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_UDP: u8 = 17;
    // __sk_buff.protocol is in network byte order.
    if ctx.skb.protocol() != u32::from(ETH_P_IP.to_be()) {
        return Ok(0);
    }
    let vihl: u8 = ctx.load(0)?;
    let proto: u8 = ctx.load(9)?;
    let frag: [u8; 2] = ctx.load(6)?;
    let daddr: [u8; 4] = ctx.load(16)?;
    // A later fragment has no ports to check.
    if vihl >> 4 != 4
        || (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        || u16::from_be_bytes(frag) & 0x1fff != 0
        || daddr[0] != 127
        || daddr[1] != 77
    {
        return Ok(0);
    }
    let dport: [u8; 2] = ctx.load(usize::from(vihl & 0x0f) * 4 + 2)?;
    let dport = u16::from_be_bytes(dport);
    let port = |i| GUARD_PORTS.get(i).copied().unwrap_or(0);
    Ok(i32::from(
        dport != 0 && (dport == port(0) || dport == port(1)),
    ))
}
