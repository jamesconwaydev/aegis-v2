// SPDX-License-Identifier: GPL-2.0-only
//! Outbound TCP connects, from `sock/inet_sock_set_state`. Two events per
//! attempt: one at CLOSE -> SYN_SENT (`ret` = -EINPROGRESS), and one for
//! the outcome (0 on ESTABLISHED, -sk_err on CLOSE).
//!
//! The outcome usually fires in softirq context, where `current` is
//! whatever happened to be running, so the SYN_SENT event is kept in
//! `CONNECTS` and the outcome reuses its subject fields.
//!
//! IPv4-mapped IPv6 addresses are passed through in `daddr` as the kernel
//! reports them; userspace normalises them (Task 7).

use aegis_common::{Event, EventKind};
use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::{LruHashMap, PerCpuArray},
    programs::TracePointContext,
};

use crate::{current, emit_val, off, read};

const IPPROTO_TCP: u16 = 6;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const TCP_ESTABLISHED: i32 = 1;
const TCP_SYN_SENT: i32 = 2;
const EINPROGRESS: i32 = 115;
const ECONNABORTED: i32 = 103;

#[map]
static CONNECTS: LruHashMap<u64, Event> = LruHashMap::with_max_entries(8192, 0);

/// Scratch for building an event off the stack (an `Event` is too big to
/// sit in a probe's 512-byte frame).
#[map]
static BUILD: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint(category = "sock", name = "inet_sock_set_state")]
pub fn aegis_connect(ctx: TracePointContext) -> u32 {
    let _ = try_connect(&ctx);
    0
}

fn try_connect(ctx: &TracePointContext) -> Result<(), i32> {
    let at = |off| unsafe { ctx.read_at::<u16>(off) };
    if at(30)? != IPPROTO_TCP {
        return Ok(());
    }
    let sk: u64 = unsafe { ctx.read_at(8)? };
    let old: i32 = unsafe { ctx.read_at(16)? };
    let new: i32 = unsafe { ctx.read_at(20)? };

    let ev = unsafe { &mut *BUILD.get_ptr_mut(0).ok_or(0)? };

    if new == TCP_SYN_SENT {
        let family = at(28)?;
        let dport = at(26)?;
        let mut daddr = [0u8; 16];
        match family {
            AF_INET => daddr[..4].copy_from_slice(&unsafe { ctx.read_at::<[u8; 4]>(36)? }),
            AF_INET6 => daddr = unsafe { ctx.read_at(56)? },
            _ => return Ok(()),
        }
        unsafe { core::ptr::write_bytes(ev as *mut Event, 0, 1) };
        ev.kind = EventKind::Connect as u32;
        current(ev);
        ev.family = family;
        ev.dport = dport;
        ev.daddr = daddr;
        ev.ret = -EINPROGRESS;
        // Store first, so a full ring buffer can't cost us the later
        // outcome event as well as this one.
        let _ = CONNECTS.insert(&sk, &*ev, 0);
        emit_val(ev);
    } else if old == TCP_SYN_SENT {
        let Some(started) = (unsafe { CONNECTS.get(&sk) }) else {
            return Ok(());
        };
        *ev = *started;
        ev.ts_ns = unsafe { bpf_ktime_get_ns() };
        ev.ret = if new == TCP_ESTABLISHED {
            0
        } else {
            match read::<i32>(sk as *const u8, off!(sock_sk_err)) {
                0 => -ECONNABORTED,
                e => -e,
            }
        };
        emit_val(ev);
        let _ = CONNECTS.remove(&sk);
    }
    Ok(())
}
