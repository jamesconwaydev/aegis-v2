// SPDX-License-Identifier: GPL-2.0-only
//! Observe-only probes. Each one writes an `aegis_common::Event` to the
//! `EVENTS` ring buffer; when the buffer is full the event is counted in
//! `DROPPED` instead.
//!
//! Kernel struct fields are read at offsets userspace resolves from the
//! running kernel's BTF and patches into `OFFSETS` before load (Rust has
//! no CO-RE), so one object works across kernel builds and arches.
#![no_std]
#![no_main]

mod connect;
mod exec;
mod sched;
mod syscalls;

use aegis_common::{Event, EventKind, KernelOffsets, HAS_TTY};
use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_task, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
    },
    macros::map,
    maps::{PerCpuArray, RingBuf},
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4 << 20, 0);

#[map]
static DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[no_mangle]
static OFFSETS: KernelOffsets = KernelOffsets {
    task_tgid: 0,
    task_real_parent: 0,
    task_group_leader: 0,
    task_start_time: 0,
    task_signal: 0,
    signal_tty: 0,
    bprm_file: 0,
    file_f_path: 0,
    sock_sk_err: 0,
};

/// Volatile, so the compiler can't fold the zero the object ships with.
macro_rules! off {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(&crate::OFFSETS.$field) as usize }
    };
}
pub(crate) use off;

/// Reads a `T` at `base + off` from kernel memory, zero on fault.
#[inline(always)]
pub(crate) fn read<T: Default>(base: *const u8, off: usize) -> T {
    unsafe { bpf_probe_read_kernel(base.wrapping_add(off) as *const T) }.unwrap_or_default()
}

/// Reserves a zeroed event, lets `fill` write it, and submits it.
#[inline(always)]
pub(crate) fn emit(kind: EventKind, fill: impl FnOnce(&mut Event)) {
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        if let Some(n) = DROPPED.get_ptr_mut(0) {
            unsafe { *n += 1 };
        }
        return;
    };
    let ev = unsafe {
        core::ptr::write_bytes(entry.as_mut_ptr(), 0, 1);
        &mut *entry.as_mut_ptr()
    };
    ev.kind = kind as u32;
    fill(ev);
    entry.submit(0);
}

/// Fills the subject fields from the current task.
#[inline(always)]
pub(crate) fn current(ev: &mut Event) {
    let pid_tgid = bpf_get_current_pid_tgid();
    ev.tgid = (pid_tgid >> 32) as u32;
    ev.pid = pid_tgid as u32;
    ev.uid = bpf_get_current_uid_gid() as u32;
    ev.comm = bpf_get_current_comm().unwrap_or_default();
    unsafe {
        ev.ts_ns = bpf_ktime_get_ns();
        ev.cgroup_id = bpf_get_current_cgroup_id();
    }

    let task = unsafe { bpf_get_current_task() } as *const u8;
    let leader: u64 = read(task, off!(task_group_leader));
    ev.start_time_ns = read(leader as *const u8, off!(task_start_time));
    let parent: u64 = read(task, off!(task_real_parent));
    ev.ppid = read(parent as *const u8, off!(task_tgid));
    let signal: u64 = read(task, off!(task_signal));
    let tty: u64 = read(signal as *const u8, off!(signal_tty));
    if tty != 0 {
        ev.flags |= HAS_TTY;
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";
