// SPDX-License-Identifier: GPL-2.0-only
//! Exec, from `lsm/bprm_check_security`. It's the earliest point where
//! the kernel has opened the file being executed, and an LSM hook on it
//! may call `bpf_d_path`, which gives the real path rather than argv[0].
//! Scripts hit the hook once for the script and once per interpreter.

use aegis_common::{EventKind, EXEC_FROM_TMP, EXEC_MEMFD, PATH_TRUNCATED};
use aya_ebpf::{
    bindings::path,
    helpers::{bpf_d_path, bpf_probe_read_kernel_str_bytes},
    macros::{lsm, map},
    maps::PerCpuArray,
    programs::LsmContext,
};

use crate::{current, emit, off};

const SCRATCH_LEN: usize = 4096;
const ENAMETOOLONG: i64 = 36;

/// Room for a full PATH_MAX path, so the prefix checks below see the
/// start of a path even when it's too long for `Event::path`.
#[map]
static SCRATCH: PerCpuArray<[u8; SCRATCH_LEN]> = PerCpuArray::with_max_entries(1, 0);

#[lsm(hook = "bprm_check_security")]
pub fn aegis_exec(ctx: LsmContext) -> i32 {
    let _ = try_exec(&ctx);
    // Observe only: never deny.
    0
}

#[inline(always)]
fn starts_with(s: &[u8; SCRATCH_LEN], prefix: &[u8]) -> bool {
    let mut i = 0;
    while i < prefix.len() {
        if s[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

fn try_exec(ctx: &LsmContext) -> Option<()> {
    let bprm: *const u8 = ctx.arg(0);
    // Plain loads, not bpf_probe_read: bpf_d_path only accepts a pointer
    // the verifier can type as `struct path` by walking BTF from `bprm`.
    // OFFSETS is frozen rodata, so the verifier sees these as constants.
    let (file_off, path_off) = (off!(bprm_file), off!(file_f_path));
    let file = unsafe { *(bprm.add(file_off) as *const *const u8) };
    let fpath = unsafe { file.add(path_off) } as *mut path;

    let buf = SCRATCH.get_ptr_mut(0)?;
    let n = unsafe { bpf_d_path(fpath, buf.cast(), SCRATCH_LEN as u32) };

    emit(EventKind::Exec, |ev| {
        current(ev);
        if n == -ENAMETOOLONG {
            ev.flags |= PATH_TRUNCATED;
        }
        if n <= 0 {
            return;
        }
        let s = unsafe { &*buf };
        // n counts the trailing NUL.
        if n as usize > ev.path.len() {
            ev.flags |= PATH_TRUNCATED;
        }
        if starts_with(s, b"/tmp/") || starts_with(s, b"/var/tmp/") || starts_with(s, b"/dev/shm/")
        {
            ev.flags |= EXEC_FROM_TMP;
        }
        // A memfd's dentry is "memfd:<name>" on an unmounted tmpfs, so
        // d_path renders it as "/memfd:<name> (deleted)".
        if starts_with(s, b"/memfd:") {
            ev.flags |= EXEC_MEMFD;
        }
        if let Ok(p) = unsafe { bpf_probe_read_kernel_str_bytes(s.as_ptr(), &mut ev.path) } {
            ev.path_len = p.len() as u32;
        }
    });
    Some(())
}
