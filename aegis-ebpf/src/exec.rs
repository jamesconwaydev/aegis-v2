// SPDX-License-Identifier: GPL-2.0-only
//! Exec, from `lsm/bprm_committed_creds`. This hook runs inside
//! `begin_new_exec` after the creds are committed: past the point of no
//! return, so a failed exec never reaches it, and after `de_thread` and
//! `__set_task_comm`, so `comm` is the new program's name. A hook on
//! `bprm_check_security` fires earlier but also fires for execs that then
//! fail, which a watcher could use to spray misleading events.
//!
//! `bprm_committed_creds` is a void LSM hook, so its return is ignored by
//! the kernel; this program observes only. `bpf_d_path` is permitted here
//! on 6.12, which gives the file's real path rather than argv[0]. Scripts
//! hit the hook once for the interpreter (the script itself fails the
//! binfmt check and never commits).

use aegis_common::{EventKind, EXEC_FROM_TMP, EXEC_MEMFD, PATH_TRUNCATED};
use aya_ebpf::{
    bindings::path,
    helpers::{bpf_d_path, bpf_probe_read_kernel_str_bytes},
    macros::{lsm, map},
    maps::PerCpuArray,
    programs::LsmContext,
};

use crate::{current, emit, off, read};

const SCRATCH_LEN: usize = 4096;
const ENAMETOOLONG: i64 = 36;
const TMPFS_MAGIC: u64 = 0x0102_1994;

/// Room for a full PATH_MAX path, so the prefix checks below see the
/// start of a path even when it's too long for `Event::path`.
#[map]
static SCRATCH: PerCpuArray<[u8; SCRATCH_LEN]> = PerCpuArray::with_max_entries(1, 0);

#[lsm(hook = "bprm_committed_creds")]
pub fn aegis_exec(ctx: LsmContext) -> i32 {
    let _ = try_exec(&ctx);
    // fmod_ret semantics: a non-zero return could only add a denial, and
    // 0 cannot override one another LSM already made. We only observe.
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

/// True when `file` lives on a tmpfs mount (`/tmp`, `/dev/shm`, a memfd,
/// or any bind mount of one). Catches what a path-prefix check misses:
/// tmpfs mounted elsewhere, and paths that d_path can't render.
#[inline(always)]
fn on_tmpfs(file: *const u8) -> bool {
    let inode: u64 = read(file, off!(file_f_inode));
    let sb: u64 = read(inode as *const u8, off!(inode_i_sb));
    let magic: u64 = read(sb as *const u8, off!(super_block_s_magic));
    magic == TMPFS_MAGIC
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
    let tmpfs = on_tmpfs(file);

    emit(EventKind::Exec, |ev| {
        current(ev);
        if tmpfs {
            ev.flags |= EXEC_FROM_TMP;
        }
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
        // A disk-backed /tmp won't trip the tmpfs check, so keep the
        // path prefixes too.
        if starts_with(s, b"/tmp/") || starts_with(s, b"/var/tmp/") || starts_with(s, b"/dev/shm/")
        {
            ev.flags |= EXEC_FROM_TMP;
        }
        // A memfd's dentry is "memfd:<name>" on an unmounted tmpfs, so
        // d_path renders it as "/memfd:<name> (deleted)". It's tmpfs too,
        // so it also carries EXEC_FROM_TMP.
        if starts_with(s, b"/memfd:") {
            ev.flags |= EXEC_MEMFD;
        }
        if let Ok(p) = unsafe { bpf_probe_read_kernel_str_bytes(s.as_ptr(), &mut ev.path) } {
            ev.path_len = p.len() as u32;
        }
    });
    Some(())
}
