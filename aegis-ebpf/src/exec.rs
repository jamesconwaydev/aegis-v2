// SPDX-License-Identifier: GPL-2.0-only
//! Exec. Two hooks cooperate so we report the file the user ran, not the
//! interpreter, and only for execs that actually commit.
//!
//! `bprm_check_security` fires once per binfmt rewrite: first for the
//! script (`bprm->file` = /tmp/evil.sh), then again for its interpreter
//! (`bprm->file` = /bin/sh). Depth 0 is recognised from kernel state:
//! until `load_script` or binfmt_misc calls `bprm_change_interp`,
//! `bprm->interp == bprm->filename`. At depth 0 we record the file's
//! resolved path and flags unconditionally, which also overwrites any
//! stale record left by an earlier exec that failed before committing;
//! later depths are skipped.
//!
//! Records are keyed by tgid. `cred_guard_mutex` allows one exec in
//! flight per thread group, and the key survives `de_thread` when a
//! non-leader thread execs (its tid becomes the tgid).
//!
//! `bprm_committed_creds` runs once, past the point of no return and
//! after `__set_task_comm`, so it has the right `comm` and never fires
//! for a failed exec; it consumes the record and emits. If no record
//! matches this bprm (e.g. tracing began mid-exec) it classifies its
//! own `bprm->file` and sets `EXEC_FALLBACK`.
//!
//! `bpf_d_path` is permitted on both hooks on 6.12, and gives the file's
//! real path rather than argv[0].

use aegis_common::{
    EventKind, EXEC_FALLBACK, EXEC_FROM_TMP, EXEC_MEMFD, PATH_MAX_EV, PATH_TRUNCATED,
};
use aya_ebpf::{
    bindings::path,
    helpers::{bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel_str_bytes},
    macros::{lsm, map},
    maps::{LruHashMap, PerCpuArray},
    programs::LsmContext,
};

use crate::{current, emit, off, read};

const SCRATCH_LEN: usize = 4096;
const ENAMETOOLONG: i64 = 36;
const TMPFS_MAGIC: u64 = 0x0102_1994;

/// The original executed file's verdict, carried from the depth-0
/// `bprm_check_security` to `bprm_committed_creds`, keyed by tgid.
#[repr(C)]
#[derive(Clone, Copy)]
struct ExecRecord {
    /// The `linux_binprm` this verdict was taken from; checked again at
    /// commit as a sanity check only.
    bprm: u64,
    flags: u32,
    path_len: u32,
    path: [u8; PATH_MAX_EV],
}

/// Room for a full PATH_MAX path, so the prefix checks below see the
/// start of a path even when it's too long for the 256-byte field.
#[map]
static SCRATCH: PerCpuArray<[u8; SCRATCH_LEN]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static RECORDS: LruHashMap<u64, ExecRecord> = LruHashMap::with_max_entries(4096, 0);

#[map]
static REC_BUILD: PerCpuArray<ExecRecord> = PerCpuArray::with_max_entries(1, 0);

#[lsm(hook = "bprm_check_security")]
pub fn aegis_exec_check(ctx: LsmContext) -> i32 {
    let _ = try_check(&ctx);
    // Gating hook: 0 allows the exec. We observe, never deny.
    0
}

#[lsm(hook = "bprm_committed_creds")]
pub fn aegis_exec(ctx: LsmContext) -> i32 {
    let _ = try_exec(&ctx);
    // bprm_committed_creds is a void LSM hook; the kernel ignores this
    // return. We only observe.
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

/// Resolves `bprm->file` and writes its path into `out`, returning
/// `(flags, path_len)`. `out` must already be zeroed.
fn classify(bprm: *const u8, out: &mut [u8; PATH_MAX_EV]) -> (u32, u32) {
    // Plain loads, not bpf_probe_read: bpf_d_path only accepts a pointer
    // the verifier can type as `struct path` by walking BTF from `bprm`.
    // OFFSETS is frozen rodata, so the verifier sees these as constants.
    let (file_off, path_off) = (off!(bprm_file), off!(file_f_path));
    let file = unsafe { *(bprm.add(file_off) as *const *const u8) };
    let fpath = unsafe { file.add(path_off) } as *mut path;

    let Some(buf) = SCRATCH.get_ptr_mut(0) else {
        return (0, 0);
    };
    let n = unsafe { bpf_d_path(fpath, buf.cast(), SCRATCH_LEN as u32) };

    let mut flags = 0;
    if on_tmpfs(file) {
        flags |= EXEC_FROM_TMP;
    }
    if n == -ENAMETOOLONG {
        flags |= PATH_TRUNCATED;
    }
    if n <= 0 {
        return (flags, 0);
    }
    let s = unsafe { &*buf };
    // n counts the trailing NUL.
    if n as usize > out.len() {
        flags |= PATH_TRUNCATED;
    }
    // A disk-backed /tmp won't trip the tmpfs check, so keep the prefixes.
    if starts_with(s, b"/tmp/") || starts_with(s, b"/var/tmp/") || starts_with(s, b"/dev/shm/") {
        flags |= EXEC_FROM_TMP;
    }
    // A memfd's dentry is "memfd:<name>" on an unmounted tmpfs, so d_path
    // renders it "/memfd:<name> (deleted)". It's tmpfs too, so it also
    // carries EXEC_FROM_TMP.
    if starts_with(s, b"/memfd:") {
        flags |= EXEC_MEMFD;
    }
    let path_len =
        unsafe { bpf_probe_read_kernel_str_bytes(s.as_ptr(), out) }.map_or(0, |p| p.len() as u32);
    (flags, path_len)
}

fn try_check(ctx: &LsmContext) -> Option<()> {
    let bprm: *const u8 = ctx.arg(0);
    // Only depth 0: a binfmt rewrite gives interp its own string.
    let filename: u64 = read(bprm, off!(bprm_filename));
    let interp: u64 = read(bprm, off!(bprm_interp));
    if filename != interp {
        return Some(());
    }
    let key = bpf_get_current_pid_tgid() >> 32;
    let rec = unsafe { &mut *REC_BUILD.get_ptr_mut(0)? };
    unsafe { core::ptr::write_bytes(rec as *mut ExecRecord, 0, 1) };
    rec.bprm = bprm as u64;
    let (flags, path_len) = classify(bprm, &mut rec.path);
    rec.flags = flags;
    rec.path_len = path_len;
    let _ = RECORDS.insert(&key, &*rec, 0);
    Some(())
}

fn try_exec(ctx: &LsmContext) -> Option<()> {
    let bprm: *const u8 = ctx.arg(0);
    let key = bpf_get_current_pid_tgid() >> 32;
    let rec = unsafe { RECORDS.get(&key) };

    emit(EventKind::Exec, |ev| {
        current(ev);
        match rec {
            // The common path: the original file's verdict, recorded at
            // the first bprm_check_security of this exec.
            Some(r) if r.bprm == bprm as u64 => {
                ev.flags |= r.flags;
                ev.path = r.path;
                ev.path_len = r.path_len;
            }
            // No matching record (tracing began mid-exec): fall back to
            // this hook's own file, which for a script is the interpreter.
            _ => {
                let (flags, path_len) = classify(bprm, &mut ev.path);
                ev.flags |= flags | EXEC_FALLBACK;
                ev.path_len = path_len;
            }
        }
    });
    let _ = RECORDS.remove(&key);
    Some(())
}
