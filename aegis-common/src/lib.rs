// SPDX-License-Identifier: MIT OR Apache-2.0
//! Types shared between the eBPF programs and userspace. The `user`
//! feature pulls in aya so userspace can implement `aya::Pod` for them.
#![cfg_attr(not(test), no_std)]

pub const PATH_MAX_EV: usize = 256;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Exec = 1,
    Fork = 2,
    Exit = 3,
    Ptrace = 4,
    MemfdCreate = 5,
    Connect = 6,
}

impl TryFrom<u32> for EventKind {
    type Error = u32;

    fn try_from(v: u32) -> Result<Self, u32> {
        Ok(match v {
            1 => Self::Exec,
            2 => Self::Fork,
            3 => Self::Exit,
            4 => Self::Ptrace,
            5 => Self::MemfdCreate,
            6 => Self::Connect,
            _ => return Err(v),
        })
    }
}

/// `Event::flags` bits.
pub const EXEC_FROM_TMP: u32 = 1;
pub const EXEC_MEMFD: u32 = 2;
pub const PATH_TRUNCATED: u32 = 4;
pub const HAS_TTY: u32 = 8;

/// One record on the `EVENTS` ring buffer. Fields after `flags` are only
/// meaningful for the kind named beside them; the rest are zero.
///
/// Padding is spelled out as `_pad*` so there are no uninitialised holes:
/// the eBPF side zeroes the whole record, and that soundness is what lets
/// userspace treat it as `aya::Pod`.
///
/// The `daddr` IPv6 bytes aren't normalised: an IPv4-mapped v6 address
/// arrives as-is, and ptrace `target_tgid` is a pid in the tracer's pid
/// namespace. Both are translated in userspace (Task 7), not here.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub kind: u32,
    pub tgid: u32,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub _pad0: u32,
    /// Thread-group leader's start time, CLOCK_MONOTONIC. With `tgid` this
    /// is the process identity that survives pid reuse.
    pub start_time_ns: u64,
    /// CLOCK_MONOTONIC.
    pub ts_ns: u64,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
    /// Exec: the file's resolved path. MemfdCreate: the memfd name.
    pub path: [u8; PATH_MAX_EV],
    pub path_len: u32,
    pub flags: u32,
    // Ptrace
    pub target_tgid: u32,
    pub ptrace_request: u32,
    // Fork
    pub child_tgid: u32,
    // Connect
    pub family: u16,
    pub dport: u16,
    pub daddr: [u8; 16],
    pub ret: i32,
    pub _pad1: u32,
    /// Fork: the child's own start time, so the child's `(tgid,
    /// start_time_ns)` identity can be formed from the fork event alone.
    pub child_start_time_ns: u64,
}

/// Kernel struct member offsets, in bytes. Rust has no CO-RE, so
/// userspace reads them from the running kernel's BTF and patches them
/// into the eBPF object's `OFFSETS` global before loading.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelOffsets {
    pub task_tgid: u32,
    pub task_real_parent: u32,
    pub task_group_leader: u32,
    pub task_start_time: u32,
    pub task_signal: u32,
    pub signal_tty: u32,
    pub signal_live: u32,
    pub bprm_file: u32,
    pub file_f_path: u32,
    pub file_f_inode: u32,
    pub inode_i_sb: u32,
    pub super_block_s_magic: u32,
    pub sock_sk_err: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for KernelOffsets {}

// The eBPF side and userspace must agree on this layout byte for byte.
const _: () = assert!(core::mem::offset_of!(Event, cgroup_id) == 40);
const _: () = assert!(core::mem::offset_of!(Event, child_start_time_ns) == 368);
const _: () = assert!(core::mem::size_of::<Event>() == 376);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_size_is_a_multiple_of_eight() {
        assert_eq!(core::mem::size_of::<Event>() % 8, 0);
    }
}
