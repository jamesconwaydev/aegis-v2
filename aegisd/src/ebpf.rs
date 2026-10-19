// SPDX-License-Identifier: MIT OR Apache-2.0
//! Loads the probes and streams their events.
//!
//! The eBPF object reads kernel structs at offsets we look up here, in
//! the running kernel's BTF, and patch into its `OFFSETS` global. Rust
//! has no CO-RE, and bindings generated from one kernel's BTF would go
//! stale with the next kernel update, so nothing is baked in at build
//! time.

mod btf;

use aegis_common::{Event, KernelOffsets};
use anyhow::{anyhow, Context as _, Result};
use aya::{
    maps::{MapData, PerCpuArray, RingBuf},
    programs::{BtfTracePoint, Lsm, TracePoint},
    Ebpf, EbpfLoader,
};
use tokio::{
    io::{unix::AsyncFd, Interest},
    sync::mpsc,
};

const BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

pub struct Config {
    /// Events buffered between the ring buffer reader and the consumer.
    /// When it fills, the reader stops draining and the kernel side
    /// counts what it can't write in `DROPPED`.
    pub channel_capacity: usize,
}

pub struct EbpfHandle {
    // Owns the loaded programs; dropping it detaches them.
    _ebpf: Ebpf,
    dropped: PerCpuArray<MapData, u64>,
}

impl EbpfHandle {
    /// Events the probes couldn't fit in the ring buffer, since load.
    pub fn dropped_events(&self) -> u64 {
        self.dropped
            .get(&0, 0)
            .map(|per_cpu| per_cpu.iter().sum())
            .unwrap_or(0)
    }
}

fn kernel_offsets(btf: &btf::Btf) -> Result<KernelOffsets> {
    Ok(KernelOffsets {
        task_tgid: btf.offset("task_struct", "tgid")?,
        task_real_parent: btf.offset("task_struct", "real_parent")?,
        task_group_leader: btf.offset("task_struct", "group_leader")?,
        task_start_time: btf.offset("task_struct", "start_time")?,
        task_signal: btf.offset("task_struct", "signal")?,
        signal_tty: btf.offset("signal_struct", "tty")?,
        signal_live: btf.offset("signal_struct", "live")?,
        bprm_file: btf.offset("linux_binprm", "file")?,
        bprm_filename: btf.offset("linux_binprm", "filename")?,
        bprm_interp: btf.offset("linux_binprm", "interp")?,
        file_f_path: btf.offset("file", "f_path")?,
        file_f_inode: btf.offset("file", "f_inode")?,
        inode_i_sb: btf.offset("inode", "i_sb")?,
        super_block_s_magic: btf.offset("super_block", "s_magic")?,
        sock_sk_err: btf.offset("sock", "sk_err")?,
    })
}

/// Loads and attaches every probe. Must be called inside a tokio
/// runtime: the ring buffer reader runs as a task on it.
pub fn start(cfg: &Config) -> Result<(EbpfHandle, mpsc::Receiver<Event>)> {
    let raw = std::fs::read(BTF_PATH).with_context(|| format!("reading {BTF_PATH}"))?;
    let offsets = kernel_offsets(&btf::Btf::parse(&raw)?)?;
    let kernel_btf = aya::Btf::from_sys_fs().context("parsing kernel BTF")?;

    let mut ebpf = EbpfLoader::new()
        .override_global("OFFSETS", &offsets, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/aegis"
        )))
        .context("loading eBPF object")?;

    // Records the original file at the first check; emits at commit.
    let check: &mut Lsm = prog(&mut ebpf, "aegis_exec_check")?;
    check.load("bprm_check_security", &kernel_btf)?;
    check.attach()?;

    let lsm: &mut Lsm = prog(&mut ebpf, "aegis_exec")?;
    lsm.load("bprm_committed_creds", &kernel_btf)?;
    lsm.attach()?;

    let fork: &mut BtfTracePoint = prog(&mut ebpf, "aegis_fork")?;
    fork.load("sched_process_fork", &kernel_btf)?;
    fork.attach()?;

    for (name, category, tracepoint) in [
        ("aegis_exit", "sched", "sched_process_exit"),
        ("aegis_ptrace", "syscalls", "sys_enter_ptrace"),
        ("aegis_memfd", "syscalls", "sys_enter_memfd_create"),
        ("aegis_connect", "sock", "inet_sock_set_state"),
    ] {
        let tp: &mut TracePoint = prog(&mut ebpf, name)?;
        tp.load()?;
        tp.attach(category, tracepoint)
            .with_context(|| format!("attaching {category}/{tracepoint}"))?;
    }

    let dropped = PerCpuArray::try_from(ebpf.take_map("DROPPED").context("no DROPPED map")?)?;
    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("no EVENTS map")?)?;
    // SAFETY: the ring buffer owns its map fd, and it moves into the
    // AsyncFd for the reader task's whole life.
    let mut ring = unsafe { AsyncFd::register_with_interest(ring, Interest::READABLE) }
        .map_err(|e| anyhow!("registering ring buffer: {e}"))?;

    let (tx, rx) = mpsc::channel(cfg.channel_capacity);
    tokio::spawn(async move {
        let mut short: u64 = 0;
        loop {
            let Ok(mut guard) = ring.readable_mut().await else {
                return;
            };
            loop {
                // Copy the event out and drop the borrow before awaiting,
                // so the item doesn't cross the send.
                let ev = {
                    let Some(item) = guard.get_inner_mut().next() else {
                        break;
                    };
                    if item.len() < size_of::<Event>() {
                        short += 1;
                        eprintln!(
                            "aegisd: skipping short ring buffer record ({} bytes, {short} so far)",
                            item.len()
                        );
                        continue;
                    }
                    // SAFETY: the kernel side writes whole `Event`s, and every
                    // bit pattern is a valid `Event`.
                    unsafe { item.as_ptr().cast::<Event>().read_unaligned() }
                };
                if tx.send(ev).await.is_err() {
                    return;
                }
            }
            guard.clear_ready();
        }
    });

    Ok((
        EbpfHandle {
            _ebpf: ebpf,
            dropped,
        },
        rx,
    ))
}

fn prog<'a, T>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut T>
where
    &'a mut T: TryFrom<&'a mut aya::programs::Program, Error = aya::programs::ProgramError>,
{
    let p = ebpf
        .program_mut(name)
        .with_context(|| format!("no program {name}"))?;
    Ok(p.try_into()?)
}
