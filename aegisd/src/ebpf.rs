// SPDX-License-Identifier: MIT OR Apache-2.0
//! Loads the probes and streams their events.
//!
//! The eBPF object reads kernel structs at offsets we look up here, in
//! the running kernel's BTF, and patch into its `OFFSETS` global. Rust
//! has no CO-RE, and bindings generated from one kernel's BTF would go
//! stale with the next kernel update, so nothing is baked in at build
//! time.

mod btf;

use std::collections::BTreeMap;

use aegis_common::{Event, KernelOffsets};
use aegis_proto::ProbeStatus;
use anyhow::{anyhow, Context as _, Result};
use aya::{
    maps::{Array, HashMap, MapData, MapError, PerCpuArray, RingBuf},
    programs::{BtfTracePoint, Lsm, TracePoint},
    Ebpf, EbpfLoader,
};
use tokio::{
    io::{unix::AsyncFd, Interest},
    sync::mpsc,
};

use crate::proctable::ProcKey;

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
    probes: Vec<ProbeStatus>,
    /// Taken by the enforcer at startup.
    pub holds: Holds,
}

/// Processes the kernel's hold hooks refuse to let act. The kernel drops
/// an entry itself when the process exits.
#[derive(Default)]
pub struct Holds {
    map: Option<HashMap<MapData, u32, u64>>,
    /// Stands in for the map when there is none (tests).
    mem: BTreeMap<u32, u64>,
}

impl Holds {
    /// Refuses pid 0-2 and aegisd itself, which must never be held, and
    /// a zero start time, which the kernel would never match.
    pub fn hold(&mut self, k: ProcKey) -> Result<()> {
        anyhow::ensure!(
            k.tgid > 2 && k.tgid != std::process::id(),
            "refusing to hold {}: pid 0, 1, 2 or aegisd",
            k.tgid
        );
        anyhow::ensure!(
            k.start_time_ns != 0,
            "refusing to hold {}: no start time",
            k.tgid
        );
        match &mut self.map {
            Some(m) => m
                .insert(k.tgid, k.start_time_ns, 0)
                .with_context(|| format!("holding {}", k.tgid))?,
            None => {
                self.mem.insert(k.tgid, k.start_time_ns);
            }
        }
        Ok(())
    }

    /// Releasing a process that has already exited is not an error.
    pub fn release(&mut self, tgid: u32) -> Result<()> {
        match &mut self.map {
            Some(m) => match m.remove(&tgid) {
                Err(MapError::SyscallError(e))
                    if e.io_error.kind() == std::io::ErrorKind::NotFound => {}
                r => r.with_context(|| format!("releasing {tgid}"))?,
            },
            None => {
                self.mem.remove(&tgid);
            }
        }
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))] // tests; metrics later
    pub fn held(&self) -> usize {
        match &self.map {
            Some(m) => m.keys().filter(Result::is_ok).count(),
            None => self.mem.len(),
        }
    }
}

impl EbpfHandle {
    /// Events the probes couldn't fit in the ring buffer, since load.
    pub fn dropped_events(&self) -> u64 {
        self.dropped
            .get(&0, 0)
            .map(|per_cpu| per_cpu.iter().sum())
            .unwrap_or(0)
    }

    /// Every probe; `start` fails unless all of them attach.
    pub fn probes(&self) -> &[ProbeStatus] {
        &self.probes
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
        inode_i_ino: btf.offset("inode", "i_ino")?,
        super_block_s_dev: btf.offset("super_block", "s_dev")?,
        task_mm: btf.offset("task_struct", "mm")?,
        mm_env_start: btf.offset("mm_struct", "env_start")?,
        mm_env_end: btf.offset("mm_struct", "env_end")?,
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

    // Before anything attaches, so self-protection has no gap.
    let mut aegisd: Array<_, u32> =
        Array::try_from(ebpf.map_mut("AEGISD").context("no AEGISD map")?)?;
    aegisd.set(0, std::process::id(), 0)?;

    let mut probes = Vec::new();
    let mut attached = |name: &str, hook: String| {
        probes.push(ProbeStatus {
            name: name.into(),
            hook,
        })
    };

    // Records the original file at the first check; emits at commit.
    let check: &mut Lsm = prog(&mut ebpf, "aegis_exec_check")?;
    check.load("bprm_check_security", &kernel_btf)?;
    check.attach()?;
    attached("aegis_exec_check", "lsm/bprm_check_security".into());

    let lsm: &mut Lsm = prog(&mut ebpf, "aegis_exec")?;
    lsm.load("bprm_committed_creds", &kernel_btf)?;
    lsm.attach()?;
    attached("aegis_exec", "lsm/bprm_committed_creds".into());

    // The hold. Each refuses a held task; ptrace also guards aegisd.
    for (name, hook) in [
        ("aegis_hold_fork", "task_alloc"),
        ("aegis_hold_connect", "socket_connect"),
        ("aegis_hold_sendmsg", "socket_sendmsg"),
        ("aegis_hold_mount", "sb_mount"),
        ("aegis_hold_move_mount", "move_mount"),
        ("aegis_hold_bpf", "bpf"),
        ("aegis_hold_modreq", "kernel_module_request"),
        ("aegis_hold_modread", "kernel_read_file"),
        ("aegis_hold_modload", "kernel_load_data"),
        ("aegis_hold_ptrace", "ptrace_access_check"),
        ("aegis_hold_write", "file_permission"),
        ("aegis_hold_userns", "userns_create"),
        ("aegis_hold_kill", "task_kill"),
    ] {
        let p: &mut Lsm = prog(&mut ebpf, name)?;
        p.load(hook, &kernel_btf)
            .with_context(|| format!("loading lsm/{hook}"))?;
        p.attach()
            .with_context(|| format!("attaching lsm/{hook}"))?;
        attached(name, format!("lsm/{hook}"));
    }

    let fork: &mut BtfTracePoint = prog(&mut ebpf, "aegis_fork")?;
    fork.load("sched_process_fork", &kernel_btf)?;
    fork.attach()?;
    attached("aegis_fork", "tp_btf/sched_process_fork".into());

    // Reads the new image's environment once the exec has set it up.
    let env: &mut BtfTracePoint = prog(&mut ebpf, "aegis_exec_env")?;
    env.load("sched_process_exec", &kernel_btf)?;
    env.attach()?;
    attached("aegis_exec_env", "tp_btf/sched_process_exec".into());

    for (name, category, tracepoint) in [
        ("aegis_exit", "sched", "sched_process_exit"),
        ("aegis_ptrace", "syscalls", "sys_enter_ptrace"),
        ("aegis_ptrace_exit", "syscalls", "sys_exit_ptrace"),
        ("aegis_memfd", "syscalls", "sys_enter_memfd_create"),
        ("aegis_connect", "sock", "inet_sock_set_state"),
    ] {
        let tp: &mut TracePoint = prog(&mut ebpf, name)?;
        tp.load()?;
        tp.attach(category, tracepoint)
            .with_context(|| format!("attaching {category}/{tracepoint}"))?;
        attached(name, format!("tracepoint/{category}/{tracepoint}"));
    }

    let holds = Holds {
        map: Some(HashMap::try_from(
            ebpf.take_map("HELD").context("no HELD map")?,
        )?),
        mem: BTreeMap::new(),
    };
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
            probes,
            holds,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_round_trip_in_map_wrapper() {
        let mut h = Holds::default();
        let k = ProcKey {
            tgid: 4242,
            start_time_ns: 7,
        };
        h.hold(k).unwrap();
        assert_eq!(h.held(), 1);
        h.release(k.tgid).unwrap();
        assert_eq!(h.held(), 0);
        // Releasing a task the kernel already dropped on exit is fine.
        h.release(k.tgid).unwrap();
    }

    #[test]
    fn hold_refuses_pid1_pid2_self_and_zero_start() {
        let mut h = Holds::default();
        for (tgid, start_time_ns) in [(0, 7), (1, 7), (2, 7), (std::process::id(), 7), (4242, 0)] {
            assert!(
                h.hold(ProcKey {
                    tgid,
                    start_time_ns
                })
                .is_err(),
                "{tgid}"
            );
        }
        assert_eq!(h.held(), 0);
    }
}
