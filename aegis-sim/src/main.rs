// SPDX-License-Identifier: MIT OR Apache-2.0
//! Safe, self-contained detection probes for the aegisd end-to-end tests.
//!
//! Each subcommand reproduces one behaviour aegisd scores, using only
//! the current host: nothing reaches the network beyond loopback, the
//! ptrace probe attaches and detaches without touching the target's
//! memory, and no real payload is ever run. This binary is a test tool;
//! it never ships in the RPM.
//!
//! The scores below assume the binary itself runs from a temp directory
//! (the harness copies it to `/tmp/aegis-sim`), so every subcommand also
//! carries the 25-point "exec from a temp directory" signal on its own
//! process.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Attack simulators for the aegisd e2e tests.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write an executable into a temp directory and run it. Exercises
    /// the "exec from a temp directory" signal (25).
    TmpDropper,
    /// Copy this binary into an in-memory file and execute that. Exercises
    /// memfd_create (20) and exec-of-a-memfd (60).
    MemfdExec,
    /// Attach to a system daemon with PTRACE_SEIZE and immediately detach,
    /// without reading or writing its memory. Exercises the
    /// "ptrace a system daemon" signal (45). Run from /tmp this reaches 70.
    PtraceDaemon,
    /// Connect to many closed loopback ports fast. Exercises the egress
    /// scan signal (40). Targets are refused to 127.0.0.0/8 or the host.
    PortScan {
        #[arg(long, default_value = "127.0.0.0/8")]
        target: String,
    },
    /// Exec from /tmp, then ptrace a daemon, then scan loopback, all in
    /// one process so the components sum past the quarantine threshold.
    Chain,
    /// Re-exec target for memfd-exec: exits 0, does nothing. Hidden.
    #[command(hide = true, name = "__noop")]
    Noop,
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("aegis-sim only runs on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    let code = match Cli::parse().cmd {
        Cmd::Noop => 0,
        Cmd::TmpDropper => linux::tmp_dropper(),
        Cmd::MemfdExec => linux::memfd_exec(),
        Cmd::PtraceDaemon => linux::ptrace_daemon(),
        Cmd::PortScan { target } => linux::port_scan(&target),
        Cmd::Chain => linux::chain(),
    };
    std::process::exit(code);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::time::Duration;

    const PTRACE_SEIZE: libc::c_uint = 0x4206;
    const PTRACE_DETACH: libc::c_uint = 17;

    fn warn(what: &str) -> i32 {
        eprintln!("aegis-sim: {what}: {}", std::io::Error::last_os_error());
        1
    }

    /// Drop a tiny executable into /tmp and run it to completion.
    pub fn tmp_dropper() -> i32 {
        let path = "/tmp/aegis-sim-dropped.sh";
        match std::fs::File::create(path).and_then(|mut f| {
            use std::os::unix::fs::PermissionsExt;
            f.write_all(b"#!/bin/sh\nexit 0\n")?;
            f.set_permissions(std::fs::Permissions::from_mode(0o755))
        }) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("aegis-sim: writing {path}: {e}");
                return 1;
            }
        }
        let status = std::process::Command::new(path).status();
        let _ = std::fs::remove_file(path);
        match status {
            Ok(s) if s.success() => 0,
            Ok(s) => {
                eprintln!("aegis-sim: dropped payload exited {s}");
                1
            }
            Err(e) => {
                eprintln!("aegis-sim: running {path}: {e}");
                1
            }
        }
    }

    /// Copy this binary into a memfd and execveat it in place. The new
    /// image runs `__noop` and exits 0, so the caller sees a clean exit.
    pub fn memfd_exec() -> i32 {
        const MFD_CLOEXEC: libc::c_uint = 0x0001;
        // 0x0008 is MFD_NOEXEC_SEAL (the opposite); MFD_EXEC is 0x0010.
        const MFD_EXEC: libc::c_uint = 0x0010;
        const AT_EMPTY_PATH: libc::c_int = 0x1000;

        let name = CString::new("aegis-sim").unwrap();
        // SAFETY: name is a valid C string; memfd_create returns an fd or -1.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), MFD_CLOEXEC | MFD_EXEC) };
        if fd < 0 {
            return warn("memfd_create");
        }
        let self_bytes = match std::fs::read("/proc/self/exe") {
            Ok(b) => b,
            Err(e) => {
                eprintln!("aegis-sim: reading /proc/self/exe: {e}");
                return 1;
            }
        };
        // Wrap the raw fd so it writes (and closes on error) like a File.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        if let Err(e) = file.write_all(&self_bytes) {
            eprintln!("aegis-sim: filling memfd: {e}");
            return 1;
        }
        let fd = file.as_raw_fd();
        let empty = CString::new("").unwrap();
        let arg0 = CString::new("aegis-sim").unwrap();
        let arg1 = CString::new("__noop").unwrap();
        let argv = [arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null::<libc::c_char>()];
        // SAFETY: fd is a live memfd holding this ELF; argv and envp are
        // NULL-terminated. On success this never returns.
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                fd,
                empty.as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
                AT_EMPTY_PATH,
            );
        }
        warn("execveat(memfd)")
    }

    /// The nearest system daemon that isn't an ancestor of this process:
    /// pid 1 always qualifies and is never our parent.
    fn ptrace_once(pid: libc::pid_t) -> i32 {
        // SAFETY: ptrace with a pid and no data pointer only reads kernel
        // bookkeeping; SEIZE does not stop the tracee.
        let seized = unsafe { libc::ptrace(PTRACE_SEIZE, pid, 0, 0) };
        if seized < 0 {
            return warn(&format!("ptrace SEIZE {pid}"));
        }
        // Detach at once. We never read or write the target's memory.
        // SAFETY: pid is the process we just seized.
        unsafe { libc::ptrace(PTRACE_DETACH, pid, 0, 0) };
        0
    }

    pub fn ptrace_daemon() -> i32 {
        ptrace_once(1)
    }

    /// Hammer closed loopback ports to trip the egress-scan detector
    /// (>=20 distinct targets or >=10 failed connects in 2 s).
    pub fn port_scan(target: &str) -> i32 {
        let hosts = match loopback_hosts(target) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("aegis-sim: refusing target {target}: {e}");
                return 1;
            }
        };
        // 40 distinct (addr, port) pairs, all refused, well over both
        // thresholds. High ports chosen to be closed on a stock host.
        let mut made = 0u32;
        'outer: for host in hosts {
            for port in 9000u16..9100 {
                let addr = SocketAddr::new(IpAddr::V4(host), port);
                // Refused connections return at once; the timeout only
                // bounds a port that is silently filtered.
                let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(200));
                made += 1;
                if made >= 40 {
                    break 'outer;
                }
            }
        }
        0
    }

    /// Addresses to probe, restricted to 127.0.0.0/8. Accepts a bare IPv4
    /// or `addr/prefix`.
    fn loopback_hosts(target: &str) -> Result<Vec<Ipv4Addr>, String> {
        let (addr_s, prefix) = match target.split_once('/') {
            Some((a, p)) => (a, p.parse::<u8>().map_err(|_| "bad prefix")?),
            None => (target, 32),
        };
        let base: Ipv4Addr = addr_s.parse().map_err(|_| "not an IPv4 address")?;
        if base.octets()[0] != 127 {
            return Err("only 127.0.0.0/8 is allowed".into());
        }
        if prefix > 32 {
            return Err("prefix out of range".into());
        }
        // Up to 32 host addresses is plenty; ports alone already cross the
        // threshold, so a single /32 works too.
        let base_u = u32::from(base);
        let count = 1u32 << (32 - u32::from(prefix.min(32)));
        let n = count.min(32);
        Ok((0..n).map(|i| Ipv4Addr::from(base_u.wrapping_add(i))).collect())
    }

    pub fn chain() -> i32 {
        // Our own exec from /tmp already raised the tmp-exec signal (25).
        // Add ptrace of a daemon (45) and an egress scan (40): 110, over
        // the quarantine threshold, all on this one process.
        let p = ptrace_daemon();
        let s = port_scan("127.0.0.0/8");
        if p != 0 || s != 0 {
            1
        } else {
            0
        }
    }
}
