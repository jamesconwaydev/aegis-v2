// SPDX-License-Identifier: MIT OR Apache-2.0
//! Safe, self-contained detection probes for the aegisd end-to-end tests.
//!
//! Each subcommand reproduces one behaviour aegisd scores, using only
//! the current host: nothing reaches the network beyond loopback and no
//! real payload is ever run. This binary is a test tool; it never ships
//! in the RPM.
//!
//! The harness installs it at two paths. Run as `/usr/local/bin/aegis-sim`
//! a subcommand scores only the signal it exercises; run as
//! `/tmp/aegis-sim` it also carries the 25-point "exec from a temp
//! directory" signal on its own process.
//!
//! There is no ptrace code here: the scenarios attach with a copy of the
//! real strace, which seizes and detaches cleanly (see
//! tests/e2e/scenarios.toml).

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
    /// memfd_create (20) and exec-of-a-memfd (65).
    MemfdExec {
        /// Wait this long first, as a container runtime does real work
        /// before its memfd. aegisd reads a process's environment just
        /// after its exec, and one already gone reads as tainted.
        #[arg(long, default_value_t = 0)]
        wait_ms: u64,
        #[command(flatten)]
        stay: Stay,
    },
    /// Connect to many closed loopback ports fast. Exercises the egress
    /// scan signal (40). Targets are refused to 127.0.0.0/8 or the host.
    PortScan {
        #[arg(long, default_value = "127.0.0.0/8")]
        target: String,
    },
    /// Scan loopback, then run `cmd` as a child and exit with its status.
    /// Run from /tmp with a ptrace step as `cmd`, the incident sums
    /// tmp exec (25) + scan (40) + ptrace (45) past quarantine.
    Chain {
        #[command(flatten)]
        stay: Stay,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
    /// Re-exec target for memfd-exec: exits 0, does nothing. Hidden.
    #[command(hide = true, name = "__noop")]
    Noop {
        #[command(flatten)]
        stay: Stay,
    },
}

/// For the enforce-mode scenarios, which need the scoring process alive
/// after its verdict, to check and then release or kill it.
#[derive(clap::Args, Clone, Copy)]
struct Stay {
    /// Sleep this many seconds before exiting, and write this process's
    /// pid to /run/aegis-sim.pid first.
    #[arg(long, default_value_t = 0)]
    stay: u64,
}

impl Stay {
    /// The pid is written before anything scores: once aegisd holds the
    /// process it may no longer write files.
    fn announce(self) -> Result<(), i32> {
        if self.stay > 0 {
            if let Err(e) = std::fs::write("/run/aegis-sim.pid", std::process::id().to_string()) {
                eprintln!("aegis-sim: writing /run/aegis-sim.pid: {e}");
                return Err(1);
            }
        }
        Ok(())
    }

    fn sleep(self) {
        std::thread::sleep(std::time::Duration::from_secs(self.stay));
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("aegis-sim only runs on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    let code = match Cli::parse().cmd {
        Cmd::Noop { stay } => {
            stay.sleep();
            0
        }
        Cmd::TmpDropper => linux::tmp_dropper(),
        Cmd::MemfdExec { wait_ms, stay } => match stay.announce() {
            Ok(()) => {
                std::thread::sleep(std::time::Duration::from_millis(wait_ms));
                linux::memfd_exec(stay.stay)
            }
            Err(c) => c,
        },
        Cmd::PortScan { target } => linux::port_scan(&target),
        Cmd::Chain { stay, cmd } => match stay.announce() {
            Ok(()) => {
                let c = linux::chain(&cmd);
                stay.sleep();
                c
            }
            Err(c) => c,
        },
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

    fn warn(what: &str) -> i32 {
        eprintln!("aegis-sim: {what}: {}", std::io::Error::last_os_error());
        1
    }

    /// Drop a tiny executable into /tmp and run it to completion.
    pub fn tmp_dropper() -> i32 {
        use std::os::unix::fs::OpenOptionsExt;
        let path = format!("/tmp/aegis-sim-dropped.{}", std::process::id());
        let path = path.as_str();
        // create_new: never follow or reuse a file someone else put there.
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(path)
            .and_then(|mut f| f.write_all(b"#!/bin/sh\nexit 0\n"))
        {
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
    /// image runs `__noop` (sleeping `stay` seconds) and exits 0, so the
    /// caller sees a clean exit.
    pub fn memfd_exec(stay: u64) -> i32 {
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
        // SAFETY: fd was just returned by memfd_create, is open, and is
        // owned by nothing else, so the File may take ownership of it.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        if let Err(e) = file.write_all(&self_bytes) {
            eprintln!("aegis-sim: filling memfd: {e}");
            return 1;
        }
        let fd = file.as_raw_fd();
        let empty = CString::new("").unwrap();
        let arg0 = CString::new("aegis-sim").unwrap();
        let arg1 = CString::new("__noop").unwrap();
        let arg2 = CString::new("--stay").unwrap();
        let arg3 = CString::new(stay.to_string()).unwrap();
        let argv = [
            arg0.as_ptr(),
            arg1.as_ptr(),
            arg2.as_ptr(),
            arg3.as_ptr(),
            std::ptr::null(),
        ];
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
        if !(8..=32).contains(&prefix) || base.octets()[0] != 127 {
            return Err("only 127.0.0.0/8 or narrower is allowed".into());
        }
        // Mask to the network, so every address below stays inside the
        // prefix, which is inside 127.0.0.0/8. Up to 32 hosts is plenty;
        // ports alone already cross the threshold, so a /32 works too.
        let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
        let net = u32::from(base) & mask;
        let n = (!mask).saturating_add(1).min(32);
        Ok((0..n).map(|i| Ipv4Addr::from(net + i)).collect())
    }

    #[cfg(test)]
    #[test]
    fn loopback_hosts_stay_inside_the_prefix() {
        let h = loopback_hosts("127.1.2.3/30").unwrap();
        assert_eq!(
            h,
            (0..4)
                .map(|i| Ipv4Addr::new(127, 1, 2, i))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            loopback_hosts("127.0.0.9").unwrap(),
            [Ipv4Addr::new(127, 0, 0, 9)]
        );
        let h = loopback_hosts("127.255.255.255/8").unwrap();
        assert_eq!(h.len(), 32);
        assert!(h.iter().all(|a| a.octets()[0] == 127));
        for bad in [
            "10.0.0.1",
            "127.0.0.0/7",
            "0.0.0.0/0",
            "127.0.0.1/33",
            "::1",
        ] {
            assert!(loopback_hosts(bad).is_err(), "{bad}");
        }
    }

    /// Scan first, then run the ptrace step as a child, so the incident
    /// the scan opens already exists when the attach lands.
    pub fn chain(cmd: &[String]) -> i32 {
        if port_scan("127.0.0.0/8") != 0 {
            return 1;
        }
        match std::process::Command::new(&cmd[0]).args(&cmd[1..]).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(e) => {
                eprintln!("aegis-sim: running {}: {e}", cmd[0]);
                1
            }
        }
    }
}
