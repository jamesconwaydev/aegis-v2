// SPDX-License-Identifier: MIT OR Apache-2.0
//! Whether the honeypot's two ports are being listened on. Shared by
//! aegisd (config check, enforcer) and aegisctl (preflight), so both
//! read /proc the same way.

use std::fs;
use std::io;
use std::path::Path;

/// Whether `table` (a /proc/net/tcp or udp file) has a socket bound to
/// 0.0.0.0:`port` in `state` (hex, as the kernel prints it).
fn bound(table: &str, port: u16, state: &str) -> bool {
    let want = format!("00000000:{port:04X}");
    table.lines().skip(1).any(|l| {
        let mut f = l.split_whitespace().skip(1);
        let (local, _remote, st) = (f.next(), f.next(), f.next());
        local == Some(want.as_str()) && st == Some(state)
    })
}

/// True when something listens on TCP `tcp_port` (LISTEN) and has UDP
/// `dns_port` bound, both on 0.0.0.0. `proc_root` is the directory
/// holding `net/tcp` and `net/udp`: `/proc`, or a fake one in tests.
/// Unreadable tables are an error, not "no".
pub fn honeypot_listening(proc_root: &Path, tcp_port: u16, dns_port: u16) -> io::Result<bool> {
    let tcp = fs::read_to_string(proc_root.join("net/tcp"))?;
    let udp = fs::read_to_string(proc_root.join("net/udp"))?;
    Ok(bound(&tcp, tcp_port, "0A") && bound(&udp, dns_port, "07"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "  sl  local_address rem_address   st tx_queue rx_queue\n";

    fn root(name: &str, tcp: &str, udp: &str) -> std::path::PathBuf {
        let r = std::env::temp_dir().join(format!("aegis-listen-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&r);
        fs::create_dir_all(r.join("net")).unwrap();
        fs::write(r.join("net/tcp"), format!("{HEAD}{tcp}")).unwrap();
        fs::write(r.join("net/udp"), format!("{HEAD}{udp}")).unwrap();
        r
    }

    // 2580 = 0x0A14, 2553 = 0x09F9
    const TCP_OK: &str = "   0: 00000000:0A14 00000000:0000 0A 00000000:00000000\n";
    const UDP_OK: &str = "   1: 00000000:09F9 00000000:0000 07 00000000:00000000\n";

    #[test]
    fn both_ports_up() {
        let r = root("ok", TCP_OK, UDP_OK);
        assert!(honeypot_listening(&r, 2580, 2553).unwrap());
    }

    #[test]
    fn missing_loopback_only_or_wrong_state_is_not_listening() {
        let loop_only = "   0: 0100007F:0A14 00000000:0000 0A 0:0\n";
        let established = "   0: 00000000:0A14 0100007F:9999 01 0:0\n";
        for (n, tcp, udp) in [
            ("none", "", UDP_OK),
            ("loop", loop_only, UDP_OK),
            ("est", established, UDP_OK),
            ("noudp", TCP_OK, ""),
        ] {
            let r = root(n, tcp, udp);
            assert!(!honeypot_listening(&r, 2580, 2553).unwrap(), "{n}");
        }
        // The right sockets on other ports don't count either.
        let r = root("ports", TCP_OK, UDP_OK);
        assert!(!honeypot_listening(&r, 2581, 2553).unwrap());
    }

    #[test]
    fn unreadable_tables_are_an_error() {
        assert!(honeypot_listening(Path::new("/nonexistent-aegis"), 1, 2).is_err());
    }
}
