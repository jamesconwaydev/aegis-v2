// SPDX-License-Identifier: MIT OR Apache-2.0
use std::net::Ipv4Addr;

use anyhow::{anyhow, Context, Result};

use super::systemd::{run_cmd, Run};

/// Where nft may live, in the order looked. The config check accepts
/// enforce mode only if one of these exists, and nft runs from the first
/// that does, so the two always agree.
pub const NFT_PATHS: [&str; 2] = ["/usr/sbin/nft", "/usr/bin/nft"];

/// The chain that sends an observed tree's traffic to the honeypot.
pub const NAT: &str = "nat_out";
/// The quarantine slice as nft matches it, and the addresses honeypot
/// incidents take.
const SLICE: &str = "aegis.slice/aegis-quarantine.slice";
const NET: &str = "127.77.0.0/16";

pub struct Nft {
    run: Run,
    paths: Vec<String>,
}

impl Nft {
    pub fn new() -> Self {
        Self {
            run: run_cmd,
            paths: NFT_PATHS.map(String::from).into(),
        }
    }

    /// For tests: always `/usr/sbin/nft`, whatever this machine has.
    #[cfg(test)]
    pub fn with(run: Run) -> Self {
        Self {
            run,
            paths: vec![NFT_PATHS[0].into()],
        }
    }

    fn nft(&self, args: &[&str]) -> Result<String> {
        let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        // Looked up per call: nftables may be installed after aegisd
        // starts in audit mode, then a reload turns enforce mode on.
        let prog = self
            .paths
            .iter()
            .find(|p| std::path::Path::new(p).is_file())
            .unwrap_or(&self.paths[0]);
        (self.run)(prog, &a)
    }

    /// `add` is a no-op when the table and chain already exist.
    pub fn ensure_table(&self) -> Result<()> {
        self.nft(&["add", "table", "inet", "aegis"])?;
        self.nft(&[
            "add",
            "chain",
            "inet",
            "aegis",
            "out",
            "{ type filter hook output priority 0; policy accept; }",
        ])?;
        Ok(())
    }

    /// Whether `listing` has the slice-wide rule `ensure_nat` adds.
    pub fn has_local_rule(listing: &str) -> bool {
        listing.contains(&format!("level 2 != \"{SLICE}\""))
    }

    /// Honeypot mode's part of the table: the `nat_out` chain, and one
    /// rule that drops anything sent to an incident address from outside
    /// the quarantine slice, so local users can't reach a tree's
    /// honeypot sessions. That rule is added only if missing: nft shows
    /// the slice by a bare id once it is gone, and then it is replaced.
    pub fn ensure_nat(&self) -> Result<()> {
        self.nft(&[
            "add",
            "chain",
            "inet",
            "aegis",
            NAT,
            "{ type nat hook output priority -100; policy accept; }",
        ])?;
        let l = self.list()?.unwrap_or_default();
        if Self::has_local_rule(&l) {
            return Ok(());
        }
        for (c, line, h) in Self::rules(&l) {
            if line.contains(&format!("ip daddr {NET} socket cgroupv2 level 2 != ")) {
                self.remove(c, h)?;
            }
        }
        self.nft(&[
            "add", "rule", "inet", "aegis", "out", "ip", "daddr", NET, "socket", "cgroupv2",
            "level", "2", "!=", SLICE, "counter", "drop",
        ])
        .map(drop)
    }

    /// Sends what the cgroup sends to the honeypot at `addr`: TCP to
    /// `tcp`, UDP to port 53 to `dns`. Two accepts go in at the head of
    /// `out`, ahead of the cgroup's drop rule, and two DNAT rules in
    /// `nat_out`. Returns the handles in that order; on an error, those
    /// added so far are in the error's context.
    pub fn redirect(
        &self,
        cgroup_path: &str,
        addr: Ipv4Addr,
        tcp: u16,
        dns: u16,
    ) -> Result<Vec<u64>> {
        let a = addr.to_string();
        let to = |p: u16| format!("{a}:{p}");
        let (tcp_s, dns_s, to_tcp, to_dns) = (tcp.to_string(), dns.to_string(), to(tcp), to(dns));
        let cg = ["socket", "cgroupv2", "level", "3", cgroup_path];
        let rules: [(&str, &str, Vec<&str>); 4] = [
            (
                "insert",
                "out",
                vec![
                    "ip", "daddr", &a, "tcp", "dport", &tcp_s, "counter", "accept",
                ],
            ),
            (
                "insert",
                "out",
                vec![
                    "ip", "daddr", &a, "udp", "dport", &dns_s, "counter", "accept",
                ],
            ),
            (
                "add",
                NAT,
                vec![
                    "meta", "l4proto", "tcp", "counter", "dnat", "ip", "to", &to_tcp,
                ],
            ),
            (
                "add",
                NAT,
                vec!["udp", "dport", "53", "counter", "dnat", "ip", "to", &to_dns],
            ),
        ];
        let mut got = Vec::new();
        for (verb, chain, tail) in rules {
            let mut args = vec!["--echo", "--handle", verb, "rule", "inet", "aegis", chain];
            args.extend(cg);
            args.extend(tail);
            let h = self.nft(&args).and_then(|out| {
                Self::echoed_handle(&out)
                    .ok_or_else(|| anyhow!("no rule handle in nft output: {}", out.trim()))
            });
            match h {
                Ok(h) => got.push(h),
                Err(e) => {
                    return Err(e.context(format!("adding the honeypot rules (added {got:?})")))
                }
            }
        }
        Ok(got)
    }

    /// Drops everything the cgroup sends; returns the rule handle.
    pub fn drop_cgroup(&self, cgroup_path: &str) -> Result<u64> {
        let out = self.nft(&[
            "--echo",
            "--handle",
            "add",
            "rule",
            "inet",
            "aegis",
            "out",
            "socket",
            "cgroupv2",
            "level",
            "3",
            cgroup_path,
            "counter",
            "drop",
        ])?;
        Self::echoed_handle(&out)
            .ok_or_else(|| anyhow!("no rule handle in nft output: {}", out.trim()))
            .context("adding the drop rule")
    }

    /// The rule handle in what `nft --echo --handle add rule` printed.
    pub fn echoed_handle(out: &str) -> Option<u64> {
        out.rsplit("# handle ")
            .next()
            .filter(|_| out.contains("# handle "))
            .and_then(|s| s.split_whitespace().next())
            .and_then(|n| n.parse().ok())
    }

    /// The live table with rule handles, both chains, or None once a
    /// ruleset flush (`systemctl reload nftables`) has taken the table
    /// with it.
    pub fn list(&self) -> Result<Option<String>> {
        match self.nft(&["-a", "list", "table", "inet", "aegis"]) {
            Ok(s) => Ok(Some(s)),
            Err(e) if format!("{e:#}").contains("No such file or directory") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Each rule line in `listing` with the chain it is in and its
    /// handle. Table and chain lines carry handles too and are skipped.
    fn rules(listing: &str) -> impl Iterator<Item = (&str, &str, u64)> {
        let mut chain = "out";
        listing.lines().filter_map(move |l| {
            let t = l.trim_start();
            if let Some(c) = t.strip_prefix("chain ") {
                chain = c.split_whitespace().next().unwrap_or("out");
                return None;
            }
            if t.starts_with("table ") {
                return None;
            }
            let h = l.rsplit_once("# handle ")?.1.trim().parse().ok()?;
            Some((chain, l, h))
        })
    }

    /// Whether `listing` still has rule `h`.
    pub fn has_rule(listing: &str, h: u64) -> bool {
        Self::rules(listing).any(|(_, _, x)| x == h)
    }

    /// The chain rule `h` is in; `out` if it isn't listed.
    pub fn chain_of(listing: &str, h: u64) -> &str {
        Self::rules(listing)
            .find(|r| r.2 == h)
            .map_or("out", |r| r.0)
    }

    /// Handles of the rules in `listing`, in either chain, that match
    /// `cgroup_path`. The quotes keep one scope's path from matching a
    /// longer one.
    pub fn handles(listing: &str, cgroup_path: &str) -> Vec<u64> {
        let q = format!("\"{cgroup_path}\"");
        Self::rules(listing)
            .filter(|(_, l, _)| l.contains(&q))
            .map(|r| r.2)
            .collect()
    }

    /// The drop rules among `handles`: what a v0.2 quarantine has.
    pub fn drops(listing: &str, cgroup_path: &str) -> Vec<u64> {
        let red = Self::redirects(listing, cgroup_path);
        Self::handles(listing, cgroup_path)
            .into_iter()
            .filter(|h| !red.iter().any(|r| r.1 == *h))
            .collect()
    }

    /// The honeypot rules `redirect` added for `cgroup_path`, by chain.
    pub fn redirects<'a>(listing: &'a str, cgroup_path: &str) -> Vec<(&'a str, u64)> {
        let q = format!("\"{cgroup_path}\"");
        Self::rules(listing)
            .filter(|(c, l, _)| l.contains(&q) && (*c == NAT || l.contains(" accept")))
            .map(|(c, _, h)| (c, h))
            .collect()
    }

    /// Handles of the rules in `listing` whose cgroup nft shows as a bare
    /// number: it prints the path only while the cgroup exists.
    pub fn unresolved(listing: &str) -> Vec<u64> {
        listing
            .lines()
            .filter(|l| {
                l.split_once("cgroupv2 level ")
                    .and_then(|(_, r)| r.split_whitespace().nth(1))
                    .is_some_and(|c| c.bytes().all(|b| b.is_ascii_digit()))
            })
            .filter_map(|l| l.rsplit_once("# handle ")?.1.trim().parse().ok())
            .collect()
    }

    pub fn remove(&self, chain: &str, handle: u64) -> Result<()> {
        self.nft(&[
            "delete",
            "rule",
            "inet",
            "aegis",
            chain,
            "handle",
            &handle.to_string(),
        ])
        .map(drop)
    }

    /// The path nft matches on: `aegis-quarantine.slice` nests under
    /// `aegis.slice`.
    pub fn scope_cgroup(slice: &str, scope: &str) -> String {
        format!("aegis.slice/{slice}/{scope}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(_: &str, _: &[String]) -> Result<String> {
        Ok("add rule inet aegis out socket cgroupv2 level 3 \"x\" counter packets 0 bytes 0 drop # handle 7\n# new generation 12 by process 1 (nft)\n".into())
    }
    fn junk(_: &str, _: &[String]) -> Result<String> {
        Ok("nothing\n".into())
    }

    #[test]
    fn nft_runs_from_the_first_path_that_exists() {
        thread_local! { static PROG: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) }; }
        fn rec(p: &str, _: &[String]) -> Result<String> {
            PROG.with(|x| *x.borrow_mut() = p.into());
            Ok(String::new())
        }
        let d = std::env::temp_dir().join(format!("aegis-nft-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let (missing, found) = (d.join("sbin-nft"), d.join("bin-nft"));
        std::fs::write(&found, "").unwrap();
        let n = Nft {
            run: rec,
            paths: [&missing, &found].map(|p| p.display().to_string()).into(),
        };
        n.remove("out", 1).unwrap();
        assert_eq!(
            PROG.with(|x| x.borrow().clone()),
            found.display().to_string()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn drop_cgroup_returns_handle() {
        assert_eq!(Nft::with(fake).drop_cgroup("x").unwrap(), 7);
        assert!(Nft::with(junk).drop_cgroup("x").is_err());
    }

    #[test]
    fn handles_match_the_quoted_cgroup_path_only() {
        let l = "table inet aegis {\n\tchain out { # handle 1\n\
                 \t\tsocket cgroupv2 level 3 \"a/b.scope\" counter packets 0 bytes 0 drop # handle 4\n\
                 \t\tsocket cgroupv2 level 3 \"a/b.scopex\" counter packets 0 bytes 0 drop # handle 5\n\
                 \t}\n}\n";
        assert_eq!(Nft::handles(l, "a/b.scope"), [4]);
        assert!(Nft::handles(l, "a/c.scope").is_empty());
        assert!(Nft::unresolved(l).is_empty());
        let gone = "\t\tsocket cgroupv2 level 3 18342 counter packets 0 bytes 0 drop # handle 9\n";
        assert_eq!(Nft::unresolved(&format!("{l}{gone}")), [9]);
    }

    #[test]
    fn rules_are_told_apart_by_chain_and_kind() {
        let l = "table inet aegis { # handle 5\n\
                 \tchain out { # handle 1\n\
                 \t\ttype filter hook output priority filter; policy accept;\n\
                 \t\tsocket cgroupv2 level 3 \"a/b.scope\" ip daddr 127.77.0.1 tcp dport 2580 counter packets 0 bytes 0 accept # handle 9\n\
                 \t\tsocket cgroupv2 level 3 \"a/b.scope\" counter packets 0 bytes 0 drop # handle 4\n\
                 \t\tip daddr 127.77.0.0/16 socket cgroupv2 level 2 != \"aegis.slice/aegis-quarantine.slice\" counter packets 0 bytes 0 drop # handle 6\n\
                 \t}\n\
                 \tchain nat_out { # handle 2\n\
                 \t\tsocket cgroupv2 level 3 \"a/b.scope\" meta l4proto tcp counter packets 0 bytes 0 dnat ip to 127.77.0.1:2580 # handle 11\n\
                 \t}\n}\n";
        assert_eq!(Nft::handles(l, "a/b.scope"), [9, 4, 11]);
        assert_eq!(Nft::drops(l, "a/b.scope"), [4]);
        assert_eq!(
            Nft::redirects(l, "a/b.scope"),
            [("out", 9), ("nat_out", 11)]
        );
        assert_eq!(Nft::chain_of(l, 11), "nat_out");
        assert!(Nft::has_local_rule(l));
        // Table and chain lines carry handles too; they aren't rules.
        assert!(Nft::has_rule(l, 6) && !Nft::has_rule(l, 5) && !Nft::has_rule(l, 2));
        assert!(Nft::unresolved(l).is_empty());
    }

    #[test]
    fn redirect_adds_accepts_then_dnat() {
        thread_local! { static ARGS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) }; }
        fn rec(_: &str, a: &[String]) -> Result<String> {
            ARGS.with(|x| x.borrow_mut().push(a.join(" ")));
            Ok("# handle 3\n".into())
        }
        let hs = Nft::with(rec)
            .redirect("c", "127.77.0.2".parse().unwrap(), 2580, 2553)
            .unwrap();
        assert_eq!(hs, [3, 3, 3, 3]);
        let a = ARGS.with(|x| x.take());
        let pre = "--echo --handle";
        assert_eq!(
            a,
            [
                format!("{pre} insert rule inet aegis out socket cgroupv2 level 3 c ip daddr 127.77.0.2 tcp dport 2580 counter accept"),
                format!("{pre} insert rule inet aegis out socket cgroupv2 level 3 c ip daddr 127.77.0.2 udp dport 2553 counter accept"),
                format!("{pre} add rule inet aegis nat_out socket cgroupv2 level 3 c meta l4proto tcp counter dnat ip to 127.77.0.2:2580"),
                format!("{pre} add rule inet aegis nat_out socket cgroupv2 level 3 c udp dport 53 counter dnat ip to 127.77.0.2:2553"),
            ]
        );
    }

    #[test]
    fn list_is_none_once_the_table_is_gone() {
        fn gone(_: &str, _: &[String]) -> Result<String> {
            Err(anyhow!(
                "nft: exit Some(1): Error: No such file or directory"
            ))
        }
        fn broken(_: &str, _: &[String]) -> Result<String> {
            Err(anyhow!("nft: failed to run or timed out"))
        }
        assert_eq!(Nft::with(gone).list().unwrap(), None);
        assert!(Nft::with(broken).list().is_err());
    }

    #[test]
    fn scope_cgroup_nests_under_aegis_slice() {
        assert_eq!(
            Nft::scope_cgroup("aegis-quarantine.slice", "a.scope"),
            "aegis.slice/aegis-quarantine.slice/a.scope"
        );
    }
}
