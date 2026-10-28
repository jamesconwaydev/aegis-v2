// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::{anyhow, Context, Result};

use super::systemd::{run_cmd, Run};

const NFT: &str = "/usr/sbin/nft";

pub struct Nft {
    run: Run,
}

impl Nft {
    pub fn new() -> Self {
        Self::with(run_cmd)
    }

    pub fn with(run: Run) -> Self {
        Self { run }
    }

    fn nft(&self, args: &[&str]) -> Result<String> {
        let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        (self.run)(NFT, &a)
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
        out.rsplit("# handle ")
            .next()
            .filter(|_| out.contains("# handle "))
            .and_then(|s| s.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| anyhow!("no rule handle in nft output: {}", out.trim()))
            .context("adding the drop rule")
    }

    /// The live `out` chain with rule handles, or None once a ruleset
    /// flush (`systemctl reload nftables`) has taken the table with it.
    pub fn list(&self) -> Result<Option<String>> {
        match self.nft(&["-a", "list", "chain", "inet", "aegis", "out"]) {
            Ok(s) => Ok(Some(s)),
            Err(e) if format!("{e:#}").contains("No such file or directory") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Handles of the rules in `listing` that match `cgroup_path`. The
    /// quotes keep one scope's path from matching a longer one.
    pub fn handles(listing: &str, cgroup_path: &str) -> Vec<u64> {
        let q = format!("\"{cgroup_path}\"");
        listing
            .lines()
            .filter(|l| l.contains(&q))
            .filter_map(|l| l.rsplit_once("# handle ")?.1.trim().parse().ok())
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

    pub fn remove(&self, handle: u64) -> Result<()> {
        self.nft(&[
            "delete",
            "rule",
            "inet",
            "aegis",
            "out",
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
