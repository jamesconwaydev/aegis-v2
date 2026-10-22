// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::{anyhow, Context, Result};

use super::systemd::{run_cmd, Run};

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
        (self.run)("nft", &a)
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
    fn scope_cgroup_nests_under_aegis_slice() {
        assert_eq!(
            Nft::scope_cgroup("aegis-quarantine.slice", "a.scope"),
            "aegis.slice/aegis-quarantine.slice/a.scope"
        );
    }
}
