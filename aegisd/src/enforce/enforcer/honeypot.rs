// SPDX-License-Identifier: MIT OR Apache-2.0
//! Honeypot mode: a quarantined tree that keeps running with its
//! network sent to the honeypot, until its window ends. The order in
//! `observe` is the safety argument: the tree is held and in its scope
//! before anything opens, and its holds open only once the guard, the
//! drop rule, the redirect rules and a listener are all in place. Any
//! step that fails leaves it frozen, as in drop mode.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, bail, Context, Result};

use super::{act, q_unit, Enforcer, QUARANTINE_SLICE};
use crate::config::{Config, NetworkMode};
use crate::enforce::nft::{Nft, NAT};
use crate::enforce::systemd::Systemd;
use crate::incident::{ActionRecord, IncidentId};
use crate::proctable::ProcKey;
use crate::spool;
use crate::telemetry::unix_secs;

/// One file per observed scope, named after it. The unit's
/// ExecStopPost freezes what is listed here, and nothing else in the
/// quarantine slice: a released tree stays there and must keep running.
pub const MARKS: &str = "/var/lib/aegis-v2/observing";
/// How long `observe` waits for the scope's cgroup: busctl returns once
/// the start job is queued.
const CGROUP_WAIT: Duration = Duration::from_secs(2);
/// Most `HELD` entries observed trees may fill between them: half of its
/// 16384, so a fork copy never fails for room and drop mode keeps the rest.
const HELD_BUDGET: usize = 8192;

/// What a quarantined tree may reach in honeypot mode: the egress guard
/// on its scope. The eBPF one is in `ebpf::EgressGuard`.
pub trait Guard: Send {
    /// Drops whatever a socket made in the cgroup at `dir` sends, unless
    /// it is IPv4 to 127.77.0.0/16 on `tcp` or `dns`.
    fn attach(&mut self, dir: &str, tcp: u16, dns: u16) -> Result<()>;
    /// Takes the guard off `dir`; nothing if it isn't there.
    fn detach(&mut self, dir: &str) -> Result<()>;
}

/// The settings honeypot mode runs with.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Honeypot {
    pub tcp_port: u16,
    pub dns_port: u16,
    pub max_tasks: u32,
    pub max_incidents: u32,
    /// `quarantine.auto_expire_seconds`.
    pub window: Duration,
    pub max_session_bytes: u64,
    pub session_seconds: u64,
}

impl Honeypot {
    /// None unless `quarantine.network = "honeypot"`.
    pub fn from_config(c: &Config) -> Option<Self> {
        (c.quarantine.network == NetworkMode::Honeypot).then(|| Self {
            tcp_port: c.honeypot.tcp_port,
            dns_port: c.honeypot.dns_port,
            max_tasks: c.honeypot.max_tasks,
            max_incidents: c.honeypot.max_incidents,
            window: Duration::from_secs(c.quarantine.auto_expire_seconds),
            max_session_bytes: c.honeypot.max_session_bytes,
            session_seconds: c.honeypot.session_seconds,
        })
    }

    /// How long sessions on an address still file into its incident
    /// after the observation ends: one open then can run to its time
    /// cap before the honeypot closes it, and filing waits for a tick.
    pub fn grace(&self) -> Duration {
        Duration::from_secs(self.session_seconds.saturating_add(60))
    }

    /// Whether an observation that closed at `t` is still in its grace.
    /// A clock set back keeps it there longer, never shorter.
    pub fn in_grace(&self, t: SystemTime) -> bool {
        t.elapsed().unwrap_or_default() < self.grace()
    }
}

/// What the enforcer needs from main for honeypot mode: the settings,
/// which a reload replaces, and the guard.
pub struct HoneypotParts {
    pub settings: Arc<Mutex<Option<Honeypot>>>,
    pub guard: Box<dyn Guard>,
}

/// A tree being observed now.
#[derive(Clone, Copy, Debug)]
pub struct Observed {
    pub addr: Ipv4Addr,
    pub cgroup_id: u64,
    pub opened: Instant,
    pub tcp: u16,
    pub dns: u16,
}

pub fn listening(tcp: u16, dns: u16) -> std::io::Result<bool> {
    aegis_proto::honeypot_listening(std::path::Path::new("/proc"), tcp, dns)
}

/// At SIGTERM, while the probes still hold: freezes each scope listed in
/// `dir`, as ExecStopPost does once aegisd has gone. Returns the failures.
pub fn freeze_marked(dir: &std::path::Path, sys: &Systemd) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|u| u.starts_with("aegis-incident-") && u.ends_with("-q.scope"))
        .filter_map(|u| sys.freeze(&u).err().map(|e| format!("{u}: {e:#}")))
        .collect()
}

/// A cgroup v2 id is its directory's inode.
pub fn cgroup_id(dir: &str) -> std::io::Result<u64> {
    Ok(std::fs::metadata(dir)?.ino())
}

fn cgroup_dir(unit: &str) -> String {
    format!(
        "/sys/fs/cgroup/{}",
        Nft::scope_cgroup(QUARANTINE_SLICE, unit)
    )
}

/// The lowest address in 127.77.0.0/16 not in `open`, skipping .0 and
/// .255 in the last octet.
pub fn pick_addr(open: &[Ipv4Addr]) -> Option<Ipv4Addr> {
    let open: std::collections::HashSet<&Ipv4Addr> = open.iter().collect();
    (1..0xffff_u32)
        .map(|i| Ipv4Addr::new(127, 77, (i >> 8) as u8, i as u8))
        .filter(|a| !matches!(a.octets()[3], 0 | 255))
        .find(|a| !open.contains(a))
}

/// The address the last `honeypot_open` recorded.
fn open_addr(acts: &[ActionRecord]) -> Option<Ipv4Addr> {
    acts.iter()
        .rev()
        .find(|a| a.ok && a.kind == "honeypot_open")?
        .detail
        .as_deref()?
        .parse()
        .ok()
}

/// When the last `honeypot_open` was recorded, in Unix ms. The record
/// keeps whole seconds, so this is never later than the open itself.
fn opened_ms(acts: &[ActionRecord]) -> u64 {
    acts.iter()
        .rev()
        .find(|a| a.ok && a.kind == "honeypot_open")
        .and_then(|a| unix_secs(&a.ts))
        .map_or(0, |s| s.saturating_mul(1000))
}

/// One action per rule `Nft::redirect` added, in its order.
fn redirect_acts(unit: &str, handles: Vec<u64>, why: Option<&str>) -> Vec<ActionRecord> {
    let kinds = ["nft_accept", "nft_accept", "nft_dnat", "nft_dnat"];
    kinds
        .iter()
        .zip(handles)
        .map(|(k, h)| {
            let mut a = act(k, Some(unit), vec![], Ok(Some(h)));
            a.detail = why.map(String::from);
            a
        })
        .collect()
}

impl Enforcer {
    /// The settings and address a new tree is observed with, or None for
    /// drop mode: the network is "drop", every observed slot is taken,
    /// or there is no address left.
    pub(super) fn plan(&self, id: &str) -> Option<(Honeypot, Ipv4Addr)> {
        let hp = (*self.honeypot.lock().unwrap_or_else(|e| e.into_inner()))?;
        if (self.observing.len() + 1) * hp.max_tasks as usize > HELD_BUDGET {
            eprintln!(
                "aegisd: {id}: {} trees of up to {} tasks observed already; \
                 quarantined with the network dropped",
                self.observing.len(),
                hp.max_tasks
            );
            return None;
        }
        if self.observing.len() >= hp.max_incidents as usize {
            eprintln!(
                "aegisd: {id}: {} trees observed already ([honeypot] max_incidents); \
                 quarantined with the network dropped",
                self.observing.len()
            );
            return None;
        }
        // An address in its grace isn't reused: its late sessions must
        // reach the incident that had it.
        let taken: Vec<Ipv4Addr> = self
            .observing
            .values()
            .map(|o| o.addr)
            .chain(
                self.closed
                    .iter()
                    .filter(|(_, (_, t))| hp.in_grace(*t))
                    .map(|(a, _)| *a),
            )
            .collect();
        let addr = pick_addr(&taken);
        if addr.is_none() {
            eprintln!(
                "aegisd: {id}: no honeypot address left; quarantined with the network dropped"
            );
        }
        Some((hp, addr?))
    }

    /// Steps 4 to 6 of the order for a tree just held and moved into
    /// `unit`: guard, drop rule, redirect rules, listener, then each held
    /// process's hold opened to the scope. True if it got that far; else
    /// the failure is recorded and the caller freezes the tree. Also
    /// returns the scope's cgroup id once known, so a caller whose tree
    /// was opened partway can close it again.
    pub(super) fn observe(
        &mut self,
        id: &str,
        unit: &str,
        held: &[ProcKey],
        hp: Honeypot,
        addr: Ipv4Addr,
        acts: &mut Vec<ActionRecord>,
    ) -> (bool, Option<u64>) {
        let not_observed = "not observed, frozen as with network = \"drop\"";
        let dir = cgroup_dir(unit);
        let cgid = match self.wait_cgroup(&dir) {
            Ok(c) => c,
            Err(e) => {
                acts.push(act(
                    "observe",
                    Some(unit),
                    vec![],
                    Err(e.context(not_observed)),
                ));
                return (false, None);
            }
        };
        if let Err(e) = self.open_up(unit, cgid, held, hp, addr, acts) {
            // The marker, if written, goes once the caller has frozen it.
            acts.push(act(
                "observe",
                Some(unit),
                vec![],
                Err(e.context(not_observed)),
            ));
            // The address was never recorded as taken: its rules go too.
            acts.extend(self.remove_redirects(unit));
            return (false, Some(cgid));
        }
        self.observing.insert(
            id.into(),
            Observed {
                addr,
                cgroup_id: cgid,
                opened: Instant::now(),
                tcp: hp.tcp_port,
                dns: hp.dns_port,
            },
        );
        let mut a = act(
            "honeypot_open",
            None,
            held.iter().map(|k| k.tgid).collect(),
            Ok(None),
        );
        a.detail = Some(addr.to_string());
        acts.push(a);
        (true, Some(cgid))
    }

    fn open_up(
        &mut self,
        unit: &str,
        cgid: u64,
        held: &[ProcKey],
        hp: Honeypot,
        addr: Ipv4Addr,
        acts: &mut Vec<ActionRecord>,
    ) -> Result<()> {
        self.guard
            .attach(&cgroup_dir(unit), hp.tcp_port, hp.dns_port)
            .context("attaching the egress guard")?;
        acts.push(act("guard", Some(unit), vec![], Ok(None)));
        let d = self.add_drop(unit);
        let ruled = d.ok;
        acts.push(d);
        if !ruled {
            bail!("the drop rule failed");
        }
        let cg = Nft::scope_cgroup(QUARANTINE_SLICE, unit);
        let hs = self
            .nft
            .ensure_nat()
            .and_then(|()| self.nft.redirect(&cg, addr, hp.tcp_port, hp.dns_port))?;
        acts.extend(redirect_acts(unit, hs, None));
        // Read from /proc, never by connecting: that would be a session.
        let up = (self.listening)(hp.tcp_port, hp.dns_port)
            .context("reading /proc/net for the honeypot's sockets")?;
        if !up {
            bail!(
                "nothing listens on 0.0.0.0:{} (TCP) and 0.0.0.0:{} (UDP)",
                hp.tcp_port,
                hp.dns_port
            );
        }
        self.mark(unit)?;
        for k in held {
            self.holds.open(*k, cgid)?;
        }
        Ok(())
    }

    fn wait_cgroup(&self, dir: &str) -> Result<u64> {
        let until = Instant::now() + CGROUP_WAIT;
        loop {
            match (self.cgroup_id)(dir) {
                Ok(c) => return Ok(c),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(anyhow!(e).context(format!("reading {dir}"))),
            }
        }
    }

    /// Closes every hold opened to cgroup `cgid`. On a tree that may not
    /// be frozen the walk runs twice, since a fork during the first can
    /// add an entry it misses. The closed are recorded with their start
    /// times: release no longer finds them by scope.
    pub(super) fn close_holds(&mut self, unit: &str, cgid: u64, frozen: bool) -> Vec<ActionRecord> {
        let mut r = self.holds.close_scope(cgid);
        if !frozen {
            r = r.and_then(|mut t| {
                t.extend(self.holds.close_scope(cgid)?);
                Ok(t)
            });
        }
        match r {
            Ok(t) if t.is_empty() => Vec::new(),
            Ok(t) => {
                let keys: Vec<(u32, u64)> = t
                    .into_iter()
                    .filter_map(|tgid| Some((tgid, self.holds.start_time(tgid).ok()??)))
                    .collect();
                let mut a = act(
                    "close",
                    Some(unit),
                    keys.iter().map(|k| k.0).collect(),
                    Ok(None),
                );
                a.start_times = keys.iter().map(|k| k.1).collect();
                vec![a]
            }
            Err(e) => vec![act("close", Some(unit), vec![], Err(e))],
        }
    }

    /// Ends an observation, as at expiry: freeze, close the holds, remove
    /// the redirect rules (the drop rule stays) and free the address. The
    /// tree is then quarantined as in drop mode.
    pub(super) fn close_observation(&mut self, id: &str, why: &str) -> Vec<ActionRecord> {
        let unit = q_unit(id);
        let mut acts = Vec::new();
        // Nothing left in the scope: nothing to freeze.
        let empty = matches!(self.sys.is_populated(QUARANTINE_SLICE, &unit), Ok(false));
        let mut frozen = false;
        if !empty {
            let a = self.freeze(&unit);
            frozen = a.ok;
            acts.push(a);
        }
        let cgid = self
            .observing
            .get(id)
            .map(|o| o.cgroup_id)
            .or_else(|| (self.cgroup_id)(&cgroup_dir(&unit)).ok());
        if let Some(c) = cgid {
            acts.extend(self.close_holds(&unit, c, frozen));
        }
        acts.extend(self.remove_redirects(&unit));
        acts.extend(self.unobserve(id, why, !frozen && !empty));
        acts
    }

    /// Removes `unit`'s accept and DNAT rules; its drop rule stays.
    fn remove_redirects(&self, unit: &str) -> Vec<ActionRecord> {
        let cg = Nft::scope_cgroup(QUARANTINE_SLICE, unit);
        match self.nft.list() {
            Ok(l) => {
                let l = l.unwrap_or_default();
                Nft::redirects(&l, &cg)
                    .into_iter()
                    .map(|(chain, h)| {
                        let r = self.nft.remove(chain, h).map(|()| Some(h));
                        act("nft_remove", Some(unit), vec![], r)
                    })
                    .collect()
            }
            Err(e) => vec![act("nft_remove", Some(unit), vec![], Err(e))],
        }
    }

    /// Before a release or kill of an observed tree: freeze it, so the
    /// set of its holds is stable, then release every hold opened to its
    /// scope, children the kernel added included.
    pub(super) fn stop_observing(&mut self, id: &str) -> Vec<ActionRecord> {
        let Some(o) = self.observing.get(id).copied() else {
            return Vec::new();
        };
        let unit = q_unit(id);
        let mut acts = vec![self.freeze(&unit)];
        let r = self.holds.release_scope(o.cgroup_id);
        let pids = r.as_ref().map(|t| t.clone()).unwrap_or_default();
        let mut a = act("unhold", None, pids, r.map(|_| None));
        a.detail = Some("holds open to the scope".into());
        acts.push(a);
        acts
    }

    /// Frees the address and takes the guard off the scope. With `keep`
    /// (a tree that could not be frozen) the guard and the marker stay.
    pub(super) fn unobserve(&mut self, id: &str, why: &str, keep: bool) -> Vec<ActionRecord> {
        let unit = q_unit(id);
        let mut acts = Vec::new();
        // At start the record alone says it was observed, and where.
        let (was, addr) = match self.observing.remove(id) {
            Some(o) => (true, Some(o.addr)),
            None => {
                let rec = self.actions(id);
                (super::observing(&rec), open_addr(&rec))
            }
        };
        if let (true, Some(a)) = (was, addr) {
            self.closed.insert(a, (id.into(), SystemTime::now()));
        }
        // Also when the record no longer says observing: a marker kept
        // after a failed freeze must not outlive a release or kill.
        if !keep {
            self.unmark(&unit);
        }
        if was {
            let mut a = act("honeypot_close", None, vec![], Ok(None));
            a.detail = Some(why.into());
            acts.push(a);
        }
        if keep {
            return acts;
        }
        if let Err(e) = self.guard.detach(&cgroup_dir(&unit)) {
            acts.push(act("guard", Some(&unit), vec![], Err(e)));
        }
        acts
    }

    /// Closes each observation whose window has passed, or every one once
    /// a reload has set the network back to "drop" or moved the ports.
    pub(super) fn expire_observations(&mut self) {
        let hp = *self.honeypot.lock().unwrap_or_else(|e| e.into_inner());
        let due: Vec<(String, &str)> = self
            .observing
            .iter()
            .filter_map(|(id, o)| {
                let why = match hp {
                    None => "quarantine.network is now \"drop\"",
                    Some(h) if (h.tcp_port, h.dns_port) != (o.tcp, o.dns) => {
                        "the honeypot ports changed"
                    }
                    Some(h) if o.opened.elapsed() >= h.window => "observation window ended",
                    Some(_) => return None,
                };
                Some((id.clone(), why))
            })
            .collect();
        for (id, why) in due {
            eprintln!("aegisd: {id}: {why}; frozen");
            let acts = self.close_observation(&id, why);
            self.finish(&id, acts, None);
        }
    }

    /// Files the honeypot's finished sessions into the incidents whose
    /// addresses they were on: observed now, or within their grace.
    /// Nothing in drop mode, where the spool isn't even looked up.
    pub(super) fn file_sessions(&mut self) {
        let Some(hp) = *self.honeypot.lock().unwrap_or_else(|e| e.into_inner()) else {
            return;
        };
        self.closed.retain(|_, (_, t)| hp.in_grace(*t));
        if !self.closed.is_empty() {
            self.keep_local_rule();
        }
        let Some(dir) = self.spool.clone() else {
            return;
        };
        let mut by_addr: HashMap<Ipv4Addr, String> = self
            .closed
            .iter()
            .map(|(a, (id, _))| (*a, id.clone()))
            .collect();
        by_addr.extend(self.observing.iter().map(|(id, o)| (o.addr, id.clone())));
        let lim = spool::Limits {
            max_session_bytes: hp.max_session_bytes,
            // Ruled: twice the time cap and a minute.
            stale: Duration::from_secs(hp.session_seconds.saturating_mul(2).saturating_add(60)),
            max_filed: spool::MAX_FILED,
        };
        let targets: HashMap<Ipv4Addr, (String, std::path::PathBuf, u64)> = by_addr
            .into_iter()
            .filter_map(|(a, id)| {
                let dir = self.store.dir_of(&IncidentId(id.clone()))?;
                spool::tidy(&dir);
                let opened = opened_ms(&self.actions(&id));
                Some((a, (id, dir, opened)))
            })
            .collect();
        let find = |a: Ipv4Addr| targets.get(&a).cloned();
        let r = match spool::sweep(&dir, lim, &find) {
            Ok(r) => r,
            Err(e) => return eprintln!("aegisd: honeypot spool {}: {e}", dir.display()),
        };
        let c = &self.filing;
        c.filed.fetch_add(r.filed.len() as u64, Ordering::Relaxed);
        c.unmatched.fetch_add(r.unmatched, Ordering::Relaxed);
        c.rejected.fetch_add(r.rejected, Ordering::Relaxed);
        if r.rejected > 0 {
            eprintln!(
                "aegisd: honeypot spool: {} sessions rejected and deleted, first {}",
                r.rejected,
                r.why.unwrap_or_default()
            );
        }
        if r.unmatched > 0 {
            eprintln!(
                "aegisd: honeypot spool: {} sessions for no observed address deleted",
                r.unmatched
            );
        }
        if r.stale > 0 {
            eprintln!(
                "aegisd: honeypot spool: {} unfinished sessions a stopped honeypot left deleted",
                r.stale
            );
        }
        if let Some(e) = &r.io {
            eprintln!("aegisd: honeypot spool: filing stopped for this tick, {e}");
        }
        for (id, s) in r.filed {
            let iid = IncidentId(id.clone());
            if let Err(e) = self
                .store
                .add_event(&iid, "honeypot_session", spool::event(&s))
            {
                eprintln!(
                    "aegisd: {id}: honeypot session {} filed, not on the timeline: {e:#}",
                    s.id
                );
            }
            self.report(&id, spool::reason(&s));
        }
    }

    /// Puts back an observed tree's honeypot rules and the slice-wide
    /// rule if a flush or an admin removed any. A partial set is removed
    /// and added again whole; the drop rule keeps the tree cut off
    /// meanwhile.
    pub(super) fn restore_redirects(&mut self, id: &str, listing: &str, why: &str) {
        let Some(o) = self.observing.get(id).copied() else {
            return;
        };
        let unit = q_unit(id);
        let cg = Nft::scope_cgroup(QUARANTINE_SLICE, &unit);
        let red = Nft::redirects(listing, &cg);
        let n = |c: &str| red.iter().filter(|r| r.0 == c).count();
        let whole = n("out") == 2 && n(NAT) == 2;
        if whole && Nft::has_local_rule(listing) {
            return;
        }
        let mut removed = Vec::new();
        let r = self.nft.ensure_nat().and_then(|()| {
            if whole {
                return Ok(Vec::new());
            }
            for (c, h) in &red {
                let r = self.nft.remove(c, *h);
                let failed = r.is_err();
                removed.push(act("nft_remove", Some(&unit), vec![], r.map(|()| Some(*h))));
                if failed {
                    bail!("removing a partial set of honeypot rules failed");
                }
            }
            self.nft.redirect(&cg, o.addr, o.tcp, o.dns)
        });
        match r {
            Ok(hs) if hs.is_empty() => {}
            Ok(hs) => {
                eprintln!("aegisd: {id}: honeypot rules {why}");
                removed.extend(redirect_acts(&unit, hs, Some(why)));
                self.finish(id, removed, None);
            }
            Err(e) => {
                if !removed.is_empty() {
                    self.finish(id, std::mem::take(&mut removed), None);
                }
                let failing = self
                    .actions(id)
                    .iter()
                    .rev()
                    .find(|a| matches!(a.kind.as_str(), "nft_accept" | "nft_dnat" | "nft_redirect"))
                    .is_some_and(|a| !a.ok);
                if failing {
                    eprintln!("aegisd: {id}: {e:#}");
                } else {
                    self.finish(
                        id,
                        vec![act("nft_redirect", Some(&unit), vec![], Err(e))],
                        None,
                    );
                }
            }
        }
    }

    /// At start: closes each observation the last aegisd left, as at
    /// expiry. Its holds and guard died with it, and the unit's
    /// ExecStopPost froze the tree; this records that and frees the
    /// address and rules.
    pub fn close_observing(&mut self) {
        self.regrace();
        let ids: Vec<String> = self
            .store
            .list()
            .into_iter()
            .filter(|s| s.state.as_deref() == Some("observing"))
            .map(|s| s.id)
            .collect();
        for id in ids {
            let acts = self.close_observation(&id, "aegisd restarted");
            self.finish(&id, acts, None);
        }
        if let Some(d) = &self.marks {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    /// Puts back the rule keeping everyone but observed trees off the
    /// honeypot addresses, if a flush took it while nothing is observed
    /// (`restore_redirects` does it while something is): late sessions
    /// on an address in its grace still file.
    fn keep_local_rule(&self) {
        let r = self.nft.list().and_then(|l| match l {
            Some(l) if Nft::has_local_rule(&l) => Ok(()),
            Some(_) => self.nft.ensure_nat(),
            None => self.nft.ensure_table().and_then(|()| self.nft.ensure_nat()),
        });
        if let Err(e) = r {
            eprintln!("aegisd: putting back the honeypot address rule: {e:#}");
        }
    }

    /// At start: puts back the grace of each address whose observation
    /// ended lately, from the record, so it isn't handed to a new tree
    /// while its late sessions may still come; and removes what a crash
    /// mid-filing left. Honeypot mode only.
    fn regrace(&mut self) {
        let Some(hp) = *self.honeypot.lock().unwrap_or_else(|e| e.into_inner()) else {
            return;
        };
        for s in self.store.list() {
            if let Some(d) = self.store.dir_of(&IncidentId(s.id.clone())) {
                spool::tidy(&d);
            }
            let acts = self.actions(&s.id);
            let last = acts
                .iter()
                .rev()
                .find(|a| a.ok && matches!(a.kind.as_str(), "honeypot_open" | "honeypot_close"));
            let Some(close) = last.filter(|a| a.kind == "honeypot_close") else {
                continue;
            };
            let (Some(addr), Some(secs)) = (open_addr(&acts), unix_secs(&close.ts)) else {
                continue;
            };
            // A clock set back must not stretch the grace past its length.
            let t = (SystemTime::UNIX_EPOCH + Duration::from_secs(secs)).min(SystemTime::now());
            if hp.in_grace(t) {
                self.closed.insert(addr, (s.id, t));
            }
        }
    }

    fn mark(&self, unit: &str) -> Result<()> {
        let Some(d) = &self.marks else {
            return Ok(());
        };
        std::fs::create_dir_all(d)
            .and_then(|()| std::fs::write(d.join(unit), ""))
            .with_context(|| format!("marking {unit} in {}", d.display()))
    }

    pub(super) fn unmark(&self, unit: &str) {
        if let Some(d) = &self.marks {
            let _ = std::fs::remove_file(d.join(unit));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        static FROZE: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    #[test]
    fn sigterm_freezes_only_the_marked_scopes() {
        fn run(_: &str, a: &[String]) -> Result<String> {
            FROZE.with(|f| f.borrow_mut().push(a.join(" ")));
            if a[1].contains("bad") {
                bail!("no such unit")
            }
            Ok(String::new())
        }
        let d = std::env::temp_dir().join(format!("aegis-marks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for f in [
            "aegis-incident-A-q.scope",
            "aegis-incident-bad-q.scope",
            "other.scope",
        ] {
            std::fs::write(d.join(f), "").unwrap();
        }
        let sys = Systemd::with(run, |_, _| true);
        let failed = freeze_marked(&d, &sys);
        let mut froze = FROZE.with(|f| f.take());
        froze.sort();
        assert_eq!(
            froze,
            [
                "freeze aegis-incident-A-q.scope",
                "freeze aegis-incident-bad-q.scope"
            ]
        );
        assert_eq!(failed.len(), 1);
        assert!(failed[0].starts_with("aegis-incident-bad-q.scope: "));
        assert!(freeze_marked(&d.join("none"), &sys).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn pick_addr_skips_taken_and_edges() {
        let a = |c, d| Ipv4Addr::new(127, 77, c, d);
        assert_eq!(pick_addr(&[]), Some(a(0, 1)));
        assert_eq!(pick_addr(&[a(0, 1), a(0, 3)]), Some(a(0, 2)));
        let first: Vec<Ipv4Addr> = (1..=254).map(|d| a(0, d)).collect();
        // .255 and the next .0 are skipped.
        assert_eq!(pick_addr(&first), Some(a(1, 1)));
        let all: Vec<Ipv4Addr> = (0..=255u8)
            .flat_map(|c| (1..=254).map(move |d| a(c, d)))
            .collect();
        assert_eq!(pick_addr(&all), None);
    }
}
