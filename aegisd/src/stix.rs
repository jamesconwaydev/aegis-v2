// SPDX-License-Identifier: MIT OR Apache-2.0
//! `incidents stix`: a STIX 2.1 bundle of what an incident saw, made on
//! demand from `incident.json` and the filed honeypot sessions.
//!
//! Two exports of the same incident are byte for byte the same. An
//! observable's id is the one STIX 2.1 itself derives from it (a UUIDv5
//! of its id-contributing properties under `SCO_NS`), so the same
//! domain or hash has the same id in every bundle, from any tool. The
//! other objects' ids are UUIDv5s of (incident id, type, value) under
//! `NS`, and their `created` and `modified` are the incident's own.

use std::collections::HashSet;

use aegis_proto::honeypot::{Protocol, Session};
use serde_json::{json, Map, Value};
use sha1::{Digest, Sha1};

use crate::incident::Incident;
use crate::telemetry::{rfc3339, unix_secs};

/// aegis-v2's namespace for the ids of objects that aren't observables.
/// Never change it: ids already shared would stop matching.
const NS: [u8; 16] = [
    0x8c, 0x9d, 0x6a, 0x8e, 0x3b, 0x5f, 0x4e, 0x1a, 0x9f, 0x27, 0x6d, 0x4c, 0x2b, 0x1a, 0x0e, 0x93,
];
/// STIX 2.1's namespace for observable ids,
/// 00abedb4-aa42-466c-9c01-fed23315a9b7 (section 2.9).
const SCO_NS: [u8; 16] = [
    0x00, 0xab, 0xed, 0xb4, 0xaa, 0x42, 0x46, 0x6c, 0x9c, 0x01, 0xfe, 0xd2, 0x33, 0x15, 0xa9, 0xb7,
];
/// Objects in one bundle. Sessions that would go past it, or past
/// `MAX_BYTES`, are left out and the observed-data says so.
const MAX_OBJECTS: usize = 20_000;
/// Bytes of objects in one bundle: under aegisctl's 16 MiB reply cap
/// with room for the observed-data that lists them all.
const MAX_BYTES: usize = 12 << 20;

/// RFC 9562 UUIDv5: SHA-1 of namespace and name, version and variant set.
fn uuid5(ns: &[u8; 16], name: &str) -> String {
    let mut h = Sha1::new();
    h.update(ns);
    h.update(name.as_bytes());
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    let x: String = b.iter().map(|v| format!("{v:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &x[..8],
        &x[8..12],
        &x[12..16],
        &x[16..20],
        &x[20..]
    )
}

/// STIX wants millisecond timestamps for `created` and `modified`.
fn ts_ms(ms: u64) -> String {
    let s = rfc3339(ms.saturating_mul(1_000_000));
    format!("{}.{:03}Z", &s[..19], ms % 1000)
}

/// A time as short as it goes: no fraction when it is whole, no
/// trailing zeros. Observable times feed their ids, and this is how
/// the OASIS stix2 library writes them, so its ids and ours agree.
fn ts_short(ms: u64) -> String {
    let s = rfc3339(ms.saturating_mul(1_000_000));
    match ms % 1000 {
        0 => s,
        f => format!("{}.{}Z", &s[..19], format!("{f:03}").trim_end_matches('0')),
    }
}

/// A STIX pattern string literal.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// The bundle, built a session at a time.
pub struct Bundle {
    inc: String,
    created: String,
    identity: String,
    objects: Vec<Value>,
    indicators: Vec<Value>,
    ids: HashSet<String>,
    /// Every observable, for the observed-data, in the order added.
    refs: Vec<String>,
    bytes: usize,
    /// Something didn't fit: nothing more is added.
    full: bool,
    first_ms: u64,
    last_ms: u64,
}

impl Bundle {
    fn own_id(&self, ty: &str, value: &str) -> String {
        format!(
            "{ty}--{}",
            uuid5(&NS, &format!("{}|{ty}|{value}", self.inc))
        )
    }

    /// Adds `o` unless its id is already in, or it doesn't fit; its id
    /// when it is in the bundle.
    fn push(&mut self, o: Value, indicator: bool) -> Option<String> {
        let id = o["id"].as_str().unwrap_or_default().to_string();
        if self.ids.contains(&id) {
            return Some(id);
        }
        let size = o.to_string().len();
        // One place is kept for the observed-data.
        if self.full || self.ids.len() + 1 >= MAX_OBJECTS || self.bytes + size > MAX_BYTES {
            self.full = true;
            return None;
        }
        self.bytes += size;
        self.ids.insert(id.clone());
        if indicator {
            self.indicators.push(o);
        } else {
            self.objects.push(o);
        }
        Some(id)
    }

    /// An observable. Its id is STIX's: a UUIDv5 under `SCO_NS` of the
    /// canonical JSON (RFC 8785) of the properties in `keys` that it
    /// has. serde_json without preserve_order sorts keys and writes
    /// compact JSON with the same escapes, so `to_string` is that form.
    /// Refs among `keys` must already be ids, so children come first.
    fn sco(&mut self, ty: &str, mut o: Value, keys: &[&str]) -> Option<String> {
        let canon: Map<String, Value> = keys
            .iter()
            .filter_map(|k| Some((k.to_string(), o.get(*k)?.clone())))
            .collect();
        let id = format!(
            "{ty}--{}",
            uuid5(&SCO_NS, &Value::Object(canon).to_string())
        );
        o["type"] = ty.into();
        o["id"] = id.into();
        let id = self.push(o, false)?;
        self.refs.push(id.clone());
        Some(id)
    }

    fn indicate(&mut self, pattern: String, name: String) {
        let o = json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": self.own_id("indicator", &pattern),
            "created": self.created,
            "modified": self.created,
            "created_by_ref": self.identity,
            "name": name,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": self.created,
        });
        self.push(o, true);
    }

    fn domain(&mut self, name: &str) {
        if self
            .sco("domain-name", json!({ "value": name }), &["value"])
            .is_some()
        {
            self.indicate(
                format!("[domain-name:value = {}]", quote(name)),
                format!("Domain name seen in {}", self.inc),
            );
        }
    }

    fn payload(&mut self, sha: &str) {
        let o = json!({ "hashes": { "SHA-256": sha } });
        if self
            .sco("file", o, &["hashes", "name", "parent_directory_ref"])
            .is_some()
        {
            self.indicate(
                format!("[file:hashes.'SHA-256' = {}]", quote(sha)),
                format!("Payload sent to the honeypot in {}", self.inc),
            );
        }
    }

    /// The host's identity and the incident's processes.
    pub fn new(inc: &Incident, host: &str) -> Self {
        let first_ms = unix_secs(&inc.created).unwrap_or(0).saturating_mul(1000);
        let last_ms = unix_secs(&inc.updated).unwrap_or(0).saturating_mul(1000);
        let mut b = Bundle {
            inc: inc.id.clone(),
            created: ts_ms(first_ms),
            identity: String::new(),
            objects: Vec::new(),
            indicators: Vec::new(),
            ids: HashSet::new(),
            refs: Vec::new(),
            bytes: 0,
            full: false,
            first_ms,
            last_ms: last_ms.max(first_ms),
        };
        let identity = json!({
            "type": "identity",
            "spec_version": "2.1",
            "id": b.own_id("identity", host),
            "created": b.created,
            "modified": b.created,
            "name": host,
            "identity_class": "system",
        });
        b.identity = b.push(identity, false).unwrap_or_default();
        for p in &inc.process_tree {
            let mut o = json!({ "pid": p.tgid });
            if let Some(exe) = &p.exe {
                let (dir, name) = exe.rsplit_once('/').unwrap_or(("", exe));
                let mut f = json!({ "name": name });
                if !dir.is_empty() {
                    if let Some(d) = b.sco("directory", json!({ "path": dir }), &["path"]) {
                        f["parent_directory_ref"] = d.into();
                    }
                }
                if let Some(f) = b.sco("file", f, &["hashes", "name", "parent_directory_ref"]) {
                    o["image_ref"] = f.into();
                }
            }
            // A process has no id-contributing properties, so STIX would
            // give it a random id; ours is per incident, so exports
            // stay identical.
            o["type"] = "process".into();
            o["id"] = b
                .own_id("process", &format!("{}:{}", p.tgid, p.start_time_ns))
                .into();
            if let Some(id) = b.push(o, false) {
                b.refs.push(id);
            }
        }
        b
    }

    /// One filed session's observables. False once the bundle is full.
    pub fn session(&mut self, s: &Session) -> bool {
        if self.full {
            return false;
        }
        self.first_ms = self.first_ms.min(s.started_ms);
        self.last_ms = self.last_ms.max(s.ended_ms);
        let ip = s.dst.ip().to_string();
        let Some(dst) = self.sco("ipv4-addr", json!({ "value": ip }), &["value"]) else {
            return false;
        };
        let mut protocols = vec!["ipv4"];
        protocols.push(if s.protocol == Protocol::Dns {
            "udp"
        } else {
            "tcp"
        });
        let app = serde_json::to_value(s.protocol).unwrap_or_default();
        if s.protocol != Protocol::Raw {
            protocols.push(app.as_str().unwrap_or_default());
        }
        let mut nt = json!({
            "start": ts_short(s.started_ms),
            "end": ts_short(s.ended_ms.max(s.started_ms)),
            // Filed means closed; STIX wants that said when `end` is.
            "is_active": false,
            "dst_ref": dst,
            "dst_port": s.dst.port(),
            // Keeps two sessions alike in all else apart.
            "src_port": s.src.port(),
            "protocols": protocols,
            "src_byte_count": s.bytes_in,
            "dst_byte_count": s.bytes_out,
        });
        if let Some(j) = &s.ja4 {
            nt["x_aegis_ja4"] = j.as_str().into();
        }
        let keys = [
            "start",
            "end",
            "src_ref",
            "dst_ref",
            "src_port",
            "dst_port",
            "protocols",
            "extensions",
        ];
        self.sco("network-traffic", nt, &keys);
        let names = s
            .dns_name
            .iter()
            .chain(&s.sni)
            .chain(s.queries.iter().map(|q| &q.name));
        for n in names {
            self.domain(n);
        }
        for h in &s.payloads {
            self.payload(h);
        }
        !self.full
    }

    /// The bundle. `unread` filed sessions never reached `session`;
    /// `capped` when filing stopped at its cap and deleted later ones.
    pub fn finish(mut self, unread: usize, capped: bool) -> Value {
        let mut seen = HashSet::new();
        let mut refs = std::mem::take(&mut self.refs);
        refs.retain(|r| seen.insert(r.clone()));
        let mut od = json!({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": self.own_id("observed-data", &self.inc),
            "created": self.created,
            "modified": self.created,
            "created_by_ref": self.identity,
            "first_observed": ts_ms(self.first_ms),
            "last_observed": ts_ms(self.last_ms.max(self.first_ms)),
            "number_observed": 1,
            "object_refs": refs,
            "x_aegis_incident": self.inc,
        });
        if self.full || unread > 0 || capped {
            od["x_aegis_truncated"] = true.into();
        }
        if capped {
            od["x_aegis_note"] = format!(
                "filing stopped at {} sessions; later ones were not kept",
                crate::spool::MAX_FILED
            )
            .into();
        }
        // Not through `push`: the budget leaves room for it.
        let mut objects = std::mem::take(&mut self.objects);
        objects.push(od);
        objects.append(&mut self.indicators);
        json!({
            "type": "bundle",
            "id": self.own_id("bundle", &self.inc),
            "objects": objects,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::filed::tests::session;
    use aegis_proto::honeypot::DnsQuery;
    use std::net::Ipv4Addr;

    pub(crate) const ID: &str = "AEG-20261029-120000-0123456789abcdef";

    /// What main does, over a list.
    fn bundle(inc: &Incident, sessions: &[Session], host: &str) -> Value {
        let mut b = Bundle::new(inc, host);
        for s in sessions {
            if !b.session(s) {
                break;
            }
        }
        b.finish(0, false)
    }

    pub(crate) fn incident() -> Incident {
        serde_json::from_value(json!({
            "id": ID,
            "created": "2026-10-29T12:00:00Z",
            "updated": "2026-10-29T12:05:00Z",
            "mode": "enforce",
            "verdict": "quarantined",
            "max_score": 90.0,
            "score": 90.0,
            "root": {"tgid": 4242, "start_time_ns": 7, "exe": "/tmp/x/dropper",
                     "exe_b64": null, "comm": "dropper", "uid": 0,
                     "selinux_domain": null, "verification": "unverified"},
            "process_tree": [
                {"tgid": 4242, "start_time_ns": 7, "exe": "/tmp/x/dropper",
                 "exe_b64": null, "comm": "dropper", "uid": 0,
                 "selinux_domain": null, "verification": "unverified"},
                {"tgid": 4243, "start_time_ns": 9, "exe": "/usr/bin/curl",
                 "exe_b64": null, "comm": "curl", "uid": 0,
                 "selinux_domain": null, "verification": "rpm_owned:curl"}
            ],
            "evidence": []
        }))
        .unwrap()
    }

    fn sessions() -> Vec<Session> {
        let mut dns = session("1793275200000-0000000a", Protocol::Dns);
        dns.dst = "198.18.0.53:53".parse().unwrap();
        dns.queries = vec![DnsQuery {
            name: "c2.example".into(),
            qtype: "A".into(),
            answer: Some(Ipv4Addr::new(198, 18, 0, 1)),
        }];
        let mut https = session("1793275201000-0000000b", Protocol::Https);
        https.dst = "198.18.0.1:443".parse().unwrap();
        https.dns_name = Some("c2.example".into());
        https.sni = Some("it's\\odd.example".into());
        https.ja4 = Some("t13d1516h2_8daaf6152771_e5627efa2ab1".into());
        let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        https.payloads = vec![sha.into()];
        https.ended_ms = https.started_ms + 2500;
        vec![dns, https]
    }

    #[test]
    fn uuid5_matches_the_rfc_example() {
        // RFC 9562 appendix A.4: the DNS namespace and "www.example.com".
        let dns = [
            0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4,
            0x30, 0xc8,
        ];
        assert_eq!(
            uuid5(&dns, "www.example.com"),
            "2ed6657d-e927-568b-95e1-2665a8aea6a2"
        );
    }

    #[test]
    fn stix_bundle_matches_the_golden_file() {
        let got = serde_json::to_string_pretty(&bundle(&incident(), &sessions(), "web01")).unwrap();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/testdata/stix-bundle.json");
        if std::env::var_os("AEGIS_BLESS").is_some() {
            std::fs::write(path, got.clone() + "\n").unwrap();
        }
        assert_eq!(got + "\n", std::fs::read_to_string(path).unwrap());
    }

    #[test]
    fn two_exports_are_identical() {
        let a = serde_json::to_vec(&bundle(&incident(), &sessions(), "web01")).unwrap();
        let b = serde_json::to_vec(&bundle(&incident(), &sessions(), "web01")).unwrap();
        assert_eq!(a, b);
    }

    /// Every `id` once, and every `*_ref` and `*_refs` names one of them.
    fn assert_refs_resolve(b: &Value) {
        let objs = b["objects"].as_array().unwrap();
        let mut ids = HashSet::new();
        for o in objs {
            assert!(ids.insert(o["id"].as_str().unwrap()), "{o}");
            let ty = o["type"].as_str().unwrap();
            assert!(o["id"].as_str().unwrap().starts_with(&format!("{ty}--")));
        }
        let mut n = 0;
        for o in objs {
            for (k, v) in o.as_object().unwrap() {
                let refs: Vec<&Value> = if k.ends_with("_refs") {
                    v.as_array().unwrap().iter().collect()
                } else if k.ends_with("_ref") {
                    vec![v]
                } else {
                    continue;
                };
                for r in refs {
                    n += 1;
                    assert!(ids.contains(r.as_str().unwrap()), "{k}: {r} in {o}");
                }
            }
        }
        assert!(n > 0);
    }

    #[test]
    fn every_ref_resolves_inside_the_bundle() {
        let b = bundle(&incident(), &sessions(), "web01");
        assert_refs_resolve(&b);
        let objs = b["objects"].as_array().unwrap();
        let ty = |t: &str| objs.iter().filter(|o| o["type"] == t).count();
        assert_eq!(
            (ty("identity"), ty("observed-data"), ty("network-traffic")),
            (1, 1, 2)
        );
        // c2.example twice, once as a query and once as the session's
        // name, is one object and one indicator.
        assert_eq!((ty("domain-name"), ty("indicator")), (2, 3));
        let nt = objs.iter().find(|o| o["x_aegis_ja4"].is_string()).unwrap();
        assert_eq!(nt["protocols"], json!(["ipv4", "tcp", "https"]));
        let ind = objs
            .iter()
            .find(|o| {
                o["name"].as_str().is_some_and(|n| n.starts_with("Domain"))
                    && o["pattern"].as_str().unwrap().contains("odd")
            })
            .unwrap();
        assert_eq!(
            ind["pattern"],
            "[domain-name:value = 'it\\'s\\\\odd.example']"
        );
    }

    #[test]
    fn a_drop_mode_incident_still_exports_its_processes() {
        let b = bundle(&incident(), &[], "web01");
        assert_refs_resolve(&b);
        let od = b["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == "observed-data")
            .unwrap();
        assert_eq!(od["first_observed"], "2026-10-29T12:00:00.000Z");
        assert_eq!(od["last_observed"], "2026-10-29T12:05:00.000Z");
    }

    #[test]
    fn sessions_past_the_object_cap_are_left_out_and_said_so() {
        let mut s = sessions().remove(1);
        s.payloads = (0..256).map(|i| format!("{i:064x}")).collect();
        let many: Vec<Session> = (0..60)
            .map(|i| {
                let mut s = s.clone();
                s.id = format!("17932752{i:05}-0000000b");
                s.payloads = (0..256).map(|j| format!("{:064x}", i * 1000 + j)).collect();
                s
            })
            .collect();
        let b = bundle(&incident(), &many, "web01");
        assert_refs_resolve(&b);
        let objs = b["objects"].as_array().unwrap();
        assert!(objs.len() <= MAX_OBJECTS);
        let od = objs.iter().find(|o| o["type"] == "observed-data").unwrap();
        assert_eq!(od["x_aegis_truncated"], true);
    }

    fn id_of(b: &Value, ty: &str, key: &str, value: &str) -> String {
        b["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == ty && o[key] == value)
            .map(|o| o["id"].as_str().unwrap().to_string())
            .unwrap_or_else(|| panic!("no {ty} {value}"))
    }

    #[test]
    fn observable_ids_are_the_ones_stix_derives() {
        // From the OASIS stix2 library 3.0.2, which follows section 2.9.
        let b = bundle(&incident(), &sessions(), "web01");
        assert_eq!(
            id_of(&b, "domain-name", "value", "c2.example"),
            "domain-name--48a20b60-d03a-5e96-ad43-977ad0c63d84"
        );
        assert_eq!(
            id_of(&b, "ipv4-addr", "value", "198.18.0.1"),
            "ipv4-addr--9b6503e8-3f22-58ad-a3b1-52235a5b12b7"
        );
        assert_eq!(
            id_of(&b, "directory", "path", "/usr/bin"),
            "directory--f4f0869b-430a-594d-b01d-307cd4d341a8"
        );
        // The ref to its directory is part of a file's id.
        assert_eq!(
            id_of(&b, "file", "name", "curl"),
            "file--7c92caf7-4315-5e38-bd75-7f14040fa160"
        );
        let payload = b["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["hashes"].is_object())
            .unwrap();
        assert_eq!(payload["id"], "file--22f8ff52-8f62-5f03-a53a-6f50f54fd74c");
        // Times count too, in the form stix2 writes them.
        let nt = |port: u64| {
            b["objects"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["dst_port"] == port)
                .unwrap()
                .clone()
        };
        assert_eq!(nt(53)["start"], "2026-10-29T12:00:00Z");
        assert_eq!(nt(53)["end"], "2026-10-29T12:00:01.5Z");
        assert_eq!(
            nt(53)["id"],
            "network-traffic--e043352d-1840-5963-bae3-9f4952ebde05"
        );
        assert_eq!(
            nt(443)["id"],
            "network-traffic--76d5daab-ebad-59db-9c5e-8c83d763caa9"
        );
    }

    #[test]
    fn the_same_domain_in_two_incidents_has_the_same_id() {
        let mut other = incident();
        other.id = "AEG-20261030-090000-fedcba9876543210".into();
        let (a, b) = (
            bundle(&incident(), &sessions(), "web01"),
            bundle(&other, &sessions(), "web01"),
        );
        let d = |b: &Value| id_of(b, "domain-name", "value", "c2.example");
        assert_eq!(d(&a), d(&b));
        // What the incident made is its own.
        let i = |b: &Value| id_of(b, "identity", "name", "web01");
        assert_ne!(i(&a), i(&b));
        assert_ne!(a["id"], b["id"]);
    }

    #[test]
    fn observed_times_cover_the_incident_and_its_sessions() {
        let mut s = sessions();
        // One before the incident was recorded, one after its update.
        s[0].started_ms = 1_793_275_100_000;
        s[1].ended_ms = 1_793_275_900_000;
        let b = bundle(&incident(), &s, "web01");
        let od = b["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == "observed-data")
            .unwrap();
        assert_eq!(od["first_observed"], "2026-10-29T11:58:20.000Z");
        assert_eq!(od["last_observed"], "2026-10-29T12:11:40.000Z");
        let b = bundle(&incident(), &sessions()[..1], "web01");
        let od = b["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == "observed-data")
            .unwrap();
        assert_eq!(od["first_observed"], "2026-10-29T12:00:00.000Z");
        assert_eq!(od["last_observed"], "2026-10-29T12:05:00.000Z");
    }

    #[test]
    fn a_bundle_stays_under_its_byte_budget() {
        let s = sessions().remove(1);
        let many: Vec<Session> = (0..400)
            .map(|i| {
                let mut s = s.clone();
                s.id = format!("17932752{i:05}-0000000b");
                // Backslashes double in a pattern, and again in JSON.
                s.sni = Some(format!("{i}{}", "\\".repeat(10_000)));
                s
            })
            .collect();
        let b = bundle(&incident(), &many, "web01");
        assert_refs_resolve(&b);
        assert!(b.to_string().len() < 16 << 20, "{}", b.to_string().len());
        let od = b["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == "observed-data")
            .unwrap();
        assert_eq!(od["x_aegis_truncated"], true);
    }

    #[test]
    fn sessions_never_read_mark_the_bundle_truncated() {
        let b = Bundle::new(&incident(), "web01").finish(3, false);
        let od = b["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == "observed-data")
            .unwrap();
        assert_eq!(od["x_aegis_truncated"], true);
    }

    #[test]
    fn two_sessions_alike_but_for_the_client_port_stay_two() {
        let mut a = sessions().remove(1);
        a.src = "10.0.0.2:40000".parse().unwrap();
        let mut b = a.clone();
        b.id = "1793275201000-0000000c".into();
        b.src = "10.0.0.2:40001".parse().unwrap();
        let bundle = bundle(&incident(), &[a, b], "web01");
        let nts: Vec<_> = bundle["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["type"] == "network-traffic")
            .collect();
        assert_eq!(nts.len(), 2);
        assert_eq!(nts[1]["src_port"], 40001);
    }

    #[test]
    fn impossible_times_do_not_overflow() {
        assert!(ts_ms(u64::MAX).ends_with('Z'));
        assert!(ts_short(u64::MAX).ends_with('Z'));
        assert_eq!(ts_short(1_793_275_200_120), "2026-10-29T12:00:00.12Z");
    }
}
