// SPDX-License-Identifier: MIT OR Apache-2.0
//! `incidents stix`: a STIX 2.1 bundle of what an incident saw, made on
//! demand from `incident.json` and the filed honeypot sessions.
//!
//! Two exports of the same incident are byte for byte the same: every id
//! is a UUIDv5 of (incident id, object type, value) under `NS`, every
//! object's `created` and `modified` is the incident's own `created`, and
//! objects go in the order the inputs give them.

use std::collections::HashSet;

use aegis_proto::honeypot::{Protocol, Session};
use serde_json::{json, Value};
use sha1::{Digest, Sha1};

use crate::incident::Incident;
use crate::telemetry::{rfc3339, unix_secs};

/// aegis-v2's namespace for STIX ids. Never change it: ids already
/// shared would stop matching.
const NS: [u8; 16] = [
    0x8c, 0x9d, 0x6a, 0x8e, 0x3b, 0x5f, 0x4e, 0x1a, 0x9f, 0x27, 0x6d, 0x4c, 0x2b, 0x1a, 0x0e, 0x93,
];
/// Objects in one bundle. Processes come first and are at most 3 x 4096
/// (`MAX_TREE`); sessions that would go past it are left out and the
/// observed-data says so.
const MAX_OBJECTS: usize = 20_000;

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
    let s = rfc3339(ms * 1_000_000);
    format!("{}.{:03}Z", &s[..19], ms % 1000)
}

/// A STIX pattern string literal.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

struct Bundle {
    inc: String,
    created: String,
    identity: String,
    objects: Vec<Value>,
    ids: HashSet<String>,
    indicators: Vec<Value>,
}

impl Bundle {
    fn id(&self, ty: &str, value: &str) -> String {
        format!(
            "{ty}--{}",
            uuid5(&NS, &format!("{}|{ty}|{value}", self.inc))
        )
    }

    /// Adds an object of type `ty` for `value` once; its id either way.
    fn add(&mut self, ty: &str, value: &str, mut o: Value) -> String {
        let id = self.id(ty, value);
        if self.ids.insert(id.clone()) {
            o["type"] = ty.into();
            o["id"] = id.clone().into();
            self.objects.push(o);
        }
        id
    }

    /// An indicator for an observable, once per pattern.
    fn indicate(&mut self, pattern: String, name: String) {
        let id = self.id("indicator", &pattern);
        if self.ids.insert(id.clone()) {
            self.indicators.push(json!({
                "type": "indicator",
                "spec_version": "2.1",
                "id": id,
                "created": self.created,
                "modified": self.created,
                "created_by_ref": self.identity,
                "name": name,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": self.created,
            }));
        }
    }

    fn domain(&mut self, name: &str, refs: &mut Vec<String>) {
        refs.push(self.add("domain-name", name, json!({ "value": name })));
        self.indicate(
            format!("[domain-name:value = {}]", quote(name)),
            format!("Domain name seen in {}", self.inc),
        );
    }

    fn payload(&mut self, sha: &str, refs: &mut Vec<String>) {
        refs.push(self.add("file", sha, json!({ "hashes": { "SHA-256": sha } })));
        self.indicate(
            format!("[file:hashes.'SHA-256' = {}]", quote(sha)),
            format!("Payload sent to the honeypot in {}", self.inc),
        );
    }

    fn session(&mut self, s: &Session, refs: &mut Vec<String>) {
        let ip = s.dst.ip().to_string();
        let dst = self.add("ipv4-addr", &ip, json!({ "value": ip }));
        refs.push(dst.clone());
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
            "start": ts_ms(s.started_ms),
            "end": ts_ms(s.ended_ms.max(s.started_ms)),
            // Filed means closed; STIX wants that said when `end` is.
            "is_active": false,
            "dst_ref": dst,
            "dst_port": s.dst.port(),
            "protocols": protocols,
            "src_byte_count": s.bytes_in,
            "dst_byte_count": s.bytes_out,
        });
        if let Some(j) = &s.ja4 {
            nt["x_aegis_ja4"] = j.as_str().into();
        }
        refs.push(self.add("network-traffic", &s.id, nt));
        let names = s
            .dns_name
            .iter()
            .chain(&s.sni)
            .chain(s.queries.iter().map(|q| &q.name));
        for n in names {
            self.domain(n, refs);
        }
        for h in &s.payloads {
            self.payload(h, refs);
        }
    }
}

/// The bundle for `inc` and its filed `sessions` (oldest first), with
/// the host it was seen on named `host`.
pub fn bundle(inc: &Incident, sessions: &[Session], host: &str) -> Value {
    let first_ms = unix_secs(&inc.created).unwrap_or(0) * 1000;
    let last_ms = unix_secs(&inc.updated).unwrap_or(0) * 1000;
    let mut b = Bundle {
        inc: inc.id.clone(),
        created: ts_ms(first_ms),
        identity: String::new(),
        objects: Vec::new(),
        ids: HashSet::new(),
        indicators: Vec::new(),
    };
    let created = b.created.clone();
    b.identity = b.add(
        "identity",
        host,
        json!({
            "spec_version": "2.1",
            "created": created,
            "modified": created,
            "name": host,
            "identity_class": "system",
        }),
    );
    let mut refs = Vec::new();
    for p in &inc.process_tree {
        let mut o = json!({ "pid": p.tgid });
        if let Some(exe) = &p.exe {
            let (dir, name) = exe.rsplit_once('/').unwrap_or(("", exe));
            let mut f = json!({ "name": name });
            if !dir.is_empty() {
                let d = b.add("directory", dir, json!({ "path": dir }));
                refs.push(d.clone());
                f["parent_directory_ref"] = d.into();
            }
            let f = b.add("file", exe, f);
            refs.push(f.clone());
            o["image_ref"] = f.into();
        }
        refs.push(b.add("process", &format!("{}:{}", p.tgid, p.start_time_ns), o));
    }
    let (mut first, mut last) = (first_ms, last_ms);
    let mut truncated = false;
    for (i, s) in sessions.iter().enumerate() {
        // Each session adds at most 2 + 2 per name or payload.
        let most = 2 + 2 * (2 + s.queries.len() + s.payloads.len());
        if b.ids.len() + most > MAX_OBJECTS {
            truncated = true;
            break;
        }
        if i == 0 {
            (first, last) = (s.started_ms, s.ended_ms);
        }
        first = first.min(s.started_ms);
        last = last.max(s.ended_ms);
        b.session(s, &mut refs);
    }
    let mut seen = HashSet::new();
    refs.retain(|r| seen.insert(r.clone()));
    let mut od = json!({
        "spec_version": "2.1",
        "created": created,
        "modified": created,
        "created_by_ref": b.identity,
        "first_observed": ts_ms(first),
        "last_observed": ts_ms(last.max(first)),
        "number_observed": 1,
        "object_refs": refs,
        "x_aegis_incident": inc.id,
    });
    if truncated {
        od["x_aegis_truncated"] = true.into();
    }
    let inc_id = inc.id.clone();
    b.add("observed-data", &inc_id, od);
    let mut objects = std::mem::take(&mut b.objects);
    objects.append(&mut b.indicators);
    json!({
        "type": "bundle",
        "id": b.id("bundle", &inc_id),
        "objects": objects,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::filed::tests::session;
    use aegis_proto::honeypot::DnsQuery;
    use std::net::Ipv4Addr;

    pub(crate) const ID: &str = "AEG-20261029-120000-0123456789abcdef";

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
        let mut dns = session("1761739200000-0000000a", Protocol::Dns);
        dns.dst = "198.18.0.53:53".parse().unwrap();
        dns.queries = vec![DnsQuery {
            name: "c2.example".into(),
            qtype: "A".into(),
            answer: Some(Ipv4Addr::new(198, 18, 0, 1)),
        }];
        let mut https = session("1761739201000-0000000b", Protocol::Https);
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
                s.id = format!("17617392{i:05}-0000000b");
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
}
