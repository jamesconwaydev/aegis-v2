// SPDX-License-Identifier: MIT OR Apache-2.0
//! What aegisd and aegis-honeypot both read: the `[honeypot]` config
//! section and the `session.json` each session leaves in the spool. One
//! definition, so the two sides can't disagree about either.

use std::net::{Ipv4Addr, SocketAddrV4};

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

fn port<'de, D: Deserializer<'de>>(d: D) -> Result<u16, D::Error> {
    let v = u32::deserialize(d)?;
    match u16::try_from(v) {
        Ok(p) if p >= 1024 => Ok(p),
        _ => Err(de::Error::custom(format!(
            "must be a port from 1024 to 65535, got {v}"
        ))),
    }
}

/// Refuses zero (the type's default) with "must be at least 1".
/// aegisd's other settings use it too.
pub fn at_least_one<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default + PartialEq>(
    d: D,
) -> Result<T, D::Error> {
    let v = T::deserialize(d)?;
    if v == T::default() {
        Err(de::Error::custom("must be at least 1"))
    } else {
        Ok(v)
    }
}

/// The honeypot's listeners and limits. aegisd reads it only when
/// `quarantine.network = "honeypot"` in enforce mode; the honeypot
/// always does.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HoneypotConfig {
    /// Where the redirected TCP connections land.
    #[serde(deserialize_with = "port")]
    pub tcp_port: u16,
    /// Where the redirected DNS queries land.
    #[serde(deserialize_with = "port")]
    pub dns_port: u16,
    /// Most bytes kept from one session.
    #[serde(deserialize_with = "at_least_one")]
    pub max_session_bytes: u64,
    /// Longest one session may run.
    #[serde(deserialize_with = "at_least_one")]
    pub session_seconds: u64,
    /// `pids.max` on an observed tree's scope.
    #[serde(deserialize_with = "at_least_one")]
    pub max_tasks: u32,
    /// Trees observed at once; more get drop quarantine.
    #[serde(deserialize_with = "at_least_one")]
    pub max_incidents: u32,
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            tcp_port: 2580,
            dns_port: 2553,
            max_session_bytes: 4_194_304,
            session_seconds: 300,
            max_tasks: 256,
            max_incidents: 32,
        }
    }
}

/// What a session was answered as. Chosen from the original destination
/// port, or from the client's first bytes when the port says nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Ssh,
    Http,
    /// TLS, then HTTP inside it.
    Https,
    Smtp,
    /// SMTP inside implicit TLS (port 465).
    Smtps,
    Dns,
    /// Nothing recognised: read and record, answer nothing.
    Raw,
}

/// `spool/<addr>/done/<id>/session.json`. Written by the honeypot when a
/// session closes; aegisd reads it through a size cap and nothing else.
///
/// That cap is 64 KiB, so every list here (and every one added later)
/// needs a bound the honeypot enforces that keeps the whole record under
/// it; past the bound the honeypot stops adding and sets `truncated`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    /// `<unix-ms>-<8 hex>`, also the directory name.
    pub id: String,
    pub protocol: Protocol,
    /// The incident address the tree was redirected to (127.77.0.0/16).
    pub addr: Ipv4Addr,
    /// The client end, as the honeypot saw it.
    pub src: SocketAddrV4,
    /// Where the tree was really connecting to.
    pub dst: SocketAddrV4,
    pub started_ms: u64,
    pub ended_ms: u64,
    /// Bytes recorded from the client and to it, after the byte cap.
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// The byte cap was reached and the session was closed there.
    pub truncated: bool,
    /// The time cap closed the session.
    pub timed_out: bool,
    /// SHA-256 (hex) of each payload file in the session directory; at
    /// most 256.
    pub payloads: Vec<String>,
    /// The name the tree looked up before connecting to `dst`, when the
    /// honeypot's DNS handed out that address.
    pub dns_name: Option<String>,
    /// Each DNS question asked in this session and what it was told; at
    /// most 32.
    pub queries: Vec<DnsQuery>,
    /// The server name a TLS client asked for. Printable text: bytes
    /// that aren't valid UTF-8, and control characters, are U+FFFD.
    pub sni: Option<String>,
    /// The client's JA4 TLS fingerprint (FoxIO), from its ClientHello,
    /// whether or not the handshake went on to complete.
    pub ja4: Option<String>,
    /// Each HTTP request, in order. The honeypot stops adding them before
    /// this record reaches 40 KiB, and sets `truncated`.
    pub requests: Vec<HttpRequest>,
    /// Each login tried, in order. The honeypot stops adding them before
    /// this record reaches 40 KiB, or at 32, and sets `truncated`.
    pub credentials: Vec<Credential>,
    /// Each shell command run, split at `;`, `&&`, `||` and `|`, as
    /// printable text (see `sni`), at most 1 KiB each. Bounded like
    /// `credentials`, and at 256.
    pub commands: Vec<String>,
    /// Each file sent up by scp or sftp. Bounded like `credentials`.
    pub uploads: Vec<Upload>,
    /// The name an SMTP client gave in its first HELO or EHLO, as
    /// printable text (see `sni`), at most 256 bytes.
    pub helo: Option<String>,
    /// Each message handed over by SMTP. Bounded like `credentials`, and
    /// at 32.
    pub mails: Vec<Mail>,
}

/// One message handed over by SMTP, never relayed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mail {
    /// The MAIL FROM address, empty for the null sender. Printable text
    /// (see `sni`), at most 256 bytes, like each of `to`.
    pub from: String,
    /// Each RCPT TO address, at most 100.
    pub to: Vec<String>,
    /// SHA-256 (hex) of the message as received, dot-stuffing undone,
    /// one of `payloads`; None when it was empty or couldn't be kept.
    pub message: Option<String>,
}

/// One login. Printable text (see `sni`), at most 256 bytes each.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub user: String,
    /// The password as typed.
    pub password: Option<String>,
    /// A public key offered: its algorithm and SHA-256 fingerprint, as
    /// `ssh-keygen -l` prints them (`ssh-ed25519 SHA256:...`).
    pub key: Option<String>,
}

/// One uploaded file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upload {
    /// The name the client gave it, as printable text (see `sni`), at
    /// most 255 bytes. Never used as a path.
    pub name: String,
    /// SHA-256 (hex) of the contents kept, one of `payloads`; None when
    /// they couldn't be kept.
    pub payload: Option<String>,
}

/// One HTTP request as the client sent it, as printable text (see `sni`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequest {
    pub method: String,
    /// The request target, query string included.
    pub path: String,
    /// `Name: value`, in the order sent.
    pub headers: Vec<String>,
    /// SHA-256 (hex) of the body, one of `payloads`; None when there was
    /// no body or it couldn't be kept.
    pub body: Option<String>,
}

/// One DNS question and its answer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsQuery {
    /// Lower case, no trailing dot; bytes that aren't printable ASCII
    /// written as `\DDD`.
    pub name: String,
    /// `A`, `AAAA`, ..., or `TYPE<n>` for one with no mnemonic.
    pub qtype: String,
    /// The address given, for an A question.
    pub answer: Option<Ipv4Addr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Session {
        Session {
            id: "1761696000000-0badf00d".into(),
            protocol: Protocol::Raw,
            addr: Ipv4Addr::new(127, 77, 0, 5),
            src: "10.0.0.2:40000".parse().unwrap(),
            dst: "1.2.3.4:6667".parse().unwrap(),
            started_ms: 1,
            ended_ms: 2,
            bytes_in: 3,
            bytes_out: 0,
            truncated: true,
            timed_out: false,
            payloads: vec!["ab".into()],
            dns_name: Some("c2.example".into()),
            queries: vec![DnsQuery {
                name: "c2.example".into(),
                qtype: "A".into(),
                answer: Some(Ipv4Addr::new(198, 18, 0, 1)),
            }],
            sni: Some("c2.example".into()),
            ja4: Some("t13d1516h2_8daaf6152771_e5627efa2ab1".into()),
            requests: vec![HttpRequest {
                method: "GET".into(),
                path: "/x".into(),
                headers: vec!["Host: c2.example".into()],
                body: None,
            }],
            credentials: vec![Credential {
                user: "root".into(),
                password: Some("123456".into()),
                key: None,
            }],
            commands: vec!["uname -a".into()],
            uploads: vec![Upload {
                name: "x.sh".into(),
                payload: Some("ab".into()),
            }],
            helo: Some("bot".into()),
            mails: vec![Mail {
                from: String::new(),
                to: vec!["a@example.com".into()],
                message: Some("ab".into()),
            }],
        }
    }

    #[test]
    fn session_round_trips_as_plain_json() {
        let s = sample();
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("\"protocol\":\"raw\""), "{j}");
        assert!(j.contains("\"dst\":\"1.2.3.4:6667\""), "{j}");
        assert!(j.contains("\"answer\":\"198.18.0.1\""), "{j}");
        assert!(j.contains("\"headers\":[\"Host: c2.example\"]"), "{j}");
        assert!(j.contains("\"commands\":[\"uname -a\"]"), "{j}");
        assert!(j.contains("\"password\":\"123456\",\"key\":null"), "{j}");
        assert!(
            j.contains("\"uploads\":[{\"name\":\"x.sh\",\"payload\":\"ab\"}]"),
            "{j}"
        );
        assert!(
            j.contains("\"mails\":[{\"from\":\"\",\"to\":[\"a@example.com\"],\"message\":\"ab\"}]"),
            "{j}"
        );
        assert_eq!(serde_json::from_str::<Session>(&j).unwrap(), s);
    }

    #[test]
    fn session_refuses_unknown_and_missing_fields() {
        let mut v = serde_json::to_value(sample()).unwrap();
        v["extra"] = 1.into();
        assert!(serde_json::from_value::<Session>(v.clone()).is_err());
        v.as_object_mut().unwrap().remove("extra");
        v.as_object_mut().unwrap().remove("dst");
        assert!(serde_json::from_value::<Session>(v).is_err());
    }
}
