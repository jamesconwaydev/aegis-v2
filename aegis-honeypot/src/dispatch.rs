// SPDX-License-Identifier: MIT OR Apache-2.0
//! Which handler answers a connection. The client chose the port, and
//! on an unknown port it chose the first bytes too, so both are hostile.

use aegis_proto::honeypot::Protocol;

/// How much of the client's opening the peek looks at.
pub const PEEK: usize = 8;

const METHODS: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

/// The protocol a well-known original destination port means.
pub fn by_port(port: u16) -> Option<Protocol> {
    Some(match port {
        22 => Protocol::Ssh,
        80 | 8080 => Protocol::Http,
        443 | 8443 => Protocol::Https,
        25 | 587 => Protocol::Smtp,
        465 => Protocol::Smtps,
        53 => Protocol::Dns,
        _ => return None,
    })
}

/// Whether `first` could still become an HTTP method and its space.
pub fn partial_method(first: &[u8]) -> bool {
    METHODS
        .iter()
        .any(|m| m.len() > first.len() && m.starts_with(first))
}

/// For any other port: the protocol the client's opening bytes look
/// like (empty when it waits to be spoken to), else raw.
pub fn by_bytes(first: &[u8]) -> Protocol {
    // A TLS handshake record: content type 22, then version 3.x.
    if first.starts_with(&[0x16, 0x03]) {
        Protocol::Https
    } else if first.starts_with(b"SSH-") {
        Protocol::Ssh
    } else if METHODS.iter().any(|m| first.starts_with(m)) {
        Protocol::Http
    } else {
        Protocol::Raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_ports_decide_without_looking() {
        for (port, want) in [
            (22, Protocol::Ssh),
            (80, Protocol::Http),
            (8080, Protocol::Http),
            (443, Protocol::Https),
            (8443, Protocol::Https),
            (25, Protocol::Smtp),
            (587, Protocol::Smtp),
            (465, Protocol::Smtps),
            (53, Protocol::Dns),
        ] {
            assert_eq!(by_port(port), Some(want), "{port}");
        }
    }

    #[test]
    fn other_ports_peek_then_fall_back_to_raw() {
        for port in [0, 21, 23, 81, 444, 2580, 4444, 65535] {
            assert_eq!(by_port(port), None, "{port}");
        }
        for (first, want) in [
            (&b"\x16\x03\x01\x02\x00\x01"[..], Protocol::Https),
            (b"SSH-2.0-OpenSSH_9.9", Protocol::Ssh),
            (b"GET / HTTP/1.1", Protocol::Http),
            (b"OPTIONS ", Protocol::Http),
            (b"", Protocol::Raw),
            (b"\x16", Protocol::Raw),
            (b"\x16\x02", Protocol::Raw),
            (b"SSH", Protocol::Raw),
            (b"GETX / ", Protocol::Raw),
            (b"get / ", Protocol::Raw),
            (b"\x00\x00\x00\x00", Protocol::Raw),
        ] {
            assert_eq!(by_bytes(first), want, "{first:?}");
        }
    }
}
