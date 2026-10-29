// SPDX-License-Identifier: MIT OR Apache-2.0
//! An HTTP/1.1 request head, and the chunk sizes of a chunked body,
//! read from client bytes. Lenient where real clients are sloppy (a
//! bare LF ends a line), strict wherever a length comes from.

use aegis_proto::honeypot::HttpRequest;

use crate::hello::text;

/// The most a head may take, request line to blank line.
pub const MAX_HEAD: usize = 8 * 1024;
/// The most header lines one head may carry.
pub const MAX_HEADERS: usize = 100;

#[derive(Debug, PartialEq)]
pub enum Body {
    /// Content-Length, or 0 without one.
    Length(u64),
    Chunked,
}

#[derive(Debug, PartialEq)]
pub struct Head {
    pub request: HttpRequest,
    pub body: Body,
    /// The client wants the connection closed after the answer.
    pub close: bool,
    /// Bytes the head took, blank line included.
    pub len: usize,
}

#[derive(Debug, PartialEq)]
pub enum Parsed {
    More,
    Bad,
    Done(Head),
}

/// The request head at the start of `buf`.
pub fn head(buf: &[u8]) -> Parsed {
    let b = &buf[..buf.len().min(MAX_HEAD)];
    // The blank line: LF, then LF or CR LF.
    let end = (0..b.len()).find_map(|i| match b[i..] {
        [b'\n', b'\n', ..] => Some(i + 2),
        [b'\n', b'\r', b'\n', ..] => Some(i + 3),
        _ => None,
    });
    match end {
        Some(len) => parse(&b[..len]).map_or(Parsed::Bad, |(request, body, close)| {
            Parsed::Done(Head {
                request,
                body,
                close,
                len,
            })
        }),
        None if buf.len() >= MAX_HEAD => Parsed::Bad,
        None => Parsed::More,
    }
}

fn token(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(|c| c.is_ascii_graphic() && *c != b':')
}

fn parse(b: &[u8]) -> Option<(HttpRequest, Body, bool)> {
    let mut lines = b
        .split(|&c| c == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.is_empty());
    let mut first = lines.next()?.split(|&c| c == b' ');
    let (method, path, version) = (first.next()?, first.next()?, first.next()?);
    if first.next().is_some()
        || method.is_empty()
        || !method.iter().all(u8::is_ascii_uppercase)
        || path.is_empty()
    {
        return None;
    }
    let mut close = match version {
        b"HTTP/1.1" => false,
        b"HTTP/1.0" => true,
        _ => return None,
    };
    let (mut length, mut chunked, mut headers) = (None, false, Vec::new());
    for l in lines {
        let i = l.iter().position(|&c| c == b':')?;
        let (name, value) = (&l[..i], l[i + 1..].trim_ascii());
        if !token(name) || headers.len() == MAX_HEADERS {
            return None;
        }
        headers.push(format!("{}: {}", text(name), text(value)));
        let tokens = || value.split(|&c| c == b',').map(<[u8]>::trim_ascii);
        if name.eq_ignore_ascii_case(b"content-length") {
            let n = value
                .iter()
                .all(u8::is_ascii_digit)
                .then(|| std::str::from_utf8(value).ok()?.parse::<u64>().ok())??;
            if length.is_some_and(|l| l != n) {
                return None;
            }
            length = Some(n);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            // Only chunked says where the body ends (RFC 9112 6.3).
            if !tokens().next_back()?.eq_ignore_ascii_case(b"chunked") {
                return None;
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case(b"connection") {
            for t in tokens() {
                if t.eq_ignore_ascii_case(b"close") {
                    close = true;
                } else if t.eq_ignore_ascii_case(b"keep-alive") {
                    close = false;
                }
            }
        }
    }
    let body = if chunked {
        Body::Chunked
    } else {
        Body::Length(length.unwrap_or(0))
    };
    let request = HttpRequest {
        method: text(method),
        path: text(path),
        headers,
        body: None,
    };
    Some((request, body, close))
}

/// A chunk-size line (RFC 9112 7.1), extensions ignored; None unless
/// it's hex digits that fit a u64.
pub fn chunk_size(line: &[u8]) -> Option<u64> {
    let hex = line.split(|&c| c == b';').next()?.trim_ascii();
    if hex.is_empty() || hex.len() > 16 || !hex.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()
}

/// Whether `path` asks for an image, which gets a GIF.
pub fn image(path: &str) -> bool {
    let p = path
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    [".gif", ".png", ".jpg", ".ico"]
        .iter()
        .any(|e| p.ends_with(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(b: &[u8]) -> Head {
        match head(b) {
            Parsed::Done(h) => h,
            p => panic!("{p:?} for {:?}", String::from_utf8_lossy(b)),
        }
    }

    #[test]
    fn a_curl_request_is_read_whole() {
        let req = b"GET /index.html?q=1 HTTP/1.1\r\nHost: c2.example\r\n\
            User-Agent: curl/8.12.1\r\nAccept: */*\r\n\r\nNEXT";
        let h = done(req);
        assert_eq!(
            h.request,
            HttpRequest {
                method: "GET".into(),
                path: "/index.html?q=1".into(),
                headers: vec![
                    "Host: c2.example".into(),
                    "User-Agent: curl/8.12.1".into(),
                    "Accept: */*".into(),
                ],
                body: None,
            }
        );
        assert_eq!(
            (h.body, h.close, h.len),
            (Body::Length(0), false, req.len() - 4)
        );
    }

    #[test]
    fn bare_line_feeds_end_lines_too() {
        let h = done(b"POST /up HTTP/1.0\nContent-Length: 12\n\n");
        assert_eq!(h.body, Body::Length(12));
        // 1.0 closes unless it asks not to.
        assert!(h.close);
        assert!(!done(b"GET / HTTP/1.0\nConnection: Keep-Alive\n\n").close);
        assert!(done(b"GET / HTTP/1.1\r\nConnection: TE, close\r\n\r\n").close);
    }

    #[test]
    fn chunked_wins_and_lengths_must_agree() {
        let h = done(
            b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, Chunked\r\nContent-Length: 3\r\n\r\n",
        );
        assert_eq!(h.body, Body::Chunked);
        let h = done(b"POST / HTTP/1.1\r\nContent-Length: 7\r\ncontent-length: 7\r\n\r\n");
        assert_eq!(h.body, Body::Length(7));
        assert_eq!(
            done(b"PUT / HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\n").body,
            Body::Length(u64::MAX)
        );
    }

    #[test]
    fn heads_that_lie_or_sprawl_are_refused() {
        let many = format!(
            "GET / HTTP/1.1\r\n{}\r\n",
            "A: b\r\n".repeat(MAX_HEADERS + 1)
        );
        let most = format!("GET / HTTP/1.1\r\n{}\r\n", "A: b\r\n".repeat(MAX_HEADERS));
        assert!(matches!(head(most.as_bytes()), Parsed::Done(_)));
        for bad in [
            &b"GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\nContent-Length: +1\r\n\r\n",
            b"GET / HTTP/1.1\r\nContent-Length: 18446744073709551616\r\n\r\n",
            b"GET / HTTP/1.1\r\nContent-Length: \r\n\r\n",
            b"GET / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
            b"GET / HTTP/1.1\r\nNo colon\r\n\r\n",
            b"GET / HTTP/1.1\r\nBad name: x\r\n\r\n",
            b"GET / HTTP/1.1\r\n folded: x\r\n\r\n",
            b"GET / HTTP/1.1\r\n: x\r\n\r\n",
            b"GET /\r\n\r\n",
            b"GET / HTTP/2.0\r\n\r\n",
            b"get / HTTP/1.1\r\n\r\n",
            b"GET  / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1 x\r\n\r\n",
            b"\r\n\r\n",
            many.as_bytes(),
        ] {
            assert_eq!(head(bad), Parsed::Bad, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn a_head_is_awaited_up_to_its_cap() {
        assert_eq!(head(b""), Parsed::More);
        assert_eq!(head(b"GET / HTTP/1.1\r\nHost: x\r\n"), Parsed::More);
        let mut long = b"GET /".to_vec();
        long.resize(MAX_HEAD - 1, b'a');
        assert_eq!(head(&long), Parsed::More);
        long.push(b'a');
        assert_eq!(head(&long), Parsed::Bad);
        // A blank line past the cap doesn't count either.
        long.extend(b" HTTP/1.1\r\n\r\n");
        assert_eq!(head(&long), Parsed::Bad);
    }

    #[test]
    fn what_is_recorded_is_printable() {
        let h = done(b"GET /\x1b[2J HTTP/1.1\r\nX-A: \xff\x07ok\r\n\r\n");
        assert_eq!(h.request.path, "/\u{fffd}[2J");
        assert_eq!(h.request.headers, ["X-A: \u{fffd}\u{fffd}ok"]);
    }

    #[test]
    fn chunk_sizes_are_hex_that_fits() {
        for (line, want) in [
            (&b"0"[..], Some(0)),
            (b"1a", Some(26)),
            (b"1A;name=value", Some(26)),
            (b"ff ", Some(255)),
            (b"ffffffffffffffff", Some(u64::MAX)),
            (b"10000000000000000", None),
            (b"0000000000000000001", None),
            (b"+5", None),
            (b"-1", None),
            (b"", None),
            (b";x", None),
            (b"g", None),
        ] {
            assert_eq!(
                chunk_size(line),
                want,
                "{:?}",
                String::from_utf8_lossy(line)
            );
        }
    }

    #[test]
    fn image_paths_are_known_by_their_ending() {
        for (p, want) in [
            ("/favicon.ico", true),
            ("/a/b.GIF", true),
            ("/x.png?v=3", true),
            ("/x.jpg#top", true),
            ("/", false),
            ("/x.jpg.html", false),
            ("/gif", false),
        ] {
            assert_eq!(image(p), want, "{p}");
        }
    }
}
