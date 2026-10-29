// SPDX-License-Identifier: MIT OR Apache-2.0
//! HTTP, plain or inside TLS: every request recorded, every one
//! answered the way a stock nginx would. The pcap holds what crossed
//! the wire (ciphertext, for HTTPS); session.json holds the requests.

use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;

use anyhow::Result;
use rustls::{ServerConfig, ServerConnection};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::hello::{self, Parsed as HelloParsed};
use crate::http::{self, Body, Head, Parsed};
use crate::serve::Handler;
use crate::session::Session;

/// One read's worth.
const CHUNK: usize = 16 * 1024;
/// The longest chunk-size or trailer line waited for.
const MAX_LINE: usize = 1024;

const PAGE: &[u8] = b"<!DOCTYPE html>\n<html>\n<head><title>Welcome</title></head>\n\
    <body>\n<h1>Welcome</h1>\n<p>It works.</p>\n</body>\n</html>\n";
/// 1x1, transparent.
const GIF: &[u8] = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b";
const BAD_PAGE: &[u8] = b"<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n\
    <center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";

fn answer(status: &str, kind: &str, body: &[u8], close: bool, head_only: bool) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nServer: nginx\r\nContent-Type: {kind}\r\n\
         Content-Length: {}\r\nConnection: {}\r\n\r\n",
        body.len(),
        if close { "close" } else { "keep-alive" },
    )
    .into_bytes();
    if !head_only {
        out.extend_from_slice(body);
    }
    out
}

/// How a request body ended.
enum End {
    Done,
    /// The client went, or the byte cap was reached.
    Gone,
    /// Framing no server would accept.
    Bad,
}

/// The client, plain or through TLS. Every byte on the wire is recorded
/// in the session as it passes.
struct Wire {
    io: TcpStream,
    tls: Option<ServerConnection>,
    /// Off the socket and recorded, not yet through TLS.
    raw: Vec<u8>,
    /// Plaintext not yet parsed.
    buf: Vec<u8>,
    /// The byte cap is reached: what's read already is the last.
    full: bool,
}

impl Wire {
    fn new(io: TcpStream, tls: Option<ServerConnection>, raw: Vec<u8>) -> Self {
        Self {
            io,
            tls,
            raw,
            buf: Vec::new(),
            full: false,
        }
    }

    /// Plaintext into `out`; 0 once the client is gone or the cap is
    /// reached.
    async fn read(&mut self, s: &mut Session, out: &mut [u8]) -> Result<usize> {
        loop {
            if let Some(c) = &mut self.tls {
                match c.reader().read(out) {
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    r => return Ok(r?),
                }
                if !self.raw.is_empty() {
                    let n = c.read_tls(&mut &self.raw[..])?;
                    self.raw.drain(..n);
                    let state = c.process_new_packets();
                    // The alert for a failed handshake goes out first.
                    self.flush(s).await?;
                    state?;
                    continue;
                }
            } else if !self.raw.is_empty() {
                let n = out.len().min(self.raw.len());
                out[..n].copy_from_slice(&self.raw[..n]);
                self.raw.drain(..n);
                return Ok(n);
            }
            if self.full {
                return Ok(0);
            }
            self.raw.resize(CHUNK, 0);
            let n = self.io.read(&mut self.raw).await;
            self.raw.truncate(*n.as_ref().unwrap_or(&0));
            if n? == 0 {
                return Ok(0);
            }
            self.full = !s.record(true, &self.raw)?;
        }
    }

    async fn send(&mut self, s: &mut Session, data: &[u8]) -> Result<()> {
        self.full |= !s.record(false, data)?;
        self.io.write_all(data).await?;
        Ok(())
    }

    /// Whatever TLS has queued for the client.
    async fn flush(&mut self, s: &mut Session) -> Result<()> {
        let mut out = Vec::new();
        if let Some(c) = &mut self.tls {
            while c.wants_write() {
                c.write_tls(&mut out)?;
            }
        }
        if out.is_empty() {
            return Ok(());
        }
        self.send(s, &out).await
    }

    async fn write(&mut self, s: &mut Session, data: &[u8]) -> Result<()> {
        match &mut self.tls {
            Some(c) => {
                c.writer().write_all(data)?;
                self.flush(s).await
            }
            None => self.send(s, data).await,
        }
    }

    /// One more read onto `buf`; false when there's no more.
    async fn fill(&mut self, s: &mut Session) -> Result<bool> {
        let mut b = std::mem::take(&mut self.buf);
        let at = b.len();
        b.resize(at + CHUNK, 0);
        let n = self.read(s, &mut b[at..]).await;
        b.truncate(at + *n.as_ref().unwrap_or(&0));
        self.buf = b;
        Ok(n? > 0)
    }

    /// The next line, without its line ending. None when the client
    /// goes, or sends a line longer than any honest one.
    async fn line(&mut self, s: &mut Session) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(i) = self.buf.iter().position(|&c| c == b'\n') {
                let mut l: Vec<u8> = self.buf.drain(..=i).collect();
                l.pop();
                if l.last() == Some(&b'\r') {
                    l.pop();
                }
                return Ok(Some(l));
            }
            if self.buf.len() > MAX_LINE || !self.fill(s).await? {
                return Ok(None);
            }
        }
    }

    /// Reads `n` body bytes into `body` while it stays within `limit`;
    /// past that `body` is dropped and the rest only read. False when
    /// the client went first.
    async fn take(
        &mut self,
        s: &mut Session,
        mut n: u64,
        body: &mut Option<Vec<u8>>,
        limit: usize,
    ) -> Result<bool> {
        while n > 0 {
            if self.buf.is_empty() && !self.fill(s).await? {
                return Ok(false);
            }
            let k = self.buf.len().min(usize::try_from(n).unwrap_or(usize::MAX));
            *body = body.take().filter(|b| b.len() + k <= limit).map(|mut b| {
                b.extend_from_slice(&self.buf[..k]);
                b
            });
            self.buf.drain(..k);
            n -= k as u64;
        }
        Ok(true)
    }

    /// A chunked body (RFC 9112 7.1), trailers read and dropped.
    async fn chunked(
        &mut self,
        s: &mut Session,
        body: &mut Option<Vec<u8>>,
        limit: usize,
    ) -> Result<End> {
        loop {
            let Some(line) = self.line(s).await? else {
                return Ok(End::Gone);
            };
            let Some(size) = http::chunk_size(&line) else {
                return Ok(End::Bad);
            };
            if size == 0 {
                break;
            }
            if !self.take(s, size, body, limit).await? {
                return Ok(End::Gone);
            }
            match self.line(s).await? {
                Some(l) if l.is_empty() => {}
                Some(_) => return Ok(End::Bad),
                None => return Ok(End::Gone),
            }
        }
        loop {
            match self.line(s).await? {
                Some(l) if l.is_empty() => return Ok(End::Done),
                Some(_) => {}
                None => return Ok(End::Gone),
            }
        }
    }
}

/// Requests and answers until the client is done, or a cap is.
async fn exchange(s: &mut Session, mut w: Wire) -> Result<()> {
    loop {
        let head = loop {
            match http::head(&w.buf) {
                Parsed::Done(h) => break h,
                Parsed::More => {
                    if !w.fill(s).await? {
                        return Ok(());
                    }
                }
                Parsed::Bad => {
                    return w
                        .write(
                            s,
                            &answer("400 Bad Request", "text/html", BAD_PAGE, true, false),
                        )
                        .await
                }
            }
        };
        let Head {
            mut request,
            body: framing,
            close,
            len,
        } = head;
        w.buf.drain(..len);
        // A body that can't be kept within the cap isn't held in memory
        // either.
        let limit = usize::try_from(s.room()).unwrap_or(usize::MAX);
        let mut body = Some(Vec::new());
        let end = match framing {
            Body::Length(n) => {
                if w.take(s, n, &mut body, limit).await? {
                    End::Done
                } else {
                    End::Gone
                }
            }
            Body::Chunked => w.chunked(s, &mut body, limit).await?,
        };
        match body {
            Some(b) if !b.is_empty() => request.body = s.payload(&b)?,
            Some(_) => {}
            None => s.rec.truncated = true,
        }
        let head_only = request.method == "HEAD";
        let (kind, page) = if http::image(&request.path) {
            ("image/gif", GIF)
        } else {
            ("text/html", PAGE)
        };
        s.request(request);
        match end {
            End::Done => {}
            End::Gone => return Ok(()),
            End::Bad => {
                return w
                    .write(
                        s,
                        &answer("400 Bad Request", "text/html", BAD_PAGE, true, false),
                    )
                    .await
            }
        }
        w.write(s, &answer("200 OK", kind, page, close, head_only))
            .await?;
        if close {
            return Ok(());
        }
    }
}

pub struct Http;

impl Handler for Http {
    async fn serve(&self, s: &mut Session, io: TcpStream) -> Result<()> {
        exchange(s, Wire::new(io, None, Vec::new())).await
    }
}

/// TLS with a leaf for whatever name was asked, then HTTP inside.
pub struct Https<'a>(pub &'a Arc<ServerConfig>);

impl Handler for Https<'_> {
    async fn serve(&self, s: &mut Session, mut io: TcpStream) -> Result<()> {
        // The ClientHello first, recorded and fingerprinted before rustls
        // sees it, so a handshake that fails still leaves both.
        let mut raw = Vec::new();
        let mut buf = vec![0u8; CHUNK];
        loop {
            match hello::parse(&raw) {
                HelloParsed::More if raw.len() < hello::MAX => {}
                HelloParsed::Hello(h) => {
                    s.rec.sni = h.sni;
                    s.rec.ja4 = Some(h.ja4);
                    break;
                }
                _ => break,
            }
            let n = io.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            raw.extend_from_slice(&buf[..n]);
            if !s.record(true, &buf[..n])? {
                return Ok(());
            }
        }
        let tls = ServerConnection::new(self.0.clone())?;
        exchange(s, Wire::new(io, Some(tls), raw)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use aegis_proto::honeypot::{self, Protocol};
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName};
    use sha2::{Digest, Sha256};

    use crate::serve::tests::{bounded, pair, server, INCIDENT};
    use crate::serve::{handle, Server};

    /// One connection forced to `p`, the client run by `client`; the
    /// filed session and its directory, which the caller removes.
    async fn session<F, Fut>(
        srv: &std::rc::Rc<Server>,
        p: Protocol,
        client: F,
    ) -> (honeypot::Session, PathBuf)
    where
        F: FnOnce(TcpStream) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let (c, io) = pair(INCIDENT).await;
        let (r, ()) = bounded(srv, async {
            tokio::join!(handle(srv.clone(), io, Some(p)), client(c))
        })
        .await;
        r.unwrap();
        let done = srv.spool.join(INCIDENT.to_string()).join("done");
        let mut d: Vec<_> = std::fs::read_dir(&done).unwrap().collect();
        assert_eq!(d.len(), 1);
        let dir = d.pop().unwrap().unwrap().path();
        let rec =
            serde_json::from_slice(&std::fs::read(dir.join("session.json")).unwrap()).unwrap();
        (rec, dir)
    }

    fn sha(b: &[u8]) -> String {
        Sha256::digest(b)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// One response: its head, and the body its Content-Length gives.
    async fn response(c: &mut TcpStream) -> (String, Vec<u8>) {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(c.read_u8().await.unwrap());
        }
        let head = String::from_utf8(head).unwrap();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        let mut body = vec![0; len];
        if !head.starts_with("HEAD") {
            c.read_exact(&mut body).await.unwrap();
        }
        (head, body)
    }

    fn cleanup(p: &Path) {
        std::fs::remove_dir_all(p).unwrap();
    }

    #[tokio::test]
    async fn a_curl_request_is_recorded_and_answered_like_nginx() {
        let srv = server("wcurl", 100_000, Duration::from_secs(5));
        let (rec, _) = session(&srv, Protocol::Http, |mut c| async move {
            c.write_all(b"GET /admin?x=1 HTTP/1.1\r\nHost: c2.example\r\nUser-Agent: curl/8.12.1\r\nAccept: */*\r\n\r\n")
                .await
                .unwrap();
            let (head, body) = response(&mut c).await;
            assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
            assert!(head.contains("\r\nServer: nginx\r\n"), "{head}");
            assert!(head.contains("\r\nContent-Type: text/html\r\n"), "{head}");
            assert!(head.contains("\r\nConnection: keep-alive\r\n"), "{head}");
            assert_eq!(body, PAGE);
            // Kept alive: an image next, then a HEAD that closes.
            c.write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: c2.example\r\n\r\n")
                .await
                .unwrap();
            let (head, body) = response(&mut c).await;
            assert!(head.contains("\r\nContent-Type: image/gif\r\n"), "{head}");
            assert_eq!(body, GIF);
            c.write_all(b"HEAD / HTTP/1.1\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut rest = Vec::new();
            c.read_to_end(&mut rest).await.unwrap();
            let rest = String::from_utf8(rest).unwrap();
            assert!(rest.contains("\r\nConnection: close\r\n"), "{rest}");
            assert!(rest.ends_with("\r\n\r\n"), "a HEAD answer has no body: {rest}");
        })
        .await;
        assert_eq!(rec.protocol, Protocol::Http);
        let got: Vec<_> = rec
            .requests
            .iter()
            .map(|r| (r.method.as_str(), r.path.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("GET", "/admin?x=1"),
                ("GET", "/favicon.ico"),
                ("HEAD", "/")
            ]
        );
        assert_eq!(
            rec.requests[0].headers,
            ["Host: c2.example", "User-Agent: curl/8.12.1", "Accept: */*"]
        );
        assert!(rec.payloads.is_empty());
        assert!(!rec.truncated && !rec.timed_out);
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn a_chunked_body_is_stored_once_by_its_hash() {
        let srv = server("wchunk", 100_000, Duration::from_secs(5));
        let post = b"POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
            5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: y\r\n\r\n";
        let (rec, dir) = session(&srv, Protocol::Http, |mut c| async move {
            // Twice, a byte at a time the second time.
            c.write_all(post).await.unwrap();
            response(&mut c).await;
            for b in post {
                c.write_all(&[*b]).await.unwrap();
            }
            response(&mut c).await;
            c.write_all(b"PUT /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc")
                .await
                .unwrap();
            response(&mut c).await;
        })
        .await;
        let h = sha(b"hello world");
        let bodies: Vec<_> = rec.requests.iter().map(|r| r.body.clone()).collect();
        assert_eq!(
            bodies,
            [Some(h.clone()), Some(h.clone()), Some(sha(b"abc"))]
        );
        assert_eq!(rec.payloads, [h.clone(), sha(b"abc")]);
        assert_eq!(std::fs::read(dir.join(&h)).unwrap(), b"hello world");
        assert!(!rec.truncated);
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn framing_no_server_accepts_gets_a_400_and_a_close() {
        for (name, req) in [
            ("wbad1", &b"GET / HTTP/9\r\n\r\n"[..]),
            (
                "wbad2",
                b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            ),
        ] {
            let srv = server(name, 100_000, Duration::from_secs(5));
            let (rec, _) = session(&srv, Protocol::Http, |mut c| async move {
                c.write_all(req).await.unwrap();
                let mut rest = Vec::new();
                c.read_to_end(&mut rest).await.unwrap();
                let rest = String::from_utf8(rest).unwrap();
                assert!(rest.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{rest}");
                assert!(rest.contains("\r\nConnection: close\r\n"), "{rest}");
            })
            .await;
            assert!(!rec.timed_out);
            cleanup(&srv.spool);
        }
    }

    #[tokio::test]
    async fn keep_alive_ends_at_the_byte_cap() {
        let srv = server("wcap", 3000, Duration::from_secs(5));
        let (rec, _) = session(&srv, Protocol::Http, |mut c| async move {
            for _ in 0..100 {
                if c.write_all(b"GET / HTTP/1.1\r\n\r\n").await.is_err() {
                    return;
                }
                let mut b = [0u8; 4096];
                if matches!(c.read(&mut b).await, Ok(0) | Err(_)) {
                    return;
                }
            }
            panic!("never cut off");
        })
        .await;
        assert!(rec.truncated && !rec.timed_out);
        assert!(!rec.requests.is_empty());
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn a_body_that_never_ends_ends_at_the_byte_cap() {
        let srv = server("wendless", 3000, Duration::from_secs(5));
        let (rec, _) = session(&srv, Protocol::Http, |mut c| async move {
            c.write_all(b"POST / HTTP/1.1\r\nContent-Length: 1000000000000\r\n\r\n")
                .await
                .unwrap();
            // Nothing is answered until the body is in, so only the
            // bytes read can stop this.
            for _ in 0..1600 {
                if c.write_all(&[b'x'; 64 * 1024]).await.is_err() {
                    return;
                }
            }
            panic!("never cut off");
        })
        .await;
        assert!(rec.truncated && !rec.timed_out);
        assert_eq!(rec.requests.len(), 1);
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn keep_alive_ends_at_the_time_cap() {
        let srv = server("wtime", 1_000_000, Duration::from_secs(1));
        let (rec, _) = session(&srv, Protocol::Http, |mut c| async move {
            loop {
                if c.write_all(b"GET / HTTP/1.1\r\n\r\n").await.is_err() {
                    return;
                }
                let mut b = [0u8; 4096];
                if matches!(c.read(&mut b).await, Ok(0) | Err(_)) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        assert!(rec.timed_out);
        assert!(rec.requests.len() > 2, "{}", rec.requests.len());
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn a_body_too_big_to_keep_is_read_past_and_flagged() {
        let srv = server("wbig", 4000, Duration::from_secs(5));
        let (rec, _) = session(&srv, Protocol::Http, |mut c| async move {
            c.write_all(b"POST / HTTP/1.1\r\nContent-Length: 3000\r\n\r\n")
                .await
                .unwrap();
            c.write_all(&[b'x'; 3000]).await.unwrap();
            let _ = response(&mut c).await;
        })
        .await;
        assert_eq!(rec.requests.len(), 1);
        assert_eq!(rec.requests[0].body, None);
        assert!(rec.payloads.is_empty());
        assert!(rec.truncated);
        cleanup(&srv.spool);
    }

    /// A blocking rustls client trusting `ca`, asking for `name`: sends
    /// `req`, returns all it gets back, or the error that stopped it.
    fn tls_client(
        c: std::net::TcpStream,
        ca: &[u8],
        name: ServerName<'static>,
        req: &'static [u8],
    ) -> std::io::Result<Vec<u8>> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(ca).unwrap())
            .unwrap();
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let conn = rustls::ClientConnection::new(Arc::new(cfg), name).unwrap();
        let mut s = rustls::StreamOwned::new(conn, c);
        s.write_all(req)?;
        let mut out = Vec::new();
        // The honeypot closes without close_notify, as plenty of servers
        // do; what came before the close is the answer.
        let _ = s.read_to_end(&mut out);
        Ok(out)
    }

    async fn blocking_client(
        c: TcpStream,
        name: &'static str,
        ca: Vec<u8>,
    ) -> std::io::Result<Vec<u8>> {
        let c = c.into_std().unwrap();
        c.set_nonblocking(false).unwrap();
        let name = ServerName::try_from(name).unwrap();
        tokio::task::spawn_blocking(move || {
            tls_client(
                c,
                &ca,
                name,
                b"GET /x HTTP/1.1\r\nHost: c2.example\r\nConnection: close\r\n\r\n",
            )
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn https_gets_a_cert_for_its_name_and_is_recorded_inside() {
        let (srv, ca) =
            crate::serve::tests::server_with_ca("wtls", 100_000, Duration::from_secs(5));
        let (rec, _) = session(&srv, Protocol::Https, |c| async move {
            // The client checks the leaf is for c2.example and chains to
            // ca.pem.
            let got = blocking_client(c, "c2.example", ca).await.unwrap();
            let got = String::from_utf8(got).unwrap();
            assert!(got.starts_with("HTTP/1.1 200 OK\r\n"), "{got}");
        })
        .await;
        assert_eq!(rec.protocol, Protocol::Https);
        assert_eq!(rec.sni.as_deref(), Some("c2.example"));
        let ja4 = rec.ja4.unwrap();
        assert!(ja4.starts_with("t13d"), "{ja4}");
        assert_eq!(rec.requests.len(), 1);
        assert_eq!(rec.requests[0].path, "/x");
        assert!(rec.bytes_in > 0 && rec.bytes_out > 0);
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn a_client_without_a_name_still_gets_a_cert() {
        let (srv, ca) =
            crate::serve::tests::server_with_ca("wnosni", 100_000, Duration::from_secs(5));
        let (rec, _) = session(&srv, Protocol::Https, |c| async move {
            // No SNI for an address: the leaf is for the default name,
            // which this client then refuses. Without a cert at all it
            // would have been sent an alert instead.
            let e = blocking_client(c, "127.77.0.1", ca).await.unwrap_err();
            assert!(e.to_string().contains("not valid for name"), "{e}");
        })
        .await;
        assert_eq!(rec.sni, None);
        assert!(rec.ja4.unwrap().starts_with("t13i"));
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn a_client_that_quits_after_its_hello_is_still_fingerprinted() {
        let srv = server("wquit", 100_000, Duration::from_secs(5));
        let (rec, _) = session(&srv, Protocol::Https, |mut c| async move {
            c.write_all(include_bytes!("testdata/ja4/tls12.bin"))
                .await
                .unwrap();
            c.shutdown().await.unwrap();
        })
        .await;
        assert_eq!(rec.sni.as_deref(), Some("contile.services.mozilla.com"));
        assert_eq!(
            rec.ja4.as_deref(),
            Some("t13d1715h2_5b57614c22b0_3d5424432f57")
        );
        assert!(rec.requests.is_empty());
        cleanup(&srv.spool);
    }

    #[test]
    fn the_gif_is_a_whole_gif() {
        assert_eq!(GIF.len(), 43);
        assert!(GIF.starts_with(b"GIF89a\x01\x00\x01\x00") && GIF.ends_with(b";"));
    }
}
