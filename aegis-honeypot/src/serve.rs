// SPDX-License-Identifier: MIT OR Apache-2.0
//! From an accepted connection to a filed session: where it was going,
//! what to answer it as, and the caps around the answer.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use aegis_proto::honeypot::Protocol;
use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::dispatch::{by_bytes, by_port, PEEK};
use crate::session::{Session, Slots};

/// How long a client on an unknown port gets to speak first. A client
/// that waits to be spoken to is answered as raw after this.
const PEEK_WAIT: Duration = Duration::from_secs(2);

/// Answers one protocol. `io` is the client; everything it sends and
/// everything sent back goes through `s`.
pub trait Handler {
    async fn serve(&self, s: &mut Session, io: TcpStream) -> Result<()>;
}

/// Accepts, records up to the byte cap and says nothing.
pub struct CatchAll;

impl Handler for CatchAll {
    async fn serve(&self, s: &mut Session, mut io: TcpStream) -> Result<()> {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = io.read(&mut buf).await?;
            if n == 0 || !s.record(true, &buf[..n])? {
                return Ok(());
            }
        }
    }
}

pub struct Server {
    pub spool: PathBuf,
    pub max_bytes: u64,
    pub max_time: Duration,
    pub slots: Slots,
}

/// Where the tree was connecting before the redirect. None when the
/// connection wasn't NATed (or isn't IPv4).
fn original_dst(io: &TcpStream) -> Option<SocketAddrV4> {
    // SAFETY: a zeroed sockaddr_in is valid, and getsockopt writes at
    // most `len` bytes into it.
    let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            io.as_raw_fd(),
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            (&raw mut a).cast(),
            &mut len,
        )
    };
    (r == 0 && i32::from(a.sin_family) == libc::AF_INET).then(|| {
        SocketAddrV4::new(
            Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
            u16::from_be(a.sin_port),
        )
    })
}

/// One connection, start to `done/`. `forced` skips dispatch, for a
/// listener that only ever carries one protocol.
pub async fn handle(srv: Rc<Server>, io: TcpStream, forced: Option<Protocol>) -> Result<()> {
    // The units only listen on AF_INET.
    let (SocketAddr::V4(local), SocketAddr::V4(src)) = (io.local_addr()?, io.peer_addr()?) else {
        return Ok(());
    };
    let addr = *local.ip();
    // Over a cap: dropping `io` closes it, and nothing is recorded.
    let Some(_slot) = srv.slots.take(addr) else {
        return Ok(());
    };
    let dst = original_dst(&io).unwrap_or(local);
    let protocol = match forced.or(by_port(dst.port())) {
        Some(p) => p,
        None => {
            let mut first = [0u8; PEEK];
            let n = match timeout(PEEK_WAIT, io.peek(&mut first)).await {
                Ok(Ok(n)) => n,
                _ => 0,
            };
            by_bytes(&first[..n])
        }
    };
    let mut s = Session::open(&srv.spool, srv.max_bytes, protocol, addr, src, dst)?;
    // Every protocol is answered as catch-all until its own handler lands.
    match timeout(srv.max_time, CatchAll.serve(&mut s, io)).await {
        Ok(Ok(())) => {}
        // A reset or a broken pipe is how plenty of clients say goodbye.
        Ok(Err(e)) => eprintln!("aegis-honeypot: session {}: {e:#}", s.rec.id),
        Err(_) => s.rec.timed_out = true,
    }
    s.close()?;
    Ok(())
}

/// Accepts forever, one local task per connection.
pub async fn accept(srv: Rc<Server>, l: TcpListener, forced: Option<Protocol>) {
    loop {
        match l.accept().await {
            Ok((io, _)) => {
                let srv = srv.clone();
                tokio::task::spawn_local(async move {
                    if let Err(e) = handle(srv, io, forced).await {
                        eprintln!("aegis-honeypot: {e:#}");
                    }
                });
            }
            Err(e) => {
                // Out of fds or memory: back off rather than spin.
                eprintln!("aegis-honeypot: accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::honeypot;
    use std::path::Path;
    use tokio::io::AsyncWriteExt;

    fn server(name: &str, max_bytes: u64, max_time: Duration) -> Rc<Server> {
        let spool = crate::session::tests::spool(name);
        Rc::new(Server {
            spool,
            max_bytes,
            max_time,
            slots: Slots::default(),
        })
    }

    /// Runs `client` against one handled connection; returns what the
    /// client read before the server closed, and the filed session.
    async fn one<F, Fut>(srv: &Rc<Server>, forced: Option<Protocol>, client: F) -> honeypot::Session
    where
        F: FnOnce(TcpStream) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = l.local_addr().unwrap();
        let (c, accepted) = tokio::join!(TcpStream::connect(at), l.accept());
        let (io, _) = accepted.unwrap();
        let (r, ()) = tokio::join!(handle(srv.clone(), io, forced), client(c.unwrap()));
        r.unwrap();
        only_session(&srv.spool)
    }

    fn only_session(spool: &Path) -> honeypot::Session {
        let done = spool.join("127.0.0.1/done");
        let mut d: Vec<_> = std::fs::read_dir(&done).unwrap().collect();
        assert_eq!(d.len(), 1);
        let p = d.pop().unwrap().unwrap().path();
        let rec = serde_json::from_slice(&std::fs::read(p.join("session.json")).unwrap()).unwrap();
        std::fs::remove_dir_all(spool).unwrap();
        rec
    }

    async fn eof(mut c: TcpStream) {
        let mut got = Vec::new();
        // The honeypot sends nothing; a reset is as good as a close.
        let _ = c.read_to_end(&mut got).await;
        assert!(got.is_empty(), "{got:?}");
    }

    #[tokio::test]
    async fn catch_all_keeps_up_to_the_cap_then_closes() {
        let srv = server("hcap", 10, Duration::from_secs(30));
        let rec = one(&srv, None, |mut c| async move {
            c.write_all(b"0123456789abcdefghij").await.unwrap();
            eof(c).await;
        })
        .await;
        assert_eq!(rec.protocol, Protocol::Raw);
        assert_eq!((rec.bytes_in, rec.bytes_out), (10, 0));
        assert!(rec.truncated);
        assert!(!rec.timed_out);
        // Not NATed in the test, so the original destination is where
        // it landed.
        assert_eq!(rec.addr, Ipv4Addr::LOCALHOST);
        assert_eq!(rec.dst.ip(), &Ipv4Addr::LOCALHOST);
    }

    #[tokio::test(start_paused = true)]
    async fn time_cap_closes_a_silent_session() {
        let srv = server("htime", 10, Duration::from_secs(300));
        let rec = one(&srv, None, eof).await;
        assert!(rec.timed_out);
        assert!(!rec.truncated);
        assert_eq!(rec.protocol, Protocol::Raw);
        assert!(rec.ended_ms >= rec.started_ms);
    }

    #[tokio::test]
    async fn a_client_that_hangs_up_ends_the_session() {
        let srv = server("hbye", 100, Duration::from_secs(30));
        let rec = one(&srv, None, |mut c| async move {
            c.write_all(b"\x00\x01").await.unwrap();
            c.shutdown().await.unwrap();
        })
        .await;
        assert_eq!(rec.bytes_in, 2);
        assert!(!rec.timed_out && !rec.truncated);
    }

    #[tokio::test]
    async fn an_unknown_port_is_dispatched_on_the_first_bytes() {
        let srv = server("hpeek", 100, Duration::from_secs(30));
        let rec = one(&srv, None, |mut c| async move {
            c.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
            c.shutdown().await.unwrap();
        })
        .await;
        assert_eq!(rec.protocol, Protocol::Http);
        // The peek consumed nothing: every byte is in the session.
        assert_eq!(rec.bytes_in, 18);
    }

    #[tokio::test]
    async fn a_forced_listener_skips_dispatch() {
        let srv = server("hforce", 100, Duration::from_secs(30));
        let rec = one(&srv, Some(Protocol::Dns), |mut c| async move {
            c.write_all(b"SSH-2.0-x\r\n").await.unwrap();
            c.shutdown().await.unwrap();
        })
        .await;
        assert_eq!(rec.protocol, Protocol::Dns);
    }

    #[tokio::test]
    async fn a_full_address_gets_no_session() {
        let srv = server("hfull", 100, Duration::from_secs(30));
        let _held: Vec<_> = std::iter::from_fn(|| srv.slots.take(Ipv4Addr::LOCALHOST)).collect();
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (c, accepted) = tokio::join!(TcpStream::connect(l.local_addr().unwrap()), l.accept());
        handle(srv.clone(), accepted.unwrap().0, None)
            .await
            .unwrap();
        eof(c.unwrap()).await;
        assert!(!srv.spool.exists());
    }

    #[tokio::test]
    async fn an_un_natted_connection_has_no_original_destination() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (c, accepted) = tokio::join!(TcpStream::connect(l.local_addr().unwrap()), l.accept());
        drop(c);
        assert_eq!(original_dst(&accepted.unwrap().0), None);
    }
}
