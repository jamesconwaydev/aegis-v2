// SPDX-License-Identifier: MIT OR Apache-2.0
//! From an accepted connection to a filed session: where it was going,
//! what to answer it as, and the caps around the answer.

use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use aegis_proto::honeypot::Protocol;
use anyhow::Result;
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::dispatch::{by_bytes, by_port, PEEK};
use crate::dns::{self, Names};
use crate::pcap::FIXED_COST;
use crate::session::{Conn, Floor, Session, Slots, Transport};
use crate::ssh::Ssh;
use crate::web::{Http, Https};

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

/// DNS over TCP: each message framed by a two-byte length (RFC 1035
/// 4.2.2), answered in turn.
pub struct Dns<'a>(&'a RefCell<Names>);

impl Handler for Dns<'_> {
    async fn serve(&self, s: &mut Session, mut io: TcpStream) -> Result<()> {
        // The largest frame there is; the length can't ask for more.
        let mut buf = vec![0u8; 2 + usize::from(u16::MAX)];
        loop {
            io.read_exact(&mut buf[..2]).await?;
            let end = 2 + usize::from(u16::from_be_bytes([buf[0], buf[1]]));
            io.read_exact(&mut buf[2..end]).await?;
            if !s.record(true, &buf[..end])? {
                return Ok(());
            }
            let Some((reply, asked)) = dns::answer(
                &buf[2..end],
                &mut self.0.borrow_mut(),
                s.rec.addr,
                std::time::Instant::now(),
            ) else {
                continue;
            };
            if let Some(q) = asked {
                s.query(q);
            }
            // At most 512 bytes, so the length always fits.
            let out = [&(reply.len() as u16).to_be_bytes()[..], &reply].concat();
            let more = s.record(false, &out)?;
            io.write_all(&out).await?;
            if !more {
                return Ok(());
            }
        }
    }
}

pub struct Server {
    pub spool: PathBuf,
    pub max_bytes: u64,
    pub max_time: Duration,
    pub floor: Floor,
    pub slots: Slots,
    /// UDP DNS sessions' own; see `udp::slots`.
    pub udp_slots: Slots,
    /// Shared by DNS and the TCP side, which labels connections from it.
    pub names: RefCell<Names>,
    /// HTTPS, with a leaf from the host's CA for each name asked.
    pub tls: Arc<ServerConfig>,
    pub ssh: Ssh,
    /// SSH sessions' own count, within TCP's; see `ssh::slots`.
    pub ssh_slots: Slots,
}

impl Server {
    /// Sessions open now, TCP and UDP.
    pub fn open(&self) -> usize {
        self.slots.open() + self.udp_slots.open()
    }
}

/// What the spool must have free for one more session: the floor, plus
/// all that the `open` sessions (this one among them) may still write,
/// their pcap and a full session.json each.
pub fn reserve(floor: Floor, open: usize, cap: u64) -> Floor {
    let each = cap.saturating_add(FIXED_COST).saturating_add(64 * 1024);
    Floor {
        bytes: floor
            .bytes
            .saturating_add((open as u64).saturating_mul(each)),
        inodes: floor.inodes,
    }
}

/// Whether a connection landed on an incident address. aegisd redirects
/// observed trees into 127.77.0.0/16 only; anything else on loopback is
/// some local user, who mustn't fill the spool.
pub fn incident_addr(ip: Ipv4Addr) -> bool {
    ip.octets()[..2] == [127, 77]
}

/// How plenty of clients say goodbye, or fail TLS or SSH (scanners,
/// clients that won't trust the cert); not worth a log line each. An
/// I/O error russh passes on is judged as the I/O error it is.
fn quiet(e: &anyhow::Error) -> bool {
    use std::io::ErrorKind::{BrokenPipe, ConnectionReset, UnexpectedEof};
    let ssh = e.downcast_ref::<russh::Error>();
    let io = match ssh {
        Some(russh::Error::IO(e)) => Some(e),
        _ => e.downcast_ref::<std::io::Error>(),
    };
    e.downcast_ref::<rustls::Error>().is_some()
        || ssh.is_some_and(|e| !matches!(e, russh::Error::IO(_)))
        || io.is_some_and(|e| matches!(e.kind(), ConnectionReset | BrokenPipe | UnexpectedEof))
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
    let dst = original_dst(&io).unwrap_or(local);
    run(srv, io, *local.ip(), src, dst, forced).await
}

/// The rest of `handle`, from where the connection landed (`addr`) and
/// where it was going (`dst`).
async fn run(
    srv: Rc<Server>,
    io: TcpStream,
    addr: Ipv4Addr,
    src: SocketAddrV4,
    dst: SocketAddrV4,
    forced: Option<Protocol>,
) -> Result<()> {
    // Not an incident address, or over a cap: dropping `io` closes it,
    // and nothing is recorded.
    if !incident_addr(addr) {
        return Ok(());
    }
    let Some(_slot) = srv.slots.take(addr) else {
        return Ok(());
    };
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
    // Held until russh's task for the connection has ended.
    let _ssh = match protocol {
        Protocol::Ssh => match srv.ssh_slots.take(addr) {
            Some(s) => Some(s),
            None => return Ok(()),
        },
        _ => None,
    };
    let opened = Session::open(
        &srv.spool,
        srv.max_bytes,
        reserve(srv.floor, srv.open(), srv.max_bytes),
        Conn {
            protocol,
            transport: Transport::Tcp,
            addr,
            src,
            dst,
        },
    )?;
    let Some(mut s) = opened else {
        eprintln!(
            "aegis-honeypot: {} is low on space or inodes; not recording",
            srv.spool.display()
        );
        return Ok(());
    };
    s.rec.dns_name = srv
        .names
        .borrow_mut()
        .label(addr, *dst.ip(), std::time::Instant::now());
    // The rest are answered as catch-all until their own handlers land.
    let served = match protocol {
        Protocol::Ssh => {
            let served;
            (s, served) = srv.ssh.serve(s, io, srv.max_time).await;
            served
        }
        Protocol::Dns => timeout(srv.max_time, Dns(&srv.names).serve(&mut s, io)).await,
        Protocol::Http => timeout(srv.max_time, Http.serve(&mut s, io)).await,
        Protocol::Https => timeout(srv.max_time, Https(&srv.tls).serve(&mut s, io)).await,
        _ => timeout(srv.max_time, CatchAll.serve(&mut s, io)).await,
    };
    match served {
        Ok(Ok(())) => {}
        Ok(Err(e)) if quiet(&e) => {}
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
pub(crate) mod tests {
    use super::*;
    use crate::pcap::SEGMENT_COST;
    use crate::session::tests::NO_FLOOR;
    use aegis_proto::honeypot;
    use std::future::Future;
    use std::path::Path;
    use tokio::io::AsyncWriteExt;

    /// An incident address; any 127/8 address is local on Linux.
    pub const INCIDENT: Ipv4Addr = Ipv4Addr::new(127, 77, 0, 1);

    pub fn server(name: &str, max_bytes: u64, max_time: Duration) -> Rc<Server> {
        server_with_ca(name, max_bytes, max_time).0
    }

    /// A server, and the CA (PEM) its HTTPS leaves chain to.
    pub fn server_with_ca(name: &str, max_bytes: u64, max_time: Duration) -> (Rc<Server>, Vec<u8>) {
        let spool = crate::session::tests::spool(name);
        let (tls, ca) = crate::ca::tests::tls(name);
        let srv = Rc::new(Server {
            spool,
            max_bytes,
            max_time,
            floor: NO_FLOOR,
            slots: Slots::default(),
            udp_slots: crate::udp::slots(),
            names: RefCell::default(),
            tls,
            ssh: crate::ssh::tests::ssh(name),
            ssh_slots: crate::ssh::slots(),
        });
        (srv, ca)
    }

    /// Fails a test that would otherwise hang. Past the time cap and the
    /// peek, so it never fires first when the code is right.
    pub async fn bounded<T>(srv: &Server, f: impl Future<Output = T>) -> T {
        timeout(srv.max_time * 2 + PEEK_WAIT, f)
            .await
            .expect("hung past the time cap")
    }

    /// A connected (client, accepted) pair landing on `ip`.
    pub async fn pair(ip: Ipv4Addr) -> (TcpStream, TcpStream) {
        let l = TcpListener::bind((ip, 0)).await.unwrap();
        let (c, accepted) = tokio::join!(TcpStream::connect(l.local_addr().unwrap()), l.accept());
        (c.unwrap(), accepted.unwrap().0)
    }

    /// Runs `client` against one handled connection to an incident
    /// address, and returns the filed session.
    pub async fn one<F, Fut>(
        srv: &Rc<Server>,
        forced: Option<Protocol>,
        client: F,
    ) -> honeypot::Session
    where
        F: FnOnce(TcpStream) -> Fut,
        Fut: Future<Output = ()>,
    {
        let (c, io) = pair(INCIDENT).await;
        let (r, ()) = bounded(srv, async {
            tokio::join!(handle(srv.clone(), io, forced), client(c))
        })
        .await;
        r.unwrap();
        only_session(&srv.spool)
    }

    fn only_session(spool: &Path) -> honeypot::Session {
        let done = spool.join("127.77.0.1/done");
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

    /// Hands one connection to `ip` to `srv` and checks it was closed
    /// with nothing filed.
    async fn refused(srv: &Rc<Server>, ip: Ipv4Addr) {
        let (c, io) = pair(ip).await;
        bounded(srv, async {
            handle(srv.clone(), io, None).await.unwrap();
            eof(c).await;
        })
        .await;
        let done = srv.spool.join(ip.to_string()).join("done");
        if let Ok(mut d) = std::fs::read_dir(&done) {
            assert!(d.next().is_none(), "{} has a session", done.display());
        }
    }

    #[test]
    fn only_incident_addresses_are_served() {
        for (ip, ok) in [
            ([127, 77, 0, 1], true),
            ([127, 77, 255, 254], true),
            ([127, 0, 0, 1], false),
            ([127, 78, 0, 1], false),
            ([127, 76, 255, 255], false),
            ([10, 77, 0, 1], false),
        ] {
            assert_eq!(incident_addr(Ipv4Addr::from(ip)), ok, "{ip:?}");
        }
    }

    #[test]
    fn the_reservation_saturates_instead_of_wrapping() {
        let f = |bytes| Floor { bytes, inodes: 7 };
        assert_eq!(reserve(f(5), 0, 100).bytes, 5);
        assert_eq!(
            reserve(f(5), 2, 100).bytes,
            5 + 2 * (100 + FIXED_COST + 65536)
        );
        assert_eq!(reserve(f(u64::MAX - 1), 512, u64::MAX).bytes, u64::MAX);
        assert_eq!(reserve(f(5), 512, 100).inodes, 7);
    }

    #[test]
    fn goodbyes_are_not_logged() {
        use std::io::{Error, ErrorKind};
        for k in [
            ErrorKind::ConnectionReset,
            ErrorKind::BrokenPipe,
            ErrorKind::UnexpectedEof,
        ] {
            assert!(quiet(&Error::from(k).into()), "{k:?}");
        }
        assert!(quiet(&rustls::Error::NoCertificatesPresented.into()));
        assert!(quiet(&russh::Error::Disconnect.into()));
        assert!(quiet(
            &russh::Error::IO(ErrorKind::ConnectionReset.into()).into()
        ));
        assert!(!quiet(&Error::from(ErrorKind::PermissionDenied).into()));
        // A full disk under the SSH session is still worth a line.
        assert!(!quiet(
            &russh::Error::IO(ErrorKind::StorageFull.into()).into()
        ));
        assert!(!quiet(&anyhow::anyhow!("disk full")));
    }

    #[tokio::test]
    async fn catch_all_keeps_up_to_the_cap_then_closes() {
        // Room for 66 bytes in one segment, fewer in more: however the
        // 200 bytes arrive, the cap ends the session.
        let srv = server("hcap", 10 + 2 * SEGMENT_COST, Duration::from_secs(5));
        let rec = one(&srv, None, |mut c| async move {
            c.write_all(&[b'x'; 200]).await.unwrap();
            eof(c).await;
        })
        .await;
        assert_eq!(rec.protocol, Protocol::Raw);
        assert!(rec.bytes_in <= 10 + SEGMENT_COST, "{}", rec.bytes_in);
        assert_eq!(rec.bytes_out, 0);
        assert!(rec.truncated);
        assert!(!rec.timed_out);
        // Not NATed in the test, so the original destination is where
        // it landed.
        assert_eq!(rec.addr, INCIDENT);
        assert_eq!(rec.dst.ip(), &INCIDENT);
    }

    #[tokio::test(start_paused = true)]
    async fn time_cap_closes_a_silent_session() {
        let srv = server("htime", 1000, Duration::from_secs(300));
        let rec = one(&srv, None, eof).await;
        assert!(rec.timed_out);
        assert!(!rec.truncated);
        assert_eq!(rec.protocol, Protocol::Raw);
        assert!(rec.ended_ms >= rec.started_ms);
    }

    #[tokio::test]
    async fn a_client_that_hangs_up_ends_the_session() {
        let srv = server("hbye", 1000, Duration::from_secs(5));
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
        let srv = server("hpeek", 1000, Duration::from_secs(5));
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
        let srv = server("hforce", 1000, Duration::from_secs(5));
        let rec = one(&srv, Some(Protocol::Dns), |mut c| async move {
            c.write_all(b"SSH-2.0-x\r\n").await.unwrap();
            c.shutdown().await.unwrap();
        })
        .await;
        assert_eq!(rec.protocol, Protocol::Dns);
    }

    #[tokio::test]
    async fn a_non_incident_address_gets_no_session() {
        let srv = server("hlocal", 1000, Duration::from_secs(5));
        refused(&srv, Ipv4Addr::LOCALHOST).await;
        assert_eq!(std::fs::read_dir(&srv.spool).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn a_full_address_gets_no_session() {
        let srv = server("hfull", 1000, Duration::from_secs(5));
        let _held: Vec<_> = std::iter::from_fn(|| srv.slots.take(INCIDENT)).collect();
        refused(&srv, INCIDENT).await;
        assert_eq!(std::fs::read_dir(&srv.spool).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn ssh_past_its_own_cap_is_refused_while_http_is_served() {
        let srv = server("hsshcap", 1000, Duration::from_secs(5));
        let held: Vec<_> = std::iter::from_fn(|| srv.ssh_slots.take(INCIDENT)).collect();
        assert_eq!(held.len(), 8);
        let (c, io) = pair(INCIDENT).await;
        bounded(&srv, async {
            handle(srv.clone(), io, Some(Protocol::Ssh)).await.unwrap();
            eof(c).await;
        })
        .await;
        let done = srv.spool.join("127.77.0.1/done");
        assert!(std::fs::read_dir(&done).map_or(true, |mut d| d.next().is_none()));
        let rec = one(&srv, Some(Protocol::Http), |c| async move { drop(c) }).await;
        assert_eq!(rec.protocol, Protocol::Http);
    }

    #[tokio::test]
    async fn a_full_disk_gets_no_session() {
        let mut s = Rc::into_inner(server("hdisk", 1000, Duration::from_secs(5))).unwrap();
        s.floor = Floor {
            bytes: u64::MAX,
            inodes: 0,
        };
        let srv = Rc::new(s);
        refused(&srv, INCIDENT).await;
        std::fs::remove_dir_all(&srv.spool).unwrap();
    }

    #[tokio::test]
    async fn open_sessions_reserve_their_cap_against_the_floor() {
        let spool = crate::session::tests::spool("hreserve");
        let (avail, _) = crate::session::free(&spool).unwrap();
        // The fixed floor takes half of what's free and each session
        // reserves a third: room for the new session alone, not for it
        // and one already open.
        let srv = Rc::new(Server {
            spool,
            max_bytes: avail / 3,
            max_time: Duration::from_secs(5),
            floor: Floor {
                bytes: avail / 2,
                inodes: 0,
            },
            slots: Slots::default(),
            udp_slots: crate::udp::slots(),
            names: RefCell::default(),
            tls: crate::ca::tests::tls("hreserve").0,
            ssh: crate::ssh::tests::ssh("hreserve"),
            ssh_slots: crate::ssh::slots(),
        });
        let other = srv.slots.take(Ipv4Addr::new(127, 77, 0, 9)).unwrap();
        refused(&srv, INCIDENT).await;
        // With nothing else open, the same session is recorded.
        drop(other);
        let s = one(&srv, None, |c| async move { drop(c) }).await;
        assert_eq!(s.addr, INCIDENT);
    }

    fn framed(id: u16, name: &str, t: u16) -> Vec<u8> {
        let b = crate::dns::wire::query(id, name, t);
        [&(b.len() as u16).to_be_bytes()[..], &b].concat()
    }

    async fn reply(c: &mut TcpStream) -> crate::dns::wire::Reply {
        let mut len = [0u8; 2];
        c.read_exact(&mut len).await.unwrap();
        let mut b = vec![0u8; u16::from_be_bytes(len).into()];
        c.read_exact(&mut b).await.unwrap();
        crate::dns::wire::read(&b)
    }

    #[tokio::test]
    async fn dns_over_tcp_answers_each_framed_query() {
        use crate::dns::wire::{A, AAAA};
        let srv = server("hdns", 10_000, Duration::from_secs(5));
        let (q1, q2) = (framed(1, "c2.example.", A), framed(2, "c2.example.", AAAA));
        let sent = q1.len() + q2.len() + 7;
        let rec = one(&srv, Some(Protocol::Dns), |mut c| async move {
            // Both at once: the framing, not the reads, splits them.
            c.write_all(&[q1, q2].concat()).await.unwrap();
            let a = reply(&mut c).await;
            assert_eq!(a.a.len(), 1);
            assert_eq!(a.id, 1);
            assert!(reply(&mut c).await.a.is_empty());
            c.write_all(&[0, 5, 1, 2, 3, 4, 5]).await.unwrap();
            assert_eq!(reply(&mut c).await.rcode(), 1);
            c.shutdown().await.unwrap();
        })
        .await;
        assert_eq!(rec.protocol, Protocol::Dns);
        assert_eq!(rec.bytes_in, sent as u64);
        assert!(rec.bytes_out > 0);
        let asked: Vec<_> = rec
            .queries
            .iter()
            .map(|q| (q.name.as_str(), q.answer))
            .collect();
        assert_eq!(
            asked,
            [
                ("c2.example", Some(Ipv4Addr::new(198, 18, 0, 1))),
                ("c2.example", None)
            ]
        );
        assert!(!rec.truncated && !rec.timed_out);
    }

    #[tokio::test]
    async fn dns_over_udp_never_takes_the_places_tcp_needs() {
        use crate::dns::wire::{query, A};
        let srv = server("hudp", 10_000, Duration::from_secs(5));
        let mut g = crate::udp::Groups::default();
        let q = query(1, "c2.example.", A);
        let now = tokio::time::Instant::now();
        // A stub resolver uses a new port for each lookup.
        for port in 4000..4100 {
            let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), port);
            let to = SocketAddrV4::new(INCIDENT, 2553);
            assert!(g.datagram(&srv, &q, src, to, now).is_some(), "unanswered");
        }
        assert_eq!(srv.udp_slots.open(), 16);
        let rec = one(&srv, None, |c| async move { drop(c) }).await;
        assert_eq!(rec.addr, INCIDENT);
    }

    #[tokio::test]
    async fn port_53_is_answered_as_dns() {
        let srv = server("h53", 10_000, Duration::from_secs(5));
        let (c, io) = pair(INCIDENT).await;
        let src = match c.local_addr().unwrap() {
            SocketAddr::V4(a) => a,
            a => panic!("{a}"),
        };
        let dst = SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53);
        let q = framed(9, "x.example.", crate::dns::wire::A);
        bounded(&srv, async {
            let client = async move {
                let mut c = c;
                c.write_all(&q).await.unwrap();
                assert_eq!(reply(&mut c).await.id, 9);
            };
            let (r, ()) = tokio::join!(run(srv.clone(), io, INCIDENT, src, dst, None), client);
            r.unwrap();
        })
        .await;
        let rec = only_session(&srv.spool);
        assert_eq!((rec.protocol, rec.dst), (Protocol::Dns, dst));
    }

    #[tokio::test]
    async fn a_connection_to_a_given_address_is_labelled_with_its_name() {
        let srv = server("hlabel", 1000, Duration::from_secs(5));
        let ip = srv
            .names
            .borrow_mut()
            .address(INCIDENT, "c2.example", std::time::Instant::now());
        for (dst, want) in [
            (SocketAddrV4::new(ip, 443), Some("c2.example")),
            (SocketAddrV4::new(Ipv4Addr::new(198, 18, 0, 2), 443), None),
            (
                SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443),
                None,
            ),
        ] {
            let (c, io) = pair(INCIDENT).await;
            let src = match c.local_addr().unwrap() {
                SocketAddr::V4(a) => a,
                a => panic!("{a}"),
            };
            drop(c);
            bounded(&srv, run(srv.clone(), io, INCIDENT, src, dst, None))
                .await
                .unwrap();
            let rec = only_session(&srv.spool);
            assert_eq!(rec.dst, dst);
            assert_eq!(rec.dns_name.as_deref(), want, "{dst}");
            std::fs::create_dir(&srv.spool).unwrap();
        }
    }

    #[tokio::test]
    async fn an_un_natted_connection_has_no_original_destination() {
        let (c, io) = pair(INCIDENT).await;
        drop(c);
        assert_eq!(original_dst(&io), None);
    }
}
