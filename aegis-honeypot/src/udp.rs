// SPDX-License-Identifier: MIT OR Apache-2.0
//! DNS over UDP. The socket is bound to 0.0.0.0, so a datagram's own
//! destination (IP_PKTINFO) is the only place that says which incident
//! address it was sent to, and the reply has to leave from that address
//! or the client drops it.

use std::collections::hash_map::{Entry, HashMap};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::rc::Rc;
use std::time::Duration;

use aegis_proto::honeypot::{DnsQuery, Protocol};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::time::{sleep_until, Instant};

use crate::dns;
use crate::serve::{incident_addr, reserve, Server};
use crate::session::{Conn, Session, Slot, Slots, Transport};

/// Queries from one client port this close together are one session.
pub const GROUP: Duration = Duration::from_secs(5);

/// Open UDP sessions per incident address, and in all. Their own count,
/// apart from TCP's: a stub resolver takes a new port per lookup, and
/// each port holds its session for 5 s, so sharing would let a tree's
/// lookups crowd out the connections that follow them.
pub fn slots() -> Slots {
    Slots::new(16, 256)
}

struct Group {
    s: Session,
    _slot: Slot,
    opened: Instant,
    last: Instant,
}

impl Group {
    fn deadline(&self, max_time: Duration) -> Instant {
        (self.last + GROUP).min(self.opened + max_time)
    }
}

/// The open UDP sessions, one per incident address and client port. Each
/// holds a slot, so the slot caps bound this map too.
#[derive(Default)]
pub struct Groups(HashMap<(Ipv4Addr, SocketAddrV4), Group>);

impl Groups {
    /// Records one datagram from `src` to `local` and returns the reply
    /// to send. Over a cap the reply is still sent, since it costs no
    /// disk and no fd, but nothing is recorded.
    pub fn datagram(
        &mut self,
        srv: &Server,
        msg: &[u8],
        src: SocketAddrV4,
        local: SocketAddrV4,
        now: Instant,
    ) -> Option<Vec<u8>> {
        let addr = *local.ip();
        if !incident_addr(addr) {
            return None;
        }
        let (reply, asked) =
            match dns::answer(msg, &mut srv.names.borrow_mut(), addr, now.into_std()) {
                Some((r, q)) => (Some(r), q),
                None => (None, None),
            };
        let key = (addr, src);
        let g = match self.0.entry(key) {
            Entry::Occupied(e) => Some(e.into_mut()),
            Entry::Vacant(e) => open(srv, src, local, now).map(|g| e.insert(g)),
        };
        let kept = g.map(|g| {
            g.last = now;
            record(&mut g.s, msg, asked, reply.as_deref())
                .inspect_err(|e| eprintln!("aegis-honeypot: session {}: {e}", g.s.rec.id))
        });
        // Past the cap, or unwritable: file what there is.
        if matches!(kept, Some(Ok(false) | Err(_))) {
            file(self.0.remove(&key));
        }
        reply
    }

    /// Files every session whose client went quiet, or that ran out of
    /// time.
    pub fn expire(&mut self, now: Instant, max_time: Duration) {
        let due: Vec<_> = self
            .0
            .iter()
            .filter(|(_, g)| g.deadline(max_time) <= now)
            .map(|(k, _)| *k)
            .collect();
        for k in due {
            let mut g = self.0.remove(&k);
            if let Some(g) = &mut g {
                g.s.rec.timed_out = g.opened + max_time <= now;
            }
            file(g);
        }
    }

    /// When `expire` next has something to do.
    pub fn next(&self, max_time: Duration) -> Option<Instant> {
        self.0.values().map(|g| g.deadline(max_time)).min()
    }
}

/// A new session for `src`, or None over a cap.
fn open(srv: &Server, src: SocketAddrV4, local: SocketAddrV4, now: Instant) -> Option<Group> {
    let addr = *local.ip();
    let slot = srv.udp_slots.take(addr)?;
    // The original destination of a DNATed datagram isn't kept anywhere
    // an unprivileged socket can read, so `dst` is where it landed.
    let opened = Session::open(
        &srv.spool,
        srv.max_bytes,
        reserve(srv.floor, srv.open(), srv.max_bytes),
        Conn {
            protocol: Protocol::Dns,
            transport: Transport::Udp,
            addr,
            src,
            dst: local,
        },
    );
    match opened {
        Ok(Some(s)) => Some(Group {
            s,
            _slot: slot,
            opened: now,
            last: now,
        }),
        Ok(None) => {
            eprintln!(
                "aegis-honeypot: {} is low on space or inodes; not recording",
                srv.spool.display()
            );
            None
        }
        Err(e) => {
            eprintln!("aegis-honeypot: {e}");
            None
        }
    }
}

/// The query, its question and the reply, while they fit.
fn record(
    s: &mut Session,
    msg: &[u8],
    asked: Option<DnsQuery>,
    reply: Option<&[u8]>,
) -> io::Result<bool> {
    if !s.datagram(true, msg)? {
        return Ok(false);
    }
    if let Some(q) = asked {
        s.query(q);
    }
    reply.map_or(Ok(true), |r| s.datagram(false, r))
}

fn file(g: Option<Group>) {
    if let Some(g) = g {
        let id = g.s.rec.id.clone();
        if let Err(e) = g.s.close() {
            eprintln!("aegis-honeypot: session {id}: {e}");
        }
    }
}

/// Asks the kernel to say where each datagram was sent (IP_PKTINFO).
pub fn pktinfo(fd: RawFd) -> io::Result<()> {
    let on: libc::c_int = 1;
    // SAFETY: setsockopt reads `len` bytes from `on`; a bad fd is only
    // an error.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            (&raw const on).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Room for one in_pktinfo control message, aligned for cmsghdr.
type Control = [u64; 8];

/// One datagram into `buf`: its length, its sender and the local
/// address it was sent to. None for anything but IPv4 with PKTINFO.
fn recv(fd: RawFd, buf: &mut [u8]) -> io::Result<Option<(usize, SocketAddrV4, Ipv4Addr)>> {
    // SAFETY: every pointer in `m` points at a live local or `buf`, with
    // its true length, and recvmsg writes no further than those lengths.
    // The cmsg walk only follows what the kernel wrote into `ctl`.
    unsafe {
        let mut from: libc::sockaddr_in = std::mem::zeroed();
        let mut ctl: Control = [0; 8];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut m: libc::msghdr = std::mem::zeroed();
        m.msg_name = (&raw mut from).cast();
        m.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        m.msg_iov = &raw mut iov;
        m.msg_iovlen = 1;
        m.msg_control = ctl.as_mut_ptr().cast();
        m.msg_controllen = std::mem::size_of::<Control>() as _;
        let n = libc::recvmsg(fd, &raw mut m, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // A cut control message can't be trusted to say where it went.
        if m.msg_flags & libc::MSG_CTRUNC != 0 {
            return Ok(None);
        }
        let whole = libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize;
        let mut local = None;
        let mut c = libc::CMSG_FIRSTHDR(&raw const m);
        while !c.is_null() {
            if (*c).cmsg_level == libc::IPPROTO_IP
                && (*c).cmsg_type == libc::IP_PKTINFO
                && (*c).cmsg_len as usize >= whole
            {
                let pi: libc::in_pktinfo = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast());
                local = Some(Ipv4Addr::from(u32::from_be(pi.ipi_addr.s_addr)));
            }
            c = libc::CMSG_NXTHDR(&raw const m, c);
        }
        let ipv4 = m.msg_namelen as usize == std::mem::size_of::<libc::sockaddr_in>()
            && i32::from(from.sin_family) == libc::AF_INET;
        let src = SocketAddrV4::new(
            Ipv4Addr::from(u32::from_be(from.sin_addr.s_addr)),
            u16::from_be(from.sin_port),
        );
        Ok(local.filter(|_| ipv4).map(|l| (n as usize, src, l)))
    }
}

/// Sends `data` to `to` from the local address `from`.
fn send(fd: RawFd, data: &[u8], to: SocketAddrV4, from: Ipv4Addr) -> io::Result<usize> {
    // SAFETY: as in `recv`; sendmsg only reads through `m`, and the one
    // cmsg written fits `ctl` (CMSG_SPACE of in_pktinfo is 32 bytes).
    unsafe {
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = to.port().to_be();
        sa.sin_addr.s_addr = u32::from(*to.ip()).to_be();
        let mut ctl: Control = [0; 8];
        let mut iov = libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast(),
            iov_len: data.len(),
        };
        let mut m: libc::msghdr = std::mem::zeroed();
        m.msg_name = (&raw mut sa).cast();
        m.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        m.msg_iov = &raw mut iov;
        m.msg_iovlen = 1;
        m.msg_control = ctl.as_mut_ptr().cast();
        let len = std::mem::size_of::<libc::in_pktinfo>() as u32;
        m.msg_controllen = libc::CMSG_SPACE(len) as _;
        let c = libc::CMSG_FIRSTHDR(&raw const m);
        (*c).cmsg_level = libc::IPPROTO_IP;
        (*c).cmsg_type = libc::IP_PKTINFO;
        (*c).cmsg_len = libc::CMSG_LEN(len) as _;
        let pi = libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from(from).to_be(),
            },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };
        std::ptr::write_unaligned(libc::CMSG_DATA(c).cast(), pi);
        let n = libc::sendmsg(fd, &raw const m, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

/// Answers and records DNS on `sock` forever.
pub async fn serve(srv: Rc<Server>, sock: UdpSocket) {
    let port = sock.local_addr().map_or(0, |a| a.port());
    let fd = sock.as_raw_fd();
    // The largest UDP payload there is, so no datagram is cut short.
    let mut buf = vec![0u8; 65535];
    let mut groups = Groups::default();
    loop {
        // With nothing open, an hour is as good as forever.
        let wake = groups
            .next(srv.max_time)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));
        tokio::select! {
            r = sock.async_io(Interest::READABLE, || recv(fd, &mut buf)) => match r {
                Ok(Some((n, src, ip))) => {
                    let local = SocketAddrV4::new(ip, port);
                    if let Some(reply) = groups.datagram(&srv, &buf[..n], src, local, Instant::now()) {
                        // Lost like any datagram if it fails; the client asks again.
                        let _ = sock.async_io(Interest::WRITABLE, || send(fd, &reply, src, ip)).await;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("aegis-honeypot: dns-udp: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            () = sleep_until(wake) => {}
        }
        groups.expire(Instant::now(), srv.max_time);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{self, query, A, AAAA};
    use crate::session::tests::{spool, NO_FLOOR};
    use aegis_proto::honeypot;
    use std::cell::RefCell;
    use std::path::Path;

    const INCIDENT: Ipv4Addr = Ipv4Addr::new(127, 77, 0, 1);

    fn server(name: &str, max_bytes: u64, max_time: Duration) -> Server {
        Server {
            spool: spool(name),
            max_bytes,
            max_time,
            floor: NO_FLOOR,
            slots: Slots::default(),
            udp_slots: slots(),
            names: RefCell::default(),
            tls: crate::ca::tests::tls(name).0,
            mail: "mail.web1".into(),
            ssh: crate::ssh::tests::ssh(name),
            ssh_slots: crate::ssh::slots(),
        }
    }

    fn cli(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), port)
    }

    fn at(ip: Ipv4Addr) -> SocketAddrV4 {
        SocketAddrV4::new(ip, 2553)
    }

    /// Every filed session for `ip`, oldest first.
    fn filed(spool: &Path, ip: Ipv4Addr) -> Vec<honeypot::Session> {
        let Ok(d) = std::fs::read_dir(spool.join(ip.to_string()).join("done")) else {
            return Vec::new();
        };
        let mut v: Vec<honeypot::Session> = d
            .map(|e| {
                let p = e.unwrap().path().join("session.json");
                serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
            })
            .collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    #[test]
    fn queries_from_one_port_within_the_window_are_one_session() {
        let srv = server("ugroup", 10_000, Duration::from_secs(300));
        let mut g = Groups::default();
        let t0 = Instant::now();
        let q = query(1, "c2.example.", A);
        assert!(g.datagram(&srv, &q, cli(4000), at(INCIDENT), t0).is_some());
        let q2 = query(2, "c2.example.", AAAA);
        let s4 = Duration::from_secs(4);
        assert!(g
            .datagram(&srv, &q2, cli(4000), at(INCIDENT), t0 + s4)
            .is_some());
        assert_eq!(g.next(srv.max_time), Some(t0 + s4 + GROUP));
        g.expire(t0 + s4 + GROUP - Duration::from_millis(1), srv.max_time);
        assert!(filed(&srv.spool, INCIDENT).is_empty(), "filed while live");
        g.expire(t0 + s4 + GROUP, srv.max_time);
        assert_eq!(g.next(srv.max_time), None);

        let s = filed(&srv.spool, INCIDENT);
        assert_eq!(s.len(), 1);
        let s = &s[0];
        assert_eq!(s.protocol, Protocol::Dns);
        assert_eq!((s.addr, s.src, s.dst), (INCIDENT, cli(4000), at(INCIDENT)));
        let asked: Vec<_> = s
            .queries
            .iter()
            .map(|q| (q.qtype.as_str(), q.answer))
            .collect();
        assert_eq!(
            asked,
            [("A", Some(Ipv4Addr::new(198, 18, 0, 1))), ("AAAA", None)]
        );
        assert!(!s.truncated && !s.timed_out);
        let done = srv.spool.join("127.77.0.1/done").join(&s.id);
        let pkts = crate::pcap::tests::read(&std::fs::read(done.join("stream.pcap")).unwrap());
        assert_eq!(pkts.len(), 4);
        assert_eq!(pkts[0].data, q);
        assert_eq!(pkts[1].src, at(INCIDENT));
        assert_eq!(s.bytes_in, (q.len() + q2.len()) as u64);
        std::fs::remove_dir_all(&srv.spool).unwrap();
    }

    #[test]
    fn another_port_or_a_pause_starts_another_session() {
        let srv = server("usplit", 10_000, Duration::from_secs(300));
        let mut g = Groups::default();
        let t0 = Instant::now();
        let q = query(1, "a.example.", A);
        g.datagram(&srv, &q, cli(4000), at(INCIDENT), t0);
        g.datagram(&srv, &q, cli(4001), at(INCIDENT), t0);
        g.expire(t0 + GROUP, srv.max_time);
        g.datagram(&srv, &q, cli(4000), at(INCIDENT), t0 + GROUP);
        g.expire(t0 + GROUP * 2, srv.max_time);
        assert_eq!(srv.udp_slots.open(), 0, "a filed session kept its place");
        let s = filed(&srv.spool, INCIDENT);
        assert_eq!(s.len(), 3);
        assert!(s.iter().all(|s| s.queries.len() == 1));
        std::fs::remove_dir_all(&srv.spool).unwrap();
    }

    #[test]
    fn the_time_cap_ends_a_session_that_never_goes_quiet() {
        let srv = server("utime", 10_000, Duration::from_secs(10));
        let mut g = Groups::default();
        let t0 = Instant::now();
        let q = query(1, "a.example.", A);
        for i in 0..3 {
            g.datagram(
                &srv,
                &q,
                cli(4000),
                at(INCIDENT),
                t0 + Duration::from_secs(4 * i),
            );
        }
        assert_eq!(g.next(srv.max_time), Some(t0 + srv.max_time));
        g.expire(t0 + srv.max_time, srv.max_time);
        let s = filed(&srv.spool, INCIDENT);
        assert_eq!(s.len(), 1);
        assert!(s[0].timed_out);
        assert_eq!(s[0].queries.len(), 3);
        std::fs::remove_dir_all(&srv.spool).unwrap();
    }

    #[test]
    fn the_byte_cap_files_the_session_at_once() {
        let q = query(1, "a.example.", A);
        // Room for the query, not for its reply.
        let cap = q.len() as u64 + 2 * crate::pcap::DATAGRAM_COST;
        let srv = server("ucap", cap, Duration::from_secs(300));
        let mut g = Groups::default();
        let t0 = Instant::now();
        // Answered all the same.
        assert!(g.datagram(&srv, &q, cli(4000), at(INCIDENT), t0).is_some());
        assert_eq!(g.next(srv.max_time), None);
        assert_eq!(srv.udp_slots.open(), 0, "a filed session kept its place");
        let s = filed(&srv.spool, INCIDENT);
        assert_eq!(s.len(), 1);
        assert!(s[0].truncated);
        assert_eq!((s[0].bytes_in, s[0].bytes_out), (q.len() as u64, 0));
        std::fs::remove_dir_all(&srv.spool).unwrap();
    }

    #[test]
    fn a_non_incident_address_gets_no_answer_and_no_session() {
        let srv = server("ulocal", 10_000, Duration::from_secs(300));
        let mut g = Groups::default();
        let q = query(1, "a.example.", A);
        let local = at(Ipv4Addr::LOCALHOST);
        assert_eq!(g.datagram(&srv, &q, cli(4000), local, Instant::now()), None);
        assert_eq!(g.next(srv.max_time), None);
        assert_eq!(std::fs::read_dir(&srv.spool).unwrap().count(), 0);
        assert_eq!(
            srv.names
                .borrow()
                .name_of(Ipv4Addr::LOCALHOST, Ipv4Addr::new(198, 18, 0, 1)),
            None
        );
        std::fs::remove_dir_all(&srv.spool).unwrap();
    }

    #[test]
    fn a_full_address_is_answered_but_not_recorded() {
        let srv = server("ufull", 10_000, Duration::from_secs(300));
        let _held: Vec<_> = std::iter::from_fn(|| srv.udp_slots.take(INCIDENT)).collect();
        let mut g = Groups::default();
        let q = query(1, "a.example.", A);
        assert!(g
            .datagram(&srv, &q, cli(4000), at(INCIDENT), Instant::now())
            .is_some());
        assert_eq!(g.next(srv.max_time), None);
        assert_eq!(std::fs::read_dir(&srv.spool).unwrap().count(), 0);
        std::fs::remove_dir_all(&srv.spool).unwrap();
    }

    /// The reply's answers, or its response code when it has none.
    fn answers(reply: &[u8]) -> Result<Vec<Ipv4Addr>, u8> {
        let r = wire::read(reply);
        if r.rcode() != 0 {
            return Err(r.rcode());
        }
        Ok(r.a)
    }

    #[tokio::test]
    async fn over_loopback_the_reply_comes_from_the_address_asked() {
        let srv = Rc::new(server("usock", 10_000, Duration::from_secs(300)));
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        pktinfo(sock.as_raw_fd()).unwrap();
        sock.set_nonblocking(true).unwrap();
        let port = sock.local_addr().unwrap().port();
        let sock = UdpSocket::from_std(sock).unwrap();
        // 127.0.0.1 and not the incident address, so a reply sent without
        // PKTINFO would come from 127.0.0.1.
        if let Err(e) = std::net::UdpSocket::bind((INCIDENT, 0)) {
            eprintln!("skipped: {INCIDENT} isn't local here: {e}");
            return;
        }
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let to = SocketAddrV4::new(INCIDENT, port);
        let ask = |msg: Vec<u8>, to: SocketAddrV4| {
            let c = &c;
            async move {
                c.send_to(&msg, to).await.unwrap();
                let mut buf = [0u8; 1024];
                let (n, from) =
                    tokio::time::timeout(Duration::from_millis(500), c.recv_from(&mut buf))
                        .await
                        .ok()?
                        .unwrap();
                Some((buf[..n].to_vec(), from))
            }
        };
        let client = async {
            let (r1, from) = ask(query(1, "c2.example.", A), to).await.unwrap();
            assert_eq!(from, to.into(), "the reply came from the wrong address");
            let (r2, _) = ask(query(2, "C2.EXAMPLE.", A), to).await.unwrap();
            let (r3, _) = ask(query(3, "other.example.", A), to).await.unwrap();
            assert_eq!(answers(&r1), Ok(vec![Ipv4Addr::new(198, 18, 0, 1)]));
            assert_eq!(answers(&r1), answers(&r2));
            assert_eq!(answers(&r3), Ok(vec![Ipv4Addr::new(198, 18, 0, 2)]));
            let (r, _) = ask(query(4, "c2.example.", AAAA), to).await.unwrap();
            assert_eq!(answers(&r), Ok(vec![]));
            let (r, _) = ask(vec![0xab, 0xcd, 0, 0, 0], to).await.unwrap();
            assert_eq!(answers(&r), Err(1));
            let lo = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
            assert!(
                ask(query(5, "c2.example.", A), lo).await.is_none(),
                "answered on 127.0.0.1"
            );
        };
        tokio::task::LocalSet::new()
            .run_until(async {
                tokio::select! {
                    () = serve(srv.clone(), sock) => unreachable!(),
                    () = client => {}
                }
            })
            .await;
        assert!(!srv.spool.join("127.0.0.1").exists());
        std::fs::remove_dir_all(&srv.spool).unwrap();
    }

    #[test]
    fn a_socket_without_pktinfo_gives_no_local_address() {
        let srv = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let c = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        c.send_to(b"x", srv.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 4];
        assert!(matches!(recv(srv.as_raw_fd(), &mut buf), Ok(None)));
        // With it, the same datagram says where it went.
        pktinfo(srv.as_raw_fd()).unwrap();
        c.send_to(b"y", srv.local_addr().unwrap()).unwrap();
        let (n, from, local) = recv(srv.as_raw_fd(), &mut buf).unwrap().unwrap();
        assert_eq!((n, &buf[..1], local), (1, &b"y"[..], Ipv4Addr::LOCALHOST));
        assert_eq!(std::net::SocketAddr::from(from), c.local_addr().unwrap());
    }
}
