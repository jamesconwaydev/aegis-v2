// SPDX-License-Identifier: MIT OR Apache-2.0
//! The control socket. See `aegis_proto` for the wire format.
//!
//! Connection tasks only parse and frame. Each request goes to the main
//! loop over a channel and is answered there, so the daemon's state has
//! one owner. `IncidentPcap` is the exception: it reads only an
//! incident's files, and its answer is a stream the connection writes
//! itself, so a `Streamer` answers it there.

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aegis_proto::{Request, Response, MAX_REQUEST};
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::timeout;

pub type Call = (Request, oneshot::Sender<Response>);

/// Answers `IncidentPcap`, whose reply is a byte stream: the reply line,
/// and the bytes that follow it with their count. Runs on a blocking
/// thread, as does reading the bytes.
pub type Streamer = Arc<dyn Fn(Request) -> (Response, Option<Body>) + Send + Sync>;

/// The bytes after a reply line, and how many there are.
pub type Body = (u64, Box<dyn Read + Send>);

/// An idle client is dropped after this long, as is one that stops
/// reading its replies.
const IDLE: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 16;
/// Pcap exports at once: each holds an index of up to about 24 MiB.
const MAX_EXPORTS: usize = 2;

/// Binds `path`, mode 0600, holding a lock that keeps a second aegisd
/// out. The returned `File` owns that lock: keep it for the daemon's
/// life, and dropping it releases the lock. Any existing socket is stale
/// once we hold the lock, so it's unlinked; a non-socket at the path is
/// an error rather than something to clobber.
pub fn bind(path: &Path) -> Result<(UnixListener, File)> {
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    if let Some(dir) = path.parent() {
        check_private_dir(dir)?;
    }
    let lock_path = path.with_file_name("aegisd.lock");
    // No truncate, and no following a symlink planted at the path.
    // std opens with O_CLOEXEC already.
    let lock = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .with_context(|| format!("opening {}", lock_path.display()))?;
    // SAFETY: flock on a valid fd; LOCK_NB makes it return instead of block.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!(
            "another aegisd is running (lock held on {})",
            lock_path.display()
        );
    }
    match std::fs::symlink_metadata(path) {
        Ok(md) if !md.file_type().is_socket() => {
            bail!("{} exists and is not a socket", path.display())
        }
        Ok(_) => std::fs::remove_file(path)
            .with_context(|| format!("removing stale {}", path.display()))?,
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("checking {}", path.display())),
    }
    let l = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    // Between bind and here the socket has the umask's mode. That's
    // harmless: every peer is checked by uid before it is served.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok((l, lock))
}

/// The socket's directory must belong to us (root, for the daemon) and
/// be writable by no one else; otherwise another user could swap the
/// lock file or the socket under us. Checked on the opened directory,
/// not the path, and without following a symlink.
fn check_private_dir(dir: &Path) -> Result<()> {
    let d = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .with_context(|| format!("opening {}", dir.display()))?;
    let md = d.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    if md.uid() != me || md.mode() & 0o022 != 0 {
        bail!(
            "{} must be owned by uid {me} and not group or world writable \
             (uid {}, mode {:o})",
            dir.display(),
            md.uid(),
            md.mode() & 0o7777
        );
    }
    Ok(())
}

/// Serves until the listener fails. Only peers with uid `allowed_uid`
/// are answered (aegisd passes 0).
pub async fn serve(
    listener: UnixListener,
    calls: mpsc::Sender<Call>,
    allowed_uid: u32,
    streams: Streamer,
) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let exports = Arc::new(Semaphore::new(MAX_EXPORTS));
    loop {
        let mut s = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                eprintln!("aegisd: control socket accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            tokio::spawn(async move { reply(&mut s, &err("too many connections")).await });
            continue;
        };
        let calls = calls.clone();
        let streams = streams.clone();
        let exports = exports.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let _ = connection(s, calls, allowed_uid, streams, exports).await;
        });
    }
}

fn err(msg: &str) -> Response {
    Response::Error(msg.into())
}

async fn reply(w: &mut (impl AsyncWrite + Unpin), r: &Response) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(r).map_err(std::io::Error::other)?;
    line.push(b'\n');
    match timeout(IDLE, w.write_all(&line)).await {
        Ok(r) => r,
        Err(_) => Err(ErrorKind::TimedOut.into()),
    }
}

/// Sends exactly `n` bytes of `r`, each write within `IDLE`. An error,
/// or `r` ending early, is an error: the client then sees the stream
/// stop short of what the reply line promised.
async fn pump(
    w: &mut (impl AsyncWrite + Unpin),
    n: u64,
    r: Box<dyn Read + Send>,
) -> std::io::Result<()> {
    let (tx, mut rx) = mpsc::channel::<std::io::Result<Vec<u8>>>(2);
    tokio::task::spawn_blocking(move || {
        let mut r = r.take(n);
        loop {
            let mut buf = vec![0u8; 64 * 1024];
            let got = match r.read(&mut buf) {
                Ok(0) => return,
                Ok(k) => {
                    buf.truncate(k);
                    Ok(buf)
                }
                Err(e) => Err(e),
            };
            let failed = got.is_err();
            // The client went away, or the read failed: stop reading.
            if tx.blocking_send(got).is_err() || failed {
                return;
            }
        }
    });
    let mut sent = 0u64;
    while let Some(chunk) = rx.recv().await {
        let chunk = chunk?;
        match timeout(IDLE, w.write_all(&chunk)).await {
            Ok(r) => r?,
            Err(_) => return Err(ErrorKind::TimedOut.into()),
        }
        sent += chunk.len() as u64;
    }
    if sent == n {
        Ok(())
    } else {
        Err(ErrorKind::UnexpectedEof.into())
    }
}

async fn connection(
    mut s: UnixStream,
    calls: mpsc::Sender<Call>,
    allowed_uid: u32,
    streams: Streamer,
    exports: Arc<Semaphore>,
) -> std::io::Result<()> {
    if s.peer_cred()?.uid() != allowed_uid {
        return reply(&mut s, &err("permission denied")).await;
    }
    let (rd, mut wr) = s.split();
    let mut rd = BufReader::new(rd);
    let mut line = Vec::new();
    loop {
        line.clear();
        // Read one byte past the limit (plus room for the newline), so a
        // request of exactly MAX_REQUEST still fits and anything longer is
        // caught whether or not its newline arrived.
        let mut capped = (&mut rd).take(MAX_REQUEST as u64 + 2);
        let n = match timeout(IDLE, capped.read_until(b'\n', &mut line)).await {
            Ok(r) => r?,
            Err(_) => return Ok(()),
        };
        if n == 0 {
            return Ok(());
        }
        let had_newline = line.last() == Some(&b'\n');
        if had_newline {
            line.pop();
        }
        // Checked after stripping the newline, so MAX_REQUEST exactly is
        // fine and MAX_REQUEST + 1 is rejected even with its newline read.
        if line.len() > MAX_REQUEST {
            return reply(&mut wr, &err("request too long")).await;
        }
        let resp = match serde_json::from_slice::<Request>(&line) {
            Ok(req @ Request::IncidentPcap { .. }) => {
                // Held from the index the opener builds to the last byte.
                let Ok(_export) = exports.clone().try_acquire_owned() else {
                    let busy = format!("busy: {MAX_EXPORTS} pcap exports are running; try again");
                    reply(&mut wr, &err(&busy)).await?;
                    continue;
                };
                let f = streams.clone();
                let (resp, body) = tokio::task::spawn_blocking(move || f(req))
                    .await
                    .unwrap_or_else(|_| (err("internal: the export failed"), None));
                reply(&mut wr, &resp).await?;
                if let Some((n, r)) = body {
                    pump(&mut wr, n, r).await?;
                }
                continue;
            }
            Ok(req) => {
                let (tx, rx) = oneshot::channel();
                if calls.send((req, tx)).await.is_err() {
                    return Ok(());
                }
                rx.await.unwrap_or_else(|_| err("daemon shutting down"))
            }
            Err(e) => err(&format!("bad request: {e}")),
        };
        reply(&mut wr, &resp).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::{ProbeStatus, TelemetryDropped};
    use tokio::io::AsyncBufReadExt;

    /// A socket in its own directory, so each test gets its own lock
    /// file (`bind` locks `aegisd.lock` beside the socket).
    fn sock(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("aegis-ipc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d.join("aegisd.sock")
    }

    fn status() -> Response {
        Response::Status {
            version: "0.1.0".into(),
            mode: "audit".into(),
            uptime_s: 5,
            events_total: 42,
            dropped_events: 1,
            probes: vec![ProbeStatus {
                name: "aegis_exec".into(),
                hook: "lsm/bprm_committed_creds".into(),
            }],
            incidents_open: 0,
            incident_errors: 0,
            incident_dropped: 0,
            verify_skipped: 0,
            deferred_overflow: 0,
            incident_suppressed: 0,
            enforce_dropped: 0,
            network: "drop".into(),
            incidents_observing: 0,
            telemetry_dropped: TelemetryDropped::default(),
        }
    }

    /// Serves `path` for peers with `uid`, answering every call with
    /// `status()`. The lock moves into the server task so it is held for
    /// the test, as the daemon holds it for its life.
    fn start(path: &Path, uid: u32) {
        start_streaming(path, uid, Arc::new(|_| (err("no streams here"), None)));
    }

    fn start_streaming(path: &Path, uid: u32, streams: Streamer) {
        let (l, lock) = bind(path).unwrap();
        let (tx, mut rx) = mpsc::channel::<Call>(4);
        tokio::spawn(async move {
            let _lock = lock;
            serve(l, tx, uid, streams).await;
        });
        tokio::spawn(async move {
            while let Some((_, reply)) = rx.recv().await {
                let _ = reply.send(status());
            }
        });
    }

    async fn lines(s: UnixStream) -> tokio::io::Lines<BufReader<UnixStream>> {
        BufReader::new(s).lines()
    }

    fn me() -> u32 {
        // SAFETY: getuid has no preconditions.
        unsafe { libc::getuid() }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ipc_rejects_non_root_peer() {
        let p = sock("deny");
        // Only some other uid is allowed, so we are the non-root peer
        // even when the tests run as root.
        start(&p, me().wrapping_add(1));
        let mut s = UnixStream::connect(&p).await.unwrap();
        s.write_all(b"\"Status\"\n").await.unwrap();
        let mut l = lines(s).await;
        assert_eq!(
            l.next_line().await.unwrap().as_deref(),
            Some(r#"{"error":"permission denied"}"#)
        );
        // Closed after: EOF, or a reset since our request went unread.
        assert!(!matches!(l.next_line().await, Ok(Some(_))));
        let _ = std::fs::remove_file(&p);
    }

    #[tokio::test]
    async fn ipc_status_roundtrip() {
        let p = sock("ok");
        start(&p, me());
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let mut s = UnixStream::connect(&p).await.unwrap();
        // Two requests on one connection, one in the {"Status":null} form.
        s.write_all(b"\"Status\"\n{\"Status\":null}\nnope\n")
            .await
            .unwrap();
        let mut l = lines(s).await;
        for _ in 0..2 {
            let r: Response = serde_json::from_str(&l.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(r, status());
        }
        let bad = l.next_line().await.unwrap().unwrap();
        assert!(bad.starts_with(r#"{"error":"bad request"#), "{bad}");
        let _ = std::fs::remove_file(&p);
    }

    #[tokio::test]
    async fn ipc_refuses_long_line_and_live_socket() {
        let p = sock("long");
        start(&p, me());
        // A second daemon on the same lock must not start.
        assert!(bind(&p).is_err());
        // One byte over the limit, with its newline, is still refused.
        let mut s = UnixStream::connect(&p).await.unwrap();
        let mut over = vec![b' '; MAX_REQUEST + 1];
        over.push(b'\n');
        s.write_all(&over).await.unwrap();
        let mut l = lines(s).await;
        assert_eq!(
            l.next_line().await.unwrap().as_deref(),
            Some(r#"{"error":"request too long"}"#)
        );
        assert!(!matches!(l.next_line().await, Ok(Some(_))));
        // A request of exactly the limit is fine.
        let mut s = UnixStream::connect(&p).await.unwrap();
        let mut req = vec![b' '; MAX_REQUEST - 8];
        req.extend_from_slice(b"\"Status\"\n");
        assert_eq!(req.len() - 1, MAX_REQUEST);
        s.write_all(&req).await.unwrap();
        let mut l = lines(s).await;
        let r: Response = serde_json::from_str(&l.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(r, status());
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn ipc_refuses_a_world_writable_socket_dir() {
        let p = sock("wdir");
        let d = p.parent().unwrap();
        std::fs::create_dir_all(d).unwrap();
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = bind(&p).unwrap_err().to_string();
        assert!(e.contains("not group or world writable"), "{e}");
        // A symlink planted where the lock goes is not followed.
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.join("aegisd.lock")).unwrap();
        assert!(bind(&p).is_err());
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn ipc_replaces_stale_socket() {
        let p = sock("stale");
        let d = p.parent().unwrap();
        std::fs::create_dir_all(d).unwrap();
        // The incident tests set umask 0 while they run, so don't trust
        // the mode create_dir_all gave us.
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(std::os::unix::net::UnixListener::bind(&p).unwrap());
        assert!(p.exists());
        start(&p, me());
        assert!(UnixStream::connect(&p).await.is_ok());
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// Yields `n` bytes of 7, then fails if `fail`.
    struct Sevens(u64, bool);
    impl std::io::Read for Sevens {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return if self.1 {
                    Err(ErrorKind::Other.into())
                } else {
                    Ok(0)
                };
            }
            let k = b.len().min(self.0 as usize);
            b[..k].fill(7);
            self.0 -= k as u64;
            Ok(k)
        }
    }

    #[tokio::test]
    async fn ipc_streams_a_pcap_then_serves_the_next_request() {
        let p = sock("stream");
        const N: u64 = 300_000;
        start_streaming(
            &p,
            me(),
            Arc::new(|req| match req {
                Request::IncidentPcap { id } if id == "good" => (
                    Response::Pcap {
                        bytes: N,
                        sessions: 1,
                        left_out: 0,
                        notes: vec![],
                    },
                    Some((
                        N,
                        Box::new(Sevens(N, false)) as Box<dyn std::io::Read + Send>,
                    )),
                ),
                // Fails partway: the client must see the stream end short.
                _ => (
                    Response::Pcap {
                        bytes: N,
                        sessions: 1,
                        left_out: 0,
                        notes: vec![],
                    },
                    Some((
                        N,
                        Box::new(Sevens(1000, true)) as Box<dyn std::io::Read + Send>,
                    )),
                ),
            }),
        );
        let mut s = UnixStream::connect(&p).await.unwrap();
        s.write_all(b"{\"IncidentPcap\":{\"id\":\"good\"}}\n\"Status\"\n")
            .await
            .unwrap();
        let mut r = BufReader::new(s);
        let mut head = String::new();
        r.read_line(&mut head).await.unwrap();
        assert_eq!(
            head,
            "{\"Pcap\":{\"bytes\":300000,\"sessions\":1,\"left_out\":0,\"notes\":[]}}\n"
        );
        let mut body = vec![0u8; N as usize];
        r.read_exact(&mut body).await.unwrap();
        assert!(body.iter().all(|&b| b == 7));
        let mut next = String::new();
        r.read_line(&mut next).await.unwrap();
        assert_eq!(serde_json::from_str::<Response>(&next).unwrap(), status());

        let mut s = UnixStream::connect(&p).await.unwrap();
        s.write_all(b"{\"IncidentPcap\":{\"id\":\"bad\"}}\n")
            .await
            .unwrap();
        let mut r = BufReader::new(s);
        let mut head = String::new();
        r.read_line(&mut head).await.unwrap();
        let mut rest = Vec::new();
        let _ = r.read_to_end(&mut rest).await;
        assert_eq!(rest.len(), 1000);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    use std::sync::atomic::AtomicBool;
    static GATE: AtomicBool = AtomicBool::new(false);
    static GATE2: AtomicBool = AtomicBool::new(false);

    /// `n` bytes of 7, once its gate opens.
    struct Gated(u64, &'static AtomicBool);
    impl std::io::Read for Gated {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            while !self.1.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Sevens(self.0, false)
                .read(b)
                .inspect(|k| self.0 -= *k as u64)
        }
    }

    #[tokio::test]
    async fn ipc_runs_two_pcap_exports_at_once_and_refuses_a_third() {
        let p = sock("busy");
        start_streaming(
            &p,
            me(),
            Arc::new(|_| {
                let head = Response::Pcap {
                    bytes: 10,
                    sessions: 1,
                    left_out: 0,
                    notes: vec![],
                };
                (
                    head,
                    Some((
                        10,
                        Box::new(Gated(10, &GATE)) as Box<dyn std::io::Read + Send>,
                    )),
                )
            }),
        );
        let ask = || async {
            let mut s = UnixStream::connect(&p).await.unwrap();
            s.write_all(b"{\"IncidentPcap\":{\"id\":\"x\"}}\n\"Status\"\n")
                .await
                .unwrap();
            let mut r = BufReader::new(s);
            let mut head = String::new();
            r.read_line(&mut head).await.unwrap();
            (r, head)
        };
        let (mut a, ha) = ask().await;
        let (mut b, hb) = ask().await;
        let (_, hc) = ask().await;
        // Open before asserting: a gated reader left waiting would hang
        // the runtime's shutdown.
        GATE.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            ha.starts_with("{\"Pcap\"") && hb.starts_with("{\"Pcap\""),
            "{ha}{hb}"
        );
        assert!(hc.starts_with("{\"error\":\"busy"), "{hc}");
        for r in [&mut a, &mut b] {
            let mut body = [0u8; 10];
            r.read_exact(&mut body).await.unwrap();
            // The next reply comes once the export is over.
            let mut next = String::new();
            r.read_line(&mut next).await.unwrap();
            assert!(next.starts_with("{\"Status\""), "{next}");
        }
        let (_, hd) = ask().await;
        assert!(hd.starts_with("{\"Pcap\""), "{hd}");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[tokio::test]
    async fn an_export_slot_comes_back_after_an_error_or_a_hang_up() {
        let p = sock("slots");
        start_streaming(
            &p,
            me(),
            Arc::new(|req| {
                let Request::IncidentPcap { id } = req else {
                    unreachable!()
                };
                let (n, r): (u64, Box<dyn std::io::Read + Send>) = match id.as_str() {
                    "err" => return (err("nothing to export"), None),
                    "big" => (64 << 20, Box::new(Sevens(64 << 20, false))),
                    "small" => (10, Box::new(Sevens(10, false))),
                    _ => (10, Box::new(Gated(10, &GATE2))),
                };
                let head = Response::Pcap {
                    bytes: n,
                    sessions: 1,
                    left_out: 0,
                    notes: vec![],
                };
                (head, Some((n, r)))
            }),
        );
        let ask = |id: &'static str| {
            let p = p.clone();
            async move {
                let mut s = UnixStream::connect(&p).await.unwrap();
                let req = format!("{{\"IncidentPcap\":{{\"id\":\"{id}\"}}}}\n");
                s.write_all(req.as_bytes()).await.unwrap();
                let mut r = BufReader::new(s);
                let mut head = String::new();
                r.read_line(&mut head).await.unwrap();
                (r, head)
            }
        };
        for _ in 0..3 {
            assert!(ask("err").await.1.contains("nothing to export"));
        }
        // Gone mid-stream: the server's next write fails.
        for _ in 0..3 {
            let (r, head) = ask("big").await;
            assert!(head.starts_with("{\"Pcap\""), "{head}");
            drop(r);
        }
        // Each hung-up export ends when its write fails; wait for that.
        let mut free = false;
        for _ in 0..200 {
            if ask("small").await.1.starts_with("{\"Pcap\"") {
                free = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Both slots: two exports held open at once.
        let (_a, ha) = ask("gated").await;
        let (_b, hb) = ask("gated").await;
        GATE2.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(free);
        assert!(
            ha.starts_with("{\"Pcap\"") && hb.starts_with("{\"Pcap\""),
            "{ha}{hb}"
        );
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
}
