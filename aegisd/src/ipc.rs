// SPDX-License-Identifier: MIT OR Apache-2.0
//! The control socket. See `aegis_proto` for the wire format.
//!
//! Connection tasks only parse and frame. Each request goes to the main
//! loop over a channel and is answered there, so the daemon's state has
//! one owner.

use std::fs::File;
use std::io::ErrorKind;
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

/// An idle client is dropped after this long, as is one that stops
/// reading its replies.
const IDLE: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 16;

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
pub async fn serve(listener: UnixListener, calls: mpsc::Sender<Call>, allowed_uid: u32) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
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
        tokio::spawn(async move {
            let _slot = slot;
            let _ = connection(s, calls, allowed_uid).await;
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

async fn connection(
    mut s: UnixStream,
    calls: mpsc::Sender<Call>,
    allowed_uid: u32,
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
            telemetry_dropped: TelemetryDropped::default(),
        }
    }

    /// Serves `path` for peers with `uid`, answering every call with
    /// `status()`. The lock moves into the server task so it is held for
    /// the test, as the daemon holds it for its life.
    fn start(path: &Path, uid: u32) {
        let (l, lock) = bind(path).unwrap();
        let (tx, mut rx) = mpsc::channel::<Call>(4);
        tokio::spawn(async move {
            let _lock = lock;
            serve(l, tx, uid).await;
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
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        drop(std::os::unix::net::UnixListener::bind(&p).unwrap());
        assert!(p.exists());
        start(&p, me());
        assert!(UnixStream::connect(&p).await.is_ok());
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
}
