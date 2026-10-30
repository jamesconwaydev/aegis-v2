// SPDX-License-Identifier: MIT OR Apache-2.0
//! SSH: any login gets in after a moment, to a shell that answers like
//! a fresh Rocky box, and scp or sftp take any file sent up. Every
//! login, command and file is recorded; the pcap holds the ciphertext.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::Shutdown;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{ready, Context as TaskContext, Poll};
use std::time::Duration;

use aegis_proto::honeypot::{Credential, Upload};
use anyhow::{bail, Context, Result};
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use russh::server::{self, Auth, Msg, PublicKeyOffer, VerifiedPublicKey};
use russh::{kex, Channel, ChannelId, MethodKind, MethodSet, Preferred, SshId};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{error::Elapsed, timeout, timeout_at};

use crate::ca;
use crate::hello;
use crate::session::{random, Held, Session, Slots, MAX_HELD};
use crate::shell::{self, Host};
use crate::upload::{Event, Scp, Sftp};

/// Where the host key lives, in the state directory.
const HOST_KEY: &str = "ssh_host_ed25519_key";
/// What Rocky 10's sshd says first.
const BANNER: &str = "SSH-2.0-OpenSSH_9.9";
/// Logins one connection may try, as sshd's MaxAuthTries. Past it the
/// connection closes, so a brute forcer can't hold a slot.
const MAX_TRIES: usize = 6;
/// Channels open at once on one connection.
const MAX_CHANNELS: usize = 4;
/// The longest line typed or run that's kept; the rest is dropped.
const MAX_LINE: usize = 4096;
/// The most of a user name, password or command recorded.
const MAX_FIELD: usize = 256;
const MAX_COMMAND: usize = 1024;
/// The most of an uploaded file's name recorded.
const MAX_NAME: usize = 255;

/// How long russh's task gets to end once its socket is shut, so its
/// handler can file a half-sent upload before the session closes.
const GRACE: Duration = Duration::from_secs(2);

/// Open SSH sessions per incident address, and in all, within TCP's
/// own caps. An SSH session can hold a few hundred KiB (russh's 256 KiB
/// packet buffer, one held upload), so fewer of them may be open at
/// once than other connections.
pub fn slots() -> Slots {
    Slots::new(8, 64)
}

/// The session, shared by the socket wrapper and the handler russh
/// runs on a task of its own. Taken back when the connection ends;
/// whatever russh still does after that records nothing.
type Shared = Arc<Mutex<Option<Session>>>;

fn lock(sh: &Shared) -> MutexGuard<'_, Option<Session>> {
    sh.lock().unwrap_or_else(PoisonError::into_inner)
}

fn with<T>(sh: &Shared, f: impl FnOnce(&mut Session) -> io::Result<T>) -> io::Result<T> {
    match lock(sh).as_mut() {
        Some(s) => f(s),
        None => Err(ErrorKind::BrokenPipe.into()),
    }
}

/// The host key: made on first start, kept after. One that won't parse
/// is never replaced; the start fails until an operator moves it.
fn host_key(dir: &Path) -> Result<PrivateKey> {
    let path = dir.join(HOST_KEY);
    let _lock = ca::lock(dir)?;
    // A start that died part-way may have left a tmp copy of the key.
    ca::remove(&ca::tmp(&path)).with_context(|| ca::tmp(&path).display().to_string())?;
    match std::fs::read(&path) {
        Ok(b) => PrivateKey::from_openssh(&b)
            .ok()
            .filter(|k| k.algorithm() == Algorithm::Ed25519 && !k.is_encrypted())
            .with_context(|| {
                format!(
                    "{} is not an unencrypted ed25519 key; move it aside to make a new one",
                    path.display()
                )
            }),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            random(&mut seed).context("no randomness for the host key")?;
            let key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
            let pem = key.to_openssh(LineEnding::LF)?;
            let file = |e: io::Error| anyhow::anyhow!("{}: {e}", path.display());
            ca::create_once(&path, 0o400, &pem).map_err(file)?;
            ca::sync_dir(dir).map_err(file)?;
            Ok(key)
        }
        Err(e) => bail!("{}: {e}", path.display()),
    }
}

pub struct Ssh {
    config: Arc<server::Config>,
    host: Arc<Host>,
}

impl Ssh {
    /// The server, with the host key in `dir`.
    pub fn load(dir: &Path, host: Host) -> Result<Self> {
        let config = server::Config {
            server_id: SshId::Standard(BANNER.into()),
            methods: MethodSet::from(&[MethodKind::Password, MethodKind::PublicKey][..]),
            // Every attempt waits in `login` instead.
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key(dir)?],
            max_auth_attempts: MAX_TRIES,
            // Every client has curve25519. The finite-field groups cost
            // an 8192-bit modexp each, on the one thread every session
            // shares, and a client can ask for one again at any time.
            preferred: Preferred {
                kex: Cow::Borrowed(&[
                    kex::MLKEM768X25519_SHA256,
                    kex::CURVE25519,
                    kex::CURVE25519_PRE_RFC_8731,
                    kex::EXTENSION_SUPPORT_AS_SERVER,
                    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
                ]),
                ..Preferred::default()
            },
            // The session's own time cap ends it.
            inactivity_timeout: None,
            ..Default::default()
        };
        Ok(Self {
            config: Arc::new(config),
            host: Arc::new(host),
        })
    }

    /// Runs one connection under `max_time`, and hands the session back.
    pub async fn serve(
        &self,
        s: Session,
        io: TcpStream,
        max_time: Duration,
    ) -> (Session, Result<Result<()>, Elapsed>) {
        let addr = s.rec.addr;
        let sh: Shared = Arc::new(Mutex::new(Some(s)));
        let r = match dup(io) {
            Ok((peer, io)) => {
                let wire = Wire {
                    io,
                    s: sh.clone(),
                    full: false,
                };
                let client = Client {
                    s: sh.clone(),
                    host: self.host.clone(),
                    tries: 0,
                    chans: HashMap::new(),
                };
                let end = tokio::time::Instant::now() + max_time;
                let started =
                    timeout_at(end, server::run_stream(self.config.clone(), wire, client)).await;
                let r = match started {
                    Ok(Ok(mut running)) => {
                        let r = timeout_at(end, &mut running).await;
                        // russh runs the connection on a task of its own,
                        // which dropping its future doesn't stop; this
                        // wakes it to an error wherever it waits, and
                        // the wait lets its handler file what it holds.
                        let _ = peer.shutdown(Shutdown::Both);
                        if r.is_err() && timeout(GRACE, running).await.is_err() {
                            // Its fd stays open past the slot until it ends.
                            eprintln!(
                                "aegis-honeypot: an SSH session for {addr} is still running \
                                 {}s after its socket was shut",
                                GRACE.as_secs()
                            );
                        }
                        r
                    }
                    Ok(Err(e)) => Ok(Err(e)),
                    Err(e) => Err(e),
                };
                let _ = peer.shutdown(Shutdown::Both);
                r
            }
            Err(e) => Ok(Err(e.into())),
        };
        let s = lock(&sh).take().expect("only serve takes the session");
        (s, r)
    }
}

/// A second handle on the socket, to shut it from outside russh.
fn dup(io: TcpStream) -> io::Result<(std::net::TcpStream, TcpStream)> {
    let io = io.into_std()?;
    Ok((io.try_clone()?, TcpStream::from_std(io)?))
}

/// The client's socket, recording every byte either way. Once the byte
/// cap is reached it reads as closed.
struct Wire {
    io: TcpStream,
    s: Shared,
    full: bool,
}

impl AsyncRead for Wire {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.full {
            return Poll::Ready(Ok(()));
        }
        let start = buf.filled().len();
        ready!(Pin::new(&mut me.io).poll_read(cx, buf))?;
        let got = &buf.filled()[start..];
        if !got.is_empty() {
            let (more, kept) = with(&me.s, |s| {
                let before = s.rec.bytes_in;
                let more = s.record(true, got)?;
                Ok((more, s.rec.bytes_in - before))
            })?;
            me.full = !more;
            // What the cap left out isn't recorded, so it isn't acted on.
            buf.set_filled(start + usize::try_from(kept).unwrap_or(0));
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Wire {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let n = ready!(Pin::new(&mut me.io).poll_write(cx, buf))?;
        me.full |= !with(&me.s, |s| s.record(false, &buf[..n]))?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// A file coming up, the start of it held.
struct File {
    name: String,
    held: Held,
    /// Room set aside in the session for `held`.
    room: u64,
    /// Where the next bytes go if they come in order.
    next: u64,
}

#[derive(Default)]
enum Kind {
    #[default]
    Idle,
    Shell,
    Scp(Scp),
    Sftp(Sftp),
}

#[derive(Default)]
struct Chan {
    kind: Kind,
    pty: bool,
    line: Vec<u8>,
    /// The last byte typed was CR, so an LF after it is the same Enter.
    cr: bool,
    file: Option<File>,
    /// Where `cd` has taken the shell.
    cwd: String,
}

struct Client {
    s: Shared,
    host: Arc<Host>,
    tries: usize,
    chans: HashMap<ChannelId, Chan>,
}

/// Sends `out` unless the client has stopped reading what it was sent
/// already: russh would hold it all in memory.
fn send(ss: &mut server::Session, ch: ChannelId, out: Vec<u8>) -> Result<()> {
    if !out.is_empty() && !ss.has_pending_data(ch) {
        ss.data(ch, out)?;
    }
    Ok(())
}

/// Ends a channel the way a command that returned `status` would.
fn exit(ss: &mut server::Session, ch: ChannelId, status: u32) -> Result<()> {
    ss.exit_status_request(ch, status)?;
    ss.eof(ch)?;
    ss.close(ch)?;
    Ok(())
}

/// Keeps a finished (or abandoned) upload as a payload.
fn finish(file: &mut Option<File>, sh: &Shared) -> io::Result<()> {
    let Some(f) = file.take() else {
        return Ok(());
    };
    with(sh, |s| {
        s.release(f.room);
        // Nothing kept of something sent is no payload, not an empty one.
        let payload = if f.held.cut && f.held.data.is_empty() {
            None
        } else {
            s.payload(&f.held.data)?
        };
        s.rec.truncated |= f.held.cut;
        s.upload(Upload {
            name: f.name,
            payload,
        });
        Ok(())
    })
}

/// `busy`: another channel's upload is held already, and one is all a
/// session may hold.
fn on_file(file: &mut Option<File>, sh: &Shared, busy: bool, e: Event<'_>) -> io::Result<()> {
    match e {
        Event::Start(name, size) => {
            finish(file, sh)?;
            // scp says how big the file is: a small one holds only
            // that. The claim bounds the reservation, never allocates.
            let want = match (busy, size) {
                (true, _) => 0,
                (false, Some(n)) => n.min(MAX_HELD as u64),
                (false, None) => MAX_HELD as u64,
            };
            let (name, room) = with(sh, |s| Ok((s.note(name, MAX_NAME), s.hold(want))))?;
            *file = Some(File {
                name,
                room,
                held: Held::new(usize::try_from(room).unwrap_or(0)),
                next: 0,
            });
        }
        Event::Data(at, d) => {
            if let Some(f) = file {
                // Only what comes in order is kept; sftp clients write in
                // order.
                if at == f.next {
                    f.held.keep(d);
                } else {
                    f.held.cut = true;
                }
                f.next = at.saturating_add(d.len() as u64);
            }
        }
        Event::End => finish(file, sh)?,
    }
    Ok(())
}

/// Runs a line, recording each command in it.
fn run(sh: &Shared, host: &Host, cwd: &mut String, line: &[u8]) -> io::Result<shell::Ran> {
    let line = with(sh, |s| Ok(s.note(line, MAX_LINE)))?;
    let mut res = Ok(());
    let ran = shell::run(&line, host, cwd, |cmd: &str| {
        if res.is_ok() {
            res = with(sh, |s| {
                let c = s.note(cmd.as_bytes(), MAX_COMMAND);
                s.command(c);
                Ok(())
            });
        }
    });
    res.map(|()| ran)
}

impl Client {
    /// Any login is let in, after a pause like a real check's.
    async fn login(
        &mut self,
        user: &str,
        password: Option<&str>,
        key: Option<String>,
    ) -> Result<Auth> {
        self.tries += 1;
        if self.tries > MAX_TRIES {
            return Err(russh::Error::Disconnect.into());
        }
        let mut r = [0u8; 2];
        let _ = random(&mut r);
        let ms = 300 + u64::from(u16::from_ne_bytes(r)) % 901;
        tokio::time::sleep(Duration::from_millis(ms)).await;
        with(&self.s, |s| {
            let c = Credential {
                user: s.note(user.as_bytes(), MAX_FIELD),
                password: password.map(|p| s.note(p.as_bytes(), MAX_FIELD)),
                // The algorithm's name is the client's to choose.
                key: key.map(|k| s.note(k.as_bytes(), MAX_FIELD)),
            };
            s.credential(c);
            Ok(())
        })?;
        Ok(Auth::Accept)
    }

    /// Keys typed into the shell: echoed when there's a terminal, run at
    /// Enter.
    fn typed(&mut self, ch: ChannelId, data: &[u8], ss: &mut server::Session) -> Result<()> {
        let Some(c) = self.chans.get_mut(&ch) else {
            return Ok(());
        };
        let host = &self.host;
        let mut out = Vec::new();
        // Each Enter prints, so a flood of them would print far more than
        // it sent; what's past the cap is dropped.
        let put = |out: &mut Vec<u8>, b: &[u8]| {
            if out.len() + b.len() <= shell::MAX_OUT {
                out.extend_from_slice(b);
            }
        };
        for &b in data {
            let after_cr = std::mem::replace(&mut c.cr, b == b'\r');
            match b {
                b'\n' if after_cr => {}
                b'\r' | b'\n' => {
                    if c.pty {
                        put(&mut out, b"\r\n");
                    }
                    let ran = run(&self.s, host, &mut c.cwd, &std::mem::take(&mut c.line))?;
                    if c.pty {
                        put(&mut out, ran.out.replace('\n', "\r\n").as_bytes());
                    } else {
                        put(&mut out, ran.out.as_bytes());
                    }
                    if ran.exit {
                        c.kind = Kind::Idle;
                        send(ss, ch, out)?;
                        return exit(ss, ch, 0);
                    }
                    put(&mut out, shell::prompt(host, &c.cwd).as_bytes());
                }
                0x7f | 0x08 => {
                    if c.line.pop().is_some() && c.pty {
                        put(&mut out, b"\x08 \x08");
                    }
                }
                0x03 => {
                    c.line.clear();
                    put(&mut out, b"^C\r\n");
                    put(&mut out, shell::prompt(host, &c.cwd).as_bytes());
                }
                0x04 if c.line.is_empty() => {
                    c.kind = Kind::Idle;
                    put(&mut out, b"logout\r\n");
                    send(ss, ch, out)?;
                    return exit(ss, ch, 0);
                }
                // Other control keys, arrows among them, do nothing.
                0..=0x1f => {}
                _ if c.line.len() < MAX_LINE => {
                    c.line.push(b);
                    if c.pty {
                        put(&mut out, &[b]);
                    }
                }
                _ => with(&self.s, |s| {
                    s.rec.truncated = true;
                    Ok(())
                })?,
            }
        }
        send(ss, ch, out)
    }
}

/// However the connection ends (byte cap, time cap, a dropped socket),
/// a file part-way up is still filed.
impl Drop for Client {
    fn drop(&mut self) {
        for c in self.chans.values_mut() {
            if let Err(e) = finish(&mut c.file, &self.s) {
                if e.kind() != ErrorKind::BrokenPipe {
                    eprintln!("aegis-honeypot: keeping an upload: {e}");
                }
            }
        }
    }
}

impl server::Handler for Client {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth> {
        self.login(user, Some(password), None).await
    }

    /// Every key offered is recorded, even one russh can't go on to
    /// check (RSA): a client tries each it has.
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        offer: PublicKeyOffer<'_>,
    ) -> Result<Auth> {
        let k = offer.public_key;
        let key = format!("{} {}", k.algorithm(), k.fingerprint(HashAlg::Sha256));
        self.login(user, None, Some(key)).await
    }

    /// Recorded and paused for when offered.
    async fn auth_publickey(&mut self, _: &str, _: VerifiedPublicKey<'_>) -> Result<Auth> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<()> {
        // Dropping `reply` refuses the channel.
        if self.chans.len() < MAX_CHANNELS {
            self.chans.insert(channel.id(), Chan::default());
            reply.accept().await;
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        ch: ChannelId,
        _: &str,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        ss: &mut server::Session,
    ) -> Result<()> {
        if let Some(c) = self.chans.get_mut(&ch) {
            c.pty = true;
        }
        ss.channel_success(ch)?;
        Ok(())
    }

    /// No X11: russh's default leaves a client that asked waiting.
    async fn x11_request(
        &mut self,
        ch: ChannelId,
        _: bool,
        _: &str,
        _: &str,
        _: u32,
        ss: &mut server::Session,
    ) -> Result<()> {
        ss.channel_failure(ch)?;
        Ok(())
    }

    async fn shell_request(&mut self, ch: ChannelId, ss: &mut server::Session) -> Result<()> {
        let Some(c) = self.chans.get_mut(&ch) else {
            return Ok(());
        };
        c.kind = Kind::Shell;
        c.cwd = shell::HOME.into();
        ss.channel_success(ch)?;
        send(ss, ch, shell::prompt(&self.host, &c.cwd).into_bytes())
    }

    async fn exec_request(
        &mut self,
        ch: ChannelId,
        data: &[u8],
        ss: &mut server::Session,
    ) -> Result<()> {
        let Some(c) = self.chans.get_mut(&ch) else {
            return Ok(());
        };
        ss.channel_success(ch)?;
        let line = hello::text(&data[..data.len().min(MAX_LINE)]);
        let mut words = line.split_whitespace();
        // scp's sink: what `scp file host:` runs at the far end.
        if words.next() == Some("scp") && words.any(|w| w.starts_with('-') && w.contains('t')) {
            with(&self.s, |s| {
                let cmd = s.note(line.as_bytes(), MAX_COMMAND);
                s.command(cmd);
                Ok(())
            })?;
            c.kind = Kind::Scp(Scp::default());
            return send(ss, ch, vec![0]);
        }
        let ran = run(&self.s, &self.host, &mut shell::HOME.into(), data)?;
        send(ss, ch, ran.out.into_bytes())?;
        exit(ss, ch, ran.status)
    }

    async fn subsystem_request(
        &mut self,
        ch: ChannelId,
        name: &str,
        ss: &mut server::Session,
    ) -> Result<()> {
        // One at a time, as one upload is held at a time.
        let busy = self.chans.values().any(|c| matches!(c.kind, Kind::Sftp(_)));
        match self.chans.get_mut(&ch) {
            Some(c) if name == "sftp" && !busy => {
                c.kind = Kind::Sftp(Sftp::default());
                ss.channel_success(ch)?;
            }
            _ => ss.channel_failure(ch)?,
        }
        Ok(())
    }

    async fn data(&mut self, ch: ChannelId, data: &[u8], ss: &mut server::Session) -> Result<()> {
        let busy = self
            .chans
            .iter()
            .any(|(&id, c)| id != ch && c.file.is_some());
        let Some(c) = self.chans.get_mut(&ch) else {
            return Ok(());
        };
        if matches!(c.kind, Kind::Shell) {
            return self.typed(ch, data, ss);
        }
        let Chan { kind, file, .. } = c;
        let (mut out, mut res) = (Vec::new(), Ok(()));
        let mut f = |e: Event<'_>| {
            if res.is_ok() {
                res = on_file(file, &self.s, busy, e);
            }
        };
        let fed = match kind {
            Kind::Scp(p) => p.feed(data, &mut out, &mut f),
            Kind::Sftp(p) => p.feed(data, &mut out, &mut f),
            Kind::Idle | Kind::Shell => Ok(()),
        };
        res?;
        send(ss, ch, out)?;
        if fed.is_err() {
            *kind = Kind::Idle;
            finish(file, &self.s)?;
            ss.close(ch)?;
        }
        Ok(())
    }

    /// The client has sent all it will: a shell or a transfer ends as
    /// if it ran out of input. An exec has ended already.
    async fn channel_eof(&mut self, ch: ChannelId, ss: &mut server::Session) -> Result<()> {
        match self.chans.get_mut(&ch) {
            Some(c) if !matches!(c.kind, Kind::Idle) => {
                c.kind = Kind::Idle;
                finish(&mut c.file, &self.s)?;
                exit(ss, ch, 0)
            }
            _ => Ok(()),
        }
    }

    async fn channel_close(&mut self, ch: ChannelId, _: &mut server::Session) -> Result<()> {
        if let Some(mut c) = self.chans.remove(&ch) {
            finish(&mut c.file, &self.s)?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::serve::tests::{one, server};
    use crate::upload::tests::{id, pkt, replies, s as string};
    use aegis_proto::honeypot::{self, Protocol};
    use russh::client;
    use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
    use russh::{ChannelMsg, Disconnect};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aegis-ssh-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir(&d).unwrap();
        d
    }

    /// A server with a fresh host key.
    pub fn ssh(name: &str) -> Ssh {
        let d = dir(name);
        let s = Ssh::load(&d, crate::shell::tests::host()).unwrap();
        std::fs::remove_dir_all(d).unwrap();
        s
    }

    struct Trusting;

    impl client::Handler for Trusting {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    async fn connect(c: TcpStream) -> Result<client::Handle<Trusting>, russh::Error> {
        client::connect_stream(Arc::new(client::Config::default()), c, Trusting).await
    }

    async fn login(c: TcpStream) -> client::Handle<Trusting> {
        let mut h = connect(c).await.unwrap();
        let t = Instant::now();
        assert!(h
            .authenticate_password("root", "hunter2")
            .await
            .unwrap()
            .success());
        // Let in, but not at once.
        assert!(
            t.elapsed() >= Duration::from_millis(300),
            "{:?}",
            t.elapsed()
        );
        h
    }

    async fn bye(h: client::Handle<Trusting>) {
        h.disconnect(Disconnect::ByApplication, "", "")
            .await
            .unwrap();
    }

    /// What a channel sends until it closes, and its exit status.
    async fn drain(ch: &mut Channel<client::Msg>) -> (String, Option<u32>) {
        let (mut out, mut status) = (Vec::new(), None);
        while let Some(m) = ch.wait().await {
            match m {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                _ => {}
            }
        }
        (String::from_utf8(out).unwrap(), status)
    }

    /// The next data a channel sends.
    async fn next(ch: &mut Channel<client::Msg>) -> Vec<u8> {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Data { data }) => return data.to_vec(),
                Some(_) => {}
                None => panic!("closed"),
            }
        }
    }

    fn sha(b: &[u8]) -> String {
        Sha256::digest(b)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn conn() -> crate::session::Conn {
        crate::session::Conn {
            protocol: Protocol::Ssh,
            transport: crate::session::Transport::Tcp,
            addr: std::net::Ipv4Addr::new(127, 77, 0, 1),
            src: "10.0.0.2:40000".parse().unwrap(),
            dst: "1.2.3.4:22".parse().unwrap(),
        }
    }

    fn root() -> Credential {
        Credential {
            user: "root".into(),
            password: Some("hunter2".into()),
            key: None,
        }
    }

    async fn session<F, Fut>(name: &str, max_bytes: u64, client: F) -> honeypot::Session
    where
        F: FnOnce(TcpStream) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let srv = server(name, max_bytes, Duration::from_secs(20));
        one(&srv, Some(Protocol::Ssh), client).await
    }

    #[tokio::test]
    async fn a_password_login_and_an_exec_are_recorded() {
        let rec = session("pw", 1 << 20, |c| async move {
            let h = login(c).await;
            let mut ch = h.channel_open_session().await.unwrap();
            ch.exec(true, "uname -a; id && cat /etc/os-release | head -1")
                .await
                .unwrap();
            let (out, status) = drain(&mut ch).await;
            assert!(out.starts_with("Linux web1 6.12.0"), "{out}");
            assert!(out.contains("\nuid=0(root)"), "{out}");
            assert!(out.ends_with("\nbash: head: command not found\n"), "{out}");
            assert_eq!(status, Some(127));
            bye(h).await;
        })
        .await;
        assert_eq!(rec.protocol, Protocol::Ssh);
        assert_eq!(rec.credentials, [root()]);
        assert_eq!(
            rec.commands,
            ["uname -a", "id", "cat /etc/os-release", "head -1"]
        );
        assert!(rec.bytes_in > 0 && rec.bytes_out > 0);
        assert!(!rec.timed_out && !rec.truncated);
    }

    #[tokio::test]
    async fn a_shell_echoes_answers_and_exits() {
        let rec = session("shell", 1 << 20, |c| async move {
            let h = login(c).await;
            let mut ch = h.channel_open_session().await.unwrap();
            ch.request_pty(true, "xterm", 80, 24, 0, 0, &[])
                .await
                .unwrap();
            ch.request_shell(true).await.unwrap();
            ch.data(&b"whoami\rnosuch\r\nls\x7f\x7fpwd\rexit\r"[..])
                .await
                .unwrap();
            let (out, status) = drain(&mut ch).await;
            assert!(
                out.starts_with("[root@web1 ~]# whoami\r\nroot\r\n[root@web1 ~]# "),
                "{out:?}"
            );
            assert!(
                out.contains("bash: nosuch: command not found\r\n"),
                "{out:?}"
            );
            assert!(
                out.contains("ls\x08 \x08\x08 \x08pwd\r\n/root\r\n"),
                "{out:?}"
            );
            assert!(out.ends_with("exit\r\n"), "{out:?}");
            assert_eq!(status, Some(0));
            bye(h).await;
        })
        .await;
        assert_eq!(rec.commands, ["whoami", "nosuch", "pwd", "exit"]);
    }

    #[tokio::test]
    async fn a_key_login_is_recorded_by_fingerprint() {
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
        let fp = format!(
            "ssh-ed25519 {}",
            key.public_key().fingerprint(HashAlg::Sha256)
        );
        let rec = session("key", 1 << 20, |c| async move {
            let mut h = connect(c).await.unwrap();
            let k = PrivateKeyWithHashAlg::new(Arc::new(key), None);
            assert!(h
                .authenticate_publickey("admin", k)
                .await
                .unwrap()
                .success());
            bye(h).await;
        })
        .await;
        assert_eq!(
            rec.credentials,
            [Credential {
                user: "admin".into(),
                password: None,
                key: Some(fp),
            }]
        );
    }

    #[tokio::test]
    async fn an_scp_upload_is_stored_by_hash() {
        let rec = session("scp", 1 << 20, |c| async move {
            let h = login(c).await;
            let mut ch = h.channel_open_session().await.unwrap();
            ch.exec(true, "scp -t /tmp/").await.unwrap();
            assert_eq!(next(&mut ch).await, [0]);
            ch.data(&b"C0755 5 evil.sh\n"[..]).await.unwrap();
            assert_eq!(next(&mut ch).await, [0]);
            ch.data(&b"hello\0"[..]).await.unwrap();
            assert_eq!(next(&mut ch).await, [0]);
            ch.eof().await.unwrap();
            assert_eq!(drain(&mut ch).await.1, Some(0));
            bye(h).await;
        })
        .await;
        let h = sha(b"hello");
        assert_eq!(
            rec.uploads,
            [Upload {
                name: "evil.sh".into(),
                payload: Some(h.clone()),
            }]
        );
        assert_eq!(rec.payloads, [h]);
        assert_eq!(rec.commands, ["scp -t /tmp/"]);
        assert!(!rec.truncated);
    }

    #[tokio::test]
    async fn an_upload_is_held_to_its_limit_and_no_further() {
        let big: Vec<u8> = (0..MAX_HELD as u32 + 5000).map(|i| i as u8).collect();
        let sent = big.clone();
        let rec = session("big", 4 << 20, |c| async move {
            let h = login(c).await;
            let mut ch = h.channel_open_session().await.unwrap();
            ch.exec(true, "scp -t .").await.unwrap();
            assert_eq!(next(&mut ch).await, [0]);
            ch.data(format!("C0644 {} big\n", sent.len()).as_bytes())
                .await
                .unwrap();
            assert_eq!(next(&mut ch).await, [0]);
            ch.data(&[&sent[..], &[0]].concat()[..]).await.unwrap();
            assert_eq!(next(&mut ch).await, [0]);
            ch.eof().await.unwrap();
            drain(&mut ch).await;
            bye(h).await;
        })
        .await;
        let kept = sha(&big[..MAX_HELD]);
        assert_eq!(rec.uploads[0].payload.as_ref(), Some(&kept));
        assert!(rec.truncated);
    }

    #[tokio::test]
    async fn an_sftp_put_is_stored_and_the_rest_refused() {
        let rec = session("sftp", 1 << 20, |c| async move {
            let h = login(c).await;
            let mut ch = h.channel_open_session().await.unwrap();
            ch.request_subsystem(true, "sftp").await.unwrap();
            let open = [id(2), string(b"/tmp/x.sh"), id(0x1a), id(0)].concat();
            let write = [id(3), string(b"1"), vec![0; 8], string(b"hello")].concat();
            let packets = [
                pkt(1, &id(3)),
                pkt(3, &open),
                pkt(6, &write),
                pkt(4, &[id(4), string(b"1")].concat()),
                pkt(11, &[id(5), string(b"/")].concat()),
            ]
            .concat();
            ch.data(&packets[..]).await.unwrap();
            let mut got = Vec::new();
            while replies(&got).len() < 5 {
                got.extend(next(&mut ch).await);
            }
            let codes: Vec<_> = replies(&got)
                .iter()
                .map(|(t, i, rest)| (*t, *i, if *t == 101 { rest[3] } else { 0 }))
                .collect();
            assert_eq!(
                codes,
                [
                    (2, 0, 0),
                    (102, 2, 0),
                    (101, 3, 0),
                    (101, 4, 0),
                    (101, 5, 3)
                ]
            );
            ch.eof().await.unwrap();
            drain(&mut ch).await;
            bye(h).await;
        })
        .await;
        let h = sha(b"hello");
        assert_eq!(
            rec.uploads,
            [Upload {
                name: "/tmp/x.sh".into(),
                payload: Some(h),
            }]
        );
    }

    #[tokio::test]
    async fn too_many_failed_logins_close_the_connection() {
        session("tries", 1 << 20, |c| async move {
            let mut h = connect(c).await.unwrap();
            let mut failed = 0;
            while let Ok(r) = h.authenticate_none("root").await {
                assert!(!r.success());
                failed += 1;
                // The one after the last allowed is answered by the
                // disconnect, which this client reports as a failure.
                assert!(failed <= MAX_TRIES + 1, "still open after {failed}");
            }
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn logins_past_the_limit_end_the_connection() {
        let sp = crate::session::tests::spool("sshtries");
        let s = Session::open(&sp, 1 << 20, crate::session::tests::NO_FLOOR, conn())
            .unwrap()
            .unwrap();
        let sh: Shared = Arc::new(Mutex::new(Some(s)));
        let mut c = Client {
            s: sh.clone(),
            host: Arc::new(crate::shell::tests::host()),
            tries: 0,
            chans: HashMap::new(),
        };
        // Keys offered count too, though a probe isn't a failed login.
        for i in 0..MAX_TRIES {
            // A client names the algorithm, and may put anything in it.
            let key = (i % 2 == 0).then(|| "ssh-\x1b[2Jx SHA256:x".to_string());
            assert!(matches!(c.login("root", None, key).await, Ok(Auth::Accept)));
        }
        assert!(c.login("root", Some("x"), None).await.is_err());
        let s = lock(&sh).take().unwrap();
        assert_eq!(s.rec.credentials.len(), MAX_TRIES);
        assert_eq!(
            s.rec.credentials[0].key.as_deref(),
            Some("ssh-\u{fffd}[2Jx SHA256:x")
        );
        s.close().unwrap();
        std::fs::remove_dir_all(sp).unwrap();
    }

    #[test]
    fn an_scp_file_holds_only_the_room_it_declares() {
        let sp = crate::session::tests::spool("sshhold");
        let s = Session::open(&sp, 1 << 20, crate::session::tests::NO_FLOOR, conn())
            .unwrap()
            .unwrap();
        let before = s.room();
        let sh: Shared = Arc::new(Mutex::new(Some(s)));
        let mut file = None;
        on_file(&mut file, &sh, false, Event::Start(b"x", Some(5))).unwrap();
        assert_eq!(before - lock(&sh).as_ref().unwrap().room(), 5);
        // More than declared is still cut, not kept.
        on_file(&mut file, &sh, false, Event::Data(0, b"hello!")).unwrap();
        on_file(&mut file, &sh, false, Event::End).unwrap();
        let s = lock(&sh).take().unwrap();
        assert!(s.rec.truncated);
        assert_eq!(s.rec.uploads[0].payload, Some(sha(b"hello")));
        // A huge claim reserves no more than an upload may hold.
        let sh: Shared = Arc::new(Mutex::new(Some(s)));
        let before = lock(&sh).as_ref().unwrap().room();
        on_file(&mut file, &sh, false, Event::Start(b"y", Some(u64::MAX))).unwrap();
        assert_eq!(before - lock(&sh).as_ref().unwrap().room(), MAX_HELD as u64);
        drop(file);
        lock(&sh).take().unwrap().close().unwrap();
        std::fs::remove_dir_all(sp).unwrap();
    }

    #[tokio::test]
    async fn channels_past_the_limit_are_refused() {
        session("chans", 1 << 20, |c| async move {
            let h = login(c).await;
            let mut held = Vec::new();
            for _ in 0..MAX_CHANNELS {
                held.push(h.channel_open_session().await.unwrap());
            }
            assert!(h.channel_open_session().await.is_err());
            bye(h).await;
        })
        .await;
    }

    #[tokio::test]
    async fn the_time_cap_ends_a_connection_russh_still_holds() {
        let srv = server("stime", 1 << 20, Duration::from_secs(1));
        let rec = one(&srv, Some(Protocol::Ssh), |mut c| async move {
            c.write_all(b"SSH-2.0-OpenSSH_9.9\r\n").await.unwrap();
            // Then silence: only the cap can end it, and the client
            // must see it end.
            let mut got = Vec::new();
            let _ = c.read_to_end(&mut got).await;
            assert!(got.starts_with(b"SSH-2.0-OpenSSH_9.9\r\n"), "{got:?}");
        })
        .await;
        assert!(rec.timed_out);
    }

    #[tokio::test]
    async fn the_byte_cap_ends_the_connection() {
        let rec = session("sbytes", 3000, |c| async move {
            // The cap falls in the key exchange: the client never gets in.
            if let Ok(mut h) = connect(c).await {
                let r = h.authenticate_password("root", "x").await;
                assert!(!r.is_ok_and(|r| r.success()));
            }
        })
        .await;
        assert!(rec.truncated);
        assert!(rec.bytes_in + rec.bytes_out <= 3000);
    }

    #[tokio::test]
    async fn one_upload_at_a_time_is_held() {
        let rec = session("two", 4 << 20, |c| async move {
            let h = login(c).await;
            let (mut a, mut b) = (
                h.channel_open_session().await.unwrap(),
                h.channel_open_session().await.unwrap(),
            );
            for ch in [&mut a, &mut b] {
                ch.exec(true, "scp -t .").await.unwrap();
                assert_eq!(next(ch).await, [0]);
            }
            a.data(&b"C0644 3 a\nab"[..]).await.unwrap();
            assert_eq!(next(&mut a).await, [0]);
            // While a's file is still coming, b's isn't held.
            b.data(&b"C0644 2 b\nhi\0"[..]).await.unwrap();
            assert_eq!(next(&mut b).await, [0, 0]);
            a.data(&b"c\0"[..]).await.unwrap();
            assert_eq!(next(&mut a).await, [0]);
            bye(h).await;
        })
        .await;
        let got: Vec<_> = rec
            .uploads
            .iter()
            .map(|u| (u.name.as_str(), u.payload.clone()))
            .collect();
        assert_eq!(got, [("b", None), ("a", Some(sha(b"abc")))]);
        assert!(rec.truncated);
    }

    #[tokio::test]
    async fn a_flood_of_keys_gets_bounded_output() {
        session("flood", 4 << 20, |c| async move {
            let h = login(c).await;
            let mut ch = h.channel_open_session().await.unwrap();
            ch.request_shell(true).await.unwrap();
            assert_eq!(next(&mut ch).await, b"[root@web1 ~]# ");
            // Each Enter alone prints a prompt, 15 bytes for 1: past the
            // cap on what one packet may print, the rest is dropped.
            ch.data(&[b'\n'; 3000][..]).await.unwrap();
            ch.data(&b"exit\n"[..]).await.unwrap();
            let (out, _) = drain(&mut ch).await;
            assert!(out.len() <= shell::MAX_OUT, "{}", out.len());
            bye(h).await;
        })
        .await;
    }

    #[tokio::test]
    async fn costly_key_exchanges_are_not_offered() {
        session("kex", 1 << 20, |c| async move {
            let cfg = client::Config {
                preferred: russh::Preferred {
                    kex: std::borrow::Cow::Borrowed(&[russh::kex::DH_G18_SHA512]),
                    ..Default::default()
                },
                ..Default::default()
            };
            if let Ok(mut h) = client::connect_stream(Arc::new(cfg), c, Trusting).await {
                assert!(h.authenticate_password("root", "x").await.is_err());
            }
        })
        .await;
    }

    #[tokio::test]
    async fn an_upload_the_byte_cap_cuts_is_still_recorded() {
        let big = vec![7u8; 1 << 20];
        let rec = session("cutup", 600 << 10, |c| async move {
            let h = login(c).await;
            let mut ch = h.channel_open_session().await.unwrap();
            ch.exec(true, "scp -t .").await.unwrap();
            assert_eq!(next(&mut ch).await, [0]);
            ch.data(&b"C0644 1048576 big\n"[..]).await.unwrap();
            assert_eq!(next(&mut ch).await, [0]);
            // The cap closes the connection part-way.
            let _ = ch.data(&big[..]).await;
            drain(&mut ch).await;
        })
        .await;
        assert!(rec.truncated);
        assert_eq!(
            rec.uploads,
            [Upload {
                name: "big".into(),
                payload: Some(sha(&[7u8; MAX_HELD])),
            }]
        );
    }

    #[tokio::test]
    async fn an_upload_the_client_drops_is_still_recorded() {
        let rec = session("dropup", 4 << 20, |c| async move {
            let h = login(c).await;
            let mut ch = h.channel_open_session().await.unwrap();
            ch.exec(true, "scp -t .").await.unwrap();
            assert_eq!(next(&mut ch).await, [0]);
            ch.data(&b"C0644 1000 half\nhello"[..]).await.unwrap();
            assert_eq!(next(&mut ch).await, [0]);
            // Gone, with no EOF or close on the channel.
            drop(ch);
            drop(h);
        })
        .await;
        assert_eq!(
            rec.uploads,
            [Upload {
                name: "half".into(),
                payload: Some(sha(b"hello")),
            }]
        );
    }

    #[tokio::test]
    async fn a_second_sftp_channel_is_refused() {
        session("sftp2", 1 << 20, |c| async move {
            let h = login(c).await;
            let a = h.channel_open_session().await.unwrap();
            a.request_subsystem(true, "sftp").await.unwrap();
            let mut b = h.channel_open_session().await.unwrap();
            b.request_subsystem(true, "sftp").await.unwrap();
            loop {
                match b.wait().await {
                    Some(ChannelMsg::Failure) => break,
                    Some(ChannelMsg::Success) | None => panic!("a second sftp"),
                    Some(_) => {}
                }
            }
            bye(h).await;
        })
        .await;
    }

    #[tokio::test]
    async fn forwarding_and_agents_are_refused() {
        session("fwd", 1 << 20, |c| async move {
            let h = login(c).await;
            assert!(h
                .channel_open_direct_tcpip("10.0.0.9", 22, "127.0.0.1", 5000)
                .await
                .is_err());
            assert!(h.tcpip_forward("0.0.0.0", 8080).await.is_err());
            assert!(h
                .channel_open_direct_streamlocal("/run/docker.sock")
                .await
                .is_err());
            assert!(h.streamlocal_forward("/tmp/s").await.is_err());
            let mut ch = h.channel_open_session().await.unwrap();
            ch.request_x11(true, false, "MIT-MAGIC-COOKIE-1", "00", 0)
                .await
                .unwrap();
            ch.agent_forward(true).await.unwrap();
            let mut failed = 0;
            while failed < 2 {
                match ch.wait().await {
                    Some(ChannelMsg::Failure) => failed += 1,
                    Some(ChannelMsg::Success) | None => panic!("granted"),
                    Some(_) => {}
                }
            }
            bye(h).await;
        })
        .await;
    }

    #[tokio::test]
    async fn the_read_that_crosses_the_cap_hands_on_only_what_was_recorded() {
        let sp = crate::session::tests::spool("sshwire");
        let (mut c, io) = crate::serve::tests::pair(crate::serve::tests::INCIDENT).await;
        let s = Session::open(
            &sp,
            100 + 2 * crate::pcap::SEGMENT_COST,
            crate::session::tests::NO_FLOOR,
            conn(),
        )
        .unwrap()
        .unwrap();
        let sh: Shared = Arc::new(Mutex::new(Some(s)));
        let mut w = Wire {
            io,
            s: sh.clone(),
            full: false,
        };
        c.write_all(&[1; 300]).await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = w.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        let s = lock(&sh).take().unwrap();
        assert!(s.rec.truncated);
        assert_eq!(got.len() as u64, s.rec.bytes_in);
        s.close().unwrap();
        std::fs::remove_dir_all(sp).unwrap();
    }

    #[test]
    fn the_host_key_is_made_once_and_kept() {
        let d = dir("hostkey");
        std::fs::write(d.join("ssh_host_ed25519_key.tmp"), "half").unwrap();
        let first = host_key(&d).unwrap();
        let path = d.join(HOST_KEY);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert!(!d.join("ssh_host_ed25519_key.tmp").exists());
        assert_eq!(first.algorithm(), Algorithm::Ed25519);
        let again = host_key(&d).unwrap();
        assert_eq!(again.public_key(), first.public_key());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_host_key_that_wont_parse_stops_the_start() {
        let d = dir("badkey");
        let p = d.join(HOST_KEY);
        use russh::keys::ssh_key::private::{RsaKeypair, RsaPrivateKey};
        use russh::keys::ssh_key::public::RsaPublicKey;
        use russh::keys::ssh_key::{Cipher, Kdf, Mpint};
        let ed = PrivateKey::from(Ed25519Keypair::from_seed(&[3; 32]));
        let kdf = Kdf::Bcrypt {
            salt: vec![0; 16],
            rounds: 1,
        };
        let encrypted = ed.encrypt_with(Cipher::Aes256Ctr, kdf, 0, "pw").unwrap();
        // Toy numbers: only the algorithm is looked at.
        let m = |b: &[u8]| Mpint::from_positive_bytes(b);
        let rsa = RsaKeypair::new(
            RsaPublicKey::new(m(&[1, 0, 1]), m(&[0xc5; 256])).unwrap(),
            RsaPrivateKey::new(m(&[3]), m(&[5]), m(&[7]), m(&[11])).unwrap(),
        )
        .unwrap();
        let rsa = PrivateKey::from(rsa);
        let pem = |k: &PrivateKey| k.to_openssh(LineEnding::LF).unwrap().as_bytes().to_vec();
        for junk in [
            b"not a key".to_vec(),
            vec![],
            b"\xff\xfe".to_vec(),
            pem(&encrypted),
            pem(&rsa),
        ] {
            std::fs::write(&p, &junk).unwrap();
            let e = format!("{:#}", host_key(&d).unwrap_err());
            assert!(e.contains(HOST_KEY), "{e}");
            assert_eq!(std::fs::read(&p).unwrap(), junk);
        }
        std::fs::remove_dir_all(d).unwrap();
    }
}
