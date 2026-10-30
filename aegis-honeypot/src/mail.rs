// SPDX-License-Identifier: MIT OR Apache-2.0
//! SMTP that answers like a stock postfix: every login succeeds, every
//! message is accepted and kept, and nothing is ever relayed. The pcap
//! holds what crossed the wire (ciphertext, after STARTTLS or on 465);
//! session.json holds the envelope.

use std::sync::Arc;

use aegis_proto::honeypot::{Credential, Mail};
use anyhow::Result;
use rustls::{ServerConfig, ServerConnection};
use tokio::net::TcpStream;
use tokio::time::{timeout_at, Instant};

use crate::serve::Handler;
use crate::session::{random, Held, Session, MAX_HELD};
use crate::smtp::{self, Cmd, Dot, MAX_ADDR, MAX_LINE, MAX_RCPT};
use crate::web::{self, Wire};

/// `mail` is the name the server goes by: `mail.<short hostname>`.
/// `implicit`: TLS from the first byte (465), not after STARTTLS.
/// `until`: the session's time cap, no later than the one around
/// `serve`, so a message still arriving then is kept.
pub struct Smtp<'a> {
    pub tls: &'a Arc<ServerConfig>,
    pub mail: &'a str,
    pub implicit: bool,
    pub until: Instant,
}

enum Line {
    Cmd(Vec<u8>),
    /// Longer than `MAX_LINE`; read to its end and dropped.
    Long,
    Gone,
}

/// The next command line, without its line ending. Never holds more
/// than `MAX_LINE` of it.
async fn line(w: &mut Wire, s: &mut Session) -> Result<Line> {
    let mut long = false;
    loop {
        let look = if long {
            w.buf.len()
        } else {
            w.buf.len().min(MAX_LINE)
        };
        if let Some(i) = w.buf[..look].iter().position(|&c| c == b'\n') {
            if long {
                w.buf.drain(..=i);
                return Ok(Line::Long);
            }
            let mut l: Vec<u8> = w.buf.drain(..=i).collect();
            l.pop();
            if l.last() == Some(&b'\r') {
                l.pop();
            }
            return Ok(Line::Cmd(l));
        }
        if !long && w.buf.len() >= MAX_LINE {
            // Its end may be in what's here already.
            long = true;
            continue;
        }
        if long {
            w.buf.clear();
        }
        if !w.fill(s).await? {
            return Ok(Line::Gone);
        }
    }
}

/// TLS over `io` once its ClientHello is recorded and fingerprinted.
/// None when the client went or the cap was reached first.
async fn tls(s: &mut Session, mut io: TcpStream, cfg: &Arc<ServerConfig>) -> Result<Option<Wire>> {
    let Some(raw) = web::hello(s, &mut io, |_| false).await? else {
        return Ok(None);
    };
    let c = ServerConnection::new(cfg.clone())?;
    Ok(Some(Wire::new(io, Some(c), raw)))
}

/// What the client has said so far that the next command depends on.
/// STARTTLS forgets all of it (RFC 3207 4.2).
#[derive(Default)]
struct State {
    helo: bool,
    authed: bool,
    from: Option<String>,
    to: Vec<String>,
}

/// Like postfix's own queue ids: 11 upper-case hex digits.
fn queue_id() -> String {
    let mut r = [0u8; 8];
    // A zero id only costs realism.
    let _ = random(&mut r);
    format!("{:011X}", u64::from_ne_bytes(r) >> 20)
}

fn ehlo(name: &str, tls: bool) -> String {
    // Never offered again once TLS is up, as postfix doesn't.
    let starttls = if tls { "" } else { "250-STARTTLS\r\n" };
    format!(
        "250-{name}\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n{starttls}\
         250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n\
         250-DSN\r\n250 SMTPUTF8\r\n"
    )
}

/// Writes one reply, which ends in CRLF already.
async fn say(w: &mut Wire, s: &mut Session, r: &str) -> Result<()> {
    w.write(s, r.as_bytes()).await
}

enum Answer {
    Got(Vec<u8>),
    /// Cancelled, too long or not base64; answered already.
    Refused,
    Gone,
}

/// One AUTH answer, base64-decoded: `first` when the command carried
/// it, else the line the client sends after `prompt`.
async fn answer(
    w: &mut Wire,
    s: &mut Session,
    first: Option<&[u8]>,
    prompt: &str,
) -> Result<Answer> {
    let l;
    let b = match first {
        Some(f) => f,
        None => {
            say(w, s, prompt).await?;
            l = match line(w, s).await? {
                Line::Gone => return Ok(Answer::Gone),
                Line::Long => {
                    say(w, s, "500 5.5.0 Error: line too long\r\n").await?;
                    return Ok(Answer::Refused);
                }
                Line::Cmd(l) => l,
            };
            if l == b"*" {
                say(w, s, "501 5.7.0 Authentication aborted\r\n").await?;
                return Ok(Answer::Refused);
            }
            &l
        }
    };
    // "=" is an empty initial response (RFC 4954 4).
    let b = if b == b"=" { &b""[..] } else { b };
    match smtp::base64(b) {
        Some(d) => Ok(Answer::Got(d)),
        None => {
            say(w, s, "501 5.5.2 Cannot decode response\r\n").await?;
            Ok(Answer::Refused)
        }
    }
}

/// AUTH PLAIN or LOGIN, recorded and always accepted. False when the
/// client went.
async fn auth(
    w: &mut Wire,
    s: &mut Session,
    st: &mut State,
    mech: &[u8],
    first: Option<&[u8]>,
) -> Result<bool> {
    let (user, password) = if mech.eq_ignore_ascii_case(b"PLAIN") {
        let d = match answer(w, s, first, "334 \r\n").await? {
            Answer::Got(d) => d,
            Answer::Refused => return Ok(true),
            Answer::Gone => return Ok(false),
        };
        let Some((u, p)) = smtp::plain(&d) else {
            say(
                w,
                s,
                "535 5.7.8 Error: authentication failed: bad protocol / cancel\r\n",
            )
            .await?;
            return Ok(true);
        };
        (s.note(u, MAX_ADDR), s.note(p, MAX_ADDR))
    } else if mech.eq_ignore_ascii_case(b"LOGIN") {
        // "Username:", then "Password:".
        let u = match answer(w, s, first, "334 VXNlcm5hbWU6\r\n").await? {
            Answer::Got(d) => d,
            Answer::Refused => return Ok(true),
            Answer::Gone => return Ok(false),
        };
        let p = match answer(w, s, None, "334 UGFzc3dvcmQ6\r\n").await? {
            Answer::Got(d) => d,
            Answer::Refused => return Ok(true),
            Answer::Gone => return Ok(false),
        };
        (s.note(&u, MAX_ADDR), s.note(&p, MAX_ADDR))
    } else {
        say(
            w,
            s,
            "535 5.7.8 Error: authentication failed: Invalid authentication mechanism\r\n",
        )
        .await?;
        return Ok(true);
    };
    s.credential(Credential {
        user,
        password: Some(password),
        key: None,
    });
    st.authed = true;
    say(w, s, "235 2.7.0 Authentication successful\r\n").await?;
    Ok(true)
}

/// The message after DATA, kept up to `MAX_HELD`, and filed with its
/// envelope. False when the client went, or a cap came, before its end.
async fn data(w: &mut Wire, s: &mut Session, st: &mut State, until: Instant) -> Result<bool> {
    // Set aside first, so the pcap can't use up what the message needs.
    // Every byte kept is charged twice, in the pcap and the payload, so
    // half the room is what a message can use.
    let room = s.hold((MAX_HELD as u64).min(s.room() / 2));
    let mut held = Held::new(usize::try_from(room).unwrap_or(0));
    let mut dot = Dot::default();
    let ended = loop {
        if let Some(n) = dot.feed(&w.buf, &mut |b| held.keep(b)) {
            w.buf.drain(..n);
            break true;
        }
        w.buf.clear();
        match timeout_at(until, w.fill(s)).await {
            Ok(more) => {
                if !more? {
                    break false;
                }
            }
            Err(_) => {
                s.rec.timed_out = true;
                break false;
            }
        }
    };
    s.release(room);
    let message = if held.data.is_empty() {
        None
    } else {
        s.payload(&held.data)?
    };
    // Cut short by the client or a cap: kept as far as it came.
    s.rec.truncated |= held.cut || !ended;
    s.mail(Mail {
        from: st.from.take().unwrap_or_default(),
        to: std::mem::take(&mut st.to),
        message,
    });
    if ended {
        say(w, s, &format!("250 2.0.0 Ok: queued as {}\r\n", queue_id())).await?;
    }
    Ok(ended)
}

impl Handler for Smtp<'_> {
    async fn serve(&self, s: &mut Session, io: TcpStream) -> Result<()> {
        let mut w = if self.implicit {
            match tls(s, io, self.tls).await? {
                Some(w) => w,
                None => return Ok(()),
            }
        } else {
            Wire::new(io, None, Vec::new())
        };
        say(&mut w, s, &format!("220 {} ESMTP Postfix\r\n", self.mail)).await?;
        let mut st = State::default();
        loop {
            let l = match line(&mut w, s).await? {
                Line::Gone => return Ok(()),
                Line::Long => {
                    say(&mut w, s, "500 5.5.0 Error: line too long\r\n").await?;
                    continue;
                }
                Line::Cmd(l) => l,
            };
            let r = match smtp::command(&l) {
                Cmd::Helo(b"") => "501 Syntax: HELO hostname\r\n".into(),
                Cmd::Ehlo(b"") => "501 Syntax: EHLO hostname\r\n".into(),
                c @ (Cmd::Helo(n) | Cmd::Ehlo(n)) => {
                    if s.rec.helo.is_none() {
                        s.rec.helo = Some(s.note(n, MAX_ADDR));
                    }
                    st.helo = true;
                    st.from = None;
                    st.to.clear();
                    if matches!(c, Cmd::Ehlo(_)) {
                        ehlo(self.mail, w.tls.is_some())
                    } else {
                        format!("250 {}\r\n", self.mail)
                    }
                }
                Cmd::Mail(_) | Cmd::Auth(..) if !st.helo => {
                    "503 5.5.1 Error: send HELO/EHLO first\r\n".into()
                }
                Cmd::Mail(_) if st.from.is_some() => {
                    "503 5.5.1 Error: nested MAIL command\r\n".into()
                }
                Cmd::Mail(None) => "501 5.5.4 Syntax: MAIL FROM:<address>\r\n".into(),
                Cmd::Mail(Some(a)) => {
                    st.from = Some(s.note(a, MAX_ADDR));
                    "250 2.1.0 Ok\r\n".into()
                }
                Cmd::Rcpt(_) | Cmd::Data if st.from.is_none() => {
                    "503 5.5.1 Error: need MAIL command\r\n".into()
                }
                Cmd::Rcpt(None) => "501 5.5.4 Syntax: RCPT TO:<address>\r\n".into(),
                Cmd::Rcpt(Some(_)) if st.to.len() >= MAX_RCPT => {
                    "452 4.5.3 Error: too many recipients\r\n".into()
                }
                Cmd::Rcpt(Some(a)) => {
                    let a = s.note(a, MAX_ADDR);
                    st.to.push(a);
                    "250 2.1.5 Ok\r\n".into()
                }
                Cmd::Data if st.to.is_empty() => "503 5.5.1 Error: need RCPT command\r\n".into(),
                Cmd::Data => {
                    say(&mut w, s, "354 End data with <CR><LF>.<CR><LF>\r\n").await?;
                    if !data(&mut w, s, &mut st, self.until).await? {
                        return Ok(());
                    }
                    continue;
                }
                Cmd::Rset => {
                    st.from = None;
                    st.to.clear();
                    "250 2.0.0 Ok\r\n".into()
                }
                Cmd::Noop => "250 2.0.0 Ok\r\n".into(),
                Cmd::Quit => return say(&mut w, s, "221 2.0.0 Bye\r\n").await,
                Cmd::Vrfy => "502 5.5.1 VRFY command is disabled\r\n".into(),
                Cmd::StartTls if w.tls.is_some() => {
                    "554 5.5.1 Error: TLS already active\r\n".into()
                }
                Cmd::StartTls => {
                    say(&mut w, s, "220 2.0.0 Ready to start TLS\r\n").await?;
                    // What came after the command in plaintext is
                    // dropped with the old buffer, never read as commands
                    // inside TLS (RFC 3207 5; CVE-2011-0411).
                    let Wire { io, .. } = w;
                    w = match tls(s, io, self.tls).await? {
                        Some(w) => w,
                        None => return Ok(()),
                    };
                    st = State::default();
                    continue;
                }
                Cmd::Auth(..) if st.authed => "503 5.5.1 Error: already authenticated\r\n".into(),
                Cmd::Auth(..) if st.from.is_some() => {
                    "503 5.5.1 Error: MAIL transaction in progress\r\n".into()
                }
                Cmd::Auth(b"", _) => "501 5.5.4 Syntax: AUTH mechanism\r\n".into(),
                Cmd::Auth(m, first) => {
                    if !auth(&mut w, s, &mut st, m, first).await? {
                        return Ok(());
                    }
                    continue;
                }
                Cmd::Empty => "500 5.5.2 Error: bad syntax\r\n".into(),
                Cmd::Unknown => "502 5.5.2 Error: command not recognized\r\n".into(),
            };
            say(&mut w, s, &r).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpStream as Std;
    use std::time::Duration;

    use aegis_proto::honeypot::{self, Protocol};

    use crate::serve::tests::{server, server_with_ca};
    use crate::serve::Server;
    use crate::web::tests::{cleanup, session, sha, std_stream, tls_client, Tls};

    /// One reply, every line of it.
    fn said(c: &mut impl Read) -> String {
        let mut r = Vec::new();
        let mut b = [0u8];
        loop {
            if c.read(&mut b).unwrap_or(0) == 0 {
                panic!("closed after {:?}", String::from_utf8_lossy(&r));
            }
            r.push(b[0]);
            let last = r[..r.len() - 1]
                .iter()
                .rposition(|&c| c == b'\n')
                .map_or(0, |i| i + 1);
            if r.ends_with(b"\r\n") && r.get(last + 3) == Some(&b' ') {
                return String::from_utf8(r).unwrap();
            }
        }
    }

    /// Sends `line` and returns the reply.
    fn ask(c: &mut (impl Read + Write), line: &str) -> String {
        c.write_all(format!("{line}\r\n").as_bytes()).unwrap();
        said(c)
    }

    /// Everything until the server closes.
    fn rest(c: &mut impl Read) -> Vec<u8> {
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        out
    }

    /// One connection forced to `p`, `talk` on its own thread; the
    /// filed session and its directory.
    async fn smtp(
        srv: &std::rc::Rc<Server>,
        p: Protocol,
        talk: impl FnOnce(Std) + Send + 'static,
    ) -> (honeypot::Session, std::path::PathBuf) {
        session(srv, p, |c| async move {
            let c = std_stream(c);
            tokio::task::spawn_blocking(move || talk(c)).await.unwrap();
        })
        .await
    }

    /// MAIL, one RCPT and DATA with `msg`, which ends in its dot line.
    fn send(c: &mut (impl Read + Write), msg: &[u8]) -> String {
        assert_eq!(ask(c, "MAIL FROM:<boss@corp.example>"), "250 2.1.0 Ok\r\n");
        assert_eq!(ask(c, "RCPT TO:<victim@corp.example>"), "250 2.1.5 Ok\r\n");
        assert_eq!(ask(c, "DATA"), "354 End data with <CR><LF>.<CR><LF>\r\n");
        c.write_all(msg).unwrap();
        said(c)
    }

    fn queued(r: &str) {
        let id = r.strip_prefix("250 2.0.0 Ok: queued as ").unwrap();
        let id = id.strip_suffix("\r\n").unwrap();
        assert_eq!(id.len(), 11, "{r}");
        assert!(id
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));
    }

    #[tokio::test]
    async fn a_plain_session_is_recorded_and_its_message_kept() {
        let srv = server("mplain", 100_000, Duration::from_secs(5));
        let (rec, dir) = smtp(&srv, Protocol::Smtp, |mut c| {
            assert_eq!(said(&mut c), "220 mail.web1 ESMTP Postfix\r\n");
            assert_eq!(
                ask(&mut c, "EHLO bot.example"),
                "250-mail.web1\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n\
                 250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n\
                 250-DSN\r\n250 SMTPUTF8\r\n"
            );
            // \0root\0hunter2
            assert_eq!(
                ask(&mut c, "AUTH PLAIN AHJvb3QAaHVudGVyMg=="),
                "235 2.7.0 Authentication successful\r\n"
            );
            // Split across writes, the end line too, with a stuffed dot.
            assert_eq!(
                ask(&mut c, "MAIL FROM:<boss@corp.example> SIZE=99"),
                "250 2.1.0 Ok\r\n"
            );
            assert_eq!(ask(&mut c, "RCPT TO:<a@corp.example>"), "250 2.1.5 Ok\r\n");
            assert_eq!(ask(&mut c, "rcpt to:<b@corp.example>"), "250 2.1.5 Ok\r\n");
            assert!(ask(&mut c, "DATA").starts_with("354 "));
            for part in [
                &b"Subject: invoice\r\n\r\n..dotted\r\nbye\r"[..],
                b"\n.",
                b"\r",
                b"\n",
            ] {
                c.write_all(part).unwrap();
                std::thread::sleep(Duration::from_millis(20));
            }
            queued(&said(&mut c));
            assert_eq!(ask(&mut c, "QUIT"), "221 2.0.0 Bye\r\n");
            assert!(rest(&mut c).is_empty());
        })
        .await;
        assert_eq!(rec.protocol, Protocol::Smtp);
        assert_eq!(rec.helo.as_deref(), Some("bot.example"));
        assert_eq!(rec.credentials.len(), 1);
        assert_eq!(rec.credentials[0].user, "root");
        assert_eq!(rec.credentials[0].password.as_deref(), Some("hunter2"));
        let msg = b"Subject: invoice\r\n\r\n.dotted\r\nbye\r\n";
        assert_eq!(rec.mails.len(), 1);
        let m = &rec.mails[0];
        assert_eq!(m.from, "boss@corp.example");
        assert_eq!(m.to, ["a@corp.example", "b@corp.example"]);
        assert_eq!(m.message, Some(sha(msg)));
        assert_eq!(rec.payloads, [sha(msg)]);
        assert_eq!(std::fs::read(dir.join(sha(msg))).unwrap(), msg);
        assert!(!rec.truncated && !rec.timed_out);
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn auth_login_is_recorded_from_its_prompts() {
        let srv = server("mlogin", 100_000, Duration::from_secs(5));
        let (rec, _) = smtp(&srv, Protocol::Smtp, |mut c| {
            said(&mut c);
            assert_eq!(ask(&mut c, "HELO x"), "250 mail.web1\r\n");
            assert_eq!(ask(&mut c, "AUTH LOGIN"), "334 VXNlcm5hbWU6\r\n");
            // admin@corp.example, then Winter2026!
            assert_eq!(
                ask(&mut c, "YWRtaW5AY29ycC5leGFtcGxl"),
                "334 UGFzc3dvcmQ6\r\n"
            );
            assert_eq!(
                ask(&mut c, "V2ludGVyMjAyNiE="),
                "235 2.7.0 Authentication successful\r\n"
            );
            assert_eq!(
                ask(&mut c, "AUTH LOGIN"),
                "503 5.5.1 Error: already authenticated\r\n"
            );
        })
        .await;
        assert_eq!(rec.credentials.len(), 1);
        assert_eq!(rec.credentials[0].user, "admin@corp.example");
        assert_eq!(rec.credentials[0].password.as_deref(), Some("Winter2026!"));
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn auth_answers_that_are_not_logins_record_nothing() {
        let srv = server("mbadauth", 100_000, Duration::from_secs(5));
        let (rec, _) = smtp(&srv, Protocol::Smtp, |mut c| {
            said(&mut c);
            assert!(ask(&mut c, "AUTH PLAIN").starts_with("503 5.5.1 Error: send HELO/EHLO first"));
            ask(&mut c, "EHLO x");
            assert_eq!(ask(&mut c, "AUTH"), "501 5.5.4 Syntax: AUTH mechanism\r\n");
            assert!(ask(&mut c, "AUTH CRAM-MD5").starts_with("535 5.7.8 "));
            assert_eq!(
                ask(&mut c, "AUTH PLAIN !!!"),
                "501 5.5.2 Cannot decode response\r\n"
            );
            assert_eq!(ask(&mut c, "AUTH PLAIN"), "334 \r\n");
            assert_eq!(ask(&mut c, "*"), "501 5.7.0 Authentication aborted\r\n");
            // No NULs in it: not a PLAIN answer.
            assert!(ask(&mut c, "AUTH PLAIN cm9vdA==").starts_with("535 5.7.8 "));
            assert_eq!(ask(&mut c, "AUTH LOGIN"), "334 VXNlcm5hbWU6\r\n");
            assert_eq!(
                ask(&mut c, &"A".repeat(2000)),
                "500 5.5.0 Error: line too long\r\n"
            );
            assert_eq!(ask(&mut c, "NOOP"), "250 2.0.0 Ok\r\n");
        })
        .await;
        assert!(rec.credentials.is_empty());
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn commands_out_of_order_get_postfixs_refusals() {
        let srv = server("morder", 100_000, Duration::from_secs(5));
        let (rec, _) = smtp(&srv, Protocol::Smtp, |mut c| {
            said(&mut c);
            for (line, want) in [
                (
                    "MAIL FROM:<a@b>",
                    "503 5.5.1 Error: send HELO/EHLO first\r\n",
                ),
                ("EHLO", "501 Syntax: EHLO hostname\r\n"),
                ("HELO", "501 Syntax: HELO hostname\r\n"),
                ("EHLO first.example", ""),
                ("EHLO second.example", ""),
                ("RCPT TO:<a@b>", "503 5.5.1 Error: need MAIL command\r\n"),
                ("DATA", "503 5.5.1 Error: need MAIL command\r\n"),
                ("MAIL FROM:a", "250 2.1.0 Ok\r\n"),
                (
                    "MAIL FROM:<a@b>",
                    "503 5.5.1 Error: nested MAIL command\r\n",
                ),
                (
                    "AUTH PLAIN AHJvb3QAeA==",
                    "503 5.5.1 Error: MAIL transaction in progress\r\n",
                ),
                ("DATA", "503 5.5.1 Error: need RCPT command\r\n"),
                ("RCPT TO:<>", "501 5.5.4 Syntax: RCPT TO:<address>\r\n"),
                ("RSET", "250 2.0.0 Ok\r\n"),
                ("RCPT TO:<a@b>", "503 5.5.1 Error: need MAIL command\r\n"),
                ("MAIL TO:<a@b>", "501 5.5.4 Syntax: MAIL FROM:<address>\r\n"),
                ("VRFY root", "502 5.5.1 VRFY command is disabled\r\n"),
                ("BDAT 1 LAST", "502 5.5.2 Error: command not recognized\r\n"),
                ("", "500 5.5.2 Error: bad syntax\r\n"),
                ("NOOP", "250 2.0.0 Ok\r\n"),
            ] {
                let got = ask(&mut c, line);
                if !want.is_empty() {
                    assert_eq!(got, want, "{line}");
                }
            }
        })
        .await;
        // The first name is the one kept; nothing was sent.
        assert_eq!(rec.helo.as_deref(), Some("first.example"));
        assert!(rec.mails.is_empty());
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn an_oversize_line_gets_a_500_and_the_session_goes_on() {
        let srv = server("mlong", 1_000_000, Duration::from_secs(5));
        let (rec, _) = smtp(&srv, Protocol::Smtp, |mut c| {
            said(&mut c);
            // 999 bytes and CRLF is one too many; 998 is the most.
            let at_most = format!("NOOP {}", "x".repeat(998 - 5));
            assert_eq!(ask(&mut c, &at_most), "250 2.0.0 Ok\r\n");
            let long = format!("NOOP {}", "x".repeat(999 - 5));
            assert_eq!(ask(&mut c, &long), "500 5.5.0 Error: line too long\r\n");
            // Much longer, across many reads: one 500 for all of it.
            c.write_all(&vec![b'y'; 100_000]).unwrap();
            assert_eq!(ask(&mut c, ""), "500 5.5.0 Error: line too long\r\n");
            assert_eq!(ask(&mut c, "EHLO x").lines().next(), Some("250-mail.web1"));
        })
        .await;
        assert!(!rec.truncated);
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn recipients_stop_at_their_bound() {
        let srv = server("mrcpt", 1_000_000, Duration::from_secs(5));
        let (rec, _) = smtp(&srv, Protocol::Smtp, |mut c| {
            said(&mut c);
            ask(&mut c, "EHLO x");
            ask(&mut c, "MAIL FROM:<>");
            for i in 0..crate::smtp::MAX_RCPT {
                assert_eq!(
                    ask(&mut c, &format!("RCPT TO:<u{i}@x>")),
                    "250 2.1.5 Ok\r\n"
                );
            }
            assert_eq!(
                ask(&mut c, "RCPT TO:<one-more@x>"),
                "452 4.5.3 Error: too many recipients\r\n"
            );
            ask(&mut c, "DATA");
            queued(&ask(&mut c, "."));
        })
        .await;
        let m = &rec.mails[0];
        assert_eq!(m.from, "");
        assert_eq!(m.to.len(), crate::smtp::MAX_RCPT);
        assert_eq!(m.to[99], "u99@x");
        // Empty: nothing to keep.
        assert_eq!(m.message, None);
        assert!(rec.payloads.is_empty());
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn a_message_past_256_kib_keeps_its_start_and_is_flagged() {
        let srv = server("mbig", 4 << 20, Duration::from_secs(5));
        let line = format!("{}\r\n", "z".repeat(98));
        let body = line.repeat(3000).into_bytes();
        let sent = body.clone();
        let (rec, dir) = smtp(&srv, Protocol::Smtp, move |mut c| {
            said(&mut c);
            ask(&mut c, "EHLO x");
            let mut msg = sent;
            msg.extend_from_slice(b".\r\n");
            queued(&send(&mut c, &msg));
            // Two messages in one session, each kept.
            queued(&send(&mut c, b"second\r\n.\r\n"));
        })
        .await;
        let kept = &body[..crate::session::MAX_HELD];
        assert_eq!(rec.mails[0].message, Some(sha(kept)));
        assert_eq!(std::fs::read(dir.join(sha(kept))).unwrap(), kept);
        assert_eq!(rec.mails[1].message, Some(sha(b"second\r\n")));
        assert!(rec.truncated);
        assert!(rec.bytes_in > body.len() as u64);
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn a_message_cut_off_is_kept_as_far_as_it_came() {
        let srv = server("mcut", 100_000, Duration::from_secs(5));
        let (rec, dir) = smtp(&srv, Protocol::Smtp, |mut c| {
            said(&mut c);
            ask(&mut c, "EHLO x");
            ask(&mut c, "MAIL FROM:<a@b>");
            ask(&mut c, "RCPT TO:<c@d>");
            ask(&mut c, "DATA");
            c.write_all(b"half a mess").unwrap();
        })
        .await;
        assert_eq!(rec.mails[0].message, Some(sha(b"half a mess")));
        assert!(dir.join(sha(b"half a mess")).is_file());
        assert!(rec.truncated);
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn a_message_still_arriving_at_the_time_cap_is_kept() {
        let srv = server("mslow", 100_000, Duration::from_secs(1));
        let (rec, _) = smtp(&srv, Protocol::Smtp, |mut c| {
            said(&mut c);
            ask(&mut c, "EHLO x");
            ask(&mut c, "MAIL FROM:<a@b>");
            ask(&mut c, "RCPT TO:<c@d>");
            ask(&mut c, "DATA");
            c.write_all(b"slow").unwrap();
            rest(&mut c);
        })
        .await;
        assert!(rec.timed_out);
        assert_eq!(rec.mails[0].message, Some(sha(b"slow")));
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn data_that_never_ends_ends_at_the_byte_cap() {
        let srv = server("mendless", 20_000, Duration::from_secs(5));
        let (rec, _) = smtp(&srv, Protocol::Smtp, |mut c| {
            said(&mut c);
            ask(&mut c, "EHLO x");
            ask(&mut c, "MAIL FROM:<a@b>");
            ask(&mut c, "RCPT TO:<c@d>");
            ask(&mut c, "DATA");
            for _ in 0..1600 {
                if c.write_all(&[b'x'; 64 * 1024]).is_err() {
                    return;
                }
            }
            panic!("never cut off");
        })
        .await;
        assert!(rec.truncated && !rec.timed_out);
        assert_eq!(rec.mails.len(), 1);
        cleanup(&srv.spool);
    }

    /// The client's half of a STARTTLS session on 25 or 587, up to the
    /// handshake; what was written with STARTTLS goes with it.
    fn starttls(mut c: Std, with: &str, ca: &[u8]) -> Tls {
        said(&mut c);
        let e = ask(&mut c, "EHLO bot.example");
        assert!(e.contains("\r\n250-STARTTLS\r\n"), "{e}");
        c.write_all(format!("STARTTLS\r\n{with}").as_bytes())
            .unwrap();
        assert_eq!(said(&mut c), "220 2.0.0 Ready to start TLS\r\n");
        tls_client(c, "mx.corp.example", ca)
    }

    #[tokio::test]
    async fn starttls_records_the_hello_and_the_mail_inside() {
        let (srv, ca) = server_with_ca("mstarttls", 100_000, Duration::from_secs(5));
        let (rec, dir) = smtp(&srv, Protocol::Smtp, move |c| {
            let mut t = starttls(c, "", &ca);
            // Everything before TLS is forgotten, the EHLO too.
            assert_eq!(
                ask(&mut t, "MAIL FROM:<a@b>"),
                "503 5.5.1 Error: send HELO/EHLO first\r\n"
            );
            // Not offered twice; the client says EHLO again.
            let e = ask(&mut t, "EHLO bot.example");
            assert!(e.starts_with("250-mail.web1\r\n"), "{e}");
            assert!(!e.contains("STARTTLS"), "{e}");
            assert_eq!(
                ask(&mut t, "STARTTLS"),
                "554 5.5.1 Error: TLS already active\r\n"
            );
            assert_eq!(ask(&mut t, "AUTH LOGIN dXNlcg=="), "334 UGFzc3dvcmQ6\r\n");
            assert!(ask(&mut t, "cGFzcw==").starts_with("235 "));
            queued(&send(&mut t, b"inside\r\n.\r\n"));
            assert_eq!(ask(&mut t, "QUIT"), "221 2.0.0 Bye\r\n");
        })
        .await;
        assert_eq!(rec.protocol, Protocol::Smtp);
        assert_eq!(rec.sni.as_deref(), Some("mx.corp.example"));
        assert!(rec.ja4.unwrap().starts_with("t13d"));
        assert_eq!(rec.credentials[0].user, "user");
        assert_eq!(rec.credentials[0].password.as_deref(), Some("pass"));
        assert_eq!(rec.mails[0].message, Some(sha(b"inside\r\n")));
        assert!(dir.join(sha(b"inside\r\n")).is_file());
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn plaintext_sent_with_starttls_is_never_run_inside_tls() {
        let (srv, ca) = server_with_ca("minject", 100_000, Duration::from_secs(5));
        let (rec, _) = smtp(&srv, Protocol::Smtp, move |c| {
            // MAIL is there too, so a leak would show in the record as
            // well as in the replies.
            let mut t = starttls(c, "RSET\r\nMAIL FROM:<injected@x>\r\n", &ca);
            // Had RSET run, its 250 would be the first thing read.
            let e = ask(&mut t, "EHLO bot.example");
            assert!(e.starts_with("250-mail.web1\r\n"), "{e}");
            // A transaction from before TLS is gone as well.
            assert_eq!(
                ask(&mut t, "RCPT TO:<a@b>"),
                "503 5.5.1 Error: need MAIL command\r\n"
            );
        })
        .await;
        assert!(rec.mails.is_empty());
        assert!(rec.ja4.is_some());
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn implicit_tls_on_465_speaks_smtp_inside() {
        let (srv, ca) = server_with_ca("msmtps", 100_000, Duration::from_secs(5));
        let (rec, _) = smtp(&srv, Protocol::Smtps, move |c| {
            let mut t = tls_client(c, "smtp.corp.example", &ca);
            assert_eq!(said(&mut t), "220 mail.web1 ESMTP Postfix\r\n");
            let e = ask(&mut t, "EHLO bot.example");
            assert!(e.contains("250-AUTH PLAIN LOGIN\r\n"), "{e}");
            assert!(!e.contains("STARTTLS"), "{e}");
            queued(&send(&mut t, b"over 465\r\n.\r\n"));
        })
        .await;
        assert_eq!(rec.protocol, Protocol::Smtps);
        assert_eq!(rec.sni.as_deref(), Some("smtp.corp.example"));
        assert!(rec.ja4.is_some());
        assert_eq!(rec.mails[0].message, Some(sha(b"over 465\r\n")));
        cleanup(&srv.spool);
    }

    #[tokio::test]
    async fn a_failed_handshake_is_still_fingerprinted() {
        let srv = server("mhs", 100_000, Duration::from_secs(5));
        let (rec, _) = smtp(&srv, Protocol::Smtps, |mut c| {
            c.write_all(include_bytes!("testdata/ja4/tls12.bin"))
                .unwrap();
            c.shutdown(std::net::Shutdown::Write).unwrap();
            rest(&mut c);
        })
        .await;
        assert_eq!(rec.sni.as_deref(), Some("contile.services.mozilla.com"));
        assert_eq!(
            rec.ja4.as_deref(),
            Some("t13d1715h2_5b57614c22b0_3d5424432f57")
        );
        cleanup(&srv.spool);
    }

    #[test]
    fn queue_ids_look_like_postfixs() {
        let (a, b) = (super::queue_id(), super::queue_id());
        assert_ne!(a, b);
        queued(&format!("250 2.0.0 Ok: queued as {a}\r\n"));
    }
}
