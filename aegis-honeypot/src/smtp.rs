// SPDX-License-Identifier: MIT OR Apache-2.0
//! SMTP as a client sends it: command lines, the addresses and AUTH
//! answers in them, and the end of a message. Pure, so the fuzz target
//! reaches all of it; the server that drives it is `mail.rs`.

/// The longest command line, its CRLF included (RFC 5321 4.5.3.1.4).
pub const MAX_LINE: usize = 1000;
/// Recipients one message may have; postfix allows 1000.
pub const MAX_RCPT: usize = 100;
/// The most of an address or name recorded: as long as a path may be
/// (RFC 5321 4.5.3.1.3).
pub const MAX_ADDR: usize = 256;

#[derive(Debug, PartialEq)]
pub enum Cmd<'a> {
    Helo(&'a [u8]),
    Ehlo(&'a [u8]),
    /// The address, or None when the argument isn't `FROM:<address>`.
    Mail(Option<&'a [u8]>),
    Rcpt(Option<&'a [u8]>),
    Data,
    Rset,
    Noop,
    Quit,
    StartTls,
    Vrfy,
    /// The mechanism, and the initial response if one was sent.
    Auth(&'a [u8], Option<&'a [u8]>),
    Empty,
    Unknown,
}

/// One command line, without its line ending.
pub fn command(line: &[u8]) -> Cmd<'_> {
    let (verb, arg) = word(line.trim_ascii());
    let is = |v: &[u8]| verb.eq_ignore_ascii_case(v);
    if verb.is_empty() {
        Cmd::Empty
    } else if is(b"HELO") {
        Cmd::Helo(arg)
    } else if is(b"EHLO") {
        Cmd::Ehlo(arg)
    } else if is(b"MAIL") {
        Cmd::Mail(path(arg, b"FROM:"))
    } else if is(b"RCPT") {
        // The null path is for senders only.
        Cmd::Rcpt(path(arg, b"TO:").filter(|a| !a.is_empty()))
    } else if is(b"DATA") {
        Cmd::Data
    } else if is(b"RSET") {
        Cmd::Rset
    } else if is(b"NOOP") {
        Cmd::Noop
    } else if is(b"QUIT") {
        Cmd::Quit
    } else if is(b"STARTTLS") {
        Cmd::StartTls
    } else if is(b"VRFY") {
        Cmd::Vrfy
    } else if is(b"AUTH") {
        let (mech, first) = word(arg);
        Cmd::Auth(mech, (!first.is_empty()).then_some(first))
    } else {
        Cmd::Unknown
    }
}

/// The first word of `b`, and the rest with its spaces trimmed.
fn word(b: &[u8]) -> (&[u8], &[u8]) {
    match b.iter().position(|&c| c == b' ') {
        Some(i) => (&b[..i], b[i + 1..].trim_ascii()),
        None => (b, &[]),
    }
}

/// The address in `FROM:<a@b> params` or `TO:<a@b>`, after `key`.
fn path<'a>(arg: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    if !arg.get(..key.len())?.eq_ignore_ascii_case(key) {
        return None;
    }
    let rest = arg[key.len()..].trim_ascii_start();
    match rest.strip_prefix(b"<") {
        Some(r) => r.get(..r.iter().position(|&c| c == b'>')?),
        // postfix takes an address without brackets too.
        None => Some(word(rest).0).filter(|a| !a.is_empty()),
    }
}

/// Standard base64 (RFC 4648 4), padding required, nothing else
/// allowed. The output is never longer than the input.
pub fn base64(b: &[u8]) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    }
    let (quads, rest) = b.as_chunks::<4>();
    if !rest.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(quads.len() * 3);
    for (i, q) in quads.iter().enumerate() {
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && i + 1 < quads.len()) {
            return None;
        }
        let mut n = 0u32;
        for &c in &q[..4 - pad] {
            n = n << 6 | value(c)?;
        }
        n <<= 6 * pad;
        out.extend_from_slice(&n.to_be_bytes()[1..4 - pad]);
    }
    Some(out)
}

/// The user and password in an AUTH PLAIN response (RFC 4616):
/// `authzid NUL authcid NUL passwd`.
pub fn plain(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut f = b.split(|&c| c == 0);
    let (_, user, password) = (f.next()?, f.next()?, f.next()?);
    f.next().is_none().then_some((user, password))
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum At {
    /// The start of a line.
    #[default]
    Start,
    /// A line that began with a dot.
    Dot,
    /// A line that began with a dot and a CR.
    DotCr,
    /// Anywhere else.
    Mid,
}

/// Finds the end of a message (a line holding only a dot) across reads
/// and undoes dot-stuffing (RFC 5321 4.5.2). It holds no bytes of its
/// own, so a line of any length costs nothing.
#[derive(Default)]
pub struct Dot(At);

impl Dot {
    /// Hands each run of message bytes in `b` to `keep`. Some(n) when
    /// the end line finishes at `b[n - 1]`; the rest of `b` is the next
    /// command.
    pub fn feed(&mut self, b: &[u8], keep: &mut impl FnMut(&[u8])) -> Option<usize> {
        // The start of the run not yet handed on; a dropped dot (or the
        // CR after one, until it's known not to end the message) moves
        // it past.
        let mut from = 0;
        for (i, &c) in b.iter().enumerate() {
            self.0 = match (self.0, c) {
                (At::Dot | At::DotCr, b'\n') => {
                    self.0 = At::Start;
                    return Some(i + 1);
                }
                (At::Start, b'.') => {
                    keep(&b[from..i]);
                    from = i + 1;
                    At::Dot
                }
                (At::Dot, b'\r') => {
                    from = i + 1;
                    At::DotCr
                }
                (At::DotCr, _) => {
                    keep(b"\r");
                    At::Mid
                }
                (_, b'\n') => At::Start,
                _ => At::Mid,
            };
        }
        keep(&b[from..]);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_case_blind_and_take_their_arguments() {
        for (line, want) in [
            (&b"EHLO bot.example"[..], Cmd::Ehlo(b"bot.example")),
            (b"ehlo  [10.0.0.2] ", Cmd::Ehlo(b"[10.0.0.2]")),
            (b"HELO", Cmd::Helo(b"")),
            (
                b"MAIL FROM:<a@b.example> SIZE=10",
                Cmd::Mail(Some(b"a@b.example")),
            ),
            (b"mail from: <a@b>", Cmd::Mail(Some(b"a@b"))),
            (b"MAIL FROM:<>", Cmd::Mail(Some(b""))),
            (b"MAIL FROM:a@b BODY=8BITMIME", Cmd::Mail(Some(b"a@b"))),
            (b"MAIL TO:<a@b>", Cmd::Mail(None)),
            (b"MAIL FROM:<a@b", Cmd::Mail(None)),
            (b"MAIL FROM:", Cmd::Mail(None)),
            (b"MAIL", Cmd::Mail(None)),
            (b"RCPT TO:<x@y>", Cmd::Rcpt(Some(b"x@y"))),
            (b"RCPT TO:<>", Cmd::Rcpt(None)),
            (b"RCPT FROM:<x@y>", Cmd::Rcpt(None)),
            (b"DATA", Cmd::Data),
            (b"rset", Cmd::Rset),
            (b"NOOP hello", Cmd::Noop),
            (b"QUIT", Cmd::Quit),
            (b"StartTLS", Cmd::StartTls),
            (b"VRFY root", Cmd::Vrfy),
            (
                b"AUTH PLAIN AGEAYg==",
                Cmd::Auth(b"PLAIN", Some(b"AGEAYg==")),
            ),
            (b"AUTH login", Cmd::Auth(b"login", None)),
            (b"AUTH", Cmd::Auth(b"", None)),
            (b"", Cmd::Empty),
            (b"   ", Cmd::Empty),
            (b"BDAT 10 LAST", Cmd::Unknown),
            (b"MAILX FROM:<a@b>", Cmd::Unknown),
            (b"\xff\x00", Cmd::Unknown),
        ] {
            assert_eq!(command(line), want, "{:?}", String::from_utf8_lossy(line));
        }
    }

    #[test]
    fn base64_decodes_only_what_rfc_4648_allows() {
        for (s, want) in [
            (&b""[..], Some(&b""[..])),
            (b"Zg==", Some(b"f")),
            (b"Zm8=", Some(b"fo")),
            (b"Zm9v", Some(b"foo")),
            (b"Zm9vYmFy", Some(b"foobar")),
            (b"AHJvb3QAMTIzNDU2", Some(b"\x00root\x00123456")),
            (b"+/+/", Some(b"\xfb\xff\xbf")),
            (b"Zg", None),
            (b"Zg=", None),
            (b"Zg===", None),
            (b"Z===", None),
            (b"Zg==Zg==", None),
            (b"Zm9v\r", None),
            (b"Zm 9v", None),
            (b"Zm9-", None),
        ] {
            assert_eq!(
                base64(s).as_deref(),
                want,
                "{:?}",
                String::from_utf8_lossy(s)
            );
        }
    }

    #[test]
    fn plain_gives_the_user_and_password() {
        assert_eq!(
            plain(b"\x00root\x00123456"),
            Some((&b"root"[..], &b"123456"[..]))
        );
        assert_eq!(plain(b"admin\0root\0pw"), Some((&b"root"[..], &b"pw"[..])));
        // NUL can't be in a password, so a third one is a bad answer.
        assert_eq!(plain(b"\0root\0p\0w"), None);
        assert_eq!(plain(b"\0root"), None);
        assert_eq!(plain(b"root"), None);
    }

    /// The message and where it ended, from `parts` fed in turn.
    fn read(parts: &[&[u8]]) -> (Vec<u8>, Option<(usize, usize)>) {
        let mut d = Dot::default();
        let mut got = Vec::new();
        for (i, p) in parts.iter().enumerate() {
            if let Some(n) = d.feed(p, &mut |b| got.extend_from_slice(b)) {
                return (got, Some((i, n)));
            }
        }
        (got, None)
    }

    #[test]
    fn a_message_ends_at_a_lone_dot_with_its_stuffing_undone() {
        let msg = b"Subject: x\r\n\r\n..leading dot\r\n.\r\nQUIT\r\n";
        let want = b"Subject: x\r\n\r\n.leading dot\r\n".to_vec();
        let (got, end) = read(&[msg]);
        assert_eq!(got, want);
        assert_eq!(end, Some((0, msg.len() - 6)));
        // Cut anywhere, it reads the same.
        for cut in 0..=msg.len() {
            let (a, b) = msg.split_at(cut);
            let (got, end) = read(&[a, b]);
            assert_eq!(got, want, "cut at {cut}");
            let (i, n) = end.unwrap();
            assert_eq!(
                if i == 0 { n } else { cut + n },
                msg.len() - 6,
                "cut at {cut}"
            );
        }
        // A byte at a time.
        let bytes: Vec<&[u8]> = msg.chunks(1).collect();
        assert_eq!(read(&bytes).0, want);
    }

    #[test]
    fn only_a_line_holding_just_a_dot_ends_it() {
        for (msg, want, ends) in [
            // Straight away: an empty message.
            (&b".\r\n"[..], &b""[..], true),
            (b".\n", b"", true),
            (b"a\n.\n", b"a\n", true),
            (b"a\r\n. \r\n", b"a\r\n \r\n", false),
            (b"a\r\n.x\r\n", b"a\r\nx\r\n", false),
            (b"a\r\n.\r\r\n", b"a\r\n\r\r\n", false),
            (b"a.\r\nb", b"a.\r\nb", false),
            (b"\r\n..\r\n", b"\r\n.\r\n", false),
        ] {
            let (got, end) = read(&[msg]);
            assert_eq!(got, want, "{:?}", String::from_utf8_lossy(msg));
            assert_eq!(end.is_some(), ends, "{:?}", String::from_utf8_lossy(msg));
        }
    }
}
