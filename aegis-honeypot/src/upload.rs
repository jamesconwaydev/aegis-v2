// SPDX-License-Identifier: MIT OR Apache-2.0
//! The two ways a client sends a file up over SSH: scp's sink protocol
//! (`scp -t`) and the write path of SFTP version 3. Both are fed the
//! client's bytes, which are hostile: every length is checked against
//! what arrived, nothing the client claims sizes an allocation, and a
//! name is only ever handed on as bytes, never used as a path.

/// What a client did with a file. Data comes at the offset it gives.
#[derive(Debug, PartialEq)]
pub enum Event<'a> {
    Start(&'a [u8]),
    Data(u64, &'a [u8]),
    End,
}

/// Bytes no real client sends: the channel is closed.
#[derive(Debug, PartialEq)]
pub struct Bad;

/// The longest scp control line waited for.
pub const MAX_LINE: usize = 1024;
/// The longest SFTP packet held. OpenSSH's clients write 32 KiB at a
/// time unless the server offers more.
pub const MAX_PACKET: usize = 64 * 1024;

/// scp's sink side: control lines, then each file's bytes.
#[derive(Default)]
pub struct Scp {
    line: Vec<u8>,
    /// Bytes of the current file still to come, or None between files.
    left: Option<u64>,
    /// Where the next of them goes.
    at: u64,
    /// A file's bytes are done; the source's status byte comes next.
    ack: bool,
}

/// `C<mode> <size> <name>`: the mode four octal digits, the size plain
/// decimal, the name one path component.
fn file_line(l: &[u8]) -> Option<(u64, &[u8])> {
    let mut parts = l.get(1..)?.splitn(3, |&b| b == b' ');
    let (mode, size, name) = (parts.next()?, parts.next()?, parts.next()?);
    let size = std::str::from_utf8(size).ok()?;
    let ok = mode.len() == 4
        && mode.iter().all(|b| (b'0'..=b'7').contains(b))
        && !size.is_empty()
        && size.bytes().all(|b| b.is_ascii_digit())
        && !name.is_empty()
        && !name.contains(&b'/')
        && name != b"..";
    ok.then(|| Some((size.parse().ok()?, name))).flatten()
}

impl Scp {
    /// Takes the next of the client's bytes. Replies go to `out`.
    pub fn feed(
        &mut self,
        mut data: &[u8],
        out: &mut Vec<u8>,
        f: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Bad> {
        while let Some((&first, rest)) = data.split_first() {
            if let Some(left) = self.left {
                let n = data.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                f(Event::Data(self.at, &data[..n]));
                self.at += n as u64;
                data = &data[n..];
                if left == n as u64 {
                    self.left = None;
                    self.ack = true;
                    f(Event::End);
                } else {
                    self.left = Some(left - n as u64);
                }
            } else if self.ack {
                if first != 0 {
                    return Err(Bad);
                }
                self.ack = false;
                out.push(0);
                data = rest;
            } else {
                let end = data.iter().position(|&b| b == b'\n');
                let take = end.unwrap_or(data.len());
                if self.line.len() + take > MAX_LINE {
                    return Err(Bad);
                }
                self.line.extend_from_slice(&data[..take]);
                let Some(end) = end else {
                    return Ok(());
                };
                data = &data[end + 1..];
                match self.line.first() {
                    Some(b'C') => {
                        let (size, name) = file_line(&self.line).ok_or(Bad)?;
                        f(Event::Start(name));
                        out.push(0);
                        self.at = 0;
                        if size == 0 {
                            self.ack = true;
                            f(Event::End);
                        } else {
                            self.left = Some(size);
                        }
                    }
                    // Directories and times: nothing to keep.
                    Some(b'D' | b'E' | b'T') => out.push(0),
                    // The source's warnings and errors.
                    Some(1 | 2) => {}
                    _ => return Err(Bad),
                }
                self.line.clear();
            }
        }
        Ok(())
    }
}

/// An SFTP server that takes one file at a time and refuses the rest.
#[derive(Default)]
pub struct Sftp {
    buf: Vec<u8>,
    /// A file is open for writing, under `HANDLE`.
    open: bool,
}

const VERSION: u8 = 2;
const OPEN: u8 = 3;
const CLOSE: u8 = 4;
const WRITE: u8 = 6;
const REALPATH: u8 = 16;
const STATUS: u8 = 101;
const HANDLE_REPLY: u8 = 102;
const NAME: u8 = 104;
const FXF_WRITE: u32 = 2;
const OK: u32 = 0;
const PERMISSION_DENIED: u32 = 3;
const HANDLE: &[u8] = b"1";

/// Reads a packet's fields, each checked against what's left.
struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Bad> {
        let (a, b) = self.0.split_at_checked(n).ok_or(Bad)?;
        self.0 = b;
        Ok(a)
    }

    fn u32(&mut self) -> Result<u32, Bad> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| Bad)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, Bad> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Bad)?,
        ))
    }

    fn string(&mut self) -> Result<&'a [u8], Bad> {
        let n = self.u32()?;
        self.take(usize::try_from(n).map_err(|_| Bad)?)
    }
}

/// Appends one reply packet made of `parts`.
fn reply(out: &mut Vec<u8>, parts: &[&[u8]]) {
    let len: usize = parts.iter().map(|p| p.len()).sum();
    out.extend_from_slice(&(len as u32).to_be_bytes());
    for p in parts {
        out.extend_from_slice(p);
    }
}

fn string(b: &[u8]) -> Vec<u8> {
    [&(b.len() as u32).to_be_bytes()[..], b].concat()
}

fn status(out: &mut Vec<u8>, id: u32, code: u32) {
    let msg: &[u8] = if code == OK {
        b"Success"
    } else {
        b"Permission denied"
    };
    reply(
        out,
        &[
            &[STATUS],
            &id.to_be_bytes(),
            &code.to_be_bytes(),
            &string(msg),
            &string(b""),
        ],
    );
}

impl Sftp {
    /// Takes the next of the client's bytes. Replies go to `out`.
    pub fn feed(
        &mut self,
        data: &[u8],
        out: &mut Vec<u8>,
        f: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Bad> {
        // Never more than one packet and one read held.
        self.buf.extend_from_slice(data);
        let mut at = 0;
        while let Some(len) = self.buf.get(at..at + 4) {
            let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
            if len == 0 || len > MAX_PACKET {
                return Err(Bad);
            }
            let Some(p) = self.buf.get(at + 4..at + 4 + len) else {
                break;
            };
            packet(p, &mut self.open, out, f)?;
            at += 4 + len;
        }
        self.buf.drain(..at);
        Ok(())
    }
}

/// Answers one packet: version 3, a cwd of /root, and one file open
/// for writing at a time. Everything else is refused.
fn packet(
    p: &[u8],
    open: &mut bool,
    out: &mut Vec<u8>,
    f: &mut impl FnMut(Event<'_>),
) -> Result<(), Bad> {
    let mut r = R(p);
    let t = r.take(1)?[0];
    if t == 1 {
        r.u32()?;
        reply(out, &[&[VERSION], &3u32.to_be_bytes()]);
        return Ok(());
    }
    let id = r.u32()?;
    match t {
        OPEN => {
            let name = r.string()?;
            if r.u32()? & FXF_WRITE == 0 || *open {
                status(out, id, PERMISSION_DENIED);
            } else {
                *open = true;
                f(Event::Start(name));
                reply(out, &[&[HANDLE_REPLY], &id.to_be_bytes(), &string(HANDLE)]);
            }
        }
        CLOSE => {
            if *open && r.string()? == HANDLE {
                *open = false;
                f(Event::End);
                status(out, id, OK);
            } else {
                status(out, id, PERMISSION_DENIED);
            }
        }
        WRITE => {
            let (h, off, data) = (r.string()?, r.u64()?, r.string()?);
            if *open && h == HANDLE {
                f(Event::Data(off, data));
                status(out, id, OK);
            } else {
                status(out, id, PERMISSION_DENIED);
            }
        }
        // sftp(1) asks where it is before anything else, and quits
        // without an answer.
        REALPATH => {
            let path = match r.string()? {
                b"" | b"." => b"/root".to_vec(),
                p if p.starts_with(b"/") => p.to_vec(),
                p => [b"/root/", p].concat(),
            };
            let path = string(&path);
            reply(
                out,
                &[
                    &[NAME],
                    &id.to_be_bytes(),
                    &1u32.to_be_bytes(),
                    &path,
                    &path,
                    &[0; 4],
                ],
            );
        }
        _ => status(out, id, PERMISSION_DENIED),
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An event, owned.
    #[derive(Debug, PartialEq)]
    pub enum Ev {
        Start(Vec<u8>),
        Data(u64, Vec<u8>),
        End,
    }

    pub fn own(e: Event<'_>) -> Ev {
        match e {
            Event::Start(n) => Ev::Start(n.to_vec()),
            Event::Data(o, d) => Ev::Data(o, d.to_vec()),
            Event::End => Ev::End,
        }
    }

    fn scp(chunks: &[&[u8]]) -> (Result<(), Bad>, Vec<u8>, Vec<Ev>) {
        let (mut s, mut out, mut evs) = (Scp::default(), Vec::new(), Vec::new());
        for c in chunks {
            if let Err(e) = s.feed(c, &mut out, &mut |e| evs.push(own(e))) {
                return (Err(e), out, evs);
            }
        }
        (Ok(()), out, evs)
    }

    #[test]
    fn scp_takes_a_file_however_it_arrives() {
        let want = vec![
            Ev::Start(b"evil.sh".to_vec()),
            Ev::Data(0, b"hel".to_vec()),
            Ev::Data(3, b"lo".to_vec()),
            Ev::End,
        ];
        let (r, out, evs) = scp(&[b"T1 0 1 0\nC0755 5 evi", b"l.sh\nhel", b"lo\0"]);
        assert_eq!(r, Ok(()));
        assert_eq!(evs, want);
        // One for the time, one for the header, one for the data.
        assert_eq!(out, [0, 0, 0]);
        // All at once, the same.
        let (_, out, evs) = scp(&[b"T1 0 1 0\nC0755 5 evil.sh\nhello\0"]);
        assert_eq!(out, [0, 0, 0]);
        assert_eq!(evs[0], want[0]);
        assert_eq!(evs[1], Ev::Data(0, b"hello".to_vec()));
    }

    #[test]
    fn scp_takes_several_files_and_directories() {
        let (r, out, evs) = scp(&[b"D0755 0 d\nC0644 0 empty\n\0C0644 2 b\nhi\0E\n"]);
        assert_eq!(r, Ok(()));
        assert_eq!(out, [0; 6]);
        assert_eq!(
            evs,
            [
                Ev::Start(b"empty".to_vec()),
                Ev::End,
                Ev::Start(b"b".to_vec()),
                Ev::Data(0, b"hi".to_vec()),
                Ev::End
            ]
        );
        // The source's own warnings get no answer.
        let (r, out, _) = scp(&[b"\x01scp: x: No such file\n"]);
        assert_eq!((r, out), (Ok(()), vec![]));
    }

    #[test]
    fn scp_refuses_what_no_client_sends() {
        for bad in [
            &b"X\n"[..],
            b"C0644 5\n",
            b"C0644 -5 a\n",
            b"C0644 5x a\n",
            b"C0644 99999999999999999999 a\n",
            b"C0644 5 \n",
            b"C0644 5 a/b\n",
            b"C0644 5 ..\n",
            b"C0999 5 a\n",
            b"C 5 a\n",
            b"C0644 1 a\nxy",
        ] {
            assert_eq!(
                scp(&[bad]).0,
                Err(Bad),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        // A line longer than any real one, with or without its newline.
        assert_eq!(scp(&[&[b'T'; MAX_LINE + 1]]).0, Err(Bad));
        // A size the client claims sizes nothing: data is passed on as
        // it comes.
        let (r, _, evs) = scp(&[b"C0644 18446744073709551615 a\nxyz"]);
        assert_eq!(r, Ok(()));
        assert_eq!(evs[1], Ev::Data(0, b"xyz".to_vec()));
    }

    /// An SFTP packet: length, type, then `body`.
    pub fn pkt(t: u8, body: &[u8]) -> Vec<u8> {
        [&(body.len() as u32 + 1).to_be_bytes()[..], &[t], body].concat()
    }

    pub fn s(b: &[u8]) -> Vec<u8> {
        [&(b.len() as u32).to_be_bytes()[..], b].concat()
    }

    pub fn id(n: u32) -> Vec<u8> {
        n.to_be_bytes().to_vec()
    }

    /// Splits replies into (type, id, rest).
    pub fn replies(mut out: &[u8]) -> Vec<(u8, u32, Vec<u8>)> {
        let mut r = Vec::new();
        while !out.is_empty() {
            let len = u32::from_be_bytes(out[..4].try_into().unwrap()) as usize;
            let p = &out[4..4 + len];
            let id = if p[0] == 2 {
                0
            } else {
                u32::from_be_bytes(p[1..5].try_into().unwrap())
            };
            r.push((p[0], id, p[5.min(p.len())..].to_vec()));
            out = &out[4 + len..];
        }
        r
    }

    fn status(code: u32) -> Vec<u8> {
        let msg: &[u8] = if code == 0 {
            b"Success"
        } else {
            b"Permission denied"
        };
        [&code.to_be_bytes()[..], &s(msg), &s(b"")].concat()
    }

    /// The result, the replies split up, and the events.
    type Fed = (Result<(), Bad>, Vec<(u8, u32, Vec<u8>)>, Vec<Ev>);

    fn sftp(input: &[u8]) -> Fed {
        let (mut p, mut out, mut evs) = (Sftp::default(), Vec::new(), Vec::new());
        let r = p.feed(input, &mut out, &mut |e| evs.push(own(e)));
        (r, replies(&out), evs)
    }

    #[test]
    fn sftp_takes_a_put_and_refuses_the_rest() {
        let open = |n, flags: u32| {
            pkt(
                3,
                &[id(n), s(b"/tmp/x.sh"), flags.to_be_bytes().to_vec(), id(0)].concat(),
            )
        };
        let write = |n, h: &[u8], off: u64, d: &[u8]| {
            pkt(6, &[id(n), s(h), off.to_be_bytes().to_vec(), s(d)].concat())
        };
        let input = [
            pkt(1, &id(3)),
            pkt(16, &[id(1), s(b".")].concat()),
            pkt(17, &[id(2), s(b"/tmp/x.sh")].concat()),
            // Read only: refused.
            open(3, 1),
            // WRITE|CREAT|TRUNC.
            open(4, 0x1a),
            // A second file while one is open: refused.
            open(5, 0x1a),
            write(6, b"1", 0, b"hel"),
            write(7, b"1", 3, b"lo"),
            write(8, b"2", 5, b"!"),
            pkt(4, &[id(9), s(b"1")].concat()),
            pkt(11, &[id(10), s(b"/")].concat()),
            pkt(16, &[id(11), s(b"up")].concat()),
        ]
        .concat();
        // Byte by byte, as a slow client's bytes might come.
        let (mut p, mut out, mut evs) = (Sftp::default(), Vec::new(), Vec::new());
        for b in input.chunks(1) {
            p.feed(b, &mut out, &mut |e| evs.push(own(e))).unwrap();
        }
        let name = |p: &[u8]| [&id(1)[..], &s(p), &s(p), &id(0)].concat();
        assert_eq!(
            replies(&out),
            [
                (2, 0, vec![]),
                (104, 1, name(b"/root")),
                (101, 2, status(3)),
                (101, 3, status(3)),
                (102, 4, s(b"1")),
                (101, 5, status(3)),
                (101, 6, status(0)),
                (101, 7, status(0)),
                (101, 8, status(3)),
                (101, 9, status(0)),
                (101, 10, status(3)),
                (104, 11, name(b"/root/up")),
            ]
        );
        assert_eq!(
            evs,
            [
                Ev::Start(b"/tmp/x.sh".to_vec()),
                Ev::Data(0, b"hel".to_vec()),
                Ev::Data(3, b"lo".to_vec()),
                Ev::End
            ]
        );
        // All at once, the same.
        let (r, rs, evs2) = sftp(&input);
        assert_eq!(r, Ok(()));
        assert_eq!(rs, replies(&out));
        assert_eq!(evs2, evs);
        // VERSION 3 exactly, no extensions.
        let mut o = Vec::new();
        Sftp::default()
            .feed(&pkt(1, &id(6)), &mut o, &mut |_| {})
            .unwrap();
        assert_eq!(o, [0, 0, 0, 5, 2, 0, 0, 0, 3]);
    }

    #[test]
    fn sftp_refuses_what_no_client_sends() {
        for bad in [
            // Too big to hold, or nothing.
            [&((MAX_PACKET + 1) as u32).to_be_bytes()[..], &[3]].concat(),
            vec![0, 0, 0, 0],
            // No id.
            pkt(3, &[0, 0]),
            // A string longer than the packet.
            pkt(16, &[id(1), vec![0, 0, 0, 9, b'x']].concat()),
            pkt(1, &[]),
            pkt(6, &[id(1), s(b"1"), vec![0; 7]].concat()),
        ] {
            assert_eq!(sftp(&bad).0, Err(Bad), "{bad:?}");
        }
        // A length that's coming is waited for, not refused.
        assert_eq!(sftp(&[0, 0, 1]).0, Ok(()));
        assert_eq!(sftp(&[0, 1, 0, 0, 3]).0, Ok(()));
    }
}
