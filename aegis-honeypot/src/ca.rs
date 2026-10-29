// SPDX-License-Identifier: MIT OR Apache-2.0
//! The host's honeypot CA, and a leaf for whatever name a TLS client
//! asks for, signed by it. `ca.key` never leaves the state directory;
//! `ca.pem` is what a host that wants to see inside HTTPS trusts, and
//! `ca.name` the subject it was made with, so a renamed host still
//! signs as the CA its clients trust.

use std::ffi::OsString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SerialNumber,
};
use rustls::crypto::{ring, SecureRandom};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};

/// The name a leaf carries when the client sent no usable SNI.
pub const DEFAULT_NAME: &str = "localhost";

pub struct Certs {
    issuer: Issuer<'static, KeyPair>,
    /// One key for every leaf: minting is then one signature, cheap
    /// enough to do per handshake with no cache to bound.
    leaf: KeyPair,
    signer: Arc<dyn SigningKey>,
    random: &'static dyn SecureRandom,
}

impl fmt::Debug for Certs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Certs")
    }
}

fn remove(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn tmp(path: &Path) -> PathBuf {
    let mut t = OsString::from(path);
    t.push(".tmp");
    PathBuf::from(t)
}

/// Makes what's in `dir` durable: the links `create_once` made.
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Writes `path` whole or not at all, and never over a file already
/// there: the bytes go to a synced tmp file first, and the hard link
/// into place fails if `path` exists. `load` has removed any old tmp.
fn create_once(path: &Path, mode: u32, data: &str) -> io::Result<()> {
    let tmp = tmp(path);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(data.as_bytes())?;
    f.sync_all()?;
    let linked = std::fs::hard_link(&tmp, path);
    remove(&tmp)?;
    linked
}

fn named(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

impl Certs {
    /// The CA in `dir`. On first start, or once `ca.key` is moved aside,
    /// a new key and a fresh `ca.pem` and `ca.name` to go with it (any
    /// left over are replaced: they're public). After that the three are
    /// kept; a lost `ca.pem` is made again from the key. A `ca.key` that
    /// won't parse, or has no `ca.name`, is an error and never replaced.
    pub fn load(dir: &Path, host: &str) -> Result<Self> {
        let (key_path, pem_path, name_path) =
            (dir.join("ca.key"), dir.join("ca.pem"), dir.join("ca.name"));
        // One start at a time, from here to the last file, or two could
        // pair a key with the other's ca.pem. Released when it closes.
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(dir.join("ca.lock"))
            .with_context(|| dir.join("ca.lock").display().to_string())?;
        // SAFETY: a valid fd for as long as `lock` lives; flock only
        // takes the lock.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            bail!("ca.lock: {}", io::Error::last_os_error());
        }
        // A start that died part-way may have left a tmp copy, of the
        // private key even; never leave one lying about.
        for p in [&key_path, &pem_path, &name_path] {
            remove(&tmp(p)).with_context(|| tmp(p).display().to_string())?;
        }
        let (key, name, fresh) = match std::fs::read(&key_path) {
            Ok(pem) => {
                let key = std::str::from_utf8(&pem)
                    .ok()
                    .and_then(|p| KeyPair::from_pem(p).ok())
                    .with_context(|| {
                        format!(
                            "{} is not a key; move it aside to make a new CA",
                            key_path.display()
                        )
                    })?;
                let name = std::fs::read_to_string(&name_path)
                    .ok()
                    .map(|n| n.trim().to_string())
                    .filter(|n| !n.is_empty())
                    .with_context(|| {
                        format!(
                            "{} is missing or empty, so {} can't sign as the CA clients trust; \
                             move ca.key aside to make a new CA",
                            name_path.display(),
                            key_path.display()
                        )
                    })?;
                (key, name, false)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => (
                KeyPair::generate()?,
                format!("Aegis Honeypot CA {host}"),
                true,
            ),
            Err(e) => bail!("{}: {e}", key_path.display()),
        };
        let now = OffsetDateTime::now_utc();
        let mut ca = CertificateParams::default();
        ca.distinguished_name = named(&name);
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca.not_before = now - Duration::days(1);
        ca.not_after = now + Duration::days(3653);
        let pem = ca.self_signed(&key)?.pem();
        let file = |p: &Path, e: io::Error| anyhow!("{}: {e}", p.display());
        if fresh {
            // The key goes last: a start that dies before it leaves no
            // key, and the next makes the whole set again.
            for (p, data) in [(&name_path, format!("{name}\n")), (&pem_path, pem)] {
                remove(p)
                    .and_then(|()| create_once(p, 0o644, &data))
                    .map_err(|e| file(p, e))?;
            }
            // Durable before the key exists, so a power cut can't keep
            // the key and lose its name.
            sync_dir(dir).map_err(|e| file(dir, e))?;
            create_once(&key_path, 0o400, &key.serialize_pem()).map_err(|e| file(&key_path, e))?;
            sync_dir(dir).map_err(|e| file(dir, e))?;
        } else {
            match create_once(&pem_path, 0o644, &pem) {
                Err(e) if e.kind() != ErrorKind::AlreadyExists => return Err(file(&pem_path, e)),
                _ => {}
            }
        }
        drop(lock);
        let leaf = KeyPair::generate()?;
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.serialize_der()));
        let provider = ring::default_provider();
        Ok(Self {
            issuer: Issuer::new(ca, key),
            signer: ring::sign::any_supported_type(&der)?,
            leaf,
            random: provider.secure_random,
        })
    }

    /// A leaf for `name`, valid from yesterday for a year.
    fn mint(&self, name: &str) -> Result<CertifiedKey> {
        let mut p = CertificateParams::new(vec![name.to_string()])?;
        // RFC 5280's upper bound on a CN; the SAN carries any name.
        p.distinguished_name = if name.len() <= 64 {
            named(name)
        } else {
            DistinguishedName::new()
        };
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        // Every leaf shares a key, so rcgen's default serial (a hash of
        // it) would repeat: random, and positive (RFC 5280 4.1.2.2).
        let mut serial = [0u8; 16];
        self.random
            .fill(&mut serial)
            .map_err(|_| anyhow!("no randomness for a serial"))?;
        serial[0] &= 0x7f;
        p.serial_number = Some(SerialNumber::from_slice(&serial));
        let now = OffsetDateTime::now_utc();
        p.not_before = now - Duration::days(1);
        p.not_after = now + Duration::days(365);
        let cert = p.signed_by(&self.leaf, &self.issuer)?;
        Ok(CertifiedKey::new(
            vec![cert.der().clone()],
            self.signer.clone(),
        ))
    }
}

impl ResolvesServerCert for Certs {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // rustls has already refused a name that isn't a DNS name, and
        // turned an IP address into None.
        let name = hello.server_name().unwrap_or(DEFAULT_NAME);
        self.mint(name).ok().map(Arc::new)
    }
}

/// TLS 1.2 and 1.3 with ring, a leaf per name from `certs`.
pub fn config(certs: Certs) -> Result<Arc<ServerConfig>> {
    let c = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(certs));
    Ok(Arc::new(c))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, ServerConnection};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aegis-ca-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir(&d).unwrap();
        d
    }

    /// A server config on a fresh CA, and the CA to trust it by.
    pub fn tls(name: &str) -> (Arc<ServerConfig>, Vec<u8>) {
        let d = dir(name);
        let c = config(Certs::load(&d, "test").unwrap()).unwrap();
        let pem = std::fs::read(d.join("ca.pem")).unwrap();
        std::fs::remove_dir_all(d).unwrap();
        (c, pem)
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// A full handshake in memory, for `name`, by a client that trusts
    /// only `ca`.
    fn handshake(srv: &Arc<ServerConfig>, ca: &[u8], name: &str) -> Result<(), rustls::Error> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(ca).unwrap())
            .unwrap();
        let cfg = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(name.to_string()).unwrap();
        let mut c = ClientConnection::new(Arc::new(cfg), name)?;
        let mut s = ServerConnection::new(srv.clone())?;
        for _ in 0..10 {
            let mut b = Vec::new();
            while c.wants_write() {
                c.write_tls(&mut b).unwrap();
            }
            let mut r = &b[..];
            while !r.is_empty() {
                s.read_tls(&mut r).unwrap();
                s.process_new_packets()?;
            }
            let mut b = Vec::new();
            while s.wants_write() {
                s.write_tls(&mut b).unwrap();
            }
            let mut r = &b[..];
            while !r.is_empty() {
                c.read_tls(&mut r).unwrap();
                c.process_new_packets()?;
            }
            if !c.is_handshaking() && !s.is_handshaking() {
                return Ok(());
            }
        }
        panic!("the handshake never finished");
    }

    fn files(d: &Path) -> [Vec<u8>; 3] {
        ["ca.key", "ca.pem", "ca.name"].map(|f| std::fs::read(d.join(f)).unwrap())
    }

    #[test]
    fn the_first_start_makes_the_ca_and_later_ones_keep_it() {
        let d = dir("first");
        // A tmp file left by a start that died doesn't block the next.
        std::fs::write(d.join("ca.key.tmp"), "half").unwrap();
        let first = config(Certs::load(&d, "web1").unwrap()).unwrap();
        assert_eq!(mode(&d.join("ca.key")), 0o400);
        for f in ["ca.pem", "ca.name"] {
            assert_eq!(mode(&d.join(f)) & 0o622, 0o600, "{f}");
        }
        assert!(!d.join("ca.key.tmp").exists());
        let [k, p, n] = files(&d);
        assert!(String::from_utf8_lossy(&k).starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(String::from_utf8_lossy(&p).starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(n, b"Aegis Honeypot CA web1\n");
        handshake(&first, &p, "c2.example").unwrap();
        // The host has been renamed since: everything is kept, and the
        // leaves still chain to the ca.pem it already trusts.
        let later = config(Certs::load(&d, "web2").unwrap()).unwrap();
        assert_eq!(files(&d), [k.clone(), p.clone(), n.clone()]);
        handshake(&later, &p, "c2.example").unwrap();
        // A lost ca.pem comes back from the key that's there.
        std::fs::remove_file(d.join("ca.pem")).unwrap();
        let again = config(Certs::load(&d, "web3").unwrap()).unwrap();
        let [k2, p2, _] = files(&d);
        assert_eq!(k2, k);
        handshake(&again, &p2, "c2.example").unwrap();
        handshake(&again, &p, "c2.example").unwrap();
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_new_key_gets_a_new_ca_pem_and_name() {
        let d = dir("rekey");
        Certs::load(&d, "web1").unwrap();
        let [_, old, _] = files(&d);
        // Moved aside by an operator: the stale ca.pem and ca.name go too.
        std::fs::rename(d.join("ca.key"), d.join("old.key")).unwrap();
        let srv = config(Certs::load(&d, "web2").unwrap()).unwrap();
        let [_, new, name] = files(&d);
        assert_eq!(name, b"Aegis Honeypot CA web2\n");
        handshake(&srv, &new, "c2.example").unwrap();
        assert!(handshake(&srv, &old, "c2.example").is_err());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn no_tmp_copy_of_the_key_outlives_a_start() {
        let d = dir("tmp");
        Certs::load(&d, "web1").unwrap();
        // Left by a start that died after writing them.
        for f in ["ca.key.tmp", "ca.pem.tmp", "ca.name.tmp"] {
            std::fs::write(d.join(f), "left over").unwrap();
        }
        Certs::load(&d, "web1").unwrap();
        for f in ["ca.key.tmp", "ca.pem.tmp", "ca.name.tmp"] {
            assert!(!d.join(f).exists(), "{f}");
        }
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_second_start_waits_for_the_first() {
        use std::os::fd::AsRawFd;
        let d = dir("lock");
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(d.join("ca.lock"))
            .unwrap();
        // SAFETY: a valid fd; flock only takes the lock.
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let dd = d.clone();
        let t = std::thread::spawn(move || tx.send(Certs::load(&dd, "web1").is_ok()).unwrap());
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(300))
                .is_err(),
            "loaded while another start held the lock"
        );
        assert!(!d.join("ca.key").exists());
        drop(lock);
        assert!(rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap());
        t.join().unwrap();
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_ca_key_that_wont_parse_or_has_no_name_stops_the_start() {
        let d = dir("garbage");
        for junk in [&b"not a key"[..], b"", b"\xff\xfe"] {
            std::fs::write(d.join("ca.key"), junk).unwrap();
            let e = Certs::load(&d, "web1").unwrap_err();
            assert!(format!("{e:#}").contains("ca.key"), "{e:#}");
            assert_eq!(std::fs::read(d.join("ca.key")).unwrap(), junk);
            assert!(!d.join("ca.pem").exists());
        }
        std::fs::remove_dir_all(&d).unwrap();
        let d = dir("noname");
        Certs::load(&d, "web1").unwrap();
        std::fs::remove_file(d.join("ca.name")).unwrap();
        let e = Certs::load(&d, "web1").unwrap_err();
        assert!(format!("{e:#}").contains("ca.name"), "{e:#}");
        assert!(!d.join("ca.name").exists());
        std::fs::remove_dir_all(d).unwrap();
    }

    /// The serial of a DER certificate: the INTEGER after the version
    /// in the TBSCertificate. Our certs are 256 bytes to 64 KiB long.
    fn serial(der: &[u8]) -> &[u8] {
        assert_eq!((der[0], der[1], der[4], der[5]), (0x30, 0x82, 0x30, 0x82));
        assert_eq!(der[8..13], [0xa0, 3, 2, 1, 2]);
        assert_eq!(der[13], 2);
        &der[15..15 + usize::from(der[14])]
    }

    fn count(der: &[u8], oid: &[u8]) -> usize {
        der.windows(oid.len()).filter(|w| *w == oid).count()
    }

    #[test]
    fn leaves_differ_in_serial_and_serve_tls() {
        let d = dir("leaves");
        let c = Certs::load(&d, "web1").unwrap();
        let a = c.mint("a.example").unwrap().cert[0].to_vec();
        let b = c.mint("b.example").unwrap().cert[0].to_vec();
        let (sa, sb) = (serial(&a), serial(&b));
        assert_ne!(sa, sb);
        for s in [sa, sb] {
            assert!(s.len() >= 15 && s[0] & 0x80 == 0, "{s:?}");
        }
        // id-kp-serverAuth, which Apple's clients insist on.
        assert_eq!(count(&a, &[6, 8, 0x2b, 6, 1, 5, 5, 7, 3, 1]), 1);
        // A CN is at most 64 characters (RFC 5280); a longer name is in
        // the SAN alone. The issuer's CN is always there.
        let cn = [6, 3, 0x55, 4, 3];
        assert_eq!(count(&a, &cn), 2);
        let long = format!("{}.example", "a".repeat(60));
        let l = c.mint(&long).unwrap().cert[0].to_vec();
        assert_eq!(count(&l, &cn), 1);
        assert!(count(&l, long.as_bytes()) == 1);
        let srv = config(c).unwrap();
        let ca = std::fs::read(d.join("ca.pem")).unwrap();
        handshake(&srv, &ca, &long).unwrap();
        std::fs::remove_dir_all(d).unwrap();
    }
}
