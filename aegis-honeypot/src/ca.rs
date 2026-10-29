// SPDX-License-Identifier: MIT OR Apache-2.0
//! The host's honeypot CA, and a leaf for whatever name a TLS client
//! asks for, signed by it. `ca.key` never leaves the state directory;
//! `ca.pem` is what a host that wants to see inside HTTPS trusts.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::crypto::ring;
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
}

impl fmt::Debug for Certs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Certs")
    }
}

/// Writes a file that must not exist yet.
fn create(path: &Path, mode: u32, data: &str) -> std::io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?
        .write_all(data.as_bytes())
}

fn named(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

impl Certs {
    /// The CA in `dir`, made there on first start: `ca.key` 0400 and
    /// `ca.pem`, each created only if absent. A `ca.key` that won't
    /// parse is an error, never replaced.
    pub fn load(dir: &Path, host: &str) -> Result<Self> {
        let path = dir.join("ca.key");
        let key = match std::fs::read(&path) {
            Ok(pem) => std::str::from_utf8(&pem)
                .ok()
                .and_then(|p| KeyPair::from_pem(p).ok())
                .with_context(|| {
                    format!(
                        "{} is not a key; move it aside to make a new CA",
                        path.display()
                    )
                })?,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let k = KeyPair::generate()?;
                create(&path, 0o400, &k.serialize_pem())
                    .with_context(|| path.display().to_string())?;
                k
            }
            Err(e) => bail!("{}: {e}", path.display()),
        };
        let now = OffsetDateTime::now_utc();
        let mut ca = CertificateParams::default();
        ca.distinguished_name = named(&format!("Aegis Honeypot CA {host}"));
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca.not_before = now - Duration::days(1);
        ca.not_after = now + Duration::days(3653);
        let pem = dir.join("ca.pem");
        match create(&pem, 0o644, &ca.self_signed(&key)?.pem()) {
            Err(e) if e.kind() != ErrorKind::AlreadyExists => {
                bail!("{}: {e}", pem.display())
            }
            _ => {}
        }
        let leaf = KeyPair::generate()?;
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.serialize_der()));
        Ok(Self {
            issuer: Issuer::new(ca, key),
            signer: ring::sign::any_supported_type(&der)?,
            leaf,
        })
    }

    /// A leaf for `name`, valid from yesterday for a year.
    fn mint(&self, name: &str) -> Result<CertifiedKey, rcgen::Error> {
        let mut p = CertificateParams::new(vec![name.to_string()])?;
        p.distinguished_name = named(name);
        p.use_authority_key_identifier_extension = true;
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
    use std::os::unix::fs::PermissionsExt;

    fn dir(name: &str) -> std::path::PathBuf {
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

    #[test]
    fn the_first_start_makes_the_ca_and_later_ones_keep_it() {
        let d = dir("first");
        Certs::load(&d, "web1").unwrap();
        let (key, pem) = (d.join("ca.key"), d.join("ca.pem"));
        assert_eq!(mode(&key), 0o400);
        assert_eq!(mode(&pem) & 0o600, 0o600);
        assert_eq!(mode(&pem) & 0o022, 0);
        let k = std::fs::read(&key).unwrap();
        let p = std::fs::read_to_string(&pem).unwrap();
        assert!(String::from_utf8_lossy(&k).starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(p.starts_with("-----BEGIN CERTIFICATE-----"));
        Certs::load(&d, "web1").unwrap();
        assert_eq!(std::fs::read(&key).unwrap(), k);
        assert_eq!(std::fs::read_to_string(&pem).unwrap(), p);
        // A lost ca.pem comes back from the key that's there.
        std::fs::remove_file(&pem).unwrap();
        Certs::load(&d, "web1").unwrap();
        assert_eq!(std::fs::read(&key).unwrap(), k);
        assert!(pem.is_file());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_ca_key_that_wont_parse_stops_the_start_and_stays() {
        let d = dir("garbage");
        for junk in [&b"not a key"[..], b"", b"\xff\xfe"] {
            std::fs::write(d.join("ca.key"), junk).unwrap();
            let e = Certs::load(&d, "web1").unwrap_err();
            assert!(format!("{e:#}").contains("ca.key"), "{e:#}");
            assert_eq!(std::fs::read(d.join("ca.key")).unwrap(), junk);
            assert!(!d.join("ca.pem").exists());
        }
        std::fs::remove_dir_all(d).unwrap();
    }
}
