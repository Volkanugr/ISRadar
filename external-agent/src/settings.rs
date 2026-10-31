use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolOptions {
    pub http: Option<HttpSettings>,
    pub tls_ca: Option<CertificateAuthority>,
    pub dnssec: Option<DnssecAnchor>,
    pub sip: Option<SipSettings>,
    pub capture: Option<CaptureSettings>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSettings {
    pub interface: String,
}

impl CaptureSettings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            cfg!(feature = "packet-capture"),
            "capture requires a build with --features packet-capture"
        );
        ensure!(
            !self.interface.is_empty()
                && self.interface.len() <= 64
                && self.interface != "any"
                && self
                    .interface
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b)),
            "capture requires one explicit local interface"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SipSettings {
    pub test_user: String,
    pub dedicated_test_endpoint: bool,
    pub expected_status: Option<u16>,
}

impl SipSettings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.dedicated_test_endpoint
                && self.test_user.starts_with("isradar-")
                && self.test_user.len() <= 64
                && self
                    .test_user
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
            "SIP policy checks require an attested dedicated endpoint and isradar- test identity"
        );
        ensure!(
            self.expected_status.is_none_or(|v| (200..700).contains(&v)),
            "invalid expected SIP status"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnssecAnchor {
    pub zone: String,
    pub public_key_hex: String,
    pub flags: u16,
}

impl DnssecAnchor {
    pub fn key(&self) -> Result<[u8; 32]> {
        crate::network::dns_wire::query(&self.zone, 1, 1, false).map_err(anyhow::Error::msg)?;
        ensure!(
            [256, 257].contains(&self.flags),
            "DNSSEC anchor must be a DNSKEY zone key"
        );
        ensure!(
            self.public_key_hex.len() == 64
                && self
                    .public_key_hex
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "DNSSEC anchor must be a lowercase Ed25519 key hex"
        );
        hex::decode(&self.public_key_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("DNSSEC Ed25519 key must be 32 bytes"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSettings {
    pub path: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub expected_status: Option<u16>,
    #[serde(default)]
    pub expected_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub dedicated_test_endpoint: bool,
}

impl Default for HttpSettings {
    fn default() -> Self {
        Self {
            path: "/".into(),
            body: String::new(),
            headers: BTreeMap::new(),
            expected_status: None,
            expected_headers: BTreeMap::new(),
            dedicated_test_endpoint: false,
        }
    }
}

impl HttpSettings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.path.starts_with('/')
                && !self.path.starts_with("//")
                && self.path.len() <= 512
                && self
                    .path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/-_.~".contains(&b))
                && self
                    .path
                    .split('/')
                    .all(|segment| segment != "." && segment != ".."),
            "HTTP path must be a normalized origin path without query, escapes or dot segments"
        );
        ensure!(
            self.body.len() <= 1024,
            "HTTP request body exceeds 1024 bytes"
        );
        ensure!(
            self.expected_status.is_none_or(|s| (200..600).contains(&s)),
            "invalid expected HTTP status"
        );
        ensure!(
            self.headers.len() <= 8 && self.expected_headers.len() <= 8,
            "too many HTTP headers"
        );
        for (name, value) in self.headers.iter().chain(self.expected_headers.iter()) {
            validate_header(name, value)?;
        }
        for name in self.headers.keys() {
            ensure!(
                ![
                    "host",
                    "authorization",
                    "proxy-authorization",
                    "cookie",
                    "connection",
                    "content-length",
                    "transfer-encoding",
                    "te",
                    "upgrade",
                    "trailer",
                    "expect",
                    "forwarded",
                    "x-forwarded-for",
                    "x-isradar-probe"
                ]
                .contains(&name.to_ascii_lowercase().as_str()),
                "HTTP transport/credential header is not configurable: {name}"
            );
        }
        let names: std::collections::HashSet<_> = self
            .headers
            .keys()
            .map(|name| name.to_ascii_lowercase())
            .collect();
        ensure!(
            names.len() == self.headers.len(),
            "duplicate case-insensitive HTTP header names"
        );
        Ok(())
    }
}

fn validate_header(name: &str, value: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid HTTP header name"
    );
    ensure!(
        value.len() <= 256 && value.bytes().all(|b| (32..=126).contains(&b)),
        "invalid HTTP header value"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateAuthority {
    pub file: PathBuf,
    pub sha256: String,
}

impl CertificateAuthority {
    pub fn read_der(&self) -> Result<Vec<u8>> {
        ensure!(
            self.sha256.len() == 64
                && self
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "CA fingerprint must be lowercase SHA-256 hex"
        );
        let metadata = std::fs::metadata(&self.file).context("read custom CA metadata")?;
        ensure!(
            metadata.is_file() && metadata.len() <= 65536,
            "CA must be a regular DER file of at most 65536 bytes"
        );
        let bytes = std::fs::read(&self.file)?;
        ensure!(
            !bytes.is_empty()
                && bytes.len() <= 65536
                && hex::encode(Sha256::digest(&bytes)) == self.sha256,
            "custom CA content does not match its authorized fingerprint"
        );
        Ok(bytes)
    }
}

impl ProtocolOptions {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(capture) = &self.capture {
            capture.validate()?;
        }
        if let Some(http) = &self.http {
            http.validate()?;
        }
        if let Some(ca) = &self.tls_ca {
            ca.read_der()?;
        }
        if let Some(anchor) = &self.dnssec {
            anchor.key()?;
        }
        if let Some(sip) = &self.sip {
            sip.validate()?;
        }
        Ok(())
    }
}
