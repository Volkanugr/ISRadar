use crate::config::Mode;
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Catalog,
    OfflineModel,
    OfflinePacket,
    OfflinePolicyFixture,
    TcpConnect,
    TcpEcho,
    RawTcpFlags,
    RawTcpWindow,
    RawTcpMss,
    RawTcpTimestamp,
    RawTcpSack,
    RawTcpSynFlood,
    RawIpv4Header,
    RawIpv4Fragments,
    RawIpv4Ttl,
    RawIpv4Ecn,
    RawIpv4Options,
    RawIpv6HopByHop,
    RawIpv6Destination,
    RawIpv6Routing,
    RawIpv6Fragments,
    RawIpv6NoNext,
    RawIcmpUnreachable,
    RawIcmpTimeExceeded,
    RawIcmpParameter,
    RawIcmpTimestamp,
    TcpHalfClose,
    TcpSession,
    UdpEcho,
    UdpEchoZero,
    UdpEcho1200,
    UdpEcho128,
    UdpEchoRandom,
    UdpClosedPort,
    UdpDelivery,
    IcmpEcho,
    DnsA,
    DnsUniqueA,
    DnsAaaa,
    DnsMx,
    DnsTxt,
    DnsCname,
    DnsNs,
    DnsSoa,
    DnsTcpFallback,
    DnsAny,
    DnsNxdomain,
    DnsEdns,
    DnsTcp,
    DnsRecursion,
    DnsTruncation,
    DnsCompressed,
    Dnssec,
    NtpBasic,
    NtpV3,
    SipOptions,
    SipTcp,
    SipTls,
    SipInvite,
    SipRegister,
    HttpGet,
    HttpHead,
    HttpOptions,
    HttpsGet,
    HttpsHead,
    Http2Get,
    Http3Get,
    HttpConnect,
    HttpPost,
    HttpPut,
    HttpPatch,
    HttpDelete,
    HttpTrace,
    HttpRedirect,
    HttpHeaders,
    HttpHealth,
    HttpReuse,
    HttpSlowHeaders,
    HttpSlowBody,
    Tls12,
    Tls13,
    TlsCertificate,
    TlsCipher,
    TlsAlpn,
    TlsResume,
    TlsNegotiationFailure,
    TlsExpired,
    TlsNameMismatch,
}

impl Backend {
    pub fn is_raw(self) -> bool {
        matches!(
            self,
            Self::RawTcpFlags
                | Self::RawTcpWindow
                | Self::RawTcpMss
                | Self::RawTcpTimestamp
                | Self::RawTcpSack
                | Self::RawTcpSynFlood
                | Self::RawIpv4Header
                | Self::RawIpv4Fragments
                | Self::RawIpv4Ttl
                | Self::RawIpv4Ecn
                | Self::RawIpv4Options
                | Self::RawIpv6HopByHop
                | Self::RawIpv6Destination
                | Self::RawIpv6Routing
                | Self::RawIpv6Fragments
                | Self::RawIpv6NoNext
                | Self::RawIcmpUnreachable
                | Self::RawIcmpTimeExceeded
                | Self::RawIcmpParameter
                | Self::RawIcmpTimestamp
        )
    }
    pub fn raw_packet_cost(self) -> u64 {
        if matches!(self, Self::RawIpv4Fragments | Self::RawIpv6Fragments) {
            2
        } else {
            1
        }
    }
    pub fn is_offline(self) -> bool {
        matches!(
            self,
            Self::OfflineModel | Self::OfflinePacket | Self::OfflinePolicyFixture
        )
    }
    pub fn is_tls(self) -> bool {
        matches!(
            self,
            Self::Tls12
                | Self::Tls13
                | Self::HttpsGet
                | Self::HttpsHead
                | Self::TlsCertificate
                | Self::TlsCipher
                | Self::TlsAlpn
                | Self::TlsResume
                | Self::SipTls
                | Self::Http3Get
                | Self::TlsNegotiationFailure
                | Self::TlsExpired
                | Self::TlsNameMismatch
        )
    }
    pub fn is_dns(self) -> bool {
        matches!(
            self,
            Self::DnsA
                | Self::DnsUniqueA
                | Self::DnsAaaa
                | Self::DnsMx
                | Self::DnsTxt
                | Self::DnsCname
                | Self::DnsNs
                | Self::DnsSoa
                | Self::DnsTcpFallback
                | Self::DnsAny
                | Self::DnsNxdomain
                | Self::DnsEdns
                | Self::DnsTcp
                | Self::DnsRecursion
                | Self::DnsTruncation
                | Self::DnsCompressed
                | Self::Dnssec
        )
    }
    pub fn is_http(self) -> bool {
        matches!(
            self,
            Self::HttpGet
                | Self::HttpHead
                | Self::HttpOptions
                | Self::HttpsGet
                | Self::HttpsHead
                | Self::Http2Get
                | Self::Http3Get
                | Self::HttpConnect
                | Self::HttpPost
                | Self::HttpPut
                | Self::HttpPatch
                | Self::HttpDelete
                | Self::HttpTrace
                | Self::HttpRedirect
                | Self::HttpHeaders
                | Self::HttpHealth
                | Self::HttpReuse
                | Self::HttpSlowHeaders
                | Self::HttpSlowBody
        )
    }
    pub fn http_method(self) -> Option<&'static str> {
        Some(match self {
            Self::HttpGet
            | Self::HttpsGet
            | Self::Http2Get
            | Self::Http3Get
            | Self::HttpRedirect
            | Self::HttpHealth
            | Self::HttpSlowHeaders => "GET",
            Self::HttpHead | Self::HttpsHead | Self::HttpHeaders | Self::HttpReuse => "HEAD",
            Self::HttpOptions => "OPTIONS",
            Self::HttpConnect => "CONNECT",
            Self::HttpPost | Self::HttpSlowBody => "POST",
            Self::HttpPut => "PUT",
            Self::HttpPatch => "PATCH",
            Self::HttpDelete => "DELETE",
            Self::HttpTrace => "TRACE",
            _ => return None,
        })
    }
    pub fn validate_options(self, options: &crate::settings::ProtocolOptions) -> Result<()> {
        if self == Self::HttpConnect {
            let settings = options
                .http
                .as_ref()
                .context("CONNECT self-probe requires configured dedicated endpoint settings")?;
            ensure!(
                settings.dedicated_test_endpoint
                    && settings.body.is_empty()
                    && settings.headers.is_empty(),
                "CONNECT sends only fixed headers to the configured target itself"
            );
        }
        if matches!(self, Self::SipInvite | Self::SipRegister) {
            options
                .sip
                .as_ref()
                .context("SIP INVITE/REGISTER require configured dedicated test identity settings")?
                .validate()?;
        }
        if self == Self::Dnssec {
            ensure!(
                options.dnssec.is_some(),
                "DNSSEC requires a configured pinned Ed25519 zone anchor"
            );
        }
        if matches!(
            self,
            Self::HttpPost
                | Self::HttpPut
                | Self::HttpPatch
                | Self::HttpDelete
                | Self::HttpSlowBody
        ) {
            let http = options
                .http
                .as_ref()
                .context("state-changing HTTP methods require configured HTTP settings")?;
            ensure!(
                http.dedicated_test_endpoint && http.path != "/",
                "state-changing HTTP methods require an explicitly authorized dedicated test path"
            );
            ensure!(
                self != Self::HttpSlowBody || !http.body.is_empty(),
                "slow-body validation requires a bounded request body"
            );
        }
        if matches!(self, Self::HttpHealth | Self::HttpHeaders) {
            ensure!(
                options.http.is_some(),
                "this HTTP check requires configured path/header expectations"
            );
        }
        if self.is_http() {
            if let Some(http) = &options.http {
                if !matches!(
                    self,
                    Self::HttpPost | Self::HttpPut | Self::HttpPatch | Self::HttpSlowBody
                ) {
                    ensure!(
                        http.body.is_empty(),
                        "this HTTP method/check does not send a request body"
                    );
                }
                if self == Self::HttpTrace {
                    ensure!(
                        http.headers.is_empty(),
                        "TRACE uses only fixed non-sensitive headers"
                    );
                }
                if self == Self::HttpHeaders {
                    ensure!(
                        !http.headers.is_empty() || !http.expected_headers.is_empty(),
                        "header check requires a header assertion"
                    );
                }
                if self == Self::HttpReuse {
                    ensure!(
                        http.headers.is_empty() && http.expected_headers.is_empty(),
                        "connection reuse check supports only fixed headers"
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationStatus {
    Planned,
    Implemented,
    Verified,
    Unverified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vector {
    pub id: String,
    pub name: String,
    pub family: String,
    pub category: String,
    pub layer: String,
    pub protocol: String,
    pub mode: Mode,
    pub risk: String,
    pub enabled: bool,
    pub requires_lab: bool,
    pub implementation_status: ImplementationStatus,
    pub backend: Backend,
    pub description: String,
    pub references: Vec<String>,
    pub supported_parameters: Vec<String>,
    pub automated_tests: Vec<String>,
    pub vendor_parity: String,
    #[serde(default)]
    pub ip_version: Option<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    schema_version: u32,
    vectors: Vec<Vector>,
}

#[derive(Debug, Clone)]
pub struct Registry {
    entries: BTreeMap<String, Vector>,
}

impl Registry {
    pub fn bundled() -> Result<Self> {
        Self::from_yaml(include_str!("../../vectors/catalog.yaml"))
    }

    pub fn read(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        ensure!(bytes.len() <= 4 * 1024 * 1024, "catalog exceeds 4 MiB");
        Self::from_yaml(std::str::from_utf8(&bytes)?)
    }

    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let catalog: Catalog = serde_yaml::from_str(yaml)?;
        let bundled: Catalog = serde_yaml::from_str(include_str!("../../vectors/catalog.yaml"))?;
        ensure!(
            catalog.schema_version == 1 && !catalog.vectors.is_empty(),
            "invalid catalog schema"
        );
        let mut entries = BTreeMap::new();
        for vector in catalog.vectors {
            if let Some(original) = bundled.vectors.iter().find(|v| v.id == vector.id) {
                ensure!(
                    vector.backend == original.backend
                        && vector.mode == original.mode
                        && vector.ip_version == original.ip_version
                        && vector.layer == original.layer
                        && vector.protocol == original.protocol
                        && vector.category == original.category,
                    "bundled vector identity cannot be rebound to different execution semantics"
                );
            }
            ensure!(
                !vector.id.is_empty()
                    && vector.id.len() <= 64
                    && vector
                        .id
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-'),
                "invalid vector ID"
            );
            ensure!(
                !vector.name.is_empty()
                    && !vector.description.is_empty()
                    && !vector.family.is_empty()
                    && !vector.category.is_empty()
                    && !vector.protocol.is_empty(),
                "incomplete vector metadata"
            );
            ensure!(
                ["L3", "L4", "L7"].contains(&vector.layer.as_str()),
                "unsupported OSI layer"
            );
            ensure!(
                !vector.references.is_empty()
                    && vector.references.iter().all(|r| r.starts_with("https://")),
                "vector references required"
            );
            ensure!(
                vector.ip_version.is_none_or(|v| v == 4 || v == 6),
                "invalid IP version"
            );
            ensure!(
                vector.vendor_parity == "unverified",
                "proprietary vendor parity is not verified"
            );
            ensure!(
                (vector.id == "UDP-010") == (vector.backend == Backend::UdpDelivery),
                "UDP-010 is reserved for authenticated delivery measurement"
            );
            if vector.backend.is_raw() {
                crate::network::raw::kind(&vector)?;
            }
            if vector.backend == Backend::OfflineModel {
                super::event_models::run(&vector.id).map_err(anyhow::Error::msg)?;
            }
            if vector.backend == Backend::OfflinePolicyFixture {
                crate::network::lab_fixtures::run(&vector.id).map_err(anyhow::Error::msg)?;
            }
            match vector.mode {
                Mode::LiveValidation => {
                    ensure!(
                        !vector.requires_lab
                            && !vector.backend.is_offline()
                            && vector.backend != Backend::Catalog,
                        "invalid live execution classification"
                    );
                }
                Mode::LabEmulation => ensure!(
                    vector.requires_lab && vector.backend.is_offline(),
                    "lab execution must use an offline backend"
                ),
                Mode::CatalogOnly => ensure!(
                    vector.backend == Backend::Catalog && !vector.enabled,
                    "catalog entries cannot be enabled"
                ),
            }
            if vector.backend != Backend::Catalog {
                ensure!(
                    matches!(
                        vector.implementation_status,
                        ImplementationStatus::Implemented | ImplementationStatus::Verified
                    ) && !vector.automated_tests.is_empty(),
                    "executable vector needs implementation and tests"
                );
            } else {
                ensure!(
                    !matches!(
                        vector.implementation_status,
                        ImplementationStatus::Implemented | ImplementationStatus::Verified
                    ),
                    "metadata is not an implementation"
                );
            }
            ensure!(
                entries.insert(vector.id.clone(), vector).is_none(),
                "duplicate vector ID"
            );
        }
        Ok(Self { entries })
    }

    pub fn get(&self, id: &str) -> Result<&Vector> {
        self.entries
            .get(id)
            .with_context(|| format!("unknown vector {id}"))
    }
    pub fn list(&self) -> impl Iterator<Item = &Vector> {
        self.entries.values()
    }

    pub fn coverage(&self) -> BTreeMap<String, BTreeMap<String, usize>> {
        let mut counts = BTreeMap::new();
        for layer in ["L3", "L4", "L7"] {
            let row = counts.entry(layer.to_owned()).or_insert_with(BTreeMap::new);
            for kind in [
                "network_protocol",
                "offline_model",
                "offline_fixture",
                "catalog_only",
            ] {
                row.insert(kind.to_owned(), 0);
            }
        }
        for vector in self.list() {
            let kind = if vector.backend == Backend::OfflineModel {
                "offline_model"
            } else if matches!(
                vector.backend,
                Backend::OfflinePacket | Backend::OfflinePolicyFixture
            ) {
                "offline_fixture"
            } else if vector.backend == Backend::Catalog {
                "catalog_only"
            } else {
                "network_protocol"
            };
            *counts
                .entry(vector.layer.clone())
                .or_default()
                .entry(kind.to_owned())
                .or_default() += 1;
        }
        counts
    }
}
