#![allow(dead_code)]
use external_agent::config::{Config, Health, Limits, Mode, Target};

pub fn limits(count: u64) -> Limits {
    Limits {
        duration_seconds: 10,
        probes_per_second: 50,
        concurrency: 8,
        bandwidth_bytes_per_second: 262144,
        max_probes: count,
        timeout_ms: 500,
    }
}

pub fn configured(target: Target, ids: &[&str], limits: Limits) -> (tempfile::TempDir, Config) {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        protocol: Default::default(),
        vectors: ids.iter().map(|id| id.to_string()).collect(),
        mode: Mode::LiveValidation,
        target: Some(target),
        limits,
        kill_switch: dir.path().join("STOP"),
        controller_lease: None,
        measurement: None,
        health: Health {
            consecutive_failures: 10,
            max_latency_ms: 5000,
        },
    };
    (dir, config)
}

pub fn target(address: std::net::SocketAddr) -> Target {
    Target {
        ip: address.ip(),
        port: address.port(),
        server_name: None,
    }
}

pub async fn run(config: Config) -> external_agent::results::Report {
    external_agent::engine::run(
        config,
        external_agent::vectors::registry::Registry::bundled().unwrap(),
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap()
}

pub fn tls_config(
    expired: bool,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> rustls::ServerConfig {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let certificate = if expired {
        include_bytes!("../fixtures/tls/expired.der").as_slice()
    } else {
        include_bytes!("../fixtures/tls/server.der").as_slice()
    };
    rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(versions)
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(certificate.to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            include_bytes!("../fixtures/tls/server-key.der").to_vec(),
        )),
    )
    .unwrap()
}

pub fn trust_fixture(config: &mut Config) {
    use sha2::{Digest, Sha256};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls/ca.der");
    config.protocol.tls_ca = Some(external_agent::settings::CertificateAuthority {
        sha256: hex::encode(Sha256::digest(std::fs::read(&path).unwrap())),
        file: path,
    });
}
