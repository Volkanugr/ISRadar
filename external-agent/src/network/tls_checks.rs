use crate::{
    results::{Observation, Outcome},
    settings::ProtocolOptions,
    vectors::{registry::Backend, TestContext},
};
use anyhow::{ensure, Context, Result};
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_rustls::{client::TlsStream, TlsConnector};

fn expected_rejection(backend: Backend, error: &anyhow::Error) -> bool {
    let Some(io) = error.downcast_ref::<std::io::Error>() else {
        return false;
    };
    let Some(error) = io
        .get_ref()
        .and_then(|error| error.downcast_ref::<rustls::Error>())
    else {
        return false;
    };
    matches!(
        (backend, error),
        (
            Backend::TlsExpired,
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. },
            ),
        ) | (
            Backend::TlsNameMismatch,
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName
                    | rustls::CertificateError::NotValidForNameContext { .. },
            ),
        ) | (
            Backend::TlsNegotiationFailure,
            rustls::Error::AlertReceived(
                rustls::AlertDescription::ProtocolVersion
                    | rustls::AlertDescription::HandshakeFailure,
            ),
        )
    )
}

pub(crate) fn client_config(
    backend: Backend,
    options: &ProtocolOptions,
) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(ca) = &options.tls_ca {
        roots.add(CertificateDer::from(ca.read_der()?))?;
    }
    let versions: &[&'static rustls::SupportedProtocolVersion] = match backend {
        Backend::Tls12 | Backend::TlsResume => &[&rustls::version::TLS12],
        Backend::Tls13 | Backend::TlsNegotiationFailure => &[&rustls::version::TLS13],
        _ => &[&rustls::version::TLS13, &rustls::version::TLS12],
    };
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.resumption = rustls::client::Resumption::in_memory_sessions(8);
    config.enable_sni = true;
    if backend == Backend::TlsAlpn {
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    Ok(Arc::new(config))
}

pub(crate) async fn connect(
    context: &TestContext,
    config: Arc<ClientConfig>,
) -> Result<TlsStream<TcpStream>> {
    let target = context.target.as_ref().context("TLS target required")?;
    let name = ServerName::try_from(
        target
            .server_name
            .clone()
            .context("configured TLS server_name required")?,
    )?;
    let socket = TcpStream::connect(target.address()).await?;
    Ok(TlsConnector::from(config).connect(name, socket).await?)
}

pub(crate) async fn execute(backend: Backend, context: &TestContext) -> Result<Observation> {
    let config = client_config(backend, &context.protocol)?;
    let attempts = if backend == Backend::TlsResume { 2 } else { 1 };
    let mut value = Observation::success(
        "certificate and hostname verified by rustls; safe TLS negotiation observed",
    );
    for _ in 0..attempts {
        let mut stream = match connect(context, config.clone()).await {
            Ok(stream) => stream,
            Err(error) if expected_rejection(backend, &error) => {
                let mut value = Observation::success(
                    "expected TLS rejection observed; certificate verification was never disabled",
                );
                value.response_received = true;
                value.tcp_handshake_success = true;
                value
                    .protocol_details
                    .insert("expected_tls_rejection".into(), true.into());
                value
                    .protocol_details
                    .insert("certificate_verified".into(), false.into());
                value
                    .protocol_details
                    .insert("tls_error".into(), format!("{error:#}").into());
                return Ok(value);
            }
            Err(error) => return Err(error),
        };
        if matches!(
            backend,
            Backend::TlsNegotiationFailure | Backend::TlsExpired | Backend::TlsNameMismatch
        ) {
            stream.shutdown().await?;
            let mut value = Observation::success(
                "TLS handshake succeeded; the configured negative scenario was not observed",
            );
            value.outcome = Outcome::RemoteRejection;
            value.response_received = true;
            value.tcp_handshake_success = true;
            value
                .protocol_details
                .insert("expected_tls_rejection".into(), false.into());
            return Ok(value);
        }
        let connection = &stream.get_ref().1;
        let certificates = connection
            .peer_certificates()
            .context("server provided no verified certificate chain")?;
        ensure!(
            !certificates.is_empty(),
            "server certificate chain is empty"
        );
        let cipher = connection
            .negotiated_cipher_suite()
            .context("no negotiated cipher suite")?;
        value.protocol_details.insert(
            "tls_version".into(),
            format!("{:?}", connection.protocol_version()).into(),
        );
        value.protocol_details.insert(
            "cipher_suite".into(),
            format!("{:?}", cipher.suite()).into(),
        );
        value
            .protocol_details
            .insert("peer_certificate_count".into(), certificates.len().into());
        value.protocol_details.insert(
            "leaf_certificate_sha256".into(),
            hex::encode(Sha256::digest(certificates[0].as_ref())).into(),
        );
        value
            .protocol_details
            .insert("certificate_verified".into(), true.into());
        value.protocol_details.insert(
            "handshake_kind".into(),
            format!("{:?}", connection.handshake_kind()).into(),
        );
        value.protocol_details.insert(
            "server_name".into(),
            serde_json::to_value(
                context
                    .target
                    .as_ref()
                    .and_then(|target| target.server_name.as_ref()),
            )?,
        );
        let alpn = connection
            .alpn_protocol()
            .map(|v| String::from_utf8_lossy(v).into_owned());
        value
            .protocol_details
            .insert("alpn".into(), serde_json::to_value(&alpn)?);
        if backend == Backend::TlsAlpn && alpn.is_none() {
            value.outcome = Outcome::RemoteRejection;
        }
        if backend == Backend::TlsResume {
            value.protocol_details.insert(
                "resumed".into(),
                (connection.handshake_kind() == Some(rustls::HandshakeKind::Resumed)).into(),
            );
        }
        stream.shutdown().await?;
    }
    value
        .protocol_details
        .insert("tcp_connections_in_probe".into(), attempts.into());
    if backend == Backend::TlsResume {
        value.detail = "two bounded TLS 1.2 handshakes share one session cache; resumption is reported from the second handshake".into();
        if value
            .protocol_details
            .get("resumed")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        {
            value.outcome = Outcome::RemoteRejection;
        }
    }
    value.response_received = true;
    value.tcp_handshake_success = true;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    #[tokio::test]
    async fn tls_negotiation_and_expected_errors_in_memory() {
        let file =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls/ca.der");
        let options = ProtocolOptions {
            tls_ca: Some(crate::settings::CertificateAuthority {
                sha256: hex::encode(Sha256::digest(std::fs::read(&file).unwrap())),
                file,
            }),
            ..Default::default()
        };
        for backend in [
            Backend::Tls12,
            Backend::Tls13,
            Backend::TlsAlpn,
            Backend::TlsResume,
            Backend::TlsExpired,
            Backend::TlsNameMismatch,
            Backend::TlsNegotiationFailure,
        ] {
            let client = client_config(backend, &options).unwrap();
            let versions: &[&'static rustls::SupportedProtocolVersion] =
                if backend == Backend::TlsNegotiationFailure {
                    &[&rustls::version::TLS12]
                } else {
                    &[&rustls::version::TLS13, &rustls::version::TLS12]
                };
            let certificate = if backend == Backend::TlsExpired {
                include_bytes!("../../tests/fixtures/tls/expired.der").as_slice()
            } else {
                include_bytes!("../../tests/fixtures/tls/server.der").as_slice()
            };
            let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    include_bytes!("../../tests/fixtures/tls/server-key.der").to_vec(),
                )),
            )
            .unwrap();
            server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
            let connector = TlsConnector::from(client);
            let name = ServerName::try_from(if backend == Backend::TlsNameMismatch {
                "other.example"
            } else {
                "validator.example"
            })
            .unwrap();
            for attempt in 0..if backend == Backend::TlsResume { 2 } else { 1 } {
                let (client_io, server_io) = tokio::io::duplex(16384);
                let (result, server) =
                    tokio::time::timeout(std::time::Duration::from_secs(3), async {
                        tokio::join!(
                            connector.connect(name.clone(), client_io),
                            acceptor.accept(server_io)
                        )
                    })
                    .await
                    .expect("in-memory TLS handshake timed out");
                if matches!(
                    backend,
                    Backend::TlsExpired | Backend::TlsNameMismatch | Backend::TlsNegotiationFailure
                ) {
                    let error = anyhow::Error::from(result.unwrap_err());
                    assert!(
                        expected_rejection(backend, &error),
                        "{backend:?}: {error:#}"
                    );
                    continue;
                }
                let mut stream = result.unwrap();
                let _server = server.unwrap();
                assert!(stream.get_ref().1.peer_certificates().is_some());
                if backend == Backend::TlsAlpn {
                    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                }
                if backend == Backend::Tls12 || backend == Backend::TlsResume {
                    assert_eq!(
                        stream.get_ref().1.protocol_version(),
                        Some(rustls::ProtocolVersion::TLSv1_2)
                    );
                } else if backend == Backend::Tls13 {
                    assert_eq!(
                        stream.get_ref().1.protocol_version(),
                        Some(rustls::ProtocolVersion::TLSv1_3)
                    );
                }
                if attempt == 1 {
                    assert_eq!(
                        stream.get_ref().1.handshake_kind(),
                        Some(rustls::HandshakeKind::Resumed)
                    );
                }
                stream.shutdown().await.unwrap();
            }
        }
        assert!(!expected_rejection(
            Backend::TlsExpired,
            &std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into()
        ));
    }
}
