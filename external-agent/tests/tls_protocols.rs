mod support;
use external_agent::results::Outcome;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn verified_tls_negotiation_and_resumption() {
    for id in [
        "TLS-001", "TLS-002", "TLS-003", "TLS-004", "TLS-005", "TLS-006", "TLS-008", "TLS-009",
        "TLS-010", "SIP-008",
    ] {
        let versions: &[&'static rustls::SupportedProtocolVersion] = if id == "TLS-006" {
            &[&rustls::version::TLS12]
        } else {
            &[&rustls::version::TLS13, &rustls::version::TLS12]
        };
        let mut tls = support::tls_config(id == "TLS-009", versions);
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..if id == "TLS-004" { 2 } else { 1 } {
                let (stream, _) = listener.accept().await.unwrap();
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    continue;
                };
                if id == "SIP-008" {
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        request.push(stream.read_u8().await.unwrap());
                    }
                    let text = String::from_utf8(request).unwrap();
                    let headers: Vec<_> = text
                        .lines()
                        .filter(|l| {
                            ["via:", "call-id:", "cseq:"]
                                .iter()
                                .any(|k| l.to_ascii_lowercase().starts_with(k))
                        })
                        .collect();
                    stream
                        .write_all(
                            format!(
                                "SIP/2.0 200 OK\r\n{}\r\nContent-Length: 0\r\n\r\n",
                                headers.join("\r\n")
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                } else {
                    let mut b = [0; 1];
                    let _ = stream.read(&mut b).await;
                }
            }
        });
        let mut target = support::target(address);
        target.server_name = Some(
            if id == "TLS-010" {
                "other.example"
            } else {
                "validator.example"
            }
            .into(),
        );
        let mut limits = support::limits(1);
        limits.timeout_ms = 3000;
        let (_dir, mut config) = support::configured(target, &[id], limits);
        support::trust_fixture(&mut config);

        let report = support::run(config).await;
        assert_eq!(
            report.observations[0].outcome,
            Outcome::Success,
            "{id}: {:?}",
            report.observations
        );
        if id == "TLS-004" {
            assert_eq!(report.observations[0].protocol_details["resumed"], true);
        }
        if id == "TLS-008" {
            assert_eq!(report.observations[0].protocol_details["alpn"], "h2");
        }
        tokio::time::timeout(std::time::Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn http3_uses_verified_quic_to_the_configured_peer() {
    let mut tls = support::tls_config(false, &[&rustls::version::TLS13]);
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = endpoint.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let mut http =
            h3::server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
        let resolver = http.accept().await.unwrap().unwrap();
        let (request, mut stream) = resolver.resolve_request().await.unwrap();
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.uri().host(), Some("validator.example"));
        stream
            .send_response(http::Response::builder().status(200).body(()).unwrap())
            .await
            .unwrap();
        stream.finish().await.unwrap();
        // Drive control frames and stream completion until the sender closes its endpoint.
        let _ = http.accept().await;
    });
    let mut target = support::target(address);
    target.server_name = Some("validator.example".into());
    let mut limits = support::limits(1);
    limits.timeout_ms = 3000;
    let (_dir, mut config) = support::configured(target, &["HTTP-012"], limits);
    support::trust_fixture(&mut config);

    let report = support::run(config).await;
    assert_eq!(
        report.observations[0].outcome,
        Outcome::Success,
        "{:?}",
        report.observations
    );
    assert_eq!(
        report.observations[0].protocol_details["http_version"],
        "HTTP/3"
    );
    tokio::time::timeout(std::time::Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}
