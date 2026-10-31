mod support;
use external_agent::{results::Outcome, settings::HttpSettings};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn head(stream: &mut tokio::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
        assert!(bytes.len() <= 4096);
    }
    String::from_utf8(bytes).unwrap()
}

#[tokio::test]
async fn configured_http_operations_and_connection_reuse() {
    for (id, method) in [
        ("HTTP-002", "POST"),
        ("HTTP-004", "PUT"),
        ("HTTP-005", "PATCH"),
        ("HTTP-006", "DELETE"),
        ("HTTP-008", "TRACE"),
        ("HTTP-017", "GET"),
        ("HTTP-018", "HEAD"),
        ("HTTP-019", "GET"),
        ("HTTP-013", "HEAD"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for _ in 0..if id == "HTTP-013" { 2 } else { 1 } {
                let request = head(&mut stream).await;
                assert!(
                    request.starts_with(&format!("{method} /isradar-test HTTP/1.1\r\n")),
                    "{request}"
                );
                if ["POST", "PUT", "PATCH"].contains(&method) {
                    let mut body = [0; 4];
                    stream.read_exact(&mut body).await.unwrap();
                    assert_eq!(&body, b"test");
                }
                if id == "HTTP-018" {
                    assert!(request.to_ascii_lowercase().contains("x-isradar: fixed"));
                }
                if method == "TRACE" {
                    assert!(request.to_ascii_lowercase().contains("max-forwards: 0"));
                }
                let response = if id == "HTTP-017" {
                    "HTTP/1.1 302 Found\r\nLocation: http://third-party.invalid/\r\nContent-Length: 0\r\n\r\n"
                } else {
                    "HTTP/1.1 200 OK\r\nX-Isradar: fixed\r\nContent-Length: 0\r\n\r\n"
                };
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let (_dir, mut config) =
            support::configured(support::target(address), &[id], support::limits(1));
        let mut settings = HttpSettings {
            path: "/isradar-test".into(),
            dedicated_test_endpoint: true,
            ..Default::default()
        };
        if ["POST", "PUT", "PATCH"].contains(&method) {
            settings.body = "test".into();
        }
        if id == "HTTP-018" {
            settings.headers.insert("x-isradar".into(), "fixed".into());
            settings.expected_headers = settings.headers.clone();
        }
        config.protocol.http = Some(settings);

        let report = support::run(config).await;
        assert_eq!(
            report.observations[0].outcome,
            Outcome::Success,
            "{id}: {:?}",
            report.observations
        );
        if id == "HTTP-013" {
            assert_eq!(report.metrics.http_responses_received, 2);
            assert_eq!(report.metrics.http_successes, 2);
            assert_eq!(
                report.observations[0].protocol_details["connection_reused"],
                true
            );
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn connect_authority_is_the_configured_target_only() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = head(&mut stream).await;
        assert!(
            request.starts_with(&format!("CONNECT {address} HTTP/1.1\r\n")),
            "{request}"
        );
        stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut extra = [0; 1];
        assert_eq!(stream.read(&mut extra).await.unwrap(), 0);
    });
    let mut target = support::target(address);
    target.server_name = Some("validator.example".into());
    let mut limits = support::limits(1);
    limits.probes_per_second = 1;
    limits.concurrency = 1;
    let (_dir, mut config) = support::configured(target, &["HTTP-009"], limits);
    config.protocol.http = Some(HttpSettings {
        expected_status: Some(405),
        dedicated_test_endpoint: true,
        ..Default::default()
    });

    let report = support::run(config).await;
    assert_eq!(
        report.observations[0].outcome,
        Outcome::Success,
        "{:?}",
        report.observations
    );
    server.await.unwrap();
}

#[tokio::test]
async fn http_probe_ids_survive_timeout_and_cancellation() {
    for mode in ["success", "timeout", "cancel"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (id_tx, id_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = head(&mut stream).await;
            let ids: Vec<_> = request
                .lines()
                .filter_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("x-isradar-probe")
                        .then(|| value.trim().to_string())
                })
                .collect();
            assert_eq!(ids.len(), 1);
            id_tx.send(ids[0].clone()).unwrap();
            if mode == "success" {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            } else {
                let _ = stream.read(&mut [0; 1]).await;
            }
        });
        let (_dir, config) =
            support::configured(support::target(address), &["HTTP-001"], support::limits(1));
        let cancel = tokio_util::sync::CancellationToken::new();
        let worker_cancel = cancel.clone();
        let worker = tokio::spawn(async move {
            external_agent::engine::run(
                config,
                external_agent::vectors::registry::Registry::bundled().unwrap(),
                worker_cancel,
            )
            .await
            .unwrap()
        });
        let received_id = id_rx.await.unwrap();
        if mode == "cancel" {
            cancel.cancel();
        }
        let report = worker.await.unwrap();
        assert_eq!(report.metrics.probes_started, 1);
        assert_eq!(report.http_probes.len(), 1);
        assert_eq!(report.http_probes[0].request_id, received_id);
        if mode == "cancel" {
            assert_eq!(report.termination_reason, "cancelled");
            assert_eq!(report.metrics.probes_cancelled, 1);
        } else {
            assert_eq!(
                report.observations[0].protocol_details["http_request_id"],
                received_id
            );
            assert_eq!(
                report.observations[0].outcome,
                if mode == "success" {
                    Outcome::Success
                } else {
                    Outcome::Timeout
                }
            );
        }
        server.await.unwrap();
    }
}
