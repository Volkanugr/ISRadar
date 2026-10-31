mod support;

use external_agent::{
    results::Outcome,
    settings::{HttpSettings, ProtocolOptions},
    vectors::registry::Backend,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

fn dns_qname(query: &[u8]) -> String {
    let mut labels = Vec::new();
    let mut offset = 12;
    loop {
        let length = query[offset] as usize;
        offset += 1;
        if length == 0 {
            break;
        }
        assert!(length <= 63 && offset + length < query.len());
        labels.push(std::str::from_utf8(&query[offset..offset + length]).unwrap());
        offset += length;
    }
    labels.join(".")
}

async fn http_head(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        request.push(stream.read_u8().await.unwrap());
        assert!(request.len() <= 4096);
    }
    request
}

#[tokio::test]
async fn bounded_live_variants_execute_real_protocol_exchanges() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 256];
        loop {
            let size = stream.read(&mut bytes).await.unwrap();
            if size == 0 {
                break;
            }
            stream.write_all(&bytes[..size]).await.unwrap();
        }
    });
    let (_dir, config) =
        support::configured(support::target(address), &["TCP-033"], support::limits(1));
    let report = support::run(config).await;
    assert_eq!(report.observations[0].outcome, Outcome::Success);
    assert_eq!(
        report.observations[0].protocol_details["messages_on_one_connection"],
        2
    );
    assert!(report.observations[0].application_bytes_sent > 0);
    server.await.unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut bytes = [0; 128];
        let (size, peer) = socket.recv_from(&mut bytes).await.unwrap();
        assert_eq!(size, 64);
        socket.send_to(&bytes[..size], peer).await.unwrap();
    });
    let (_dir, config) =
        support::configured(support::target(address), &["UDP-015"], support::limits(1));
    let report = support::run(config).await;
    assert_eq!(report.observations[0].outcome, Outcome::Success);
    assert_eq!(report.observations[0].application_bytes_sent, 64);
    assert_eq!(report.observations[0].application_bytes_received, 64);
    server.await.unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut query = [0u8; 512];
        let (size, peer) = socket.recv_from(&mut query).await.unwrap();
        assert_eq!(dns_qname(&query[..size]), "owned.example");
        query[2] |= 0x80;
        socket.send_to(&query[..size], peer).await.unwrap();
    });
    let mut target = support::target(address);
    target.server_name = Some("owned.example".into());
    let (_dir, config) = support::configured(target, &["DNS-021"], support::limits(1));
    let report = support::run(config).await;
    assert_eq!(report.observations[0].outcome, Outcome::Success);
    assert_eq!(report.observations[0].protocol_details["dns_rcode"], 0);
    server.await.unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut names = Vec::new();
        for _ in 0..2 {
            let mut query = [0u8; 512];
            let (size, peer) = socket.recv_from(&mut query).await.unwrap();
            names.push(dns_qname(&query[..size]));
            query[2] |= 0x80;
            query[3] = 3;
            socket.send_to(&query[..size], peer).await.unwrap();
        }
        names
    });
    let mut target = support::target(address);
    target.server_name = Some("owned.example".into());
    let (_dir, config) = support::configured(target, &["DNS-022"], support::limits(2));
    let report = support::run(config).await;
    let names = server.await.unwrap();
    assert_eq!(names.len(), 2);
    assert_ne!(names[0], names[1]);
    assert!(names
        .iter()
        .all(|name| name.starts_with("isradar-") && name.ends_with(".owned.example")));
    assert_eq!(report.metrics.responses_received, 2);
    assert_eq!(report.metrics.simulated_events, 0);
    for observation in &report.observations {
        assert_eq!(observation.outcome, Outcome::Success);
        assert_eq!(observation.protocol_details["dns_rcode"], 3);
        assert!(names.contains(
            &observation.protocol_details["dns_qname"]
                .as_str()
                .unwrap()
                .to_string()
        ));
        assert!(observation.application_bytes_sent > 12);
        assert_eq!(
            observation.application_bytes_sent,
            observation.application_bytes_received
        );
    }

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut bytes = [0u8; 4096];
        let (size, peer) = socket.recv_from(&mut bytes).await.unwrap();
        let request = String::from_utf8(bytes[..size].to_vec()).unwrap();
        assert!(request.starts_with("OPTIONS "));
        let headers: Vec<_> = request
            .lines()
            .filter(|line| {
                ["via:", "call-id:", "cseq:"]
                    .iter()
                    .any(|name| line.to_ascii_lowercase().starts_with(name))
            })
            .collect();
        let response = format!(
            "SIP/2.0 200 OK\r\n{}\r\nContent-Length: 0\r\n\r\n",
            headers.join("\r\n")
        );
        socket.send_to(response.as_bytes(), peer).await.unwrap();
    });
    let (_dir, config) =
        support::configured(support::target(address), &["SIP-011"], support::limits(1));
    let report = support::run(config).await;
    assert_eq!(report.observations[0].outcome, Outcome::Success);
    assert_eq!(report.observations[0].protocol_details["sip_status"], 200);
    server.await.unwrap();

    for (id, method, body, delayed) in [
        ("HTTP-035", "GET", "", false),
        ("HTTP-036", "POST", "isradar-test", false),
        ("HTTP-037", "GET", "", true),
        ("HTTP-038", "POST", "isradar-test", true),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let head = http_head(&mut stream).await;
            let request = String::from_utf8(head).unwrap();
            assert!(request.starts_with(&format!("{method} /isradar-test HTTP/1.1\r\n")));
            let probe_ids: Vec<_> = request
                .lines()
                .filter_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("x-isradar-probe")
                        .then(|| value.trim().to_string())
                })
                .collect();
            assert_eq!(probe_ids.len(), 1);
            if !body.is_empty() {
                let mut received_body = vec![0; body.len()];
                stream.read_exact(&mut received_body).await.unwrap();
                assert_eq!(received_body, body.as_bytes());
            }
            let response = b"HTTP/1.1 200 OK\r\nX-Isradar-Test: observed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream.write_all(response).await.unwrap();
            (
                request.len() + body.len(),
                response.len(),
                probe_ids.into_iter().next().unwrap(),
            )
        });
        let (_dir, mut config) =
            support::configured(support::target(address), &[id], support::limits(1));
        config.protocol.http = Some(HttpSettings {
            path: "/isradar-test".into(),
            body: body.into(),
            expected_status: Some(200),
            expected_headers: [("x-isradar-test".into(), "observed".into())].into(),
            dedicated_test_endpoint: true,
            ..Default::default()
        });
        let report = support::run(config).await;
        let (sent, received, probe_id) = server.await.unwrap();
        assert_eq!(report.http_probes[0].request_id, probe_id);
        let observation = &report.observations[0];
        assert_eq!(observation.outcome, Outcome::Success, "{observation:?}");
        assert_eq!(observation.http_status, Some(200));
        assert!(observation.response_received);
        assert!(observation.tcp_handshake_success);
        assert_eq!(observation.protocol_details["http_request_id"], probe_id);
        assert_eq!(report.metrics.simulated_events, 0);
        if delayed {
            assert_eq!(observation.application_bytes_sent, sent as u64);
            assert_eq!(observation.application_bytes_received, received as u64);
            assert_eq!(observation.protocol_details["workload_delay_ms"], 25);
            assert_eq!(observation.protocol_details["bounded_live_exchange"], true);
            assert!(observation.latency_ms >= 25.0);
        }
    }

    let tls = support::tls_config(false, &[&rustls::version::TLS13]);
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut byte = [0; 1];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    });
    let mut target = support::target(address);
    target.server_name = Some("validator.example".into());
    let (_dir, mut config) = support::configured(target, &["TLS-013"], support::limits(1));
    support::trust_fixture(&mut config);
    let report = support::run(config).await;
    assert_eq!(report.observations[0].outcome, Outcome::Success);
    assert!(report.observations[0].tcp_handshake_success);
    assert_eq!(report.metrics.simulated_events, 0);
    server.await.unwrap();
}

#[test]
fn slow_body_requires_a_dedicated_nonempty_test_exchange() {
    for settings in [
        HttpSettings {
            path: "/".into(),
            body: "test".into(),
            dedicated_test_endpoint: true,
            ..Default::default()
        },
        HttpSettings {
            path: "/isradar-test".into(),
            body: "test".into(),
            dedicated_test_endpoint: false,
            ..Default::default()
        },
        HttpSettings {
            path: "/isradar-test".into(),
            dedicated_test_endpoint: true,
            ..Default::default()
        },
    ] {
        let options = ProtocolOptions {
            http: Some(settings),
            ..Default::default()
        };
        assert!(Backend::HttpSlowBody.validate_options(&options).is_err());
    }
    let options = ProtocolOptions {
        http: Some(HttpSettings {
            path: "/isradar-test".into(),
            body: "test".into(),
            dedicated_test_endpoint: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    Backend::HttpSlowBody.validate_options(&options).unwrap();
}
