mod support;
#[test]
fn ntp_kiss_of_death_accepts_alarm_leap_but_requires_matching_origin() {
    let query = external_agent::vectors::protocols::ntp_query();
    let mut response = [0u8; 48];
    response[0] = 0xe4; // LI=3, version=4, mode=4; stratum=0.
    response[12..16].copy_from_slice(b"RATE");
    response[24..32].copy_from_slice(&query[40..48]);
    external_agent::vectors::protocols::ntp_response(&query, &response).unwrap();
    response[1] = 2;
    assert!(external_agent::vectors::protocols::ntp_response(&query, &response).is_err());
    response[1] = 0;
    response[24] ^= 1;
    assert!(external_agent::vectors::protocols::ntp_response(&query, &response).is_err());
}
use external_agent::{
    engine, network,
    vectors::{lab, protocols, registry::Registry},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

#[test]
fn ipv4_fixture_checksums() {
    let packet = lab::ipv4_fixture();
    lab::inspect_ipv4(&packet).unwrap();
    assert_eq!(network::internet_checksum(&packet[..20]), 0);
    assert_eq!(network::internet_checksum(&packet[20..]), 0);
    let mut corrupt = packet.clone();
    corrupt[8] ^= 1;
    assert!(lab::inspect_ipv4(&corrupt).is_err());
    assert!(lab::inspect_ipv4(&packet[..19]).is_err());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.pcap");
    lab::write_fixture_pcap(&path).unwrap();
    let pcap = std::fs::read(path).unwrap();
    assert_eq!(pcap.len(), 24 + 16 + packet.len());
    assert_eq!(&pcap[40..], packet);
    assert_eq!(u32::from_le_bytes(pcap[20..24].try_into().unwrap()), 101);
}

#[test]
fn dns_rejects_mismatched_transactions_questions_and_truncation() {
    let query = protocols::dns_query("owned.example", 1, 42).unwrap();
    assert_eq!(query[2] & 1, 0); // No recursive resolution.
    let mut response = query.clone();
    response[2] |= 0x80;
    protocols::dns_response(&query, &response).unwrap();
    let mut wrong = response.clone();
    wrong[1] ^= 1;
    assert!(protocols::dns_response(&query, &wrong).is_err());
    let mut wrong = response.clone();
    wrong[13] ^= 1;
    assert!(protocols::dns_response(&query, &wrong).is_err());
    response[2] |= 2;
    assert!(protocols::dns_response(&query, &response).is_err());
    assert!(protocols::dns_query("bad..name", 1, 42).is_err());
    assert!(protocols::dns_query("owned.example", 255, 42).is_ok());
    assert!(protocols::dns_query("owned.example", 252, 42).is_err());
}

#[test]
fn ntp_and_sip_validate_transaction_identity() {
    let query = protocols::ntp_query();
    let mut response = [0u8; 48];
    response[0] = 0x24;
    response[1] = 2;
    response[24..32].copy_from_slice(&query[40..48]);
    protocols::ntp_response(&query, &response).unwrap();
    response[24] ^= 1;
    assert!(protocols::ntp_response(&query, &response).is_err());
    let sip = b"SIP/2.0 200 OK\r\nCall-ID: test\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP localhost;branch=z9hG4bKtest\r\n\r\n";
    assert_eq!(
        protocols::sip_response(sip, "test", "z9hG4bKtest").unwrap(),
        200
    );
    assert!(protocols::sip_response(sip, "wrong", "z9hG4bKtest").is_err());
}

#[tokio::test]
async fn live_protocol_smoke() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    let (_dir, config) =
        support::configured(support::target(address), &["TCP-001"], support::limits(3));
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.metrics.tcp_handshake_successes, 3);
    assert!(report.metrics.packets_sent.is_none());
    server.abort();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        loop {
            let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
            socket.send_to(&buffer[..size], peer).await.unwrap();
        }
    });
    let (_dir, config) =
        support::configured(support::target(address), &["UDP-001"], support::limits(3));
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.metrics.responses_received, 3);
    assert_eq!(report.metrics.application_datagrams_sent, 3);
    assert!(report.metrics.application_bytes_sent > 0);
    server.abort();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
    });
    let (_dir, config) = support::configured(
        support::target(address),
        &["HTTP-001", "HTTP-003", "HTTP-007"],
        support::limits(3),
    );
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.metrics.http_successes, 3);
    assert_eq!(
        report
            .observations
            .iter()
            .map(|o| o.vector_id.as_str())
            .collect::<Vec<_>>(),
        ["HTTP-001", "HTTP-003", "HTTP-007"]
    );
    server.abort();
}

#[tokio::test]
async fn http_does_not_follow_redirects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 4096];
        let received = stream.read(&mut buffer).await.unwrap();
        assert!(received > 0);
        stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    });
    let (_dir, config) =
        support::configured(support::target(address), &["HTTP-001"], support::limits(1));
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.observations[0].http_status, Some(302));
    server.await.unwrap();
}

#[tokio::test]
async fn cancellation_closes_in_flight_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
        drop(stream);
    });
    let mut limits = support::limits(100);
    limits.timeout_ms = 5000;
    let (_dir, config) = support::configured(support::target(address), &["HTTP-001"], limits);
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        token.cancel();
    });
    let start = Instant::now();
    let report = engine::run(config, Registry::bundled().unwrap(), cancel)
        .await
        .unwrap();
    assert_eq!(report.termination_reason, "cancelled");
    assert!(report.metrics.probes_cancelled > 0);
    assert!(start.elapsed() < Duration::from_secs(2));
    server.abort();
}

#[tokio::test]
async fn kill_switch_stops_a_running_test() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (_dir, config) =
        support::configured(support::target(address), &["TCP-001"], support::limits(100));
    let stop = config.kill_switch.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        std::fs::write(stop, b"stop").unwrap();
    });
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.termination_reason, "kill_switch");
    assert!(report.metrics.probes_started < 100);
    drop(listener);
}

#[tokio::test]
async fn duration_deadline_cancels_pending_io() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut limits = support::limits(100);
    limits.duration_seconds = 1;
    limits.timeout_ms = 5000;
    let (_dir, config) = support::configured(
        support::target(socket.local_addr().unwrap()),
        &["UDP-001"],
        limits,
    );
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.termination_reason, "duration_limit");
    assert!(report.metrics.probes_cancelled > 0);
    assert!(report.metrics.application_bytes_sent > 0);
    assert!(report.actual_duration_seconds < 2.0);
}

#[tokio::test]
async fn dns_and_ntp_live_transactions() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        loop {
            let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
            buffer[2] |= 0x84;
            socket.send_to(&buffer[..size], peer).await.unwrap();
        }
    });
    let mut target = support::target(address);
    target.server_name = Some("owned.example".into());
    let (_dir, config) = support::configured(
        target,
        &[
            "DNS-001", "DNS-002", "DNS-003", "DNS-004", "DNS-005", "DNS-010", "DNS-011",
        ],
        support::limits(7),
    );
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.metrics.responses_received, 7);
    assert_eq!(report.metrics.protocol_errors, 0);
    server.abort();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut query = [0u8; 4096];
        let (_, peer) = socket.recv_from(&mut query).await.unwrap();
        let mut response = [0u8; 48];
        response[0] = 0x24;
        response[1] = 2;
        response[24..32].copy_from_slice(&query[40..48]);
        socket.send_to(&response, peer).await.unwrap();
    });
    let (_dir, config) =
        support::configured(support::target(address), &["NTP-001"], support::limits(1));
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.metrics.responses_received, 1);
    assert_eq!(report.metrics.protocol_errors, 0);
    server.await.unwrap();
}

#[tokio::test]
async fn tls_checks_reject_plaintext_services() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer).await;
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
            });
        }
    });
    let mut target = support::target(address);
    target.server_name = Some("owned.example".into());
    let (_dir, config) = support::configured(
        target,
        &["TLS-001", "TLS-002", "HTTP-015", "HTTP-016"],
        support::limits(4),
    );
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.metrics.tcp_handshake_successes, 0);
    assert_eq!(report.metrics.responses_received, 0);
    assert_eq!(
        report.metrics.protocol_errors + report.metrics.network_errors,
        4
    );
    server.abort();
}

#[tokio::test]
async fn health_failures_stop_standard_validation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let (_dir, mut config) =
        support::configured(support::target(address), &["TCP-001"], support::limits(100));
    config.health.consecutive_failures = 2;
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.termination_reason, "health_degradation");
    assert_eq!(report.metrics.remote_rejections, 2);
    assert!(report.metrics.probes_started < 100);
}

#[tokio::test]
async fn controller_disconnect_stops_running_io() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (dir, mut config) = support::configured(
        support::target(socket.local_addr().unwrap()),
        &["UDP-001"],
        support::limits(100),
    );
    let heartbeat = dir.path().join("heartbeat");
    std::fs::write(&heartbeat, b"alive").unwrap();
    config.controller_lease = Some(external_agent::config::Lease {
        heartbeat_file: heartbeat.clone(),
        max_age_seconds: 2,
    });
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        std::fs::remove_file(heartbeat).unwrap();
    });
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.termination_reason, "controller_disconnected");
}
