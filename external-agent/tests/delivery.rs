#![cfg(feature = "experimental-receiver")]
mod support;
use external_agent::{
    engine,
    measurement::{self, MeasurementConfig, ReceiverConfig},
    vectors::registry::Registry,
};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

#[test]
fn packet_authentication_rejects_forgery_wrong_run_and_wrong_kind() {
    let key = [7u8; 32];
    let run_id = [3u8; 16];
    let frame = measurement::frame(&key, &run_id, 999, false);
    assert_eq!(frame.len(), 64);
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/measurement-golden.json")).unwrap();
    assert_eq!(hex::encode(frame), golden["request_hex"].as_str().unwrap());
    assert_eq!(
        measurement::verify_frame(&key, &run_id, &frame, false).unwrap(),
        999
    );
    assert!(measurement::verify_frame(&key, &run_id, &frame, true).is_err());
    assert!(measurement::verify_frame(&[8; 32], &run_id, &frame, false).is_err());
    assert!(measurement::verify_frame(&key, &[4; 16], &frame, false).is_err());
    let mut forged = frame;
    forged[31] ^= 1;
    assert!(measurement::verify_frame(&key, &run_id, &forged, false).is_err());
    assert!(measurement::verify_frame(&key, &run_id, &frame[..63], false).is_err());
}

async fn direct_measurement(count: u64) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let mut limits = support::limits(count);
    limits.duration_seconds = 40;
    let (dir, mut config) = support::configured(support::target(address), &["UDP-010"], limits);
    let key_file = dir.path().join("measurement.key");
    let run_id = measurement::keygen(&key_file).unwrap();
    config.measurement = Some(MeasurementConfig {
        run_id: run_id.clone(),
        key_file: key_file.clone(),
        await_ack: true,
    });
    let receiver = tokio::spawn(measurement::receive_on(
        socket,
        ReceiverConfig {
            bind: address,
            allowed_peer: address.ip(),
            run_id,
            key_file: key_file.clone(),
            expected_probes: count,
            duration_seconds: 40,
        },
        CancellationToken::new(),
    ));
    let sender = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let receiver = receiver.await.unwrap().unwrap();
    let comparison = measurement::compare(
        &sender,
        &receiver,
        &measurement::read_key(&key_file).unwrap(),
    )
    .unwrap();
    assert_eq!(sender.termination_reason, "completed");
    assert_eq!(sender.metrics.application_datagrams_sent, count);
    assert_eq!(sender.metrics.application_bytes_sent, count * 64);
    assert_eq!(comparison.sent_unique, count as usize);
    assert_eq!(comparison.received_at_destination, count as usize);
    assert_eq!(comparison.acknowledged_at_sender, count as usize);
    assert_eq!(comparison.delivery_ratio, Some(1.0));
    assert!(comparison.missing_at_destination.is_empty());
}

#[tokio::test]
async fn delivery_loopback() {
    direct_measurement(10).await;
}

#[tokio::test]
#[ignore = "20-second bounded 1000-datagram acceptance test; CI includes ignored tests"]
async fn delivery_1000_packets() {
    direct_measurement(1000).await;
}

#[tokio::test]
async fn delivery_reconciliation() {
    let receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_address = receiver_socket.local_addr().unwrap();
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_address = front.local_addr().unwrap();
    let (dir, mut config) = support::configured(
        support::target(proxy_address),
        &["UDP-010"],
        support::limits(10),
    );
    let key_file = dir.path().join("measurement.key");
    let run_id = measurement::keygen(&key_file).unwrap();
    let key = measurement::read_key(&key_file).unwrap();
    let run_bytes: [u8; 16] = hex::decode(&run_id).unwrap().try_into().unwrap();
    config.limits.timeout_ms = 100;
    config.measurement = Some(MeasurementConfig {
        run_id: run_id.clone(),
        key_file: key_file.clone(),
        await_ack: true,
    });
    let receiver_cancel = CancellationToken::new();
    let receiver = tokio::spawn(measurement::receive_on(
        receiver_socket,
        ReceiverConfig {
            bind: receiver_address,
            allowed_peer: receiver_address.ip(),
            run_id,
            key_file,
            expected_probes: 10,
            duration_seconds: 10,
        },
        receiver_cancel.clone(),
    ));
    let proxy = tokio::spawn(async move {
        let mut buffer = [0u8; 128];
        loop {
            let (size, client) = front.recv_from(&mut buffer).await.unwrap();
            let sequence =
                measurement::verify_frame(&key, &run_bytes, &buffer[..size], false).unwrap();
            if sequence == 0 || sequence == 5 {
                continue;
            } // Forward-path loss.
            let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            upstream.connect(receiver_address).await.unwrap();
            upstream.send(&buffer[..size]).await.unwrap();
            if sequence == 4 {
                upstream.send(&buffer[..size]).await.unwrap();
            } // Duplicate.
            let mut ack = [0u8; 128];
            let size = upstream.recv(&mut ack).await.unwrap();
            if sequence != 3 {
                front.send_to(&ack[..size], client).await.unwrap();
            } // Reverse-path loss.
        }
    });
    let sender = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    receiver_cancel.cancel();
    let receiver = receiver.await.unwrap().unwrap();
    proxy.abort();
    let comparison = measurement::compare(&sender, &receiver, &key).unwrap();
    assert_eq!(comparison.sent_unique, 10);
    assert_eq!(comparison.received_at_destination, 8);
    assert_eq!(comparison.acknowledged_at_sender, 7);
    assert_eq!(comparison.missing_at_destination, [0, 5]);
    assert_eq!(comparison.received_without_ack, [3]);
    assert_eq!(comparison.duplicate_datagrams_at_destination, 1);
    assert_eq!(sender.metrics.timeouts, 3);
    assert_eq!(sender.termination_reason, "completed");
    let mut tampered = receiver;
    tampered.duplicates += 1;
    assert!(measurement::compare(&sender, &tampered, &key).is_err());
}

#[tokio::test]
async fn receiver_ignores_unauthenticated_and_out_of_scope_datagrams() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("key");
    let run_id = measurement::keygen(&key_file).unwrap();
    let key = measurement::read_key(&key_file).unwrap();
    let run_bytes: [u8; 16] = hex::decode(&run_id).unwrap().try_into().unwrap();
    let receiver = tokio::spawn(measurement::receive_on(
        socket,
        ReceiverConfig {
            bind: address,
            allowed_peer: address.ip(),
            run_id,
            key_file,
            expected_probes: 1,
            duration_seconds: 2,
        },
        CancellationToken::new(),
    ));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"not a measurement", address).await.unwrap();
    client
        .send_to(&measurement::frame(&key, &run_bytes, 99, false), address)
        .await
        .unwrap();
    client
        .send_to(&measurement::frame(&key, &run_bytes, 0, false), address)
        .await
        .unwrap();
    let receiver = receiver.await.unwrap().unwrap();
    assert_eq!(receiver.rejected_datagrams, 2);
    assert_eq!(receiver.received_sequences, [0]);
    assert_eq!(receiver.acks_sent, 1);
}
