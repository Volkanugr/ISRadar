mod support;
use external_agent::{
    engine,
    measurement::{self, MeasurementConfig},
    results::Outcome,
    vectors::registry::Registry,
};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

#[test]
fn sender_frame_matches_golden_vector() {
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/measurement-golden.json")).unwrap();
    let key: [u8; 32] = hex::decode(golden["key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let run_id: [u8; 16] = hex::decode(golden["run_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let frame = measurement::frame(&key, &run_id, 999, false);
    assert_eq!(hex::encode(frame), golden["request_hex"].as_str().unwrap());
    assert_eq!(
        measurement::verify_frame(&key, &run_id, &frame, false).unwrap(),
        999
    );
    assert!(measurement::verify_frame(&key, &run_id, &frame, true).is_err());
    let mut corrupt = frame;
    corrupt[31] ^= 1;
    assert!(measurement::verify_frame(&key, &run_id, &corrupt, false).is_err());
}

async fn send_without_ack(count: u64) {
    // A drain socket is a test fixture, not a shipped receiver service. It sends no ACKs.
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let mut limits = support::limits(count);
    limits.duration_seconds = 40;
    let (dir, mut config) = support::configured(support::target(address), &["UDP-010"], limits);
    let key_file = dir.path().join("measurement.key");
    let run_id = measurement::keygen(&key_file).unwrap();
    let key = measurement::read_key(&key_file).unwrap();
    config.measurement = Some(MeasurementConfig {
        run_id,
        key_file,
        await_ack: false,
    });
    let drain = tokio::spawn(async move {
        let mut buffer = [0u8; 128];
        loop {
            socket.recv_from(&mut buffer).await.unwrap();
        }
    });
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    drain.abort();
    assert_eq!(report.termination_reason, "completed");
    assert_eq!(report.metrics.probes_completed, count);
    assert_eq!(report.metrics.application_datagrams_sent, count);
    assert_eq!(report.metrics.application_bytes_sent, count * 64);
    assert_eq!(report.metrics.responses_received, 0);
    assert_eq!(report.metrics.timeouts, 0);
    assert!(report.metrics.packets_sent.is_none());
    assert!(report
        .observations
        .iter()
        .all(|o| o.outcome == Outcome::Sent && !o.response_received));
    let evidence = report.delivery.as_ref().unwrap();
    measurement::verify_sender(evidence, &key).unwrap();
    assert_eq!(evidence.sent_sequences, (0..count).collect::<Vec<_>>());
    assert!(evidence.acknowledged_sequences.is_empty());
}

#[tokio::test]
async fn sender_datagrams_without_listener_ack() {
    send_without_ack(10).await;
}

#[tokio::test]
#[ignore = "20-second sender-only 1000-datagram acceptance test; CI includes ignored tests"]
async fn sender_1000_datagrams() {
    send_without_ack(1000).await;
}

#[test]
fn sender_defaults_to_no_ack_waiting() {
    let config: MeasurementConfig = serde_json::from_value(serde_json::json!({
        "run_id": "03030303030303030303030303030303", "key_file": "measurement.key"
    }))
    .unwrap();
    assert!(!config.await_ack);
}

#[test]
#[cfg(not(feature = "experimental-receiver"))]
fn default_cli_is_sender_only() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_external-agent"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("run"));
    for command in ["receiver", "compare", "capture"] {
        assert!(!help
            .lines()
            .any(|line| line.trim_start().starts_with(command)));
    }
}
