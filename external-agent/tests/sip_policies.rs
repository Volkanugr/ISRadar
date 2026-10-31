mod support;
use external_agent::{results::Outcome, settings::SipSettings};
use tokio::net::UdpSocket;

fn reply(request: &str, code: u16) -> String {
    let headers: Vec<_> = request
        .split("\r\n")
        .filter(|line| {
            ["via:", "from:", "to:", "call-id:", "cseq:"]
                .iter()
                .any(|prefix| line.to_ascii_lowercase().starts_with(prefix))
        })
        .collect();
    format!(
        "SIP/2.0 {code} Test\r\n{}\r\nContent-Length: 0\r\n\r\n",
        headers.join("\r\n")
    )
}

#[tokio::test]
async fn sip_policy_uses_dedicated_identity_and_matching_transactions() {
    for (id, code) in [("SIP-002", 420), ("SIP-003", 200), ("SIP-002", 200)] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut b = [0; 4096];
            let (n, peer) = socket.recv_from(&mut b).await.unwrap();
            let request = std::str::from_utf8(&b[..n]).unwrap().to_owned();
            assert!(request.contains("isradar-fixture@"));
            assert!(request.contains("Max-Forwards: 0\r\n"));
            if id == "SIP-003" {
                assert!(request.starts_with("REGISTER "));
                assert!(!request.contains("Contact:"));
            } else {
                assert!(request.starts_with("INVITE "));
                assert!(request.contains("Require: isradar-no-session\r\n"));
            }
            socket
                .send_to(reply(&request, code).as_bytes(), peer)
                .await
                .unwrap();
            if id == "SIP-002" {
                let (n, from) = socket.recv_from(&mut b).await.unwrap();
                assert_eq!(from, peer);
                assert!(b[..n].starts_with(b"ACK "));
                if code == 200 {
                    let (n, from) = socket.recv_from(&mut b).await.unwrap();
                    assert_eq!(from, peer);
                    let bye = std::str::from_utf8(&b[..n]).unwrap();
                    assert!(bye.starts_with("BYE "));
                    assert!(bye.contains("CSeq: 2 BYE\r\n"));
                    socket
                        .send_to(reply(bye, 200).as_bytes(), peer)
                        .await
                        .unwrap();
                }
            }
        });
        let mut limits = support::limits(1);
        limits.probes_per_second = 1;
        limits.concurrency = 1;
        limits.timeout_ms = 2000;
        let (_dir, mut config) = support::configured(support::target(address), &[id], limits);
        config.protocol.sip = Some(SipSettings {
            test_user: "isradar-fixture".into(),
            dedicated_test_endpoint: true,
            expected_status: Some(code),
        });

        let report = support::run(config).await;
        assert_eq!(
            report.observations[0].outcome,
            Outcome::Success,
            "{id}/{code}: {:?}",
            report.observations
        );
        assert_eq!(
            report.metrics.application_datagrams_sent,
            if id == "SIP-003" {
                1
            } else if code == 200 {
                3
            } else {
                2
            }
        );
        server.await.unwrap();
    }
}
