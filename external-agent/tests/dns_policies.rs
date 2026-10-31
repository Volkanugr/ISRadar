mod support;
use ed25519_dalek::{Signer, SigningKey};
use external_agent::{
    network::{dns_wire, dnssec_wire},
    results::Outcome,
    settings::DnssecAnchor,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

fn answer(query: &[u8], id: &str) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] |= 0x80;
    match id {
        "DNS-007" => response[3] = 3,
        "DNS-012" => {
            assert_eq!(query[2] & 1, 1);
            response[3] |= 0x80;
        }
        "DNS-014" => {
            response[2] |= 2;
            response[7] = 1;
        } // Incomplete answer is valid only on the TC inspection path.
        "DNS-015" => {
            response[7] = 1;
            response.extend_from_slice(
                b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01",
            );
        }
        _ => {}
    }
    response
}

fn signed_answer(query: &[u8], key: &SigningKey, corrupt: bool) -> Vec<u8> {
    let (owner, end) = dns_wire::canonical_name(query, 12).unwrap();
    let mut response = query[..end + 4].to_vec();
    response[2] = 0x84;
    response[3] = 0x20; // AD is deliberately not trusted.
    response[6..12].copy_from_slice(&[0, 2, 0, 0, 0, 0]);
    response.extend_from_slice(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\xc0\x00\x02\x01");
    let now = chrono::Utc::now().timestamp() as u32;
    let mut fields = vec![0, 1, 15, 2];
    fields.extend_from_slice(&300u32.to_be_bytes());
    fields.extend_from_slice(&(now + 600).to_be_bytes());
    fields.extend_from_slice(&(now - 60).to_be_bytes());
    fields.extend_from_slice(
        &dnssec_wire::key_tag(&key.verifying_key().to_bytes(), 257).to_be_bytes(),
    );
    fields.extend_from_slice(b"\x07example\0");
    let mut message = fields.clone();
    message.extend_from_slice(&owner);
    message.extend_from_slice(b"\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\xc0\x00\x02\x01");
    let mut signature = key.sign(&message).to_bytes();
    if corrupt {
        signature[0] ^= 1;
    }
    fields.extend_from_slice(&signature);
    response.extend_from_slice(b"\xc0\x0c\x00\x2e\x00\x01\x00\x00\x01\x2c");
    response.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    response.extend_from_slice(&fields);
    response
}

#[tokio::test]
async fn dns_policy_and_signed_rrset_validation() {
    for id in [
        "DNS-006", "DNS-007", "DNS-012", "DNS-013", "DNS-014", "DNS-015", "DNS-016",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let socket = UdpSocket::bind(address).await.unwrap();
        let server = tokio::spawn(async move {
            if id == "DNS-016" {
                let (mut stream, _) = listener.accept().await.unwrap();
                let n = stream.read_u16().await.unwrap();
                let mut query = vec![0; n as usize];
                stream.read_exact(&mut query).await.unwrap();
                let response = answer(&query, id);
                stream.write_u16(response.len() as u16).await.unwrap();
                stream.write_all(&response).await.unwrap();
            } else {
                let mut b = [0; 4096];
                let (n, peer) = socket.recv_from(&mut b).await.unwrap();
                socket.send_to(&answer(&b[..n], id), peer).await.unwrap();
            }
        });
        let mut target = support::target(address);
        target.server_name = Some("host.example".into());
        let (_dir, config) = support::configured(target, &[id], support::limits(1));
        let report = support::run(config).await;
        assert_eq!(
            report.observations[0].outcome,
            Outcome::Success,
            "{id}: {:?}",
            report.observations
        );
        server.await.unwrap();
    }
    for corrupt in [false, true] {
        let key = SigningKey::from_bytes(&[19; 32]);
        let public_key_hex = hex::encode(key.verifying_key().to_bytes());
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut b = [0; 4096];
            let (n, peer) = socket.recv_from(&mut b).await.unwrap();
            socket
                .send_to(&signed_answer(&b[..n], &key, corrupt), peer)
                .await
                .unwrap();
        });
        let mut target = support::target(address);
        target.server_name = Some("host.example".into());
        let (_dir, mut config) = support::configured(target, &["DNS-008"], support::limits(1));
        config.protocol.dnssec = Some(DnssecAnchor {
            zone: "example".into(),
            public_key_hex,
            flags: 257,
        });

        let report = support::run(config).await;
        assert_eq!(
            report.observations[0].outcome,
            if corrupt {
                Outcome::ProtocolError
            } else {
                Outcome::Success
            },
            "{:?}",
            report.observations
        );
        server.await.unwrap();
    }
}
