mod support;
use external_agent::results::Outcome;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

#[tokio::test]
async fn additional_protocol_transports() {
    for id in ["TCP-017", "TCP-019"] {
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
            support::configured(support::target(address), &[id], support::limits(1));
        let report = support::run(config).await;
        assert_eq!(
            report.observations[0].outcome,
            Outcome::Success,
            "{id}: {:?}",
            report.observations
        );
        server.await.unwrap();
    }
    for (id, size) in [("UDP-003", 128), ("UDP-006", 64), ("NTP-006", 48)] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut bytes = [0; 4096];
            let (received, peer) = socket.recv_from(&mut bytes).await.unwrap();
            assert_eq!(received, size);
            if id == "NTP-006" {
                let stamp = bytes[40..48].to_vec();
                bytes[..48].fill(0);
                bytes[0] = 0x1c;
                bytes[1] = 2;
                bytes[24..32].copy_from_slice(&stamp);
            }
            socket.send_to(&bytes[..received], peer).await.unwrap();
        });
        let (_dir, config) =
            support::configured(support::target(address), &[id], support::limits(1));
        let report = support::run(config).await;
        assert_eq!(
            report.observations[0].outcome,
            Outcome::Success,
            "{id}: {:?}",
            report.observations
        );
        server.await.unwrap();
    }
    // A responding socket is a portable negative fixture for a claimed closed port.
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut b = [0; 128];
        let (n, p) = socket.recv_from(&mut b).await.unwrap();
        socket.send_to(&b[..n], p).await.unwrap();
    });
    let (_dir, config) =
        support::configured(support::target(address), &["UDP-002"], support::limits(1));
    assert_eq!(
        support::run(config).await.observations[0].outcome,
        Outcome::RemoteRejection
    );
    server.await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("OPTIONS "));
        let get = |name: &str| {
            request
                .lines()
                .find(|l| {
                    l.to_ascii_lowercase()
                        .starts_with(&format!("{}:", name.to_ascii_lowercase()))
                })
                .unwrap()
                .to_owned()
        };
        let response = format!(
            "SIP/2.0 200 OK\r\n{}\r\n{}\r\n{}\r\nContent-Length: 0\r\n\r\n",
            get("Via"),
            get("Call-ID"),
            get("CSeq")
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    let (_dir, config) =
        support::configured(support::target(address), &["SIP-007"], support::limits(1));
    let report = support::run(config).await;
    assert_eq!(
        report.observations[0].outcome,
        Outcome::Success,
        "{:?}",
        report.observations
    );
    server.await.unwrap();
}
