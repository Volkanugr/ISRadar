mod support;
use external_agent::{engine, vectors::registry::Registry};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn extended_live_protocols() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 128];
        loop {
            let size = stream.read(&mut buffer).await.unwrap();
            if size == 0 {
                break;
            }
            stream.write_all(&buffer[..size]).await.unwrap();
        }
    });
    let (_dir, config) =
        support::configured(support::target(address), &["TCP-018"], support::limits(1));
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.metrics.responses_received, 1);
    assert_eq!(report.metrics.application_datagrams_sent, 0);
    assert!(report.metrics.application_bytes_sent > 0);
    assert_eq!(
        report.metrics.application_bytes_sent,
        report.metrics.application_bytes_received
    );
    echo.await.unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        for _ in 0..2 {
            let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
            socket.send_to(&buffer[..size], peer).await.unwrap();
        }
    });
    let (_dir, config) = support::configured(
        support::target(address),
        &["UDP-004", "UDP-007"],
        support::limits(2),
    );
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.metrics.responses_received, 2);
    assert_eq!(report.metrics.application_datagrams_sent, 2);
    assert_eq!(report.metrics.application_bytes_sent, 1200);
    assert_eq!(report.metrics.application_bytes_received, 1200);
    echo.await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let udp = UdpSocket::bind(address).await.unwrap();
    let (send_query, get_query) = tokio::sync::oneshot::channel();
    let udp_server = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        let (size, peer) = udp.recv_from(&mut buffer).await.unwrap();
        send_query.send(buffer[..size].to_vec()).unwrap();
        buffer[2] = 0x82; // QR and TC: retry via TCP to the same authorized endpoint.
        udp.send_to(&buffer[..size], peer).await.unwrap();
    });
    let tcp_server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut query = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut query).await.unwrap();
        assert_eq!(query, get_query.await.unwrap());
        query[2] = 0x80;
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&query).await.unwrap();
    });
    let mut target = support::target(address);
    target.server_name = Some("owned.example".into());
    let (_dir, config) = support::configured(target, &["DNS-009"], support::limits(1));
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.metrics.responses_received, 1);
    assert_eq!(report.metrics.tcp_handshake_successes, 1);
    assert_eq!(report.metrics.application_datagrams_sent, 1);
    assert_eq!(report.metrics.protocol_errors, 0);
    udp_server.await.unwrap();
    tcp_server.await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let h2_server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(stream).await.unwrap();
        while let Some(Ok((_request, mut response))) = connection.accept().await {
            response
                .send_response(
                    http::Response::builder().status(200).body(()).unwrap(),
                    true,
                )
                .unwrap();
        }
    });
    let (_dir, config) =
        support::configured(support::target(address), &["HTTP-011"], support::limits(1));
    let report = engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.metrics.http_successes, 1);
    assert!(report.observations[0].detail.contains("HTTP/2"));
    h2_server.abort();
}
