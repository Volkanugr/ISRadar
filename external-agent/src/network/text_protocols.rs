use crate::{
    results::{Observation, Outcome},
    vectors::{registry::Backend, TestContext},
};
use anyhow::{ensure, Context, Result};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

async fn read_until<T: AsyncRead + Unpin>(
    stream: &mut T,
    delimiter: &[u8],
    context: &TestContext,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while bytes.len() < 4096 {
        let mut one = [0u8; 1];
        let size = stream.read(&mut one).await?;
        ensure!(size != 0, "peer closed before completing protocol response");
        context.counters.stream_received(size);
        bytes.push(one[0]);
        if bytes.ends_with(delimiter) {
            return Ok(bytes);
        }
    }
    anyhow::bail!("text protocol response exceeds 4096 bytes")
}

async fn sip_on<T: AsyncRead + AsyncWrite + Unpin>(
    mut stream: T,
    local: std::net::SocketAddr,
    secure: bool,
    context: &TestContext,
) -> Result<Observation> {
    let target = context.target.as_ref().context("SIP target required")?;
    let host = match target.ip {
        std::net::IpAddr::V4(v) => v.to_string(),
        std::net::IpAddr::V6(v) => format!("[{v}]"),
    };
    let call_id = format!("{:016x}@isradar.invalid", rand::random::<u64>());
    let branch = format!("z9hG4bK{:016x}", rand::random::<u64>());
    let transport = if secure { "TLS" } else { "TCP" };
    let query = format!("OPTIONS sip:{host}:{} SIP/2.0\r\nVia: SIP/2.0/{transport} {local};branch={branch}\r\nMax-Forwards: 0\r\nFrom: <sip:validator@isradar.invalid>;tag=check\r\nTo: <sip:{host}>\r\nCall-ID: {call_id}\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n", target.port);
    super::write_counted(&mut stream, query.as_bytes(), &context.counters).await?;
    let mut received = 0usize;
    let mut final_status = None;
    for _ in 0..8 {
        let response = read_until(&mut stream, b"\r\n\r\n", context).await?;
        received += response.len();
        let head = super::sip_wire::parse_response_head(&response, &call_id, &branch, "OPTIONS", 1)
            .map_err(anyhow::Error::msg)?;
        let body_bytes = head
            .body_bytes
            .context("SIP stream requires Content-Length")?;
        ensure!(
            response.len() + body_bytes <= 4096,
            "SIP message exceeds response cap"
        );
        super::read_counted(&mut stream, body_bytes, &context.counters).await?;
        received += body_bytes;
        let code = head.status;
        if code >= 200 {
            final_status = Some(code);
            break;
        }
    }
    let code = final_status.context("SIP OPTIONS final response missing within response cap")?;
    stream.shutdown().await?;
    let mut value = Observation::success(format!(
        "SIP OPTIONS transaction validated over {transport}: {code}"
    ));
    value.tcp_handshake_success = true;
    value.response_received = true;
    value.application_bytes_sent = query.len() as u64;
    value.application_bytes_received = received as u64;
    value
        .protocol_details
        .insert("sip_status".into(), code.into());
    value
        .protocol_details
        .insert("sip_transport".into(), transport.into());
    if code >= 300 {
        value.outcome = Outcome::RemoteRejection;
    }
    Ok(value)
}

pub(crate) async fn sip(backend: Backend, context: &TestContext) -> Result<Observation> {
    if backend == Backend::SipTls {
        let config = super::tls_checks::client_config(backend, &context.protocol)?;
        let stream = super::tls_checks::connect(context, config).await?;
        let local = stream.get_ref().0.local_addr()?;
        sip_on(stream, local, true, context).await
    } else {
        let stream = TcpStream::connect(
            context
                .target
                .as_ref()
                .context("target required")?
                .address(),
        )
        .await?;
        let local = stream.local_addr()?;
        sip_on(stream, local, false, context).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn sip_options_waits_for_final_status_in_memory() {
        for final_status in [200, 503] {
            let (client, mut server) = tokio::io::duplex(4096);
            let peer = tokio::spawn(async move {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(server.read_u8().await.unwrap());
                }
                let request = String::from_utf8(request).unwrap();
                let headers = request
                    .split("\r\n")
                    .filter(|l| {
                        l.starts_with("Via:") || l.starts_with("CSeq:") || l.starts_with("Call-ID:")
                    })
                    .collect::<Vec<_>>()
                    .join("\r\n");
                for code in [100, final_status] {
                    server
                        .write_all(
                            format!(
                                "SIP/2.0 {code} Test\r\n{headers}\r\nContent-Length: 4\r\n\r\ntest"
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                }
            });
            let context = TestContext {
                raw_allowed: false,
                protocol: Default::default(),
                target: Some(crate::config::Target {
                    ip: "127.0.0.1".parse().unwrap(),
                    port: 5060,
                    server_name: None,
                }),
                timeout_ms: 500,
                measurement: None,
                sequence: 0,
                http_request_id: None,
                counters: Default::default(),
            };
            let result = sip_on(client, "127.0.0.1:40000".parse().unwrap(), false, &context)
                .await
                .unwrap();
            assert_eq!(result.protocol_details["sip_status"], final_status);
            assert_eq!(
                result.outcome,
                if final_status == 200 {
                    Outcome::Success
                } else {
                    Outcome::RemoteRejection
                }
            );
            peer.await.unwrap();
        }
    }
}
