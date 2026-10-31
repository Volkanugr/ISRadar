use crate::{
    results::{Observation, Outcome},
    settings::HttpSettings,
    vectors::{registry::Backend, TestContext},
};
use anyhow::{ensure, Context, Result};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

pub(crate) async fn execute(backend: Backend, context: &TestContext) -> Result<Observation> {
    let target = context.target.as_ref().context("target required")?;
    let mut stream = TcpStream::connect(target.address()).await?;
    let mut value = Observation::success("bounded TCP session exchange completed");
    value.tcp_handshake_success = true;
    let messages = match backend {
        Backend::TcpSession => vec![
            format!("isradar-session-{}-first\n", context.sequence).into_bytes(),
            format!("isradar-session-{}-second\n", context.sequence).into_bytes(),
        ],
        Backend::TcpHalfClose => vec![b"isradar-half-close\n".to_vec()],
        _ => anyhow::bail!("unsupported session backend"),
    };
    for payload in &messages {
        super::write_counted(&mut stream, payload, &context.counters).await?;
        value.application_bytes_sent += payload.len() as u64;
        if backend == Backend::TcpHalfClose {
            stream.shutdown().await?;
        }
        let reply = super::read_counted(&mut stream, payload.len(), &context.counters).await?;
        ensure!(
            &reply == payload,
            "session echo did not match the sent challenge"
        );
        value.application_bytes_received += reply.len() as u64;
    }
    if backend == Backend::TcpHalfClose {
        let mut trailing = [0u8; 1];
        let size = stream.read(&mut trailing).await?;
        context.counters.stream_received(size);
        ensure!(
            size == 0,
            "peer did not close cleanly after half-close echo"
        );
        value.detail =
            "TCP write-half shutdown followed by matching echo and EOF; no arbitrary FIN injection"
                .into();
    } else {
        stream.shutdown().await?;
    }
    value.response_received = true;
    value
        .protocol_details
        .insert("messages_on_one_connection".into(), messages.len().into());

    Ok(value)
}

pub(crate) async fn reuse_http(
    context: &TestContext,
    settings: &HttpSettings,
) -> Result<Observation> {
    let target = context.target.as_ref().context("target required")?;
    let authority = if let Some(host) = &target.server_name {
        format!("{host}:{}", target.port)
    } else {
        target.address().to_string()
    };
    let stream = TcpStream::connect(target.address()).await?;
    reuse_http_on(stream, &authority, context, settings).await
}

async fn reuse_http_on<T: AsyncRead + AsyncWrite + Unpin>(
    mut stream: T,
    authority: &str,
    context: &TestContext,
    settings: &HttpSettings,
) -> Result<Observation> {
    let mut value =
        Observation::success("two complete HEAD responses received on the same TCP connection");
    value.tcp_handshake_success = true;
    let mut statuses = Vec::new();
    for iteration in 0..2 {
        let request = format!("HEAD {} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: isradar-external-agent/0.1\r\nConnection: {}\r\n\r\n", settings.path, if iteration == 0 { "keep-alive" } else { "close" });
        super::write_counted(&mut stream, request.as_bytes(), &context.counters).await?;
        value.application_bytes_sent += request.len() as u64;
        let response = read_final_http_head(&mut stream, context, &mut value).await?;
        if iteration == 0 {
            ensure!(
                response.allows_reuse(),
                "HTTP peer declined connection reuse"
            );
        }
        statuses.push(response.status);
        if settings
            .expected_status
            .is_some_and(|expected| response.status != expected)
            || (settings.expected_status.is_none() && !(200..400).contains(&response.status))
        {
            value.outcome = Outcome::RemoteRejection;
        }
    }
    value.http_status = statuses.last().copied();
    value.response_received = true;
    value
        .protocol_details
        .insert("http_statuses".into(), serde_json::to_value(statuses)?);
    value
        .protocol_details
        .insert("connection_reused".into(), true.into());
    stream.shutdown().await?;
    Ok(value)
}

pub(crate) async fn slow_http(
    backend: Backend,
    context: &TestContext,
    settings: &HttpSettings,
) -> Result<Observation> {
    ensure!(
        matches!(backend, Backend::HttpSlowHeaders | Backend::HttpSlowBody),
        "unsupported slow HTTP backend"
    );
    let target = context.target.as_ref().context("target required")?;
    let authority = if let Some(host) = &target.server_name {
        format!("{host}:{}", target.port)
    } else {
        target.address().to_string()
    };
    let mut stream = TcpStream::connect(target.address()).await?;
    let mut value = Observation::success("bounded slow HTTP exchange");
    value.tcp_handshake_success = true;
    let method = backend.http_method().context("HTTP method required")?;
    let mut request = format!(
        "{method} {} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: isradar-external-agent/0.1\r\nConnection: close\r\n",
        settings.path
    );
    for (name, header) in &settings.headers {
        request.push_str(&format!("{name}: {header}\r\n"));
    }
    if let Some(id) = &context.http_request_id {
        request.push_str(&format!("X-Isradar-Probe: {id}\r\n"));
    }
    if backend == Backend::HttpSlowBody {
        request.push_str(&format!("Content-Length: {}\r\n", settings.body.len()));
    }
    request.push_str("\r\n");
    ensure!(
        request.len() <= 4096,
        "HTTP request head exceeds 4096 bytes"
    );
    const DELAY: std::time::Duration = std::time::Duration::from_millis(25);
    if backend == Backend::HttpSlowBody {
        super::write_counted(&mut stream, request.as_bytes(), &context.counters).await?;
        value.application_bytes_sent += request.len() as u64;
        let body = settings.body.as_bytes();
        let split = body.len() / 2;
        super::write_counted(&mut stream, &body[..split], &context.counters).await?;
        value.application_bytes_sent += split as u64;
        tokio::time::sleep(DELAY).await;
        super::write_counted(&mut stream, &body[split..], &context.counters).await?;
        value.application_bytes_sent += (body.len() - split) as u64;
    } else {
        let split = request.len() - 2;
        super::write_counted(&mut stream, &request.as_bytes()[..split], &context.counters).await?;
        value.application_bytes_sent += split as u64;
        tokio::time::sleep(DELAY).await;
        super::write_counted(&mut stream, &request.as_bytes()[split..], &context.counters).await?;
        value.application_bytes_sent += (request.len() - split) as u64;
    }
    let response = read_final_http_head(&mut stream, context, &mut value).await?;
    let status = response.status;
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, header) in response.headers {
        headers.append(
            reqwest::header::HeaderName::from_bytes(name.as_bytes())?,
            reqwest::header::HeaderValue::from_str(&header)?,
        );
    }
    let mut observed = super::http_checks::observe_response(backend, settings, status, &headers);
    observed.application_bytes_sent = value.application_bytes_sent;
    observed.application_bytes_received = value.application_bytes_received;
    observed.tcp_handshake_success = true;
    observed
        .protocol_details
        .insert("workload_delay_ms".into(), 25.into());
    observed
        .protocol_details
        .insert("bounded_live_exchange".into(), true.into());
    if observed.outcome == Outcome::Success {
        observed.detail = format!(
            "real bounded {} exchange completed with 25 ms inter-chunk delay; no capacity-exhaustion claim",
            if backend == Backend::HttpSlowBody {
                "slow-body"
            } else {
                "partial-header"
            }
        );
    }
    stream.shutdown().await?;
    Ok(observed)
}

async fn read_final_http_head<T: AsyncRead + Unpin>(
    stream: &mut T,
    context: &TestContext,
    value: &mut Observation,
) -> Result<super::http_head::HttpHead> {
    let mut total = 0;
    for _ in 0..8 {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            ensure!(total < 4096, "HTTP response heads exceed 4096 bytes");
            let mut one = [0; 1];
            let size = stream.read(&mut one).await?;
            ensure!(
                size != 0,
                "HTTP peer closed before completing its response head"
            );
            context.counters.stream_received(size);
            value.application_bytes_received += size as u64;
            head.push(one[0]);
            total += size;
        }
        let response = super::http_head::parse(&head).map_err(anyhow::Error::msg)?;
        ensure!(
            response.status != 101,
            "HTTP protocol upgrade is not supported by the reuse check"
        );
        if response.status >= 200 {
            return Ok(response);
        }
    }
    anyhow::bail!("HTTP final response missing within informational response cap")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn http_reuse_handles_coalesced_informational_responses_in_memory() {
        let context = TestContext {
            raw_allowed: false,
            protocol: Default::default(),
            target: None,
            timeout_ms: 500,
            measurement: None,
            sequence: 0,
            http_request_id: None,
            counters: Default::default(),
        };
        let (client, mut server) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            for status in [200, 503] {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(server.read_u8().await.unwrap());
                }
                assert!(request.starts_with(b"HEAD / HTTP/1.1\r\n"));
                server.write_all(format!("HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 {status} Test\r\nContent-Length: 100\r\n\r\n").as_bytes()).await.unwrap();
            }
        });
        let value = reuse_http_on(client, "example:80", &context, &HttpSettings::default())
            .await
            .unwrap();
        peer.await.unwrap();
        assert_eq!(value.outcome, Outcome::RemoteRejection);
        assert_eq!(
            value.protocol_details["http_statuses"],
            serde_json::json!([200, 503])
        );
        assert_eq!(value.protocol_details["connection_reused"], true);
        for bytes in [
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec(),
            b"HTTP/1.1 103 Early Hints\r\n\r\n".repeat(8),
        ] {
            let mut input = bytes.as_slice();
            assert!(
                read_final_http_head(&mut input, &context, &mut Observation::success("test"))
                    .await
                    .is_err()
            );
        }
    }
}
