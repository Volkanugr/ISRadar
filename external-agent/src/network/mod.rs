use anyhow::{Context, Result};
#[cfg(feature = "packet-capture")]
pub mod capture;
pub mod dns_wire;
pub(crate) mod dnssec;
pub mod dnssec_wire;
pub(crate) mod http3;
pub(crate) mod http_checks;
pub mod http_head;
pub mod lab_fixtures;
pub mod packets;
pub(crate) mod raw;
pub(crate) mod sessions;
pub(crate) mod sip_policy;
pub mod sip_wire;
pub(crate) mod text_protocols;
pub(crate) mod tls_checks;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};

pub(crate) async fn udp_exchange(
    target: SocketAddr,
    payload: &[u8],
    counters: &crate::results::IoCounters,
) -> Result<Vec<u8>> {
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    // A connected UDP socket accepts responses only from this authorized peer.
    socket.connect(target).await?;
    let sent = socket.send(payload).await?;
    anyhow::ensure!(sent == payload.len(), "partial UDP datagram");
    counters.sent(sent);
    let mut bytes = [0u8; 4096];
    let size = socket.recv(&mut bytes).await?;
    counters.received(size);
    Ok(bytes[..size].to_vec())
}

pub(crate) async fn tcp_connect(target: SocketAddr) -> Result<crate::results::Observation> {
    let mut socket = tokio::net::TcpStream::connect(target).await?;
    socket.shutdown().await?;
    let mut value = crate::results::Observation::success(
        "TCP connection established and closed; no flag-policy inference",
    );
    value.tcp_handshake_success = true;
    value.response_received = true;
    Ok(value)
}

pub(crate) async fn write_counted<T: tokio::io::AsyncWrite + Unpin>(
    stream: &mut T,
    payload: &[u8],
    counters: &crate::results::IoCounters,
) -> Result<()> {
    let mut written = 0;
    while written < payload.len() {
        let size = stream.write(&payload[written..]).await?;
        anyhow::ensure!(size > 0, "TCP write returned zero");
        counters.stream_sent(size);
        written += size;
    }
    Ok(())
}

pub(crate) async fn read_counted<T: tokio::io::AsyncRead + Unpin>(
    stream: &mut T,
    size: usize,
    counters: &crate::results::IoCounters,
) -> Result<Vec<u8>> {
    anyhow::ensure!(size <= 4096, "TCP frame exceeds 4096-byte response cap");
    let mut bytes = vec![0; size];
    let mut received = 0;
    while received < size {
        let count = stream.read(&mut bytes[received..]).await?;
        anyhow::ensure!(count > 0, "TCP peer closed before the complete response");
        counters.stream_received(count);
        received += count;
    }
    Ok(bytes)
}

pub(crate) async fn tcp_echo(
    target: SocketAddr,
    payload: &[u8],
    counters: &crate::results::IoCounters,
) -> Result<crate::results::Observation> {
    let mut stream = tokio::net::TcpStream::connect(target).await?;
    write_counted(&mut stream, payload, counters).await?;
    let response = read_counted(&mut stream, payload.len(), counters).await?;
    let mut result = crate::results::Observation::success(
        "fixed-payload TCP echo matched on an established connection",
    );
    result.tcp_handshake_success = true;
    result.response_received = true;
    result.application_bytes_sent = payload.len() as u64;
    result.application_bytes_received = response.len() as u64;
    if response != payload {
        result.outcome = crate::results::Outcome::ProtocolError;
        result.detail = "TCP echo payload mismatch".into();
    }
    stream.shutdown().await?;
    Ok(result)
}

pub(crate) fn http_url(target: &crate::config::Target, https: bool) -> String {
    let host = target
        .server_name
        .clone()
        .unwrap_or_else(|| match target.ip {
            std::net::IpAddr::V4(ip) => ip.to_string(),
            std::net::IpAddr::V6(ip) => format!("[{ip}]"),
        });
    format!(
        "{}://{host}:{}/",
        if https { "https" } else { "http" },
        target.port
    )
}

// Raw transmission is isolated in the engine-gated raw module.
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) async fn icmp_echo(
    target: &crate::config::Target,
) -> Result<crate::results::Observation> {
    #[cfg(target_os = "linux")]
    let (program, args) = (
        "/bin/ping",
        vec![
            if target.ip.is_ipv6() { "-6" } else { "-4" },
            "-n",
            "-c",
            "1",
            "-W",
            "1",
            "-s",
            "16",
        ],
    );
    #[cfg(target_os = "macos")]
    let (program, args) = (
        if target.ip.is_ipv6() {
            "/sbin/ping6"
        } else {
            "/sbin/ping"
        },
        vec!["-n", "-c", "1", "-s", "16"],
    );
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    anyhow::bail!("ICMP backend supports Linux and macOS only");
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let output = tokio::process::Command::new(program)
            .args(args)
            .arg(target.ip.to_string())
            .env("LC_ALL", "C")
            .kill_on_drop(true)
            .output()
            .await
            .with_context(|| {
                format!("failed to start local ICMP helper {program}; no remote ICMP result")
            })?;
        Ok(icmp_observation(output))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn icmp_observation(output: std::process::Output) -> crate::results::Observation {
    use crate::results::{Observation, Outcome};
    let mut value =
        Observation::success("one ICMP echo via system ping; packet-level metrics unavailable");
    value.response_received = output.status.success();
    value.protocol_details.insert(
        "icmp_exit_code".into(),
        serde_json::json!(output.status.code()),
    );
    if !output.status.success() {
        value.outcome = Outcome::NetworkError;
        value.detail = format!(
            "ping exited with {}; see ICMP stdout/stderr; no blocking attribution",
            output.status
        );
        for (name, bytes) in [
            ("icmp_stdout", output.stdout),
            ("icmp_stderr", output.stderr),
        ] {
            value.protocol_details.insert(
                name.into(),
                String::from_utf8_lossy(&bytes)
                    .chars()
                    .take(1024)
                    .collect::<String>()
                    .into(),
            );
        }
    }
    value
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod icmp_tests {
    use super::icmp_observation;
    use crate::results::Outcome;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn ping_failures_retain_bounded_diagnostics_without_claiming_remote_blocking() {
        let failed = icmp_observation(std::process::Output {
            status: std::process::ExitStatus::from_raw(2 << 8),
            stdout: b"local helper output".to_vec(),
            stderr: "permission denied ".repeat(300).into_bytes(),
        });
        assert_eq!(failed.outcome, Outcome::NetworkError);
        assert!(!failed.response_received);
        assert_eq!(failed.protocol_details["icmp_exit_code"], 2);
        assert_eq!(
            failed.protocol_details["icmp_stdout"],
            "local helper output"
        );
        assert_eq!(
            failed.protocol_details["icmp_stderr"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            1024
        );
        assert!(failed.detail.contains("no blocking attribution"));
        let succeeded = icmp_observation(std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: vec![],
            stderr: vec![],
        });
        assert_eq!(succeeded.outcome, Outcome::Success);
        assert!(succeeded.response_received);
    }
}
