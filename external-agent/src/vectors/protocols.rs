use crate::{
    network,
    results::{Observation, Outcome},
    vectors::{
        registry::{Backend, Vector},
        TestContext,
    },
};
use anyhow::{ensure, Context, Result};

const ECHO: &[u8] = b"isradar-authorized-check-v1";

pub async fn execute(vector: &Vector, context: &TestContext) -> Result<Observation> {
    let target = context.target.as_ref().context("live target missing")?;
    let mut result = match vector.backend {
        backend if backend.is_raw() => network::raw::execute(vector, context).await?,
        Backend::TcpConnect => network::tcp_connect(target.address()).await?,
        Backend::TcpEcho => network::tcp_echo(target.address(), ECHO, &context.counters).await?,
        Backend::TcpHalfClose | Backend::TcpSession => {
            network::sessions::execute(vector.backend, context).await?
        }
        Backend::IcmpEcho => network::icmp_echo(target).await?,
        Backend::UdpEcho
        | Backend::UdpEchoZero
        | Backend::UdpEcho1200
        | Backend::UdpEcho128
        | Backend::UdpEchoRandom => {
            let large_payload = [0x5au8; 1200];
            let medium_payload = [0x41u8; 128];
            let mut random_payload = [0u8; 64];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_payload);
            let payload: &[u8] = match vector.backend {
                Backend::UdpEchoZero => &[],
                Backend::UdpEcho1200 => &large_payload,
                Backend::UdpEcho128 => &medium_payload,
                Backend::UdpEchoRandom => &random_payload,
                _ => ECHO,
            };
            let response =
                network::udp_exchange(target.address(), payload, &context.counters).await?;
            let mut value = Observation::success("UDP response from authorized service");
            value.application_bytes_sent = payload.len() as u64;
            value.application_bytes_received = response.len() as u64;
            value.response_received = true;
            if response != payload {
                value.outcome = Outcome::ProtocolError;
                value.detail = "UDP echo payload mismatch".into();
            }
            value
        }
        Backend::UdpClosedPort => {
            match network::udp_exchange(target.address(), ECHO, &context.counters).await {
                Ok(reply) => {
                    let mut value = Observation::success(
                        "UDP peer replied; configured closed-port behavior was not observed",
                    );
                    value.outcome = Outcome::RemoteRejection;
                    value.response_received = true;
                    value.application_bytes_sent = ECHO.len() as u64;
                    value.application_bytes_received = reply.len() as u64;
                    value
                }
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::ConnectionRefused) =>
                {
                    let mut value=Observation::success("OS reported UDP connection refused for the authorized peer; no firewall attribution");
                    value.application_bytes_sent = ECHO.len() as u64;
                    value
                        .protocol_details
                        .insert("udp_connection_refused".into(), true.into());
                    value
                }
                Err(error) => return Err(error),
            }
        }
        Backend::UdpDelivery => crate::measurement::probe(target.address(), context).await?,
        Backend::Dnssec => network::dnssec::execute(context).await?,
        Backend::DnsTcpFallback => dns_fallback(target, &context.counters).await?,
        Backend::DnsA
        | Backend::DnsUniqueA
        | Backend::DnsAaaa
        | Backend::DnsMx
        | Backend::DnsTxt
        | Backend::DnsCname
        | Backend::DnsNs
        | Backend::DnsSoa
        | Backend::DnsAny
        | Backend::DnsNxdomain
        | Backend::DnsEdns
        | Backend::DnsTcp
        | Backend::DnsRecursion
        | Backend::DnsTruncation
        | Backend::DnsCompressed => {
            let configured_name = target
                .server_name
                .as_ref()
                .context("DNS queries require configured server_name as qname")?;
            let name = if vector.backend == Backend::DnsUniqueA {
                format!("isradar-{:016x}.{configured_name}", rand::random::<u64>())
            } else {
                configured_name.clone()
            };
            let qtype = match vector.backend {
                Backend::DnsA | Backend::DnsUniqueA => 1,
                Backend::DnsAaaa => 28,
                Backend::DnsMx => 15,
                Backend::DnsTxt => 16,
                Backend::DnsCname => 5,
                Backend::DnsNs => 2,
                Backend::DnsSoa => 6,
                Backend::DnsAny => 255,
                Backend::DnsNxdomain | Backend::DnsEdns | Backend::DnsTcp => 1,
                Backend::DnsRecursion | Backend::DnsCompressed => 1,
                Backend::DnsTruncation => 16,
                _ => unreachable!(),
            };
            let mut query = network::dns_wire::query(
                &name,
                qtype,
                rand::random(),
                vector.backend == Backend::DnsEdns,
            )
            .map_err(anyhow::Error::msg)?;
            if vector.backend == Backend::DnsRecursion {
                query[2] |= 1;
            }
            let response = if vector.backend == Backend::DnsTcp {
                dns_tcp(target, &query, &context.counters).await?
            } else {
                network::udp_exchange(target.address(), &query, &context.counters).await?
            };
            if vector.backend == Backend::DnsTruncation {
                network::dns_wire::truncated_response(&query, &response)
                    .map_err(anyhow::Error::msg)?;
                let mut value=Observation::success("matched DNS TC=1 response observed for the exact configured TXT qname; no complete-answer claim");
                value.response_received = true;
                value.application_bytes_sent = query.len() as u64;
                value.application_bytes_received = response.len() as u64;
                value.vector_id = vector.id.clone();
                return Ok(value);
            }
            let summary =
                network::dns_wire::response(&query, &response).map_err(anyhow::Error::msg)?;
            if vector.backend == Backend::DnsEdns {
                ensure!(
                    summary.edns_payload_size.is_some() && response.len() <= 1232,
                    "EDNS0 was not honored within the advertised size"
                );
            }
            let mut value = Observation::success(format!(
                "DNS response validated; rcode={}; no DNSSEC authenticity claim",
                summary.rcode
            ));
            value.application_bytes_sent = query.len() as u64;
            value.application_bytes_received = response.len() as u64;
            value.response_received = true;
            value
                .protocol_details
                .insert("dns_rcode".into(), summary.rcode.into());
            value.protocol_details.insert(
                "edns_payload_size".into(),
                serde_json::to_value(summary.edns_payload_size)?,
            );
            value.protocol_details.insert(
                "dns_compression_observed".into(),
                summary.compression_observed.into(),
            );
            value.tcp_handshake_success = vector.backend == Backend::DnsTcp;
            if vector.backend == Backend::DnsCompressed {
                ensure!(
                    summary.compression_observed,
                    "DNS response did not exercise name compression"
                );
            }
            if vector.backend == Backend::DnsRecursion {
                value.protocol_details.insert(
                    "recursion_available".into(),
                    (response[3] & 0x80 != 0).into(),
                );
                if response[3] & 0x80 == 0 {
                    value.outcome = Outcome::RemoteRejection;
                }
            }
            if vector.backend == Backend::DnsUniqueA {
                value
                    .protocol_details
                    .insert("dns_qname".into(), name.into());
                if ![0, 3].contains(&summary.rcode) {
                    value.outcome = Outcome::RemoteRejection;
                }
            } else if vector.backend == Backend::DnsNxdomain && summary.rcode != 3 {
                value.outcome = Outcome::ProtocolError;
                value.detail = "expected NXDOMAIN for the exact configured qname".into();
            } else if vector.backend != Backend::DnsNxdomain && summary.rcode != 0 {
                value.outcome = Outcome::RemoteRejection;
            }
            value
        }
        Backend::NtpBasic | Backend::NtpV3 => {
            let mut query = ntp_query();
            if vector.backend == Backend::NtpV3 {
                query[0] = 0x1b;
            }
            let response =
                network::udp_exchange(target.address(), &query, &context.counters).await?;
            ntp_response(&query, &response)?;
            ensure!(
                vector.backend != Backend::NtpV3 || (response[0] >> 3) & 7 == 3,
                "NTPv3 query did not receive an NTPv3 response"
            );
            let mut value =
                Observation::success("NTP client/server response and origin timestamp validated");
            value.application_bytes_sent = query.len() as u64;
            value.application_bytes_received = response.len() as u64;
            value.response_received = true;
            value
                .protocol_details
                .insert("ntp_version".into(), ((response[0] >> 3) & 7).into());
            value
                .protocol_details
                .insert("ntp_stratum".into(), response[1].into());
            value
                .protocol_details
                .insert("ntp_leap_indicator".into(), (response[0] >> 6).into());
            if response[1] == 0 {
                value.outcome = Outcome::RemoteRejection;
                value.detail = "NTP kiss-of-death response".into();
                value.protocol_details.insert(
                    "ntp_kiss_code_hex".into(),
                    hex::encode(&response[12..16]).into(),
                );
            }
            value
        }
        Backend::SipOptions => {
            let socket = tokio::net::UdpSocket::bind(if target.ip.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .await?;
            socket.connect(target.address()).await?;
            let local = socket.local_addr()?;
            let call_id = format!("{:016x}@isradar.invalid", rand::random::<u64>());
            let branch = format!("z9hG4bK{:016x}", rand::random::<u64>());
            let host = match target.ip {
                std::net::IpAddr::V4(ip) => ip.to_string(),
                std::net::IpAddr::V6(ip) => format!("[{ip}]"),
            };
            let query = format!("OPTIONS sip:{host}:{} SIP/2.0\r\nVia: SIP/2.0/UDP {local};branch={branch};rport\r\nMax-Forwards: 0\r\nFrom: <sip:validator@isradar.invalid>;tag=check\r\nTo: <sip:{host}>\r\nCall-ID: {call_id}\r\nCSeq: 1 OPTIONS\r\nContact: <sip:validator@{local}>\r\nContent-Length: 0\r\n\r\n", target.port);
            let sent = socket.send(query.as_bytes()).await?;
            ensure!(sent == query.len(), "partial SIP datagram");
            context.counters.sent(sent);
            let mut buffer = [0u8; 4096];
            let mut received = 0usize;
            let mut final_status = None;
            for _ in 0..8 {
                let length = socket.recv(&mut buffer).await?;
                context.counters.received(length);
                received += length;
                let code = sip_response(&buffer[..length], &call_id, &branch)?;
                if code >= 200 {
                    final_status = Some(code);
                    break;
                }
            }
            let code =
                final_status.context("SIP OPTIONS final response missing within response cap")?;
            let mut value =
                Observation::success(format!("SIP OPTIONS transaction response: {code}"));
            value.application_bytes_sent = query.len() as u64;
            value.application_bytes_received = received as u64;
            value
                .protocol_details
                .insert("sip_status".into(), code.into());
            value.response_received = true;
            if code >= 300 {
                value.outcome = Outcome::RemoteRejection;
            }
            value
        }
        Backend::SipTcp | Backend::SipTls => {
            network::text_protocols::sip(vector.backend, context).await?
        }
        Backend::SipInvite | Backend::SipRegister => {
            network::sip_policy::execute(vector.backend, context).await?
        }
        backend if backend.is_http() => network::http_checks::execute(backend, context).await?,
        backend if backend.is_tls() => network::tls_checks::execute(backend, context).await?,
        _ => anyhow::bail!("not a live backend"),
    };
    result.vector_id.clone_from(&vector.id);
    Ok(result)
}

pub fn dns_query(name: &str, qtype: u16, id: u16) -> Result<Vec<u8>> {
    network::dns_wire::query(name, qtype, id, false).map_err(anyhow::Error::msg)
}

pub fn dns_response(query: &[u8], response: &[u8]) -> Result<()> {
    network::dns_wire::response(query, response)
        .map(|_| ())
        .map_err(anyhow::Error::msg)
}

async fn dns_tcp(
    target: &crate::config::Target,
    query: &[u8],
    counters: &crate::results::IoCounters,
) -> Result<Vec<u8>> {
    let mut stream = tokio::net::TcpStream::connect(target.address()).await?;
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(query);
    network::write_counted(&mut stream, &framed, counters).await?;
    let length = network::read_counted(&mut stream, 2, counters).await?;
    let length = u16::from_be_bytes([length[0], length[1]]) as usize;
    ensure!(
        (12..=4096).contains(&length),
        "DNS TCP response exceeds frame cap"
    );
    network::read_counted(&mut stream, length, counters).await
}

async fn dns_fallback(
    target: &crate::config::Target,
    counters: &crate::results::IoCounters,
) -> Result<Observation> {
    let name = target
        .server_name
        .as_ref()
        .context("DNS queries require a configured qname")?;
    let query = dns_query(name, 1, rand::random())?;
    let udp = network::udp_exchange(target.address(), &query, counters).await?;
    ensure!(
        udp.len() >= 12 && udp[..2] == query[..2] && udp[2] & 0x80 != 0 && udp[2] & 0x78 == 0,
        "DNS fallback transaction/header mismatch"
    );
    let (response, used_tcp) = if udp[2] & 2 != 0 {
        network::dns_wire::truncated_response(&query, &udp).map_err(anyhow::Error::msg)?;
        let mut stream = tokio::net::TcpStream::connect(target.address()).await?;
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&query);
        network::write_counted(&mut stream, &framed, counters).await?;
        let length = network::read_counted(&mut stream, 2, counters).await?;
        let length = u16::from_be_bytes([length[0], length[1]]) as usize;
        ensure!(
            (12..=4096).contains(&length),
            "DNS TCP response exceeds frame cap"
        );
        (
            network::read_counted(&mut stream, length, counters).await?,
            true,
        )
    } else {
        (udp.clone(), false)
    };
    let summary = network::dns_wire::response(&query, &response).map_err(anyhow::Error::msg)?;
    let mut value = Observation::success(format!(
        "DNS A response validated; TCP fallback used={used_tcp}; no DNSSEC authenticity claim"
    ));
    value.response_received = true;
    value.tcp_handshake_success = used_tcp;
    value.application_bytes_sent = query.len() as u64;
    value.application_bytes_received = udp.len() as u64;
    if used_tcp {
        value.application_bytes_sent += query.len() as u64 + 2;
        value.application_bytes_received += response.len() as u64 + 2;
    }
    value
        .protocol_details
        .insert("dns_rcode".into(), summary.rcode.into());
    if summary.rcode != 0 {
        value.outcome = Outcome::RemoteRejection;
    }
    Ok(value)
}

pub fn ntp_query() -> [u8; 48] {
    let mut query = [0; 48];
    query[0] = 0x23; // version 4, client mode; no control/monlist request.
    let seconds = (chrono::Utc::now().timestamp() as u64 + 2_208_988_800) as u32;
    query[40..44].copy_from_slice(&seconds.to_be_bytes());
    query[44..48].copy_from_slice(&rand::random::<u32>().to_be_bytes());
    query
}

pub fn ntp_response(query: &[u8], response: &[u8]) -> Result<()> {
    ensure!(
        query.len() == 48 && response.len() >= 48,
        "short NTP response"
    );
    ensure!(
        response[0] & 7 == 4
            && [3, 4].contains(&((response[0] >> 3) & 7))
            && (response[0] >> 6 != 3 || response[1] == 0)
            && response[1] <= 15,
        "invalid or unsynchronized NTP server response"
    );
    ensure!(
        response[24..32] == query[40..48],
        "NTP origin timestamp mismatch"
    );
    Ok(())
}

pub fn sip_response(response: &[u8], call_id: &str, branch: &str) -> Result<u16> {
    sip_response_for(response, call_id, branch, "OPTIONS", 1)
}

pub fn sip_response_for(
    response: &[u8],
    call_id: &str,
    branch: &str,
    method: &str,
    sequence: u32,
) -> Result<u16> {
    network::sip_wire::response_datagram(response, call_id, branch, method, sequence)
        .map_err(anyhow::Error::msg)
}
