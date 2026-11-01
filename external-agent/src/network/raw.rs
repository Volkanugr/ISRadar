use super::packets::PacketKind;
use crate::vectors::registry::{Backend, Vector};
#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::Result;

pub(crate) fn kind(vector: &Vector) -> Result<PacketKind> {
    Ok(match vector.backend {
        Backend::RawTcpFlags => PacketKind::TcpFlags(match vector.id.as_str() {
            "TCP-002" => 2,
            "TCP-003" => 18,
            "TCP-004" => 16,
            "TCP-005" => 4,
            "TCP-006" => 1,
            "TCP-007" => 8,
            "TCP-008" => 32,
            "TCP-009" => 3,
            "TCP-010" => 18,
            "TCP-011" => 20,
            "TCP-012" => 24,
            "TCP-013" => 6,
            "TCP-014" => 255,
            "TCP-015" => 0,
            "TCP-020" => 4,
            "TCP-021" => 16,
            _ => anyhow::bail!("unregistered TCP raw sample ID"),
        }),
        Backend::RawTcpWindow => PacketKind::TcpWindow,
        Backend::RawTcpMss => PacketKind::TcpMss,
        Backend::RawTcpTimestamp => PacketKind::TcpTimestamp,
        Backend::RawTcpSack => PacketKind::TcpSack,
        Backend::RawTcpSynFlood => PacketKind::TcpSynFlood,
        Backend::RawIpv4Header => PacketKind::Ipv4Udp,
        Backend::RawIpv4Fragments => PacketKind::Ipv4Fragments,
        Backend::RawIpv4Ttl => PacketKind::Ipv4Ttl,
        Backend::RawIpv4Ecn => PacketKind::Ipv4Ecn,
        Backend::RawIpv4Options => PacketKind::Ipv4Options,
        Backend::RawIpv6HopByHop => PacketKind::Ipv6HopByHop,
        Backend::RawIpv6Destination => PacketKind::Ipv6Destination,
        Backend::RawIpv6Routing => PacketKind::Ipv6Routing,
        Backend::RawIpv6Fragments => PacketKind::Ipv6Fragments,
        Backend::RawIpv6NoNext => PacketKind::Ipv6NoNext,
        Backend::RawIcmpUnreachable => PacketKind::IcmpUnreachable,
        Backend::RawIcmpTimeExceeded => PacketKind::IcmpTimeExceeded,
        Backend::RawIcmpParameter => PacketKind::IcmpParameter,
        Backend::RawIcmpTimestamp => PacketKind::IcmpTimestamp,
        _ => anyhow::bail!("not a raw validation backend"),
    })
}

pub(crate) async fn execute(
    vector: &Vector,
    context: &crate::vectors::TestContext,
) -> Result<crate::results::Observation> {
    anyhow::ensure!(
        context.raw_allowed,
        "raw validation admission was not authorized"
    );
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (vector, context);
        anyhow::bail!("raw validation requires Linux and CAP_NET_RAW");
    }
    #[cfg(target_os = "linux")]
    {
        use crate::results::{Observation, Outcome};
        use socket2::{Domain, Protocol, SockAddr, Socket, Type};
        use std::net::{SocketAddr, UdpSocket};
        let target = context.target.as_ref().context("raw target required")?;
        target.validate()?;
        let sample_kind = kind(vector)?;
        // Numeric connect selects an OS-owned route/source address; no traffic is sent here.
        let route = UdpSocket::bind(if target.ip.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        route.connect(target.address())?;
        let local = route.local_addr()?;
        let domain = if target.ip.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        // Reserve a fresh TCP port without connect/listen. Raw control flags cannot share
        // a tuple with an existing TCP session or reset an unrelated live connection.
        let reserve_tcp = if matches!(
            sample_kind,
            PacketKind::TcpFlags(_)
                | PacketKind::TcpWindow
                | PacketKind::TcpMss
                | PacketKind::TcpTimestamp
                | PacketKind::TcpSack
                | PacketKind::TcpSynFlood
                | PacketKind::IcmpUnreachable
                | PacketKind::IcmpTimeExceeded
                | PacketKind::IcmpParameter
        ) {
            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
            socket.bind(&SockAddr::from(SocketAddr::new(local.ip(), 0)))?;
            Some(socket)
        } else {
            None
        };
        let source_port = match &reserve_tcp {
            Some(socket) => socket
                .local_addr()?
                .as_socket()
                .context("reserved TCP address is not an IP socket")?
                .port(),
            None => local.port(),
        };
        let id = if sample_kind == PacketKind::IcmpTimestamp {
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis()
                % 86400000) as u32
        } else {
            rand::random::<u32>()
        };
        let mut trace = b"ISRRAW01".to_vec();
        trace.extend_from_slice(&context.sequence.to_be_bytes());
        trace.extend_from_slice(vector.id.as_bytes());
        let packets = super::packets::build(
            sample_kind,
            local.ip(),
            target.ip,
            source_port,
            target.port,
            id,
            &trace,
        )
        .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            packets.len() <= 2 && packets.iter().all(|p| p.len() <= 512),
            "raw packet sample exceeds execution bounds"
        );
        let socket = Socket::new(domain, Type::RAW, Some(Protocol::from(255)))
            .context("open bounded raw validation socket (CAP_NET_RAW required)")?;
        socket.set_nonblocking(true)?;
        if target.ip.is_ipv4() {
            socket.set_header_included_v4(true)?;
        } else {
            socket.set_header_included_v6(true)?;
        }
        // Raw destination port must be zero; the authorized service port is in the sample header.
        let destination = SockAddr::from(SocketAddr::new(target.ip, 0));
        let mut total = 0usize;
        for packet in &packets {
            let sent = socket.send_to(packet, &destination)?;
            anyhow::ensure!(sent == packet.len(), "partial raw IP packet transmission");
            context.counters.raw_accepted(sent);
            total += sent;
        }
        let mut value = Observation::success(
            "bounded raw IP sample accepted by local socket; downstream delivery is unobserved",
        );
        value.outcome = Outcome::Sent;
        value
            .protocol_details
            .insert("raw_ip_packets_accepted".into(), packets.len().into());
        value
            .protocol_details
            .insert("raw_ip_bytes_accepted".into(), total.into());
        value
            .protocol_details
            .insert("source_ip".into(), local.ip().to_string().into());
        value
            .protocol_details
            .insert("reserved_source_port".into(), source_port.into());
        value
            .protocol_details
            .insert("packet_identifier".into(), id.into());
        value
            .protocol_details
            .insert("sample".into(), format!("{sample_kind:?}").into());
        Ok(value)
    }
}
