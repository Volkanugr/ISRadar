//! Small well-formed packet samples for authorized, low-volume protocol policy checks.
//! This module builds bytes only; the executor owns limit enforcement and transmission.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    TcpFlags(u8),
    TcpWindow,
    TcpMss,
    TcpTimestamp,
    TcpSack,
    TcpSynFlood,
    Ipv4Udp,
    Ipv4Fragments,
    Ipv4Ttl,
    Ipv4Ecn,
    Ipv4Options,
    Ipv6HopByHop,
    Ipv6Destination,
    Ipv6Routing,
    Ipv6Fragments,
    Ipv6NoNext,
    IcmpUnreachable,
    IcmpTimeExceeded,
    IcmpParameter,
    IcmpTimestamp,
}

pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

fn pseudo_v4(source: Ipv4Addr, target: Ipv4Addr, protocol: u8, bytes: &[u8]) -> Vec<u8> {
    let mut pseudo = source.octets().to_vec();
    pseudo.extend_from_slice(&target.octets());
    pseudo.extend_from_slice(&[0, protocol]);
    pseudo.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(bytes);
    pseudo
}

fn pseudo_v6(source: Ipv6Addr, target: Ipv6Addr, protocol: u8, bytes: &[u8]) -> Vec<u8> {
    let mut pseudo = source.octets().to_vec();
    pseudo.extend_from_slice(&target.octets());
    pseudo.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, protocol]);
    pseudo.extend_from_slice(bytes);
    pseudo
}

// Parameters correspond to distinct, explicitly bounded fields of the wire header.
#[allow(clippy::too_many_arguments)]
fn ipv4(
    source: Ipv4Addr,
    target: Ipv4Addr,
    protocol: u8,
    id: u16,
    fragment: u16,
    ttl: u8,
    tos: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0u8; 20];
    bytes[0] = 0x45;
    bytes[1] = tos;
    bytes[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    bytes[4..6].copy_from_slice(&id.to_be_bytes());
    bytes[6..8].copy_from_slice(&fragment.to_be_bytes());
    bytes[8] = ttl;
    bytes[9] = protocol;
    bytes[12..16].copy_from_slice(&source.octets());
    bytes[16..20].copy_from_slice(&target.octets());
    let value = checksum(&bytes);
    bytes[10..12].copy_from_slice(&value.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn ipv6(source: Ipv6Addr, target: Ipv6Addr, next: u8, id: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 40];
    bytes[..4].copy_from_slice(&(0x60000000u32 | (id & 0x000fffff)).to_be_bytes());
    bytes[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes[6] = next;
    bytes[7] = 64;
    bytes[8..24].copy_from_slice(&source.octets());
    bytes[24..40].copy_from_slice(&target.octets());
    bytes.extend_from_slice(payload);
    bytes
}

fn udp(
    source: IpAddr,
    target: IpAddr,
    source_port: u16,
    target_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0u8; 8];
    bytes[..2].copy_from_slice(&source_port.to_be_bytes());
    bytes[2..4].copy_from_slice(&target_port.to_be_bytes());
    bytes[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    let sum = match (source, target) {
        (IpAddr::V4(a), IpAddr::V4(b)) => checksum(&pseudo_v4(a, b, 17, &bytes)),
        (IpAddr::V6(a), IpAddr::V6(b)) => checksum(&pseudo_v6(a, b, 17, &bytes)),
        _ => 0,
    };
    bytes[6..8].copy_from_slice(&(if sum == 0 { 65535 } else { sum }).to_be_bytes());
    bytes
}

pub fn build(
    kind: PacketKind,
    source: IpAddr,
    target: IpAddr,
    source_port: u16,
    target_port: u16,
    id: u32,
    trace: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    if source_port == 0
        || target_port == 0
        || trace.len() > 256
        || trace.len() < 8
        || (matches!(kind, PacketKind::Ipv4Fragments | PacketKind::Ipv6Fragments)
            && trace.len() < 9)
        || source.is_unspecified()
        || source.is_multicast()
        || target.is_unspecified()
        || target.is_multicast()
    {
        return Err("invalid bounded packet parameters".into());
    }
    match (source, target) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let datagram = udp(source, target, source_port, target_port, trace);
            Ok(match kind {
                PacketKind::TcpFlags(_)
                | PacketKind::TcpWindow
                | PacketKind::TcpMss
                | PacketKind::TcpTimestamp
                | PacketKind::TcpSack
                | PacketKind::TcpSynFlood => {
                    let flags = if let PacketKind::TcpFlags(flags) = kind {
                        flags
                    } else {
                        2
                    };
                    let mut segment = vec![0u8; 20];
                    segment[..2].copy_from_slice(&source_port.to_be_bytes());
                    segment[2..4].copy_from_slice(&target_port.to_be_bytes());
                    segment[4..8].copy_from_slice(&id.to_be_bytes());
                    segment[12] = 0x50;
                    segment[13] = flags;
                    segment[14..16].copy_from_slice(&1024u16.to_be_bytes());
                    match kind {
                        PacketKind::TcpWindow => {
                            segment[14..16].copy_from_slice(&4096u16.to_be_bytes())
                        }
                        PacketKind::TcpMss => segment.extend_from_slice(&[2, 4, 4, 176]), // MSS 1200
                        PacketKind::TcpSack => segment.extend_from_slice(&[4, 2, 1, 1]),
                        PacketKind::TcpTimestamp => {
                            segment.extend_from_slice(&[8, 10]);
                            segment.extend_from_slice(&id.to_be_bytes());
                            segment.extend_from_slice(&[0, 0, 0, 0, 1, 1]);
                        }
                        _ => {}
                    }
                    segment[12] = ((segment.len() / 4) as u8) << 4;
                    if flags & 0x20 != 0 {
                        segment[18..20].copy_from_slice(&1u16.to_be_bytes());
                    }
                    if flags & 0x28 != 0 {
                        segment.extend_from_slice(trace);
                    }
                    let sum = checksum(&pseudo_v4(a, b, 6, &segment));
                    segment[16..18].copy_from_slice(&sum.to_be_bytes());
                    vec![ipv4(a, b, 6, id as u16, 0, 64, 0, &segment)]
                }
                PacketKind::Ipv4Udp => vec![ipv4(a, b, 17, id as u16, 0, 64, 0, &datagram)],
                PacketKind::Ipv4Ttl => vec![ipv4(a, b, 17, id as u16, 0, 1, 0, &datagram)],
                PacketKind::Ipv4Ecn => vec![ipv4(a, b, 17, id as u16, 0, 64, 2, &datagram)],
                PacketKind::Ipv4Options => {
                    let mut packet = ipv4(a, b, 17, id as u16, 0, 64, 0, &datagram);
                    packet.splice(20..20, [1, 1, 0, 0]);
                    packet[0] = 0x46;
                    let length = packet.len() as u16;
                    packet[2..4].copy_from_slice(&length.to_be_bytes());
                    packet[10..12].fill(0);
                    let sum = checksum(&packet[..24]);
                    packet[10..12].copy_from_slice(&sum.to_be_bytes());
                    vec![packet]
                }
                PacketKind::Ipv4Fragments => vec![
                    ipv4(a, b, 17, id as u16, 0x2000, 64, 0, &datagram[..16]),
                    ipv4(a, b, 17, id as u16, 2, 64, 0, &datagram[16..]),
                ],
                PacketKind::IcmpUnreachable
                | PacketKind::IcmpTimeExceeded
                | PacketKind::IcmpParameter => {
                    // Quote a hypothetical TCP tuple to our newly reserved, unconnected source port.
                    // No established connection can own that local port.
                    let mut tcp = vec![0u8; 20];
                    tcp[..2].copy_from_slice(&target_port.to_be_bytes());
                    tcp[2..4].copy_from_slice(&source_port.to_be_bytes());
                    tcp[4..8].copy_from_slice(&id.to_be_bytes());
                    tcp[12] = 0x50;
                    let quote = ipv4(b, a, 6, id as u16, 0, 64, 0, &tcp);
                    let mut icmp = vec![0u8; 8];
                    icmp[0] = match kind {
                        PacketKind::IcmpUnreachable => 3,
                        PacketKind::IcmpParameter => 12,
                        _ => 11,
                    };
                    icmp[1] = if kind == PacketKind::IcmpUnreachable {
                        3
                    } else {
                        0
                    };
                    icmp.extend_from_slice(&quote[..28]);
                    let sum = checksum(&icmp);
                    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
                    vec![ipv4(a, b, 1, id as u16, 0, 64, 0, &icmp)]
                }
                PacketKind::IcmpTimestamp => {
                    let mut icmp = vec![13, 0, 0, 0];
                    icmp.extend_from_slice(&(id as u16).to_be_bytes());
                    icmp.extend_from_slice(&1u16.to_be_bytes());
                    icmp.extend_from_slice(&(id % 86400000).to_be_bytes());
                    icmp.extend_from_slice(&[0; 8]);
                    let sum = checksum(&icmp);
                    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
                    vec![ipv4(a, b, 1, id as u16, 0, 64, 0, &icmp)]
                }
                _ => return Err("packet kind requires IPv6".into()),
            })
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let datagram = udp(source, target, source_port, target_port, trace);
            Ok(match kind {
                PacketKind::Ipv6NoNext => vec![ipv6(a, b, 59, id, &[])],
                PacketKind::Ipv6HopByHop | PacketKind::Ipv6Destination => {
                    let mut extension = vec![17, 0, 0, 0, 0, 0, 0, 0];
                    extension.extend_from_slice(&datagram);
                    vec![ipv6(
                        a,
                        b,
                        if kind == PacketKind::Ipv6HopByHop {
                            0
                        } else {
                            60
                        },
                        id,
                        &extension,
                    )]
                }
                PacketKind::Ipv6Routing => {
                    // One-segment SRH with Segments Left=0. It never routes to another destination.
                    let mut extension = vec![17, 2, 4, 0, 0, 0, 0, 0];
                    extension.extend_from_slice(&b.octets());
                    extension.extend_from_slice(&datagram);
                    vec![ipv6(a, b, 43, id, &extension)]
                }
                PacketKind::Ipv6Fragments => {
                    let mut first = vec![17, 0, 0, 1];
                    first.extend_from_slice(&id.to_be_bytes());
                    first.extend_from_slice(&datagram[..16]);
                    let mut last = vec![17, 0, 0, 16];
                    last.extend_from_slice(&id.to_be_bytes());
                    last.extend_from_slice(&datagram[16..]);
                    vec![ipv6(a, b, 44, id, &first), ipv6(a, b, 44, id, &last)]
                }
                _ => return Err("packet kind requires IPv4".into()),
            })
        }
        _ => Err("packet address families differ".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tcp_options_ipv4_options_and_icmp_timestamps_are_real_wire_fields() {
        let (source, target) = addresses();
        let (IpAddr::V4(a), IpAddr::V4(b)) = (source, target) else {
            unreachable!()
        };
        for (kind, option) in [
            (PacketKind::TcpWindow, Vec::new()),
            (PacketKind::TcpMss, vec![2, 4, 4, 176]),
            (
                PacketKind::TcpTimestamp,
                vec![8, 10, 0, 0, 0, 42, 0, 0, 0, 0, 1, 1],
            ),
            (PacketKind::TcpSack, vec![4, 2, 1, 1]),
        ] {
            let p = build(kind, source, target, 40000, 443, 42, b"fixture-trace")
                .unwrap()
                .remove(0);
            assert_eq!(&p[40..], &option);
            assert_eq!((p[32] >> 4) as usize * 4, p.len() - 20);
            assert_eq!(checksum(&pseudo_v4(a, b, 6, &p[20..])), 0);
            if kind == PacketKind::TcpWindow {
                assert_eq!(&p[34..36], &4096u16.to_be_bytes());
            }
        }
        for kind in [
            PacketKind::Ipv4Udp,
            PacketKind::Ipv4Ttl,
            PacketKind::Ipv4Ecn,
            PacketKind::Ipv4Options,
        ] {
            let p = build(kind, source, target, 40000, 443, 42, b"fixture-trace")
                .unwrap()
                .remove(0);
            let header = (p[0] & 15) as usize * 4;
            assert_eq!(checksum(&p[..header]), 0);
            assert_eq!(checksum(&pseudo_v4(a, b, 17, &p[header..])), 0);
            if kind == PacketKind::Ipv4Ttl {
                assert_eq!(p[8], 1);
            }
            if kind == PacketKind::Ipv4Ecn {
                assert_eq!(p[1] & 3, 2);
            }
            if kind == PacketKind::Ipv4Options {
                assert_eq!(&p[20..24], &[1, 1, 0, 0]);
            }
        }
        let p = build(
            PacketKind::IcmpTimestamp,
            source,
            target,
            40000,
            443,
            42,
            b"fixture-trace",
        )
        .unwrap()
        .remove(0);
        assert_eq!(p[20], 13);
        assert_eq!(&p[28..32], &42u32.to_be_bytes());
        assert_eq!(checksum(&p[20..]), 0);
        let p = build(
            PacketKind::IcmpParameter,
            source,
            target,
            40000,
            443,
            42,
            b"fixture-trace",
        )
        .unwrap()
        .remove(0);
        assert_eq!(p[20], 12);
        assert_eq!(checksum(&p[20..]), 0);
    }
    fn addresses() -> (IpAddr, IpAddr) {
        (
            "192.0.2.1".parse().unwrap(),
            "198.51.100.1".parse().unwrap(),
        )
    }
    #[test]
    fn all_tcp_flag_samples_have_valid_headers_and_checksums() {
        let (a, b) = addresses();
        for flags in [0, 1, 2, 4, 8, 16, 32, 3, 18, 20, 24, 6, 255] {
            let packets = build(
                PacketKind::TcpFlags(flags),
                a,
                b,
                40000,
                443,
                42,
                b"isradar-trace",
            )
            .unwrap();
            let p = &packets[0];
            assert_eq!(p[33], flags);
            assert_eq!(p[9], 6);
            assert_eq!(checksum(&p[..20]), 0);
            let (IpAddr::V4(a), IpAddr::V4(b)) = (a, b) else {
                unreachable!()
            };
            assert_eq!(checksum(&pseudo_v4(a, b, 6, &p[20..])), 0);
        }
    }
    #[test]
    fn syn_flood_sample_is_a_bounded_raw_syn_burst() {
        let (a, b) = addresses();
        // A single half-open entry per sample: one pure SYN per freshly reserved source port.
        // No ACK/RST payload, no options, no downstream delivery or capacity claim.
        for source_port in [40000u16, 40001, 40002] {
            let packets = build(
                PacketKind::TcpSynFlood,
                a,
                b,
                source_port,
                80,
                42,
                b"isradar-syn-flood",
            )
            .unwrap();
            assert_eq!(packets.len(), 1);
            let p = &packets[0];
            assert_eq!(p[9], 6); // IPv4 protocol = TCP
            assert_eq!(p[33], 2); // pure SYN flag, no ACK or other control bits
            assert_eq!((p[32] >> 4) as usize * 4, 20); // 5-word header, no options
            assert_eq!(checksum(&p[..20]), 0);
            let (IpAddr::V4(source), IpAddr::V4(target)) = (a, b) else {
                unreachable!()
            };
            assert_eq!(checksum(&pseudo_v4(source, target, 6, &p[20..])), 0);
        }
    }
    #[test]
    fn ipv4_fragments_reassemble_to_one_valid_udp_datagram() {
        let (a, b) = addresses();
        let payload = b"isradar-sequence-0123456789";
        let p = build(PacketKind::Ipv4Fragments, a, b, 40000, 9000, 42, payload).unwrap();
        assert_eq!(&p[0][6..8], &[0x20, 0]);
        assert_eq!(&p[1][6..8], &[0, 2]);
        let mut udp = p[0][20..].to_vec();
        udp.extend_from_slice(&p[1][20..]);
        assert_eq!(&udp[8..], payload);
        let (IpAddr::V4(a), IpAddr::V4(b)) = (a, b) else {
            unreachable!()
        };
        assert_eq!(checksum(&pseudo_v4(a, b, 17, &udp)), 0);
        for fragment in p {
            assert_eq!(checksum(&fragment[..20]), 0);
        }
    }
    #[test]
    fn ipv6_extensions_and_fragments_keep_the_authorized_destination() {
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::2".parse().unwrap();
        for kind in [
            PacketKind::Ipv6HopByHop,
            PacketKind::Ipv6Destination,
            PacketKind::Ipv6Routing,
            PacketKind::Ipv6Fragments,
            PacketKind::Ipv6NoNext,
        ] {
            let p = build(kind, a, b, 40000, 9000, 42, b"isradar-sequence-0123456789").unwrap();
            let IpAddr::V6(dest) = b else { unreachable!() };
            for packet in &p {
                assert_eq!(&packet[24..40], &dest.octets());
                assert_eq!(
                    u16::from_be_bytes([packet[4], packet[5]]) as usize,
                    packet.len() - 40
                );
            }
            if kind == PacketKind::Ipv6Routing {
                assert_eq!(p[0][43], 0);
                assert_eq!(&p[0][48..64], &dest.octets());
            }
            if kind == PacketKind::Ipv6Fragments {
                let mut udp = p[0][48..].to_vec();
                udp.extend_from_slice(&p[1][48..]);
                let (IpAddr::V6(a), IpAddr::V6(b)) = (a, b) else {
                    unreachable!()
                };
                assert_eq!(checksum(&pseudo_v6(a, b, 17, &udp)), 0);
            }
        }
    }
    #[test]
    fn icmp_error_samples_quote_only_the_reserved_probe_tuple() {
        let (a, b) = addresses();
        for (kind, expected) in [
            (PacketKind::IcmpUnreachable, 3),
            (PacketKind::IcmpTimeExceeded, 11),
        ] {
            let p = build(kind, a, b, 40000, 443, 42, b"isradar-trace").unwrap();
            assert_eq!(p[0][20], expected);
            assert_eq!(checksum(&p[0][20..]), 0);
            assert_eq!(&p[0][48..52], &[1, 187, 156, 64]); // quoted target port 443 -> reserved local port 40000
        }
    }
    #[test]
    fn invalid_or_unbounded_parameters_are_rejected() {
        let (a, b) = addresses();
        assert!(build(PacketKind::Ipv4Udp, a, b, 0, 443, 1, b"isradar-trace").is_err());
        assert!(build(PacketKind::Ipv4Fragments, a, b, 40000, 443, 1, b"12345678").is_err());
        assert!(build(PacketKind::Ipv4Udp, a, b, 40000, 443, 1, &[0; 257]).is_err());
        assert!(build(
            PacketKind::Ipv6Fragments,
            a,
            b,
            40000,
            443,
            1,
            b"isradar-trace"
        )
        .is_err());
    }
}
