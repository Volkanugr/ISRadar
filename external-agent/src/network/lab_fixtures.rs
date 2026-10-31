//! Offline protocol fixtures required by the specification. No socket or transmit path.
use super::packets::{self, PacketKind};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureResult {
    pub classification: String,
    pub fixture_bytes: usize,
    pub fixture_messages: usize,
    pub expected_rejection: bool,
}

fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}
fn sum_ip(packet: &mut [u8]) {
    packet[10..12].fill(0);
    let sum = packets::checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
}

fn classify_v4(bytes: &[u8]) -> &'static str {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return "invalid_ipv4_version";
    }
    let header = (bytes[0] & 15) as usize * 4;
    if header < 20 || header > bytes.len() {
        return "invalid_ipv4_header_length";
    }
    if word(bytes, 2) as usize != bytes.len() {
        return "ipv4_total_length_mismatch";
    }
    if packets::checksum(&bytes[..header]) != 0 {
        return "invalid_ipv4_checksum";
    }
    if bytes[9] == 6 && word(bytes, 6) & 0x2000 != 0 && bytes.len() - header < 20 {
        return "tiny_tcp_fragment";
    }
    "valid_ipv4"
}

fn valid_quote(icmp: &[u8]) -> bool {
    if icmp.len() < 36 || icmp[8] >> 4 != 4 {
        return false;
    }
    let header = (icmp[8] & 15) as usize * 4;
    header >= 20
        && icmp.len() >= 8 + header + 8
        && word(icmp, 10) as usize >= header + 8
        && packets::checksum(&icmp[8..8 + header]) == 0
}

fn icmp_fixture(id: &str) -> Result<FixtureResult, String> {
    let a: IpAddr = "192.0.2.1".parse().unwrap();
    let b: IpAddr = "198.51.100.1".parse().unwrap();
    let mut packet = packets::build(
        PacketKind::IcmpUnreachable,
        a,
        b,
        40000,
        443,
        42,
        b"fixture-only",
    )?
    .remove(0);
    let (classification, expected) = match id {
        "ICMP-005" => {
            packet[21] = 4;
            packet[26..28].copy_from_slice(&1280u16.to_be_bytes());
            ("fragmentation_needed_mtu_1280", true)
        }
        "ICMP-007" => {
            packet[20] = 5;
            packet[21] = 1;
            packet[24..28].copy_from_slice(&[192, 0, 2, 254]);
            ("redirect_fixture_never_transmitted", true)
        }
        "ICMP-011" => ("valid_icmp_error_quotation", false),
        _ => return Err("unknown ICMP fixture".into()),
    };
    packet[22..24].fill(0);
    let sum = packets::checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&sum.to_be_bytes());
    if classify_v4(&packet) != "valid_ipv4"
        || packets::checksum(&packet[20..]) != 0
        || !valid_quote(&packet[20..])
    {
        return Err("generated ICMP fixture failed validation".into());
    }
    if id == "ICMP-005" && word(&packet, 26) != 1280 {
        return Err("invalid fixture MTU".into());
    }
    Ok(FixtureResult {
        classification: classification.into(),
        fixture_bytes: packet.len(),
        fixture_messages: 1,
        expected_rejection: expected,
    })
}

fn v6_too_big() -> Result<FixtureResult, String> {
    let mut quote = vec![0u8; 48];
    quote[0] = 0x60;
    quote[4..6].copy_from_slice(&8u16.to_be_bytes());
    quote[6] = 17;
    quote[7] = 64;
    let a: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    let b: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
    quote[8..24].copy_from_slice(&b.octets());
    quote[24..40].copy_from_slice(&a.octets());
    quote[40..42].copy_from_slice(&443u16.to_be_bytes());
    quote[42..44].copy_from_slice(&40000u16.to_be_bytes());
    quote[44..46].copy_from_slice(&8u16.to_be_bytes());
    let mut icmp = vec![2, 0, 0, 0, 0, 0, 5, 0];
    icmp.extend_from_slice(&quote);
    let mut pseudo = a.octets().to_vec();
    pseudo.extend_from_slice(&b.octets());
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    let mut complete = pseudo.clone();
    complete.extend_from_slice(&icmp);
    let sum = packets::checksum(&complete);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    pseudo.extend_from_slice(&icmp);
    if packets::checksum(&pseudo) != 0 || u32::from_be_bytes(icmp[4..8].try_into().unwrap()) != 1280
    {
        return Err("invalid ICMPv6 fixture".into());
    }
    Ok(FixtureResult {
        classification: "ipv6_packet_too_big_mtu_1280".into(),
        fixture_bytes: icmp.len(),
        fixture_messages: 1,
        expected_rejection: true,
    })
}

fn ike_fixture() -> Result<FixtureResult, String> {
    // Test-only SA_INIT syntax: AES-CBC-128/PRF-SHA256/HMAC-SHA256/DH14.
    // Fixed DH public value and nonce are fixtures, never keys for a live tunnel.
    let mut proposal = vec![0, 0, 0, 44, 1, 1, 0, 4];
    proposal.extend_from_slice(&[3, 0, 0, 12, 1, 0, 0, 12, 0x80, 14, 0, 128]);
    proposal.extend_from_slice(&[3, 0, 0, 8, 2, 0, 0, 5]);
    proposal.extend_from_slice(&[3, 0, 0, 8, 3, 0, 0, 12]);
    proposal.extend_from_slice(&[0, 0, 0, 8, 4, 0, 0, 14]);
    let mut body = vec![34, 0, 0, 48];
    body.extend_from_slice(&proposal);
    body.extend_from_slice(&[40, 0, 1, 8, 0, 14, 0, 0]);
    body.extend_from_slice(&[0; 255]);
    body.push(2);
    body.extend_from_slice(&[0, 0, 0, 36]);
    body.extend_from_slice(&[0x5a; 32]);
    let mut message = vec![0u8; 28];
    message[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    message[16] = 33;
    message[17] = 0x20;
    message[18] = 34;
    message[19] = 8;
    message[24..28].copy_from_slice(&((28 + body.len()) as u32).to_be_bytes());
    message.extend_from_slice(&body);
    let mut at = 28;
    let mut kind = message[16];
    let mut seen = Vec::new();
    while kind != 0 {
        if seen.len() >= 8 || at + 4 > message.len() {
            return Err("invalid IKE fixture payload chain".into());
        }
        let length = word(&message, at + 2) as usize;
        if length < 4 || at + length > message.len() {
            return Err("invalid IKE fixture length".into());
        }
        seen.push(kind);
        kind = message[at];
        at += length;
    }
    if at != message.len() || seen != [33, 34, 40] || message.len() != 376 {
        return Err("incomplete IKE fixture".into());
    }
    Ok(FixtureResult {
        classification: "ikev2_sa_init_header_and_payload_framing_valid".into(),
        fixture_bytes: message.len(),
        fixture_messages: 1,
        expected_rejection: false,
    })
}

pub fn run(id: &str) -> Result<FixtureResult, String> {
    match id {
        "ICMP-005" | "ICMP-007" | "ICMP-011" => icmp_fixture(id),
        "ICMP-009" => v6_too_big(),
        "SPECIAL-006" => ike_fixture(),
        "SPECIAL-007" => {
            let request = b"HELO validator.lab\r\n";
            let reply = b"250 lab.example\r\n";
            if !request.starts_with(b"HELO ")
                || !request.ends_with(b"\r\n")
                || !reply.starts_with(b"250 ")
            {
                return Err("invalid HELO fixture".into());
            }
            Ok(FixtureResult {
                classification: "smtp_helo_request_and_250_reply_syntax_valid".into(),
                fixture_bytes: request.len() + reply.len(),
                fixture_messages: 2,
                expected_rejection: false,
            })
        }
        "SIP-006" => {
            let response = b"SIP/2.0 200 OK\r\nCall-ID: fixture\r\nCSeq: invalid OPTIONS\r\n\r\n";
            let text = std::str::from_utf8(response).map_err(|_| "invalid fixture encoding")?;
            let value = text
                .split("\r\n")
                .find_map(|line| line.strip_prefix("CSeq: "))
                .ok_or("missing CSeq fixture")?;
            if value
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u32>().ok())
                .is_some()
            {
                return Err("fixture was not malformed".into());
            }
            Ok(FixtureResult {
                classification: "malformed_sip_cseq_rejected".into(),
                fixture_bytes: response.len(),
                fixture_messages: 1,
                expected_rejection: true,
            })
        }
        _ => {
            let a = "192.0.2.1".parse().unwrap();
            let b = "198.51.100.1".parse().unwrap();
            let mut packet = packets::build(
                PacketKind::Ipv4Udp,
                a,
                b,
                40000,
                9000,
                42,
                b"offline-fixture",
            )?
            .remove(0);
            let (actual, expected, messages, bytes) = match id {
                "IP-006" => {
                    packet[0] = 0x35;
                    (
                        classify_v4(&packet),
                        "invalid_ipv4_version",
                        1,
                        packet.len(),
                    )
                }
                "IP-009" => {
                    packet[0] = 0x40;
                    (
                        classify_v4(&packet),
                        "invalid_ipv4_header_length",
                        1,
                        packet.len(),
                    )
                }
                "IP-010" => {
                    let length = (packet.len() + 1) as u16;
                    packet[2..4].copy_from_slice(&length.to_be_bytes());
                    sum_ip(&mut packet);
                    (
                        classify_v4(&packet),
                        "ipv4_total_length_mismatch",
                        1,
                        packet.len(),
                    )
                }
                "IP-008" => {
                    packet[9] = 6;
                    packet[6] = 0x20;
                    packet.truncate(28);
                    packet[2..4].copy_from_slice(&28u16.to_be_bytes());
                    sum_ip(&mut packet);
                    (classify_v4(&packet), "tiny_tcp_fragment", 1, packet.len())
                }
                "IP-007" => {
                    let mut fragments = packets::build(
                        PacketKind::Ipv4Fragments,
                        a,
                        b,
                        40000,
                        9000,
                        42,
                        b"offline-fragment-overlap",
                    )?;
                    fragments[1][6..8].copy_from_slice(&1u16.to_be_bytes());
                    sum_ip(&mut fragments[1]);
                    let first_end = fragments[0].len() - 20;
                    let second_start = (word(&fragments[1], 6) & 0x1fff) as usize * 8;
                    (
                        if second_start < first_end {
                            "overlapping_ipv4_fragments"
                        } else {
                            "no_overlap"
                        },
                        "overlapping_ipv4_fragments",
                        2,
                        fragments.iter().map(Vec::len).sum(),
                    )
                }
                "IP-019" => {
                    let a = "2001:db8::1".parse().unwrap();
                    let b = "2001:db8::2".parse().unwrap();
                    let mut p = packets::build(
                        PacketKind::Ipv6Destination,
                        a,
                        b,
                        40000,
                        9000,
                        42,
                        b"offline-fixture",
                    )?
                    .remove(0);
                    let length = word(&p, 4) + 1;
                    p[4..6].copy_from_slice(&length.to_be_bytes());
                    (
                        if word(&p, 4) as usize + 40 != p.len() {
                            "ipv6_payload_length_mismatch"
                        } else {
                            "valid_ipv6"
                        },
                        "ipv6_payload_length_mismatch",
                        1,
                        p.len(),
                    )
                }
                _ => return Err(format!("unknown offline policy fixture {id}")),
            };
            if actual != expected {
                return Err(format!("fixture classification mismatch: {actual}"));
            }
            Ok(FixtureResult {
                classification: actual.into(),
                fixture_bytes: bytes,
                fixture_messages: messages,
                expected_rejection: true,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn required_unsafe_packet_cases_are_real_offline_fixtures() {
        for id in [
            "IP-006",
            "IP-007",
            "IP-008",
            "IP-009",
            "IP-010",
            "IP-019",
            "ICMP-005",
            "ICMP-007",
            "ICMP-009",
            "ICMP-011",
            "SIP-006",
            "SPECIAL-006",
            "SPECIAL-007",
        ] {
            let value = run(id).unwrap();
            assert!(value.fixture_bytes > 0 && value.fixture_messages > 0);
            assert!(!value.classification.is_empty());
        }
        assert!(run("UNKNOWN").is_err());
    }
    #[test]
    fn quotation_validation_rejects_truncation_and_header_corruption() {
        let packet = packets::build(
            PacketKind::IcmpUnreachable,
            "192.0.2.1".parse().unwrap(),
            "198.51.100.1".parse().unwrap(),
            40000,
            443,
            42,
            b"fixture-only",
        )
        .unwrap()
        .remove(0);
        let mut icmp = packet[20..].to_vec();
        assert!(valid_quote(&icmp));
        icmp[8] ^= 1;
        assert!(!valid_quote(&icmp));
        assert!(!valid_quote(&icmp[..20]));
    }
}
