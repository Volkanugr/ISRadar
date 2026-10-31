//! Bounded DNS wire codec. No resolution, recursion or DNSSEC authenticity inference.
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSummary {
    pub rcode: u16,
    pub answer_count: u16,
    pub edns_payload_size: Option<u16>,
    pub compression_observed: bool,
}

pub fn truncated_response(query: &[u8], bytes: &[u8]) -> Result<(), String> {
    if query.len() < 17
        || bytes.len() < 12
        || bytes.len() > 4096
        || bytes[..2] != query[..2]
        || bytes[2] & 0x82 != 0x82
        || bytes[2] & 0x78 != 0
        || word(bytes, 4) != 1
    {
        return Err("DNS truncation transaction/header mismatch".into());
    }
    let (a, at, ac, _, _) = question(query)?;
    let (b, bt, bc, _, _) = question(bytes)?;
    if a != b || at != bt || ac != bc {
        return Err("DNS truncated question mismatch".into());
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub owner: Vec<u8>,
    pub kind: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: std::ops::Range<usize>,
}

pub fn canonical_name(bytes: &[u8], start: usize) -> Result<(Vec<u8>, usize), String> {
    let (value, end, _) = name(bytes, start)?;
    Ok((value, end))
}

pub fn records(bytes: &[u8]) -> Result<Vec<ResourceRecord>, String> {
    if bytes.len() < 12 || bytes.len() > 4096 || word(bytes, 4) != 1 {
        return Err("invalid DNS record message".into());
    }
    let (_, _, _, mut offset, _) = question(bytes)?;
    let count = u32::from(word(bytes, 6)) + u32::from(word(bytes, 8)) + u32::from(word(bytes, 10));
    if count > 256 {
        return Err("too many DNS records".into());
    }
    let mut result = Vec::new();
    for _ in 0..count {
        let (owner, end, _) = name(bytes, offset)?;
        offset = end;
        if offset + 10 > bytes.len() {
            return Err("short DNS resource record".into());
        }
        let start = offset + 10;
        let end = start + word(bytes, offset + 8) as usize;
        if end > bytes.len() {
            return Err("short DNS RDATA".into());
        }
        result.push(ResourceRecord {
            owner,
            kind: word(bytes, offset),
            class: word(bytes, offset + 2),
            ttl: u32::from_be_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()),
            rdata: start..end,
        });
        offset = end;
    }
    if offset != bytes.len() {
        return Err("trailing DNS record bytes".into());
    }
    Ok(result)
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

pub fn query(name: &str, qtype: u16, id: u16, edns: bool) -> Result<Vec<u8>, String> {
    if ![1, 2, 5, 6, 15, 16, 28, 255].contains(&qtype) || name.is_empty() || name.len() > 253 {
        return Err("unsupported DNS type or name".into());
    }
    let mut bytes = vec![
        (id >> 8) as u8,
        id as u8,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        u8::from(edns),
    ];
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("invalid DNS label".into());
        }
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&qtype.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    if edns {
        bytes.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    } // OPT, UDP payload 1232, EDNS0, no DO bit.
    Ok(bytes)
}

fn name(bytes: &[u8], start: usize) -> Result<(Vec<u8>, usize, bool), String> {
    let mut offset = start;
    let mut resume = None;
    let mut seen = BTreeSet::new();
    let mut canonical = Vec::new();
    for _ in 0..128 {
        if offset >= bytes.len() || !seen.insert(offset) {
            return Err("DNS name pointer loop or out-of-bounds name".into());
        }
        let length = bytes[offset];
        if length & 0xc0 == 0xc0 {
            if offset + 1 >= bytes.len() {
                return Err("short DNS compression pointer".into());
            }
            if resume.is_none() {
                resume = Some(offset + 2);
            }
            offset = (((length & 63) as usize) << 8) | bytes[offset + 1] as usize;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err("invalid DNS label kind".into());
        }
        offset += 1;
        if length == 0 {
            canonical.push(0);
            if canonical.len() > 255 {
                return Err("expanded DNS name too long".into());
            }
            return Ok((canonical, resume.unwrap_or(offset), resume.is_some()));
        }
        let end = offset + length as usize;
        if end > bytes.len() || canonical.len() + length as usize + 1 > 254 {
            return Err("truncated or oversized DNS name".into());
        }
        canonical.push(length);
        canonical.extend(bytes[offset..end].iter().map(u8::to_ascii_lowercase));
        offset = end;
    }
    Err("DNS name exceeds pointer/label limit".into())
}

fn question(bytes: &[u8]) -> Result<(Vec<u8>, u16, u16, usize, bool), String> {
    let (label, end, compressed) = name(bytes, 12)?;
    if end + 4 > bytes.len() {
        return Err("short DNS question".into());
    }
    Ok((
        label,
        word(bytes, end),
        word(bytes, end + 2),
        end + 4,
        compressed,
    ))
}

pub fn response(query: &[u8], bytes: &[u8]) -> Result<DnsSummary, String> {
    if query.len() < 17 || bytes.len() < 12 || bytes.len() > 4096 {
        return Err("short or oversized DNS message".into());
    }
    if bytes[..2] != query[..2]
        || bytes[2] & 0x80 == 0
        || bytes[2] & 0x78 != 0
        || word(bytes, 4) != 1
    {
        return Err("DNS transaction/header mismatch".into());
    }
    if bytes[2] & 2 != 0 {
        return Err("truncated DNS response requires TCP fallback".into());
    }
    let (qname, qtype, qclass, _, _) = question(query)?;
    let (rname, rtype, rclass, mut offset, compressed) = question(bytes)?;
    if qname != rname || qtype != rtype || qclass != rclass {
        return Err("DNS question mismatch".into());
    }
    let count = u32::from(word(bytes, 6)) + u32::from(word(bytes, 8)) + u32::from(word(bytes, 10));
    if count > 256 {
        return Err("too many DNS records".into());
    }
    let mut summary = DnsSummary {
        rcode: u16::from(bytes[3] & 15),
        answer_count: word(bytes, 6),
        edns_payload_size: None,
        compression_observed: compressed,
    };
    let additional_start = u32::from(word(bytes, 6)) + u32::from(word(bytes, 8));
    for record_index in 0..count {
        let (owner, end, compressed) = name(bytes, offset)?;
        summary.compression_observed |= compressed;
        offset = end;
        if offset + 10 > bytes.len() {
            return Err("short DNS resource record".into());
        }
        let kind = word(bytes, offset);
        let class = word(bytes, offset + 2);
        let length = word(bytes, offset + 8) as usize;
        let start = offset + 10;
        let end = start + length;
        if end > bytes.len() {
            return Err("DNS RDATA exceeds message length".into());
        }
        match kind {
            1 if length != 4 => return Err("invalid DNS A record length".into()),
            28 if length != 16 => return Err("invalid DNS AAAA record length".into()),
            2 | 5 | 12 | 15 | 6 => {
                let mut cursor = start + if kind == 15 { 2 } else { 0 };
                if cursor >= end {
                    return Err("short domain-name RDATA".into());
                }
                let (_, next, compressed) = name(bytes, cursor)?;
                cursor = next;
                summary.compression_observed |= compressed;
                if kind == 6 {
                    let (_, next, compressed) = name(bytes, cursor)?;
                    cursor = next + 20;
                    summary.compression_observed |= compressed;
                }
                if cursor != end {
                    return Err("invalid domain-name RDATA length".into());
                }
            }
            16 => {
                let mut cursor = start;
                while cursor < end {
                    let length = bytes[cursor] as usize;
                    cursor += 1 + length;
                }
                if cursor != end || length == 0 {
                    return Err("invalid TXT record length".into());
                }
            }
            41 => {
                if record_index < additional_start
                    || owner != [0]
                    || summary.edns_payload_size.is_some()
                    || class < 512
                    || bytes[offset + 5] != 0
                {
                    return Err("invalid or duplicate EDNS OPT record".into());
                }
                summary.edns_payload_size = Some(class);
                summary.rcode |= u16::from(bytes[offset + 4]) << 4;
                let mut cursor = start;
                while cursor < end {
                    if cursor + 4 > end {
                        return Err("short EDNS option".into());
                    }
                    cursor += 4 + word(bytes, cursor + 2) as usize;
                }
                if cursor != end {
                    return Err("EDNS option length mismatch".into());
                }
            }
            _ => {}
        }
        offset = end;
    }
    if offset != bytes.len() {
        return Err("unexpected trailing DNS message bytes".into());
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn edns_extended_errors_are_not_reported_as_success() {
        let q = query("host.example", 1, 42, true).unwrap();
        let mut reply = q.clone();
        reply[2] = 0x80;
        let extended = reply.len() - 6;
        reply[extended] = 1;
        assert_eq!(response(&q, &reply).unwrap().rcode, 16); // BADVERS, low header bits are zero.
        reply[3] = 3;
        reply[extended] = 255;
        assert_eq!(response(&q, &reply).unwrap().rcode, 4083);
    }

    #[test]
    fn edns_opt_must_be_in_the_additional_section() {
        let q = query("host.example", 1, 42, true).unwrap();
        let mut reply = q.clone();
        reply[2] |= 0x80;
        assert!(response(&q, &reply).is_ok());
        reply[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
        assert!(response(&q, &reply).is_err());
        reply[6..12].copy_from_slice(&[0, 0, 0, 1, 0, 0]);
        assert!(response(&q, &reply).is_err());
    }
    #[test]
    fn truncated_answers_require_the_exact_transaction_and_question() {
        let q = query("host.example", 16, 42, false).unwrap();
        let mut r = q.clone();
        r[2] = 0x82;
        r[7] = 1;
        truncated_response(&q, &r).unwrap();
        assert!(response(&q, &r).is_err());
        r[13] = b'x';
        assert!(truncated_response(&q, &r).is_err());
        r = q.clone();
        r[2] = 0x80;
        assert!(truncated_response(&q, &r).is_err());
    }
    #[test]
    fn compressed_answer_is_validated_without_recursive_resolution() {
        let q = query("Owned.Example", 1, 42, false).unwrap();
        assert_eq!(q[2] & 1, 0);
        let mut r = q.clone();
        r[2] = 0x80;
        r[7] = 1;
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 127, 0, 0, 1]);
        let summary = response(&q, &r).unwrap();
        assert_eq!(summary.answer_count, 1);
        assert!(summary.compression_observed);
        r[1] ^= 1;
        assert!(response(&q, &r).is_err());
    }
    #[test]
    fn malformed_lengths_and_compression_cycles_are_rejected() {
        let q = query("owned.example", 1, 42, false).unwrap();
        let mut r = q.clone();
        r[2] = 0x80;
        r[7] = 1;
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 5, 127, 0, 0, 1]);
        assert!(response(&q, &r).is_err());
        let mut cycle = q.clone();
        cycle[2] = 0x80;
        cycle[12] = 0xc0;
        cycle[13] = 0x0c;
        assert!(response(&q, &cycle).is_err());
        assert!(query("bad..name", 1, 42, false).is_err());
    }
    #[test]
    fn edns_is_bounded_and_does_not_request_dnssec_or_recursion() {
        let q = query("owned.example", 1, 42, true).unwrap();
        assert_eq!(q[2], 0);
        assert_eq!(&q[q.len() - 6..q.len() - 2], &[0, 0, 0, 0]);
        let mut r = q.clone();
        r[2] = 0x80;
        assert_eq!(response(&q, &r).unwrap().edns_payload_size, Some(1232));
        r.push(0);
        assert!(response(&q, &r).is_err());
    }
}
