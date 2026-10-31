//! Canonical DNSSEC A-RRset signing input, with a locally pinned Ed25519 zone anchor.
//! This is not a recursive validator: wildcard/negative proofs and other algorithms are rejected.
use super::dns_wire;

#[derive(Debug, Clone)]
pub struct SignedSet {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn key_tag(public_key: &[u8; 32], flags: u16) -> u16 {
    let mut data = flags.to_be_bytes().to_vec();
    data.extend_from_slice(&[3, 15]);
    data.extend_from_slice(public_key);
    let mut sum = 0u32;
    for (at, byte) in data.iter().enumerate() {
        sum += if at & 1 == 0 {
            u32::from(*byte) << 8
        } else {
            u32::from(*byte)
        };
    }
    sum += (sum >> 16) & 65535;
    (sum & 65535) as u16
}

pub fn signing_inputs(
    query: &[u8],
    response: &[u8],
    zone: &str,
    key_tag: u16,
    now: u32,
) -> Result<Vec<SignedSet>, String> {
    let summary = dns_wire::response(query, response)?;
    if summary.rcode != 0 {
        return Err(
            "DNSSEC check requires a positive A answer; negative proofs are not implemented".into(),
        );
    }
    let (owner, end) = dns_wire::canonical_name(query, 12)?;
    if query.get(end..end + 4) != Some(&[0, 1, 0, 1]) {
        return Err("DNSSEC check supports an IN A RRset".into());
    }
    let zone_query = dns_wire::query(zone, 1, 1, false)?;
    let (signer, _) = dns_wire::canonical_name(&zone_query, 12)?;
    let all_records = dns_wire::records(response)?;
    let records = &all_records[..usize::from(summary.answer_count)];
    let addresses: Vec<_> = records
        .iter()
        .filter(|r| r.owner == owner && r.kind == 1 && r.class == 1)
        .collect();
    if addresses.is_empty() || addresses.len() > 64 {
        return Err("missing or excessive DNSSEC A RRset".into());
    }
    let mut label_count = 0usize;
    let mut at = 0usize;
    while owner[at] != 0 {
        label_count += 1;
        at += 1 + owner[at] as usize;
    }
    let mut result = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.owner == owner && r.kind == 46 && r.class == 1)
        .take(8)
    {
        let data = &response[record.rdata.clone()];
        if data.len() < 83
            || data[..2] != [0, 1]
            || data[2] != 15
            || data[3] as usize != label_count
            || u16::from_be_bytes([data[16], data[17]]) != key_tag
        {
            continue;
        }
        let original_ttl = u32::from_be_bytes(data[4..8].try_into().unwrap());
        let expiration = u32::from_be_bytes(data[8..12].try_into().unwrap());
        let inception = u32::from_be_bytes(data[12..16].try_into().unwrap());
        if now < inception || now > expiration || addresses.iter().any(|r| r.ttl > original_ttl) {
            continue;
        }
        let (actual_signer, next) = dns_wire::canonical_name(response, record.rdata.start + 18)?;
        if actual_signer != signer || next > record.rdata.end || record.rdata.end - next != 64 {
            continue;
        }
        let mut message = data[..18].to_vec();
        message.extend_from_slice(&signer);
        let mut canonical = Vec::new();
        for address in &addresses {
            let mut rr = owner.clone();
            rr.extend_from_slice(&[0, 1, 0, 1]);
            rr.extend_from_slice(&original_ttl.to_be_bytes());
            rr.extend_from_slice(&4u16.to_be_bytes());
            rr.extend_from_slice(&response[address.rdata.clone()]);
            canonical.push(rr);
        }
        canonical.sort();
        canonical.dedup();
        for rr in canonical {
            message.extend_from_slice(&rr);
        }
        result.push(SignedSet {
            message,
            signature: response[next..record.rdata.end].to_vec(),
        });
    }
    if result.is_empty() {
        return Err(
            "no current non-wildcard Ed25519 RRSIG matches the pinned zone/key and A RRset".into(),
        );
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    pub fn fixture(ttl: u32, now: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let query = dns_wire::query("host.example", 1, 42, false).unwrap();
        let mut reply = query.clone();
        reply[2] = 0x84;
        reply[7] = 2;
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        reply.extend_from_slice(&ttl.to_be_bytes());
        reply.extend_from_slice(&[0, 4, 192, 0, 2, 1]);
        let tag = key_tag(&[7; 32], 257);
        let mut signature_data = vec![0, 1, 15, 2];
        signature_data.extend_from_slice(&300u32.to_be_bytes());
        signature_data.extend_from_slice(&(now + 600).to_be_bytes());
        signature_data.extend_from_slice(&(now - 1).to_be_bytes());
        signature_data.extend_from_slice(&tag.to_be_bytes());
        signature_data.extend_from_slice(b"\x07example\0");
        let mut expected = signature_data.clone();
        expected.extend_from_slice(b"\x04host\x07example\0\x00\x01\x00\x01");
        expected.extend_from_slice(&300u32.to_be_bytes());
        expected.extend_from_slice(&[0, 4, 192, 0, 2, 1]);
        signature_data.extend_from_slice(&[0; 64]);
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 46, 0, 1]);
        reply.extend_from_slice(&300u32.to_be_bytes());
        reply.extend_from_slice(&(signature_data.len() as u16).to_be_bytes());
        reply.extend_from_slice(&signature_data);
        (query, reply, expected)
    }
    #[test]
    fn canonical_dnssec_input_uses_original_ttl_and_pinned_zone() {
        let (q, r, expected) = fixture(100, 1000);
        let tag = key_tag(&[7; 32], 257);
        let sets = signing_inputs(&q, &r, "example", tag, 1000).unwrap();
        assert_eq!(sets[0].message, expected);
        assert_eq!(sets[0].signature.len(), 64);
        assert!(signing_inputs(&q, &r, "other.example", tag, 1000).is_err());
        assert!(signing_inputs(&q, &r, "example", tag, 2000).is_err());
        let (q, r, _) = fixture(301, 1000);
        assert!(signing_inputs(&q, &r, "example", tag, 1000).is_err());
    }
}
