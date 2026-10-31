use crate::{results::Observation, vectors::TestContext};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};

pub(crate) async fn execute(context: &TestContext) -> Result<Observation> {
    let target = context.target.as_ref().context("DNSSEC target required")?;
    let qname = target
        .server_name
        .as_ref()
        .context("configured DNSSEC qname required")?;
    let anchor = context
        .protocol
        .dnssec
        .as_ref()
        .context("configured DNSSEC anchor required")?;
    let lower = qname.to_ascii_lowercase();
    let zone = anchor.zone.to_ascii_lowercase();
    ensure!(
        lower == zone || lower.ends_with(&format!(".{zone}")),
        "DNSSEC qname is outside pinned zone"
    );
    let mut query =
        super::dns_wire::query(qname, 1, rand::random(), true).map_err(anyhow::Error::msg)?;
    let flags = query.len() - 4;
    query[flags] |= 0x80; // EDNS DNSSEC OK; still RD=0.
    let response = super::udp_exchange(target.address(), &query, &context.counters).await?;
    let now = u32::try_from(chrono::Utc::now().timestamp())?;
    let tag = verify_rrset(&query, &response, anchor, now)?;
    let mut value=Observation::success("positive IN A RRset verified against the configured Ed25519 zone anchor; no recursive root-chain, wildcard or negative-proof claim");
    value.response_received = true;
    value.application_bytes_sent = query.len() as u64;
    value.application_bytes_received = response.len() as u64;
    value
        .protocol_details
        .insert("dnssec_verified".into(), true.into());
    value
        .protocol_details
        .insert("dnssec_key_tag".into(), tag.into());
    value
        .protocol_details
        .insert("dnssec_anchor_zone".into(), anchor.zone.clone().into());
    Ok(value)
}

fn verify_rrset(
    query: &[u8],
    response: &[u8],
    anchor: &crate::settings::DnssecAnchor,
    now: u32,
) -> Result<u16> {
    let public = anchor.key()?;
    let key = VerifyingKey::from_bytes(&public)?;
    ensure!(!key.is_weak(), "weak DNSSEC Ed25519 trust anchor");
    let tag = super::dnssec_wire::key_tag(&public, anchor.flags);
    let candidates = super::dnssec_wire::signing_inputs(query, response, &anchor.zone, tag, now)
        .map_err(anyhow::Error::msg)?;
    let verified = candidates.iter().any(|candidate| {
        Signature::from_slice(&candidate.signature)
            .is_ok_and(|sig| key.verify_strict(&candidate.message, &sig).is_ok())
    });
    ensure!(
        verified,
        "DNSSEC A RRset signature did not verify with the pinned Ed25519 zone anchor"
    );
    Ok(tag)
}

#[cfg(test)]
mod tests {
    use super::super::{dns_wire, dnssec_wire};
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn signed_answer(query: &[u8], key: &SigningKey, corrupt: bool, now: u32) -> Vec<u8> {
        let (owner, end) = dns_wire::canonical_name(query, 12).unwrap();
        let mut response = query[..end + 4].to_vec();
        response[2] = 0x84;
        response[3] = 0x20; // AD is deliberately not trusted.
        response[6..12].copy_from_slice(&[0, 2, 0, 0, 0, 0]);
        response
            .extend_from_slice(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\xc0\x00\x02\x01");
        let mut fields = vec![0, 1, 15, 2];
        fields.extend_from_slice(&300u32.to_be_bytes());
        fields.extend_from_slice(&(now + 600).to_be_bytes());
        fields.extend_from_slice(&(now - 60).to_be_bytes());
        fields.extend_from_slice(
            &dnssec_wire::key_tag(&key.verifying_key().to_bytes(), 257).to_be_bytes(),
        );
        fields.extend_from_slice(b"\x07example\0");
        let mut message = fields.clone();
        message.extend_from_slice(&owner);
        message.extend_from_slice(b"\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\xc0\x00\x02\x01");
        let mut signature = key.sign(&message).to_bytes();
        if corrupt {
            signature[0] ^= 1;
        }
        fields.extend_from_slice(&signature);
        response.extend_from_slice(b"\xc0\x0c\x00\x2e\x00\x01\x00\x00\x01\x2c");
        response.extend_from_slice(&(fields.len() as u16).to_be_bytes());
        response.extend_from_slice(&fields);
        response
    }

    #[test]
    fn dnssec_verifies_signed_rrsets_and_rejects_tampering_even_with_ad() {
        let key = SigningKey::from_bytes(&[19; 32]);
        let anchor = crate::settings::DnssecAnchor {
            zone: "example".into(),
            flags: 257,
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
        };
        let query = dns_wire::query("host.example", 1, 42, false).unwrap();
        let now = 1_700_000_000;
        let response = signed_answer(&query, &key, false, now);
        assert_eq!(
            verify_rrset(&query, &response, &anchor, now).unwrap(),
            dnssec_wire::key_tag(&key.verifying_key().to_bytes(), 257)
        );
        assert!(verify_rrset(
            &query,
            &signed_answer(&query, &key, true, now),
            &anchor,
            now
        )
        .is_err());
        assert!(verify_rrset(&query, &response, &anchor, now + 601).is_err());
        assert!(verify_rrset(&query, &response, &anchor, now - 61).is_err());
        let mut changed_address = response.clone();
        let a_record = dns_wire::records(&response).unwrap().remove(0);
        changed_address[a_record.rdata.start] ^= 1;
        assert!(verify_rrset(&query, &changed_address, &anchor, now).is_err());
        let wrong_anchor = crate::settings::DnssecAnchor {
            public_key_hex: hex::encode(
                SigningKey::from_bytes(&[20; 32]).verifying_key().to_bytes(),
            ),
            ..anchor.clone()
        };
        assert!(verify_rrset(&query, &response, &wrong_anchor, now).is_err());
    }
}
