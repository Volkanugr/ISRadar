use crate::{
    network::internet_checksum,
    results::{Observation, Outcome},
    vectors::registry::Vector,
};
use anyhow::{ensure, Result};

// An event model is an offline dataset, never an attack traffic implementation.
pub fn model(vector: &Vector) -> Result<Observation> {
    let model = super::event_models::run(&vector.id).map_err(anyhow::Error::msg)?;
    let mut observation = Observation::success(format!("offline event fixture for {}; mechanism={}; illustrative workload tokens, not measured defense performance or a named tool reproduction", vector.name, model.mechanism));
    observation.outcome = Outcome::Simulated;
    observation.simulated_events = Some(model.offered);
    observation.vector_id.clone_from(&vector.id);
    observation.protocol_details.insert("event_model".into(), serde_json::json!({
        "mechanism": model.mechanism, "offered": model.offered, "accepted": model.accepted,
        "rejected": model.rejected, "completed": model.completed, "peak_work": model.peak_work,
        "synthetic_destinations": model.synthetic_destinations, "synthetic_request_bytes": model.synthetic_request_bytes,
        "synthetic_reply_bytes": model.synthetic_reply_bytes, "cache_misses": model.cache_misses,
        "destinations": model.destinations.iter().map(|g| serde_json::json!({
            "name":g.name,"offered":g.offered,"accepted":g.accepted,"rejected":g.rejected})).collect::<Vec<_>>(),
        "protocols": model.protocols.iter().map(|g| serde_json::json!({
            "name":g.name,"offered":g.offered,"accepted":g.accepted,"rejected":g.rejected})).collect::<Vec<_>>(),
        "ticks": model.ticks.iter().map(|t| serde_json::json!({"tick":t.at,"capacity":t.capacity,
            "offered":t.offered,"accepted":t.accepted,"rejected":t.rejected,
            "active_work":t.active_work,"completed":t.completed})).collect::<Vec<_>>()
    }));
    Ok(observation)
}

pub fn ipv4_fixture() -> Vec<u8> {
    // Documentation-only addresses (RFC 5737), TTL 1, ICMP echo. Never transmitted.
    let mut bytes = vec![
        0x45, 0, 0, 28, 0, 1, 0, 0, 1, 1, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1, 8, 0, 0, 0, 0, 1, 0,
        1,
    ];
    let icmp = internet_checksum(&bytes[20..]);
    bytes[22..24].copy_from_slice(&icmp.to_be_bytes());
    let ip = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&ip.to_be_bytes());
    bytes
}

pub fn inspect_ipv4(bytes: &[u8]) -> Result<String> {
    ensure!(
        bytes.len() >= 20 && bytes[0] >> 4 == 4,
        "invalid IPv4 version or short header"
    );
    let header_len = (bytes[0] as usize & 15) * 4;
    ensure!(
        header_len >= 20 && header_len <= bytes.len(),
        "invalid IPv4 header length"
    );
    let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    ensure!(
        length >= header_len && length == bytes.len(),
        "IPv4 length mismatch"
    );
    ensure!(
        internet_checksum(&bytes[..header_len]) == 0,
        "invalid IPv4 header checksum"
    );
    let fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
    Ok(format!(
        "IPv4 header checksum valid; ttl={}; protocol={}; more_fragments={}; fragment_offset={}",
        bytes[8],
        bytes[9],
        fragment & 0x2000 != 0,
        fragment & 0x1fff
    ))
}

pub fn packet_fixture(vector: &Vector) -> Result<Observation> {
    let packet = ipv4_fixture();
    ensure!(
        internet_checksum(&packet[20..]) == 0,
        "invalid ICMP fixture checksum"
    );
    let mut value = Observation::success(format!(
        "offline IPv4/ICMP fixture: {}; ICMP checksum valid",
        inspect_ipv4(&packet)?
    ));
    value.outcome = Outcome::Simulated;
    value.simulated_events = Some(1);
    value.vector_id.clone_from(&vector.id);
    Ok(value)
}

pub fn policy_fixture(vector: &Vector) -> Result<Observation> {
    let result = crate::network::lab_fixtures::run(&vector.id).map_err(anyhow::Error::msg)?;
    let mut value=Observation::success("offline protocol fixture generated and classified; no network transmission or delivery observation");
    value.vector_id = vector.id.clone();
    value.outcome = Outcome::Simulated;
    value.simulated_events = Some(result.fixture_messages as u64);
    value.protocol_details.insert(
        "fixture_classification".into(),
        result.classification.into(),
    );
    value
        .protocol_details
        .insert("fixture_bytes".into(), result.fixture_bytes.into());
    value
        .protocol_details
        .insert("fixture_messages".into(), result.fixture_messages.into());
    value.protocol_details.insert(
        "expected_rejection".into(),
        result.expected_rejection.into(),
    );
    Ok(value)
}

pub fn write_fixture_pcap(path: &std::path::Path) -> Result<()> {
    use std::io::Write;
    let packet = ipv4_fixture();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    // Little-endian classic PCAP, LINKTYPE_RAW=101, one deterministic record.
    for bytes in [
        0xa1b2c3d4u32.to_le_bytes().to_vec(),
        2u16.to_le_bytes().to_vec(),
        4u16.to_le_bytes().to_vec(),
        0u32.to_le_bytes().to_vec(),
        0u32.to_le_bytes().to_vec(),
        65535u32.to_le_bytes().to_vec(),
        101u32.to_le_bytes().to_vec(),
        0u32.to_le_bytes().to_vec(),
        0u32.to_le_bytes().to_vec(),
        (packet.len() as u32).to_le_bytes().to_vec(),
        (packet.len() as u32).to_le_bytes().to_vec(),
        packet,
    ] {
        file.write_all(&bytes)?;
    }
    file.sync_all()?;
    Ok(())
}
