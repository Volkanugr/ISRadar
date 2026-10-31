#[cfg(feature = "experimental-receiver")]
use crate::results::Report;
use crate::{results::Observation, vectors::TestContext};
use anyhow::{ensure, Context, Result};
#[cfg(feature = "experimental-receiver")]
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
#[cfg(feature = "experimental-receiver")]
use std::net::IpAddr;
use std::{
    collections::BTreeSet,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Mutex,
};
#[cfg(feature = "experimental-receiver")]
use tokio::time::{Duration, Instant};
#[cfg(feature = "experimental-receiver")]
use tokio_util::sync::CancellationToken;

type HmacSha256 = Hmac<Sha256>;
const REQUEST: &[u8; 8] = b"ISRDP001";
const ACK: &[u8; 8] = b"ISRDA001";
pub const FRAME_SIZE: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementConfig {
    pub run_id: String,
    pub key_file: PathBuf,
    #[serde(default)]
    pub await_ack: bool,
}

impl MeasurementConfig {
    pub fn validate(&self) -> Result<()> {
        decode_run_id(&self.run_id).map(|_| ())
    }
}

fn decode_run_id(id: &str) -> Result<[u8; 16]> {
    hex::decode(id)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("run_id must contain exactly 16 bytes encoded as hex"))
}

pub fn read_key(path: &Path) -> Result<[u8; 32]> {
    hex::decode(std::fs::read_to_string(path)?.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("measurement key must contain 32 bytes encoded as hex"))
}

pub fn keygen(path: &Path) -> Result<String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(hex::encode(rand::random::<[u8; 32]>()).as_bytes())?;
    file.sync_all()?;
    Ok(hex::encode(rand::random::<[u8; 16]>()))
}

fn mac(key: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
    let mut hmac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    hmac.update(bytes);
    hmac.finalize().into_bytes().into()
}

fn verify_mac(key: &[u8; 32], bytes: &[u8], tag: &[u8]) -> Result<()> {
    let mut hmac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    hmac.update(bytes);
    hmac.verify_slice(tag)
        .map_err(|_| anyhow::anyhow!("measurement authentication failed"))
}

pub fn frame(key: &[u8; 32], run_id: &[u8; 16], sequence: u64, ack: bool) -> [u8; FRAME_SIZE] {
    let mut frame = [0u8; FRAME_SIZE];
    frame[..8].copy_from_slice(if ack { ACK } else { REQUEST });
    frame[8..24].copy_from_slice(run_id);
    frame[24..32].copy_from_slice(&sequence.to_be_bytes());
    let tag = mac(key, &frame[..32]);
    frame[32..].copy_from_slice(&tag);
    frame
}

pub fn verify_frame(key: &[u8; 32], run_id: &[u8; 16], bytes: &[u8], ack: bool) -> Result<u64> {
    ensure!(
        bytes.len() == FRAME_SIZE,
        "invalid measurement frame length"
    );
    ensure!(
        &bytes[..8] == if ack { ACK } else { REQUEST },
        "invalid measurement frame kind"
    );
    ensure!(&bytes[8..24] == run_id, "measurement run_id mismatch");
    verify_mac(key, &bytes[..32], &bytes[32..])?;
    Ok(u64::from_be_bytes(bytes[24..32].try_into()?))
}

pub struct Trace {
    key: [u8; 32],
    run_id: [u8; 16],
    sent: Mutex<BTreeSet<u64>>,
    acknowledged: Mutex<BTreeSet<u64>>,
    await_ack: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderEvidence {
    pub run_id: String,
    pub sent_sequences: Vec<u64>,
    pub acknowledged_sequences: Vec<u64>,
    pub mac: String,
}

impl Trace {
    pub fn from_config(config: &MeasurementConfig) -> Result<Self> {
        Ok(Self {
            key: read_key(&config.key_file)?,
            run_id: decode_run_id(&config.run_id)?,
            sent: Mutex::new(BTreeSet::new()),
            acknowledged: Mutex::new(BTreeSet::new()),
            await_ack: config.await_ack,
        })
    }
    pub fn evidence(&self) -> SenderEvidence {
        let mut evidence = SenderEvidence {
            run_id: hex::encode(self.run_id),
            sent_sequences: self
                .sent
                .lock()
                .expect("measurement mutex")
                .iter()
                .copied()
                .collect(),
            acknowledged_sequences: self
                .acknowledged
                .lock()
                .expect("measurement mutex")
                .iter()
                .copied()
                .collect(),
            mac: String::new(),
        };
        evidence.mac = hex::encode(mac(&self.key, &sender_bytes(&evidence)));
        evidence
    }
}

fn sender_bytes(evidence: &SenderEvidence) -> Vec<u8> {
    serde_json::to_vec(&(
        "isradar.sender-evidence.v1",
        &evidence.run_id,
        &evidence.sent_sequences,
        &evidence.acknowledged_sequences,
    ))
    .expect("serializable evidence")
}

pub fn verify_sender(evidence: &SenderEvidence, key: &[u8; 32]) -> Result<()> {
    decode_run_id(&evidence.run_id)?;
    verify_mac(key, &sender_bytes(evidence), &hex::decode(&evidence.mac)?)?;
    ensure!(
        evidence.sent_sequences.len() <= 10000 && evidence.acknowledged_sequences.len() <= 10000,
        "sender evidence exceeds limits"
    );
    let sent: BTreeSet<_> = evidence.sent_sequences.iter().copied().collect();
    let acknowledged: BTreeSet<_> = evidence.acknowledged_sequences.iter().copied().collect();
    ensure!(
        sent.len() == evidence.sent_sequences.len()
            && acknowledged.len() == evidence.acknowledged_sequences.len()
            && acknowledged.is_subset(&sent),
        "invalid sender sequence evidence"
    );
    Ok(())
}

pub(crate) async fn probe(target: SocketAddr, context: &TestContext) -> Result<Observation> {
    let trace = context
        .measurement
        .as_ref()
        .context("delivery measurement context required")?;
    let socket = tokio::net::UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(target).await?;
    let bytes = frame(&trace.key, &trace.run_id, context.sequence, false);
    let sent = socket.send(&bytes).await?;
    ensure!(sent == FRAME_SIZE, "partial measurement datagram");
    context.counters.sent(sent);
    trace
        .sent
        .lock()
        .expect("measurement mutex")
        .insert(context.sequence);
    if !trace.await_ack {
        let mut value = Observation::success(format!(
            "sequence {} accepted by local UDP socket; destination delivery is unobserved",
            context.sequence
        ));
        value.outcome = crate::results::Outcome::Sent;
        value.application_bytes_sent = sent as u64;
        return Ok(value);
    }
    let mut response = [0u8; 128];
    let length = socket.recv(&mut response).await?;
    context.counters.received(length);
    let sequence = verify_frame(&trace.key, &trace.run_id, &response[..length], true)?;
    ensure!(
        sequence == context.sequence,
        "measurement ACK sequence mismatch"
    );
    trace
        .acknowledged
        .lock()
        .expect("measurement mutex")
        .insert(sequence);
    let mut value = Observation::success(format!(
        "authenticated receiver ACK for sequence {sequence}"
    ));
    value.response_received = true;
    value.application_bytes_sent = sent as u64;
    value.application_bytes_received = length as u64;
    Ok(value)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(feature = "experimental-receiver")]
pub struct ReceiverEvidence {
    pub schema_version: u32,
    pub run_id: String,
    pub bound_address: SocketAddr,
    pub allowed_peer: IpAddr,
    pub expected_probes: u64,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub received_sequences: Vec<u64>,
    pub duplicates: u64,
    pub rejected_datagrams: u64,
    pub acks_sent: u64,
    pub termination_reason: String,
    pub mac: String,
}

#[cfg(feature = "experimental-receiver")]
fn receiver_bytes(value: &ReceiverEvidence) -> Result<Vec<u8>> {
    let mut copy = value.clone();
    copy.mac.clear();
    Ok([
        b"isradar.receiver-evidence.v1\0".as_slice(),
        &serde_json::to_vec(&copy)?,
    ]
    .concat())
}

#[cfg(feature = "experimental-receiver")]
pub struct ReceiverConfig {
    pub bind: SocketAddr,
    pub allowed_peer: IpAddr,
    pub run_id: String,
    pub key_file: PathBuf,
    pub expected_probes: u64,
    pub duration_seconds: u64,
}

#[cfg(feature = "experimental-receiver")]
pub async fn receive(
    config: ReceiverConfig,
    cancel: CancellationToken,
) -> Result<ReceiverEvidence> {
    let socket = tokio::net::UdpSocket::bind(config.bind).await?;
    receive_on(socket, config, cancel).await
}

#[cfg(feature = "experimental-receiver")]
pub async fn receive_on(
    socket: tokio::net::UdpSocket,
    config: ReceiverConfig,
    cancel: CancellationToken,
) -> Result<ReceiverEvidence> {
    ensure!(
        (1..=10000).contains(&config.expected_probes)
            && (1..=600).contains(&config.duration_seconds),
        "receiver bounds exceeded"
    );
    ensure!(
        !config.allowed_peer.is_multicast() && !config.allowed_peer.is_unspecified(),
        "receiver requires an explicit unicast sender IP"
    );
    let key = read_key(&config.key_file)?;
    let run_id = decode_run_id(&config.run_id)?;
    let bound_address = socket.local_addr()?;
    tracing::info!(event="receiver_ready", %bound_address, run_id=%config.run_id, allowed_peer=%config.allowed_peer);
    let started_at = Utc::now();
    let deadline = Instant::now() + Duration::from_secs(config.duration_seconds);
    let mut received = BTreeSet::new();
    let mut duplicates = 0;
    let mut rejected_datagrams = 0;
    let mut acks_sent = 0;
    let mut datagrams = 0;
    let mut buffer = [0u8; 128];
    let reason = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break "cancelled",
            _ = tokio::time::sleep_until(deadline) => break "duration_limit",
            value = socket.recv_from(&mut buffer) => {
                let (length, peer) = value?;
                datagrams += 1;
                if datagrams > 30000 { break "input_limit"; }
                let sequence = if peer.ip() == config.allowed_peer {
                    verify_frame(&key, &run_id, &buffer[..length], false).ok()
                } else { None };
                let Some(sequence) = sequence.filter(|s| *s < config.expected_probes) else {
                    rejected_datagrams += 1; continue;
                };
                if !received.insert(sequence) { duplicates += 1; continue; }
                // At most one same-size authenticated ACK per sequence, to the sender only.
                let ack = frame(&key, &run_id, sequence, true);
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break "cancelled",
                    _ = tokio::time::sleep_until(deadline) => break "duration_limit",
                    result = socket.send_to(&ack, peer) => { if result? == FRAME_SIZE { acks_sent += 1; } }
                }
                if received.len() as u64 == config.expected_probes { break "all_expected_received"; }
            }
        }
    };
    let mut evidence = ReceiverEvidence {
        schema_version: 1,
        run_id: config.run_id,
        bound_address,
        allowed_peer: config.allowed_peer,
        expected_probes: config.expected_probes,
        started_at,
        finished_at: Utc::now(),
        received_sequences: received.into_iter().collect(),
        duplicates,
        rejected_datagrams,
        acks_sent,
        termination_reason: reason.into(),
        mac: String::new(),
    };
    evidence.mac = hex::encode(mac(&key, &receiver_bytes(&evidence)?));
    Ok(evidence)
}

#[derive(Debug, Serialize)]
#[cfg(feature = "experimental-receiver")]
pub struct DeliveryComparison {
    pub run_id: String,
    pub sent_unique: usize,
    pub received_at_destination: usize,
    pub acknowledged_at_sender: usize,
    pub missing_at_destination: Vec<u64>,
    pub received_without_ack: Vec<u64>,
    pub unexpected_at_destination: Vec<u64>,
    pub duplicate_datagrams_at_destination: u64,
    pub delivery_ratio: Option<f64>,
    pub interpretation: String,
}

#[cfg(feature = "experimental-receiver")]
pub fn compare(
    sender: &Report,
    receiver: &ReceiverEvidence,
    key: &[u8; 32],
) -> Result<DeliveryComparison> {
    let evidence = sender
        .delivery
        .as_ref()
        .context("sender report contains no delivery evidence")?;
    ensure!(
        receiver.schema_version == 1 && evidence.run_id == receiver.run_id,
        "report schema/run mismatch"
    );
    decode_run_id(&evidence.run_id)?;
    verify_mac(key, &sender_bytes(evidence), &hex::decode(&evidence.mac)?)?;
    verify_mac(
        key,
        &receiver_bytes(receiver)?,
        &hex::decode(&receiver.mac)?,
    )?;
    let sent: BTreeSet<_> = evidence.sent_sequences.iter().copied().collect();
    let received: BTreeSet<_> = receiver.received_sequences.iter().copied().collect();
    let acknowledged: BTreeSet<_> = evidence.acknowledged_sequences.iter().copied().collect();
    ensure!(
        sent.len() == evidence.sent_sequences.len()
            && received.len() == receiver.received_sequences.len()
            && acknowledged.len() == evidence.acknowledged_sequences.len()
            && acknowledged.is_subset(&sent),
        "invalid sequence evidence"
    );
    ensure!(
        (1..=10000).contains(&receiver.expected_probes)
            && sent.len() <= 10000
            && received.iter().all(|s| *s < receiver.expected_probes)
            && acknowledged.is_subset(&received),
        "inconsistent receiver evidence"
    );
    let delivered = sent.intersection(&received).count();
    Ok(DeliveryComparison { run_id: evidence.run_id.clone(), sent_unique: sent.len(), received_at_destination: delivered,
        acknowledged_at_sender: acknowledged.len(), missing_at_destination: sent.difference(&received).copied().collect(),
        received_without_ack: received.intersection(&sent).filter(|s| !acknowledged.contains(*s)).copied().collect(),
        unexpected_at_destination: received.difference(&sent).copied().collect(), duplicate_datagrams_at_destination: receiver.duplicates,
        delivery_ratio: (!sent.is_empty()).then(|| delivered as f64 / sent.len() as f64),
        interpretation: "Counts authenticated application UDP datagrams at the receiver's placement. Missing datagrams do not identify a firewall decision or loss location. A reachable receiver is not a service-capacity or DDoS-resilience verdict. Place the receiver behind the relevant protection and correlate with independent service latency/error telemetry.".into() })
}
