use crate::config::{Limits, Mode, Target};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct IoCounters {
    pub raw_ip_packets_accepted: AtomicU64,
    pub raw_ip_bytes_accepted: AtomicU64,
    pub datagrams_sent: AtomicU64,
    pub datagrams_received: AtomicU64,
    pub application_bytes_sent: AtomicU64,
    pub application_bytes_received: AtomicU64,
}

impl IoCounters {
    pub fn raw_accepted(&self, bytes: usize) {
        self.raw_ip_packets_accepted.fetch_add(1, Ordering::Relaxed);
        self.raw_ip_bytes_accepted
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn stream_sent(&self, bytes: usize) {
        self.application_bytes_sent
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn stream_received(&self, bytes: usize) {
        self.application_bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn sent(&self, bytes: usize) {
        self.datagrams_sent.fetch_add(1, Ordering::Relaxed);
        self.application_bytes_sent
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn received(&self, bytes: usize) {
        self.datagrams_received.fetch_add(1, Ordering::Relaxed);
        self.application_bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Sent,
    RemoteRejection,
    Timeout,
    NetworkError,
    ProtocolError,
    Simulated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    #[serde(default)]
    pub protocol_details: std::collections::BTreeMap<String, serde_json::Value>,
    pub vector_id: String,
    pub outcome: Outcome,
    pub latency_ms: f64,
    pub application_bytes_sent: u64,
    pub application_bytes_received: u64,
    pub response_received: bool,
    pub tcp_handshake_success: bool,
    pub http_status: Option<u16>,
    pub detail: String,
    pub simulated_events: Option<u64>,
}

impl Observation {
    pub fn success(detail: impl Into<String>) -> Self {
        Self {
            protocol_details: Default::default(),
            vector_id: String::new(),
            outcome: Outcome::Success,
            latency_ms: 0.0,
            application_bytes_sent: 0,
            application_bytes_received: 0,
            response_received: false,
            tcp_handshake_success: false,
            http_status: None,
            detail: detail.into(),
            simulated_events: None,
        }
    }
    pub fn is_healthy(&self, max_latency_ms: u64) -> bool {
        matches!(self.outcome, Outcome::Success | Outcome::Simulated)
            && self.latency_ms <= max_latency_ms as f64
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Metrics {
    #[serde(default)]
    pub raw_ip_packets_accepted: u64,
    #[serde(default)]
    pub raw_ip_bytes_accepted: u64,
    pub probes_started: u64,
    pub probes_completed: u64,
    pub probes_cancelled: u64,
    pub responses_received: u64,
    pub application_bytes_sent: u64,
    pub application_bytes_received: u64,
    pub timeouts: u64,
    pub network_errors: u64,
    pub protocol_errors: u64,
    pub remote_rejections: u64,
    pub tcp_handshake_successes: u64,
    pub http_successes: u64,
    pub http_errors: u64,
    #[serde(default)]
    pub http_responses_received: u64,
    pub simulated_events: u64,
    pub admission_reserved_bytes: u64,
    pub actual_probes_per_second: f64,
    pub measured_application_bytes_per_second: f64,
    // Without packet capture these cannot be honestly inferred from socket calls.
    pub packets_sent: Option<u64>,
    pub wire_bytes_sent: Option<u64>,
    pub application_datagrams_sent: u64,
    pub application_datagrams_received: u64,
}

impl Metrics {
    pub fn record(&mut self, value: &Observation) {
        self.probes_completed += 1;
        self.responses_received += u64::from(value.response_received);
        self.application_bytes_sent += value.application_bytes_sent;
        self.application_bytes_received += value.application_bytes_received;
        self.tcp_handshake_successes += u64::from(value.tcp_handshake_success);
        match value.outcome {
            Outcome::Timeout => self.timeouts += 1,
            Outcome::NetworkError => self.network_errors += 1,
            Outcome::ProtocolError => self.protocol_errors += 1,
            Outcome::RemoteRejection => self.remote_rejections += 1,
            _ => {}
        }
        let statuses: Vec<u16> = value
            .protocol_details
            .get("http_statuses")
            .and_then(serde_json::Value::as_array)
            .map(|codes| {
                codes
                    .iter()
                    .filter_map(|code| code.as_u64().and_then(|v| u16::try_from(v).ok()))
                    .collect()
            })
            .unwrap_or_else(|| value.http_status.into_iter().collect());
        for code in statuses {
            self.http_responses_received += 1;
            if (200..400).contains(&code) {
                self.http_successes += 1;
            } else {
                self.http_errors += 1;
            }
        }
        self.simulated_events += value.simulated_events.unwrap_or(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reused_http_connections_count_both_response_statuses() {
        let mut observation = Observation::success("two HEAD responses on one connection");
        observation.http_status = Some(200);
        observation.response_received = true;
        observation
            .protocol_details
            .insert("http_statuses".into(), serde_json::json!([503, 200]));
        let mut metrics = Metrics::default();
        metrics.record(&observation);
        assert_eq!(metrics.http_successes, 1);
        assert_eq!(metrics.http_errors, 1);
        assert_eq!(metrics.http_responses_received, 2);
        assert_eq!(metrics.responses_received, 1);
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaptureEvidence {
    pub interface: String,
    pub filter: String,
    pub linktype: i32,
    pub packets_observed: u64,
    pub captured_packet_bytes: u64,
    pub kernel_dropped: Option<u32>,
    pub interface_dropped: Option<u32>,
    pub error: Option<String>,
    pub scope: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpProbe {
    pub request_id: String,
    pub sequence: u64,
    pub vector_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub mode: Mode,
    pub target: Option<Target>,
    pub vector_ids: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub requested_limits: Limits,
    pub actual_duration_seconds: f64,
    pub termination_reason: String,
    pub metrics: Metrics,
    pub observations: Vec<Observation>,
    /// IDs assigned at admission, including probes later cancelled or timed out.
    /// Assignment does not establish that the request was transmitted or received.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_probes: Vec<HttpProbe>,
    pub accounting_note: String,
    pub delivery: Option<crate::measurement::SenderEvidence>,
    #[serde(default)]
    pub outbound_capture: Option<CaptureEvidence>,
}

pub fn write_new(path: &std::path::Path, report: &Report) -> anyhow::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, report)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
