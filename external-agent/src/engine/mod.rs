use crate::{
    config::{Config, Mode},
    measurement::Trace,
    results::{IoCounters, Metrics, Observation, Outcome, Report},
    safety::{kill_switch, limits::Admission},
    vectors::{registry::Registry, TestContext, TrafficVector},
};
use anyhow::{ensure, Context, Result};
use chrono::Utc;
use std::sync::{atomic::Ordering, Arc};
use tokio::{
    task::JoinSet,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

pub fn validate(config: &Config, registry: &Registry) -> Result<()> {
    config.validate()?;
    if config.vectors.iter().any(|id| {
        registry.get(id).is_ok_and(|v| {
            matches!(
                v.backend,
                crate::vectors::registry::Backend::SipInvite
                    | crate::vectors::registry::Backend::HttpConnect
            )
        })
    }) {
        ensure!(config.limits.probes_per_second==1 && config.limits.concurrency==1 && config.limits.max_probes<=16 && config.limits.duration_seconds<=60,
            "INVITE/CONNECT policy probes require one worker, 1 probe/second, at most 16 probes and 60 seconds");
    }
    let raw_cost = config
        .vectors
        .iter()
        .map(|id| {
            registry
                .get(id)
                .map(|v| (v.backend.is_raw(), v.backend.raw_packet_cost()))
        })
        .collect::<Result<Vec<_>>>()?;
    if raw_cost.iter().any(|(raw, _)| *raw) {
        let cost = raw_cost
            .iter()
            .filter(|(raw, _)| *raw)
            .map(|(_, cost)| *cost)
            .max()
            .unwrap_or(1);
        ensure!(config.limits.probes_per_second == 1 && config.limits.concurrency == 1
            && config.limits.max_probes.saturating_mul(cost) <= 16 && config.limits.duration_seconds <= 60,
            "raw validation is limited to 1 probe/second, one worker, 16 total IP packet samples, and 60 seconds");
        ensure!(
            cfg!(target_os = "linux"),
            "raw validation requires Linux and operator-provisioned CAP_NET_RAW"
        );
    }
    for id in &config.vectors {
        registry
            .get(id)?
            .backend
            .validate_options(&config.protocol)?;
        registry
            .get(id)?
            .validate(config.mode, config.target.as_ref())?;
    }
    if let Some(reason) = kill_switch::stop_reason(config) {
        anyhow::bail!("execution stopped: {reason}");
    }
    if let Some(measurement) = &config.measurement {
        Trace::from_config(measurement)?;
    }
    Ok(())
}

pub async fn run(config: Config, registry: Registry, cancel: CancellationToken) -> Result<Report> {
    // Every caller validates the entire plan and its limits before any network activity.
    validate(&config, &registry)?;
    #[cfg(feature = "packet-capture")]
    let capture = config
        .protocol
        .capture
        .as_ref()
        .map(|settings| {
            crate::network::capture::Session::start(
                settings,
                config.target.as_ref().context("capture target required")?,
            )
        })
        .transpose()?;
    let raw_allowed = config
        .vectors
        .iter()
        .any(|id| registry.get(id).is_ok_and(|vector| vector.backend.is_raw()));
    let trace = config
        .measurement
        .as_ref()
        .map(Trace::from_config)
        .transpose()?
        .map(Arc::new);
    let counters = Arc::new(IoCounters::default());
    let mut metrics = Metrics::default();
    let mut observations = Vec::new();
    let http_run_id = hex::encode(rand::random::<[u8; 16]>());
    let mut http_probes = Vec::new();
    let mut workers: JoinSet<Observation> = JoinSet::new();
    let mut admission = Admission::new(&config.limits);
    let start = Instant::now();
    let started_at = Utc::now();
    let deadline = start + Duration::from_secs(config.limits.duration_seconds);
    let mut watch = tokio::time::interval(Duration::from_millis(20));
    watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut stats = tokio::time::interval(Duration::from_secs(1));
    stats.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut vector_index = 0usize;
    let mut in_vector = 0u64;
    let mut failures = 0u32;
    let mut reason = "completed".to_owned();
    // Divide one aggregate request budget across a sequential plan.
    ensure!(
        config.limits.max_probes >= config.vectors.len() as u64,
        "max_probes must cover every selected vector"
    );
    let per_vector = config.limits.max_probes / config.vectors.len() as u64;
    tracing::info!(event="run_started", vectors=?config.vectors, target=?config.target);
    loop {
        #[cfg(feature = "packet-capture")]
        if capture.as_ref().is_some_and(|capture| capture.failed()) {
            reason = "capture_failure".into();
            break;
        }
        if cancel.is_cancelled() {
            reason = "cancelled".into();
            break;
        }
        if Instant::now() >= deadline {
            reason = "duration_limit".into();
            break;
        }
        if let Some(stop) = kill_switch::stop_reason(&config) {
            reason = stop.into();
            break;
        }
        let quota = if vector_index + 1 == config.vectors.len() {
            config.limits.max_probes - per_vector * vector_index as u64
        } else {
            per_vector
        };
        if in_vector >= quota && workers.is_empty() {
            vector_index += 1;
            in_vector = 0;
            failures = 0;
            if vector_index >= config.vectors.len() {
                break;
            }
            continue;
        }
        let can_start = in_vector < quota && workers.len() < config.limits.concurrency;
        tokio::select! {
            biased;
            _ = cancel.cancelled() => { reason = "cancelled".into(); break; }
            _ = tokio::time::sleep_until(deadline) => { reason = "duration_limit".into(); break; }
            _ = watch.tick() => {},
            value = workers.join_next(), if !workers.is_empty() => {
                let value = value.context("worker set empty")?.context("probe task failed")?;
                // Delivery loss is an observation, not independent evidence of service degradation.
                if value.vector_id != "UDP-010" && value.outcome != Outcome::Sent {
                    if value.is_healthy(config.health.max_latency_ms) { failures = 0; } else { failures += 1; }
                }
                tracing::info!(event="probe_completed", vector_id=%value.vector_id, outcome=?value.outcome, latency_ms=value.latency_ms, detail=%value.detail);
                metrics.record(&value);
                observations.push(value);
                if failures >= config.health.consecutive_failures && config.mode == Mode::LiveValidation {
                    reason = "health_degradation".into(); break;
                }
            }
            _ = stats.tick() => tracing::info!(event="statistics", started=metrics.probes_started, completed=metrics.probes_completed,
                responses=metrics.responses_received, elapsed_seconds=start.elapsed().as_secs_f64()),
            _ = tokio::time::sleep_until(admission.ready_at()), if can_start => {
                // Repeat safety checks directly at admission, after any scheduling delay.
                if cancel.is_cancelled() { reason = "cancelled".into(); break; }
                if Instant::now() >= deadline { reason = "duration_limit".into(); break; }
                if let Some(stop) = kill_switch::stop_reason(&config) { reason = stop.into(); break; }
                admission.admit(Instant::now());
                let vector = registry.get(&config.vectors[vector_index])?.clone();
                let http_request_id = crate::network::http_checks::correlation_id(vector.backend, &http_run_id, metrics.probes_started);
                if let Some(id) = &http_request_id {
                    http_probes.push(crate::results::HttpProbe { request_id: id.clone(), sequence: metrics.probes_started, vector_id: vector.id.clone() });
                }
                let context = TestContext { raw_allowed, protocol: config.protocol.clone(), target: config.target.clone(), timeout_ms: config.limits.timeout_ms,
                    measurement: trace.clone(), sequence: metrics.probes_started, http_request_id, counters: counters.clone() };
                let timeout = Duration::from_millis(config.limits.timeout_ms);
                workers.spawn(async move {
                    let probe_start = Instant::now();
                    let mut value = match tokio::time::timeout(timeout, vector.execute(&context)).await {
                        Ok(Ok(value)) => value,
                        Ok(Err(error)) => {
                            let mut value = Observation::success(format!("{error:#}"));
                            value.outcome = classify_error(&error);
                            value
                        }
                        Err(_) => {
                            let mut value = Observation::success("probe timeout; delivery/protection decision is unknown");
                            value.outcome = Outcome::Timeout;
                            value
                        }
                    };
                    value.vector_id.clone_from(&vector.id);
                    if let Some(id) = &context.http_request_id {
                        value.protocol_details.insert("http_request_id".into(), id.clone().into());
                    }
                    value.latency_ms = probe_start.elapsed().as_secs_f64() * 1000.0;
                    value
                });
                metrics.probes_started += 1;
                metrics.admission_reserved_bytes += 4096;
                in_vector += 1;
            }
        }
    }
    workers.abort_all();
    // Reap cancellation so sockets/processes are closed before exporting evidence.
    while let Some(value) = workers.join_next().await {
        match value {
            Ok(value) => {
                metrics.record(&value);
                observations.push(value);
            }
            Err(error) if error.is_cancelled() => metrics.probes_cancelled += 1,
            Err(error) => return Err(error.into()),
        }
    }
    let duration = start.elapsed().as_secs_f64();
    #[cfg(feature = "packet-capture")]
    let outbound_capture = capture
        .map(crate::network::capture::Session::finish)
        .transpose()?;
    #[cfg(not(feature = "packet-capture"))]
    let outbound_capture = None;
    metrics.application_datagrams_sent = counters.datagrams_sent.load(Ordering::Relaxed);
    metrics.raw_ip_packets_accepted = counters.raw_ip_packets_accepted.load(Ordering::Relaxed);
    metrics.raw_ip_bytes_accepted = counters.raw_ip_bytes_accepted.load(Ordering::Relaxed);
    metrics.application_datagrams_received = counters.datagrams_received.load(Ordering::Relaxed);
    metrics.application_bytes_sent = counters.application_bytes_sent.load(Ordering::Relaxed);
    metrics.application_bytes_received =
        counters.application_bytes_received.load(Ordering::Relaxed);
    if duration > 0.0 {
        metrics.actual_probes_per_second = metrics.probes_started as f64 / duration;
        metrics.measured_application_bytes_per_second =
            metrics.application_bytes_sent as f64 / duration;
    }
    let report = Report { schema_version: 1, mode: config.mode, target: config.target.clone(), vector_ids: config.vectors.clone(),
        started_at, finished_at: Utc::now(), requested_limits: config.limits,
        actual_duration_seconds: duration, termination_reason: reason, metrics, observations, http_probes,
        accounting_note: "Rate counts probes, not kernel packets. Bandwidth is a 4096-byte-per-probe admission reservation, not a wire-rate guarantee. Application byte counts cover UDP and directly instrumented stream exchanges, including partial writes and timed-out/cancelled probes. Library-managed HTTP/TLS/QUIC bytes are not included. Raw socket acceptance counters are separate. Agent-attributable wire bytes/packet counts remain null. Optional outbound_capture counts sender-host traffic to the destination IP and may include other processes. Sent means accepted by the local socket; destination delivery remains unobserved without receiver evidence. No security-appliance blocking attribution is made.".into(),
        delivery: trace.as_ref().map(|t| t.evidence()),
        outbound_capture,
    };
    tracing::info!(event="run_finished", termination_reason=%report.termination_reason, completed=report.metrics.probes_completed);
    Ok(report)
}

fn classify_error(error: &anyhow::Error) -> Outcome {
    if let Some(io) = error.downcast_ref::<std::io::Error>() {
        return if io.kind() == std::io::ErrorKind::ConnectionRefused {
            Outcome::RemoteRejection
        } else if io.kind() == std::io::ErrorKind::TimedOut {
            Outcome::Timeout
        } else {
            Outcome::NetworkError
        };
    }
    if let Some(http) = error.downcast_ref::<reqwest::Error>() {
        return if http.is_timeout() {
            Outcome::Timeout
        } else {
            Outcome::NetworkError
        };
    }
    Outcome::ProtocolError
}
