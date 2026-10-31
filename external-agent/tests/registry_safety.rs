mod support;
use external_agent::{
    config::{Config, Health, Lease, Mode, Target},
    engine,
    safety::{kill_switch, limits::Admission},
    vectors::{
        registry::{Backend, Registry},
        TrafficVector,
    },
};
use std::{collections::HashSet, sync::atomic::Ordering};
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

#[test]
fn catalog_integrity() {
    let registry = Registry::bundled().unwrap();
    let vectors: Vec<_> = registry.list().collect();
    assert!(vectors.len() > 150);
    assert_eq!(
        vectors.len(),
        vectors.iter().map(|v| &v.id).collect::<HashSet<_>>().len()
    );
    for layer in ["L3", "L4", "L7"] {
        assert!(vectors.iter().any(|v| v.layer == layer));
    }
    for family in [
        "tcp",
        "udp",
        "icmp",
        "ip",
        "dns",
        "ntp",
        "sip",
        "http",
        "tls",
        "specialized",
    ] {
        assert!(vectors.iter().any(|v| v.category == family));
    }
    assert_eq!(
        registry.get("UDP-010").unwrap().backend,
        Backend::UdpDelivery
    );
    assert!(vectors.iter().all(|v| v.vendor_parity == "unverified"));
}

#[test]
fn catalog_cannot_enable_unimplemented_or_offline_as_live() {
    let registry = Registry::bundled().unwrap();
    let vector = registry.get("TCP-001").unwrap();
    let mut value = serde_json::to_value(vector).unwrap();
    value["id"] = "UNIMPLEMENTED-001".into();
    value["mode"] = "catalog_only".into();
    value["backend"] = "catalog".into();
    value["implementation_status"] = "unverified".into();
    value["enabled"] = true.into();
    assert!(Registry::from_yaml(
        &serde_json::json!({"schema_version":1,"vectors":[value]}).to_string()
    )
    .is_err());
    let vector = registry
        .list()
        .find(|v| v.backend == Backend::OfflineModel)
        .unwrap();
    let mut value = serde_json::to_value(vector).unwrap();
    value["id"] = "LAB-ONLY-001".into();
    value["backend"] = "offline_packet".into();
    value["mode"] = "live_validation".into();
    value["requires_lab"] = false.into();
    assert!(Registry::from_yaml(
        &serde_json::json!({"schema_version":1,"vectors":[value]}).to_string()
    )
    .is_err());
}

#[test]
fn raw_sample_admission_is_stricter_than_normal_traffic() {
    for id in ["TCP-002", "TCP-024", "IP-002", "IP-015", "ICMP-003"] {
        let (_dir, config) = support::configured(
            support::target("127.0.0.1:9000".parse().unwrap()),
            &[id],
            support::limits(17),
        );
        let error = engine::validate(&config, &Registry::bundled().unwrap()).unwrap_err();
        assert!(error.to_string().contains("raw validation is limited"));
    }
}

#[test]
fn duplicate_registry_ids_rejected() {
    let vector = Registry::bundled().unwrap().get("TCP-001").unwrap().clone();
    assert!(Registry::from_yaml(
        &serde_json::json!({"schema_version":1,"vectors":[vector,vector]}).to_string()
    )
    .is_err());
}

#[test]
fn external_catalog_cannot_rebind_a_bundled_vector_id() {
    let mut vector = Registry::bundled()
        .unwrap()
        .get("HTTP-001")
        .unwrap()
        .clone();
    vector.backend = Backend::HttpDelete;
    assert!(Registry::from_yaml(
        &serde_json::json!({"schema_version":1,"vectors":[vector]}).to_string()
    )
    .is_err());
}

#[test]
fn unknown_fixture_cannot_claim_an_implemented_backend() {
    let mut vector = Registry::bundled().unwrap().get("IP-006").unwrap().clone();
    vector.id = "UNKNOWN-FIXTURE-001".into();
    assert!(Registry::from_yaml(
        &serde_json::json!({"schema_version":1,"vectors":[vector]}).to_string()
    )
    .is_err());
}

#[test]
fn backend_contracts() {
    for vector in Registry::bundled().unwrap().list() {
        let ip = if vector.ip_version == Some(6) {
            "::1"
        } else {
            "127.0.0.1"
        };
        let target = Target {
            ip: ip.parse().unwrap(),
            port: if vector.backend == Backend::IcmpEcho {
                1
            } else {
                9000
            },
            server_name: Some("validator.example".into()),
        };
        if vector.backend == Backend::Catalog {
            assert!(vector.validate(vector.mode, Some(&target)).is_err());
        } else {
            vector.validate(vector.mode, Some(&target)).unwrap();
        }
        let wrong = if vector.mode == Mode::LiveValidation {
            Mode::LabEmulation
        } else {
            Mode::LiveValidation
        };
        assert!(vector.validate(wrong, Some(&target)).is_err());
    }
}

#[test]
fn limits_are_nonzero_finite_and_bounded() {
    let grant = support::limits(1000);
    grant.validate().unwrap();
    let mut requested = grant.clone();
    requested.probes_per_second = 51;
    assert!(requested.validate().is_err());
    requested = grant.clone();
    requested.max_probes = 10001;
    assert!(requested.validate().is_err());
    requested = grant.clone();
    requested.timeout_ms = 0;
    assert!(requested.validate().is_err());
    requested = grant.clone();
    requested.duration_seconds = 601;
    assert!(requested.validate().is_err());
    requested = grant.clone();
    requested.bandwidth_bytes_per_second = 0;
    assert!(requested.validate().is_err());
}

#[test]
fn admission_never_catches_up_or_uses_worker_local_buckets() {
    let mut limits = support::limits(1000);
    limits.probes_per_second = 50;
    limits.bandwidth_bytes_per_second = 4096;
    let mut admission = Admission::new(&limits);
    let now = Instant::now();
    admission.admit(now);
    assert_eq!(admission.ready_at(), now + Duration::from_secs(1));
    let delayed = now + Duration::from_secs(10);
    admission.admit(delayed);
    assert_eq!(admission.ready_at(), delayed + Duration::from_secs(1));
}

#[test]
fn targets_reject_broadcast_metadata_mapped_and_name_injection() {
    for ip in [
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "169.254.169.254",
        "::",
        "ff02::1",
        "::ffff:127.0.0.1",
        "fe80::1",
    ] {
        assert!(Target {
            ip: ip.parse().unwrap(),
            port: 9000,
            server_name: None
        }
        .validate()
        .is_err());
    }
    let mut target = support::target("127.0.0.1:9000".parse().unwrap());
    target.server_name = Some("example.com/path\r\nHost: x".into());
    assert!(target.validate().is_err());
}

#[test]
fn kill_switch_and_missing_controller_fail_closed() {
    let (dir, mut config) = support::configured(
        support::target("127.0.0.1:9000".parse().unwrap()),
        &["TCP-001"],
        support::limits(10),
    );
    assert_eq!(kill_switch::stop_reason(&config), None);
    std::fs::write(&config.kill_switch, b"stop").unwrap();
    assert_eq!(kill_switch::stop_reason(&config), Some("kill_switch"));
    std::fs::remove_file(&config.kill_switch).unwrap();
    config.controller_lease = Some(Lease {
        heartbeat_file: dir.path().join("missing"),
        max_age_seconds: 2,
    });
    assert_eq!(
        kill_switch::stop_reason(&config),
        Some("controller_disconnected")
    );
}

#[tokio::test]
async fn offline_vectors_do_not_send() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Registry::bundled().unwrap();
    let ids: Vec<_> = registry
        .list()
        .filter(|v| v.mode == Mode::LabEmulation)
        .map(|v| v.id.clone())
        .collect();
    let expected_ids: HashSet<_> = ids.iter().cloned().collect();
    let config = Config {
        protocol: Default::default(),
        limits: support::limits(ids.len() as u64),
        vectors: ids,
        mode: Mode::LabEmulation,
        target: None,
        kill_switch: dir.path().join("STOP"),
        controller_lease: None,
        measurement: None,
        health: Health::default(),
    };
    let report = engine::run(config, registry, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(report.termination_reason, "completed");
    assert_eq!(report.metrics.application_datagrams_sent, 0);
    assert_eq!(report.metrics.application_bytes_sent, 0);
    assert_eq!(report.observations.len(), expected_ids.len());
    assert_eq!(
        report
            .observations
            .iter()
            .map(|o| o.vector_id.clone())
            .collect::<HashSet<_>>(),
        expected_ids
    );
    assert!(report
        .observations
        .iter()
        .all(|o| o.outcome == external_agent::results::Outcome::Simulated));
}

#[tokio::test]
async fn engine_api_validates_entire_plan_before_sending() {
    let (_dir, mut config) = support::configured(
        support::target("127.0.0.1:9000".parse().unwrap()),
        &["TCP-001"],
        support::limits(10),
    );
    engine::validate(&config, &Registry::bundled().unwrap()).unwrap();
    config.vectors.push("TCP-002".into());
    assert!(engine::run(
        config,
        Registry::bundled().unwrap(),
        CancellationToken::new()
    )
    .await
    .is_err());
}

#[test]
fn io_counts_survive_missing_observations() {
    let counters = external_agent::results::IoCounters::default();
    counters.sent(64);
    assert_eq!(counters.datagrams_sent.load(Ordering::Relaxed), 1);
    assert_eq!(counters.application_bytes_sent.load(Ordering::Relaxed), 64);
}
