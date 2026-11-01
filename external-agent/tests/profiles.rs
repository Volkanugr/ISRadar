use external_agent::{
    config::{Config, Mode},
    engine, profiles,
    vectors::{registry::Registry, TrafficVector},
};
use std::collections::HashSet;

#[test]
fn high_priority_preset_contains_exactly_the_documented_high_vectors() {
    let guide = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors.md"),
    )
    .unwrap();
    let expected: HashSet<String> = guide
        .lines()
        .filter_map(|line| {
            let columns: Vec<_> = line.split('|').map(str::trim).collect();
            (columns.get(3) == Some(&"High")).then(|| columns[1].trim_matches('`').to_owned())
        })
        .collect();
    assert_eq!(expected.len(), 80);
    let presets = profiles::list().unwrap();
    let ids = presets.get("high-priority").unwrap();
    assert_eq!(ids.len(), expected.len());
    assert_eq!(ids.iter().cloned().collect::<HashSet<_>>(), expected);

    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("high-priority");
    let create = std::process::Command::new(env!("CARGO_BIN_EXE_external-agent"))
        .args([
            "profiles",
            "create",
            "--preset",
            "high-priority",
            "--directory",
        ])
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(destination.join("index.json")).unwrap()).unwrap();
    assert_eq!(index["preset"], "high-priority");
    let configs = index["configs"].as_array().unwrap();
    assert_eq!(configs.len(), expected.len());
    let registry = Registry::bundled().unwrap();
    let mut actual = HashSet::new();
    let (mut live, mut offline, mut raw) = (0, 0, 0);
    for filename in configs {
        let config = Config::read(&destination.join(filename.as_str().unwrap())).unwrap();
        assert_eq!(config.vectors.len(), 1);
        let vector = registry.get(&config.vectors[0]).unwrap();
        assert!(actual.insert(vector.id.clone()));
        if config.mode == Mode::LiveValidation {
            live += 1;
            assert!(config.target.as_ref().unwrap().ip.is_loopback());
        } else {
            offline += 1;
            assert!(config.target.is_none());
        }
        vector
            .validate(config.mode, config.target.as_ref())
            .unwrap();
        vector.backend.validate_options(&config.protocol).unwrap();
        if vector.backend.is_raw() {
            raw += 1;
            assert!(config.limits.max_probes * vector.backend.raw_packet_cost() <= 16);
            assert_eq!(config.limits.probes_per_second, 1);
            assert_eq!(config.limits.concurrency, 1);
        }
        if vector.backend.is_raw() && !cfg!(target_os = "linux") {
            assert!(engine::validate(&config, &registry)
                .unwrap_err()
                .to_string()
                .contains("requires Linux"));
        } else {
            engine::validate(&config, &registry).unwrap();
        }
    }
    assert_eq!(actual, expected);
    assert_eq!((live, offline, raw), (33, 47, 5));
    assert!(destination.join("ca.der").is_file());
}

#[test]
fn l4_preset_has_every_transport_case_and_no_application_or_ip_cases() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("l4");
    let created = profiles::create("l4", &destination).unwrap();
    let registry = Registry::bundled().unwrap();
    let expected: HashSet<_> = registry
        .list()
        .filter(|vector| vector.layer == "L4")
        .map(|vector| vector.id.clone())
        .collect();
    let mut actual = HashSet::new();
    let mut live = 0;
    let mut offline = 0;
    for filename in created.configs {
        let config = Config::read(&destination.join(filename)).unwrap();
        assert_eq!(config.vectors.len(), 1);
        let vector = registry.get(&config.vectors[0]).unwrap();
        actual.insert(vector.id.clone());
        vector
            .validate(config.mode, config.target.as_ref())
            .unwrap();
        if config.mode == Mode::LiveValidation {
            live += 1;
            assert!(config.target.as_ref().unwrap().ip.is_loopback());
        } else {
            offline += 1;
            assert!(config.target.is_none());
        }
        if vector.backend.is_raw() {
            assert!(config.limits.max_probes * vector.backend.raw_packet_cost() <= 16);
            assert_eq!(config.limits.probes_per_second, 1);
            assert_eq!(config.limits.concurrency, 1);
        } else {
            engine::validate(&config, &registry).unwrap();
        }
    }
    assert_eq!(actual, expected);
    assert_eq!((live, offline), (42, 7));
    assert!(destination.join("measurement.key").is_file());
}

#[test]
fn combined_lab_yaml_executes_every_offline_vector_once() {
    let temp = tempfile::tempdir().unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/profiles/lab.yaml");
    let config = Config::read(&path).unwrap();
    let registry = Registry::bundled().unwrap();
    let expected: HashSet<_> = registry
        .list()
        .filter(|vector| vector.mode == Mode::LabEmulation)
        .map(|vector| vector.id.clone())
        .collect();
    assert_eq!(config.vectors.len(), expected.len());
    assert_eq!(
        config.vectors.iter().cloned().collect::<HashSet<_>>(),
        expected
    );
    assert_eq!(config.limits.max_probes as usize, expected.len());
    let report = temp.path().join("lab-report.json");
    let run = std::process::Command::new(env!("CARGO_BIN_EXE_external-agent"))
        .args(["run", "--config"])
        .arg(path)
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let value: external_agent::results::Report =
        serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    assert_eq!(value.termination_reason, "completed");
    assert_eq!(value.observations.len(), expected.len());
    assert_eq!(
        value
            .observations
            .iter()
            .map(|item| item.vector_id.clone())
            .collect::<HashSet<_>>(),
        expected
    );
    assert!(value
        .observations
        .iter()
        .all(|item| item.outcome == external_agent::results::Outcome::Simulated));
    assert_eq!(value.metrics.application_datagrams_sent, 0);
    assert_eq!(value.metrics.application_bytes_sent, 0);
    assert_eq!(value.metrics.raw_ip_packets_accepted, 0);
}

#[test]
fn preset_templates_cover_every_vector_without_operator_keys() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("researcher");
    let created = profiles::create("researcher", &destination).unwrap();
    let registry = Registry::bundled().unwrap();
    let expected: HashSet<_> = registry.list().map(|v| v.id.clone()).collect();
    let mut seen = HashSet::new();
    for filename in created.configs {
        let config = Config::read(&destination.join(filename)).unwrap();
        let vector = registry.get(&config.vectors[0]).unwrap();
        seen.insert(vector.id.clone());
        vector
            .validate(config.mode, config.target.as_ref())
            .unwrap();
        vector.backend.validate_options(&config.protocol).unwrap();
        if vector.backend.is_raw() && !cfg!(target_os = "linux") {
            assert!(engine::validate(&config, &registry)
                .unwrap_err()
                .to_string()
                .contains("requires Linux"));
        } else {
            engine::validate(&config, &registry).unwrap();
        }
        if config.mode == Mode::LiveValidation {
            assert!(config.target.unwrap().ip.is_loopback());
        }
    }
    assert_eq!(seen, expected);
    assert!(!destination.join("operator.key").exists());
    assert!(!destination.join("authorization.json").exists());
}

#[test]
fn preset_creation_refreshes_measurement_identity_and_preserves_existing_files() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    profiles::create("basic", &first).unwrap();
    profiles::create("basic", &second).unwrap();
    let a = Config::read(&first.join("UDP-010.yaml"))
        .unwrap()
        .measurement
        .unwrap();
    let b = Config::read(&second.join("UDP-010.yaml"))
        .unwrap()
        .measurement
        .unwrap();
    assert_ne!(a.run_id, b.run_id);
    assert_ne!(
        std::fs::read(&a.key_file).unwrap(),
        std::fs::read(&b.key_file).unwrap()
    );
    let original = std::fs::read(first.join("HTTP-001.yaml")).unwrap();
    assert!(profiles::create("basic", &first).is_err());
    assert_eq!(
        std::fs::read(first.join("HTTP-001.yaml")).unwrap(),
        original
    );
    assert!(profiles::create("unknown", &temp.path().join("unknown")).is_err());
    assert!(!temp.path().join("unknown").exists());
}

#[test]
fn cli_runs_yaml_without_operator_approval() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("profiles");
    let binary = env!("CARGO_BIN_EXE_external-agent");
    let create = std::process::Command::new(binary)
        .args(["profiles", "create", "--preset", "hacker", "--directory"])
        .arg(&directory)
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    let report = temp.path().join("report.json");
    let run = std::process::Command::new(binary)
        .args(["run", "--config"])
        .arg(directory.join("HTTP-025.yaml"))
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    assert_eq!(value["termination_reason"], "completed");
    assert_eq!(value["metrics"]["application_datagrams_sent"], 0);
    assert_eq!(value["observations"][0]["outcome"], "simulated");
    let validate = std::process::Command::new(binary)
        .args(["validate", "--config"])
        .arg(directory.join("TLS-009.yaml"))
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );
}
