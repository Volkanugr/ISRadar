use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    LiveValidation,
    LabEmulation,
    CatalogOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub duration_seconds: u64,
    pub probes_per_second: u32,
    pub concurrency: usize,
    pub bandwidth_bytes_per_second: u64,
    pub max_probes: u64,
    pub timeout_ms: u64,
}

impl Limits {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=600).contains(&self.duration_seconds),
            "duration must be 1..600 seconds"
        );
        ensure!(
            (1..=50).contains(&self.probes_per_second),
            "rate must be 1..50 probes/second"
        );
        ensure!(
            (1..=8).contains(&self.concurrency),
            "concurrency must be 1..8"
        );
        ensure!(
            (4096..=262144).contains(&self.bandwidth_bytes_per_second),
            "bandwidth admission budget must be 4096..262144 bytes/second"
        );
        ensure!(
            (1..=10000).contains(&self.max_probes),
            "max_probes must be 1..10000"
        );
        ensure!(
            (50..=5000).contains(&self.timeout_ms),
            "timeout must be 50..5000 ms"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    // Numeric destinations remove DNS rebinding and resolver side effects.
    pub ip: IpAddr,
    pub port: u16,
    pub server_name: Option<String>,
}

impl Target {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.port != 0, "target port must be nonzero");
        match self.ip {
            IpAddr::V4(ip) => {
                ensure!(
                    !ip.is_unspecified()
                        && !ip.is_multicast()
                        && !ip.is_broadcast()
                        && !ip.is_link_local()
                        && ip.octets()[0] != 0,
                    "invalid unicast target"
                );
                ensure!(
                    ip.octets() != [169, 254, 169, 254],
                    "metadata destination denied"
                );
            }
            IpAddr::V6(ip) => {
                ensure!(
                    !ip.is_unspecified()
                        && !ip.is_multicast()
                        && (ip.segments()[0] & 0xffc0) != 0xfe80
                        && ip.to_ipv4_mapped().is_none(),
                    "invalid or mapped IPv6 target"
                );
            }
        }
        if let Some(name) = &self.server_name {
            ensure!(
                name.len() <= 253 && !name.is_empty() && name.parse::<IpAddr>().is_err(),
                "server_name must be a DNS name"
            );
            ensure!(
                name.split('.').all(|s| !s.is_empty()
                    && s.len() <= 63
                    && !s.starts_with('-')
                    && !s.ends_with('-')
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
                "invalid server_name"
            );
        }
        Ok(())
    }

    pub fn address(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.ip, self.port)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub heartbeat_file: PathBuf,
    pub max_age_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub consecutive_failures: u32,
    pub max_latency_ms: u64,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            consecutive_failures: 3,
            max_latency_ms: 3000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub protocol: crate::settings::ProtocolOptions,
    pub vectors: Vec<String>,
    pub mode: Mode,
    pub target: Option<Target>,
    pub limits: Limits,
    pub kill_switch: PathBuf,
    pub controller_lease: Option<Lease>,
    pub measurement: Option<crate::measurement::MeasurementConfig>,
    #[serde(default)]
    pub health: Health,
}

impl Config {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        ensure!(bytes.len() <= 65536, "configuration too large");
        let mut config: Self = serde_yaml::from_slice(&bytes)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        if config.kill_switch.is_relative() {
            config.kill_switch = base.join(&config.kill_switch);
        }
        if let Some(measurement) = &mut config.measurement {
            if measurement.key_file.is_relative() {
                measurement.key_file = base.join(&measurement.key_file);
            }
        }
        if let Some(ca) = &mut config.protocol.tls_ca {
            if ca.file.is_relative() {
                ca.file = base.join(&ca.file);
            }
        }
        if let Some(lease) = &mut config.controller_lease {
            if lease.heartbeat_file.is_relative() {
                lease.heartbeat_file = base.join(&lease.heartbeat_file);
            }
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        self.protocol.validate()?;
        ensure!(
            self.mode == Mode::LiveValidation || self.protocol.is_default(),
            "protocol options require live_validation"
        );
        ensure!(
            !self.vectors.is_empty() && self.vectors.len() <= 200,
            "choose 1..200 vectors"
        );
        ensure!(
            self.limits.max_probes >= self.vectors.len() as u64,
            "max_probes must cover every selected vector"
        );
        let unique: std::collections::HashSet<_> = self.vectors.iter().collect();
        ensure!(unique.len() == self.vectors.len(), "duplicate vector IDs");
        ensure!(
            self.mode != Mode::CatalogOnly,
            "catalog_only entries cannot execute"
        );
        ensure!(
            (1..=10).contains(&self.health.consecutive_failures),
            "health threshold must be 1..10"
        );
        ensure!(
            (1..=5000).contains(&self.health.max_latency_ms),
            "health latency must be 1..5000 ms"
        );
        ensure!(
            !self.kill_switch.as_os_str().is_empty(),
            "kill switch path is required"
        );
        if let Some(lease) = &self.controller_lease {
            ensure!(
                (1..=30).contains(&lease.max_age_seconds),
                "lease age must be 1..30 seconds"
            );
        }
        if self.vectors.iter().any(|id| id == "UDP-010") {
            ensure!(
                self.mode == Mode::LiveValidation
                    && self.vectors.len() == 1
                    && self.measurement.is_some(),
                "UDP-010 requires a standalone live measurement configuration"
            );
        }
        if let Some(measurement) = &self.measurement {
            ensure!(
                self.vectors.len() == 1 && self.vectors[0] == "UDP-010",
                "measurement configuration is only valid for UDP-010"
            );
            measurement.validate()?;
        }
        match self.mode {
            Mode::LiveValidation => {
                self.target
                    .as_ref()
                    .context("live target is required")?
                    .validate()?;
            }
            Mode::LabEmulation => ensure!(
                self.target.is_none(),
                "offline lab models do not accept network targets"
            ),
            Mode::CatalogOnly => unreachable!(),
        }
        Ok(())
    }
}
