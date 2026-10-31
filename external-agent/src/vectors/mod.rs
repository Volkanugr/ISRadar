pub mod event_models;
pub mod lab;
pub mod protocols;
pub mod registry;

use crate::{
    config::{Mode, Target},
    results::Observation,
};
use anyhow::Result;
use async_trait::async_trait;
use registry::{Backend, Vector};

// Construction stays inside the engine, after target, mode and limit checks.
pub struct TestContext {
    pub(crate) raw_allowed: bool,
    pub(crate) protocol: crate::settings::ProtocolOptions,
    pub(crate) target: Option<Target>,
    pub(crate) timeout_ms: u64,
    pub(crate) measurement: Option<std::sync::Arc<crate::measurement::Trace>>,
    pub(crate) sequence: u64,
    pub(crate) http_request_id: Option<String>,
    pub(crate) counters: std::sync::Arc<crate::results::IoCounters>,
}

#[async_trait]
pub trait TrafficVector: Send + Sync {
    fn metadata(&self) -> &Vector;
    fn id(&self) -> &str {
        &self.metadata().id
    }
    fn name(&self) -> &str {
        &self.metadata().name
    }
    fn category(&self) -> &str {
        &self.metadata().category
    }
    fn validate(&self, mode: Mode, target: Option<&Target>) -> Result<()>;
    async fn execute(&self, context: &TestContext) -> Result<Observation>;
}

#[async_trait]
impl TrafficVector for Vector {
    fn metadata(&self) -> &Vector {
        self
    }
    fn validate(&self, mode: Mode, target: Option<&Target>) -> Result<()> {
        anyhow::ensure!(
            self.enabled && self.mode == mode && self.backend != Backend::Catalog,
            "{} is not executable in the requested mode",
            self.id
        );
        if mode == Mode::LiveValidation {
            let target = target.ok_or_else(|| anyhow::anyhow!("target required"))?;
            target.validate()?;
            if let Some(version) = self.ip_version {
                anyhow::ensure!(
                    (version == 4 && target.ip.is_ipv4()) || (version == 6 && target.ip.is_ipv6()),
                    "{} requires IPv{}",
                    self.id,
                    version
                );
            }
            if self.backend.is_tls() {
                anyhow::ensure!(
                    target.server_name.is_some(),
                    "TLS validation requires a configured server_name"
                );
            }
            if self.backend == Backend::IcmpEcho {
                anyhow::ensure!(target.port == 1, "ICMP uses configured pseudo-port 1");
            }
            if self.backend.is_dns() {
                anyhow::ensure!(
                    target.server_name.is_some(),
                    "DNS requires a configured query name"
                );
            }
        }
        Ok(())
    }

    async fn execute(&self, context: &TestContext) -> Result<Observation> {
        match self.backend {
            Backend::OfflineModel => lab::model(self),
            Backend::OfflinePacket => lab::packet_fixture(self),
            Backend::OfflinePolicyFixture => lab::policy_fixture(self),
            Backend::Catalog => anyhow::bail!("catalog-only vector cannot execute"),
            _ => protocols::execute(self, context).await,
        }
    }
}
