use crate::config::Limits;
use tokio::time::{Duration, Instant};

// One shared scheduler owns this gate: no per-worker buckets or catch-up bursts.
pub struct Admission {
    next_probe: Instant,
    next_bandwidth: Instant,
    probe_spacing: Duration,
    byte_spacing: Duration,
}

impl Admission {
    pub fn new(limits: &Limits) -> Self {
        let now = Instant::now();
        Self {
            next_probe: now,
            next_bandwidth: now,
            probe_spacing: Duration::from_secs_f64(1.0 / f64::from(limits.probes_per_second)),
            byte_spacing: Duration::from_secs_f64(
                4096.0 / limits.bandwidth_bytes_per_second as f64,
            ),
        }
    }
    pub fn ready_at(&self) -> Instant {
        self.next_probe.max(self.next_bandwidth)
    }
    pub fn admit(&mut self, now: Instant) {
        self.next_probe = now + self.probe_spacing;
        self.next_bandwidth = now + self.byte_spacing;
    }
}
