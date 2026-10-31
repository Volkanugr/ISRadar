//! Optional outbound sender-host evidence, never an independent destination observer.
//! libpcap cannot attribute another process's traffic to this agent; counters retain that scope.
use crate::{config::Target, results::CaptureEvidence, settings::CaptureSettings};
use anyhow::{Context, Result};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub(crate) struct Session {
    stop: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    worker: Option<JoinHandle<CaptureEvidence>>,
}

impl Session {
    pub(crate) fn start(settings: &CaptureSettings, target: &Target) -> Result<Self> {
        settings.validate()?;
        // This filter is generated solely from a validated numeric target. No user BPF expressions.
        let filter = format!("dst host {}", target.ip);
        let mut handle = pcap::Capture::from_device(settings.interface.as_str())?
            .promisc(false)
            .snaplen(96)
            .buffer_size(1_048_576)
            .timeout(20)
            .open()
            .context("open explicitly authorized outbound capture interface")?;
        handle
            .direction(pcap::Direction::Out)
            .context("outbound-only capture is required")?;
        handle.filter(&filter, true)?;
        let mut handle = handle.setnonblock()?;
        let linktype = handle.get_datalink().0;
        let stop = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let failure = failed.clone();
        let interface = settings.interface.clone();
        let worker=thread::Builder::new().name("isradar-outbound-capture".into()).spawn(move || {
            let mut evidence=CaptureEvidence {interface,filter,linktype,packets_observed:0,captured_packet_bytes:0,
                kernel_dropped:None,interface_dropped:None,error:None,
                scope:"outbound sender-host traffic to the configured destination IP, including fragments and possible other processes; not agent attribution or destination receipt; original capture lengths exclude unobserved physical overhead".into()};
            while !signal.load(Ordering::Acquire) {
                match handle.next_packet() {
                    Ok(packet)=>{
                        evidence.packets_observed+=1;evidence.captured_packet_bytes+=u64::from(packet.header.len);
                        if evidence.packets_observed>=100_000 {
                            evidence.error=Some("outbound capture reached its 100000-packet observation cap".into());break;
                        }
                    },
                    Err(pcap::Error::TimeoutExpired)=>thread::park_timeout(Duration::from_millis(5)),
                    Err(error)=>{evidence.error=Some(error.to_string());break;}
                }
            }
            match handle.stats() {
                Ok(stats)=>{evidence.kernel_dropped=Some(stats.dropped);evidence.interface_dropped=Some(stats.if_dropped);},
                Err(error)=>{evidence.error.get_or_insert_with(||format!("capture statistics unavailable: {error}"));},
            }
            if evidence.error.is_some() {failure.store(true,Ordering::Release);}
            evidence
        })?;
        Ok(Self {
            stop,
            failed,
            worker: Some(worker),
        })
    }

    pub(crate) fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    pub(crate) fn finish(mut self) -> Result<CaptureEvidence> {
        self.stop.store(true, Ordering::Release);
        self.worker
            .take()
            .context("capture worker missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("outbound capture worker panicked"))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn libpcap_reads_the_real_offline_fixture_without_a_network_handle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("icmp.pcap");
        crate::vectors::lab::write_fixture_pcap(&path).unwrap();
        let mut capture = pcap::Capture::from_file(&path).unwrap();
        let packet = capture.next_packet().unwrap();
        assert_eq!(packet.data, crate::vectors::lab::ipv4_fixture());
        assert_eq!(packet.header.len, 28);
        assert!(matches!(
            capture.next_packet(),
            Err(pcap::Error::NoMorePackets)
        ));
    }
}
