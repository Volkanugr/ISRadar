//! Finite, deterministic event fixtures. No sockets, packet payloads or attack tool integration.
//! Units are illustrative workload tokens, not predictions of a real mitigation device.

#[derive(Debug, Clone, Copy)]
struct Scenario {
    mechanism: &'static str,
    batch: u64,
    work: u64,
    hold: u64,
    destinations: u64,
    reply_ratio: u64,
    cache_misses: bool,
    transition: bool,
    recovery: bool,
    bursty: bool,
    protocols: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub name: String,
    pub offered: u64,
    pub accepted: u64,
    pub rejected: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tick {
    pub at: u64,
    pub capacity: u64,
    pub offered: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub active_work: u64,
    pub completed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model {
    pub mechanism: &'static str,
    pub ticks: Vec<Tick>,
    pub offered: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub completed: u64,
    pub peak_work: u64,
    pub synthetic_destinations: u64,
    pub synthetic_request_bytes: u64,
    pub synthetic_reply_bytes: u64,
    pub cache_misses: u64,
    pub destinations: Vec<Group>,
    pub protocols: Vec<Group>,
}

fn scenario(id: &str) -> Result<Scenario, String> {
    let mut s = Scenario {
        mechanism: "",
        batch: 5,
        work: 1,
        hold: 1,
        destinations: 1,
        reply_ratio: 1,
        cache_misses: false,
        transition: false,
        recovery: false,
        bursty: false,
        protocols: match id.split('-').next() {
            Some("TCP") => &["TCP"],
            Some("UDP") => &["UDP"],
            Some("ICMP") => &["ICMP"],
            Some("DNS") => &["DNS"],
            Some("NTP") => &["NTP"],
            Some("SIP") => &["SIP"],
            Some("HTTP") => &["HTTP"],
            Some("TLS") => &["TLS"],
            _ => &["synthetic"],
        },
    };
    s.mechanism = match id {
        "TCP-028" => {
            s.hold = 4;
            "half_open_state"
        }
        "TCP-029" => {
            s.work = 2;
            "ack_classification"
        }
        "TCP-030" => {
            s.work = 3;
            "reset_state_lookup"
        }
        "TCP-031" => {
            s.hold = 3;
            "closing_state"
        }
        "TCP-032" => {
            s.hold = 6;
            "connection_table"
        }
        "UDP-013" => {
            s.batch = 12;
            "datagram_queue"
        }
        "UDP-014" => {
            s.reply_ratio = 4;
            "synthetic_udp_fanout"
        }
        "ICMP-013" => {
            s.batch = 10;
            "echo_processing"
        }
        "ICMP-014" => {
            s.destinations = 8;
            s.reply_ratio = 8;
            "synthetic_broadcast_fanout"
        }
        "DNS-017" => {
            s.batch = 9;
            "resolver_work_queue"
        }
        "DNS-018" => {
            s.reply_ratio = 3;
            "synthetic_dns_reflection"
        }
        "DNS-019" => {
            s.reply_ratio = 8;
            "synthetic_dns_amplification"
        }
        "DNS-020" => {
            s.cache_misses = true;
            s.work = 3;
            "unique_name_cache_misses"
        }
        "NTP-007" => {
            s.reply_ratio = 2;
            "synthetic_ntp_reflection"
        }
        "NTP-008" => {
            s.reply_ratio = 10;
            "synthetic_ntp_amplification"
        }
        "SIP-009" => {
            s.work = 2;
            "options_transaction_queue"
        }
        "SIP-010" => {
            s.hold = 4;
            s.work = 2;
            "invite_transaction_state"
        }
        "HTTP-021" => {
            s.batch = 10;
            "get_request_queue"
        }
        "HTTP-022" => {
            s.work = 2;
            "post_body_processing"
        }
        "HTTP-023" => {
            s.batch = 12;
            "head_request_queue"
        }
        "HTTP-024" => {
            s.work = 4;
            s.cache_misses = true;
            "dynamic_response_work"
        }
        "HTTP-025" => {
            s.hold = 8;
            "incomplete_header_slot_occupancy"
        }
        "HTTP-026" => {
            s.hold = 7;
            "slow_body_slot_occupancy"
        }
        "HTTP-027" => {
            s.batch = 8;
            s.hold = 2;
            "connection_reuse_work_model"
        }
        "HTTP-028" => {
            s.hold = 6;
            s.work = 2;
            "slow_post_work_model"
        }
        // These labels identify taxonomy entries, not reproductions of proprietary or named tools.
        "HTTP-029" => {
            s.batch = 11;
            "named_get_workload_model"
        }
        "HTTP-030" => {
            s.batch = 13;
            "named_head_workload_model"
        }
        "HTTP-031" => {
            s.batch = 7;
            s.work = 2;
            s.protocols = &["HTTP-GET", "HTTP-HEAD"];
            "named_alternating_workload_model"
        }
        "HTTP-032" => {
            s.work = 3;
            s.cache_misses = true;
            "named_uncached_workload_model"
        }
        "HTTP-033" => {
            s.batch = 16;
            s.bursty = true;
            "named_burst_workload_model"
        }
        "HTTP-034" => {
            s.work = 4;
            s.hold = 2;
            "named_https_workload_model"
        }
        "TLS-011" => {
            s.work = 4;
            "handshake_cpu_budget"
        }
        "TLS-012" => {
            s.work = 5;
            s.hold = 3;
            "repeated_negotiation_budget"
        }
        "SPECIAL-001" => {
            s.work = 3;
            s.destinations = 3;
            s.protocols = &["TCP", "UDP", "HTTP"];
            "mixed_protocol_work_queue"
        }
        "SPECIAL-002" => {
            s.destinations = 16;
            "synthetic_destination_distribution"
        }
        "SPECIAL-003" => {
            s.batch = 2;
            s.hold = 8;
            "low_rate_long_occupancy"
        }
        "SPECIAL-004" => {
            s.batch = 16;
            s.work = 2;
            "aggregate_byte_budget"
        }
        "SPECIAL-005" => {
            s.reply_ratio = 6;
            "synthetic_request_reply_ratio"
        }
        "SPECIAL-008" => {
            s.destinations = 3;
            s.transition = true;
            s.protocols = &["TCP", "UDP", "HTTP"];
            "shared_availability_budget"
        }
        "SPECIAL-009" => {
            s.transition = true;
            "capacity_transition"
        }
        "SPECIAL-010" => {
            s.recovery = true;
            s.hold = 3;
            "finite_recovery_window"
        }
        _ => return Err(format!("no event fixture implemented for {id}")),
    };
    Ok(s)
}

pub fn run(id: &str) -> Result<Model, String> {
    let s = scenario(id)?;
    let mut result = Model {
        mechanism: s.mechanism,
        ticks: Vec::new(),
        offered: 0,
        accepted: 0,
        rejected: 0,
        completed: 0,
        peak_work: 0,
        synthetic_destinations: s.destinations,
        synthetic_request_bytes: 0,
        synthetic_reply_bytes: 0,
        cache_misses: 0,
        destinations: (0..s.destinations)
            .map(|i| Group {
                name: format!("synthetic-{i}"),
                offered: 0,
                accepted: 0,
                rejected: 0,
            })
            .collect(),
        protocols: s
            .protocols
            .iter()
            .map(|name| Group {
                name: (*name).into(),
                offered: 0,
                accepted: 0,
                rejected: 0,
            })
            .collect(),
    };
    let mut active: Vec<(u64, u64)> = Vec::new();
    for at in 0..16 {
        let before = active.len();
        active.retain(|(expiry, _)| *expiry > at);
        let completed = (before - active.len()) as u64;
        let capacity = if s.transition && at >= 4 { 6 } else { 12 };
        let offered = if at >= 8 || (s.recovery && at >= 4) || (s.bursty && at % 2 == 1) {
            0
        } else {
            s.batch
        };
        let mut accepted = 0;
        let mut used: u64 = active.iter().map(|(_, work)| work).sum();
        for index in 0..offered {
            let sequence = result.offered + index;
            let destination = sequence as usize % result.destinations.len();
            let protocol = sequence as usize % result.protocols.len();
            // Mixed models share one finite budget; each protocol has a distinct work cost.
            let work = s.work + protocol as u64;
            let admitted = used + work <= capacity;
            for group in [
                &mut result.destinations[destination],
                &mut result.protocols[protocol],
            ] {
                group.offered += 1;
                if admitted {
                    group.accepted += 1;
                } else {
                    group.rejected += 1;
                }
            }
            if admitted {
                active.push((at + s.hold, work));
                used += work;
                accepted += 1;
            }
        }
        let rejected = offered - accepted;
        result.offered += offered;
        result.accepted += accepted;
        result.rejected += rejected;
        result.completed += completed;
        result.peak_work = result.peak_work.max(used);
        result.ticks.push(Tick {
            at,
            capacity,
            offered,
            accepted,
            rejected,
            active_work: used,
            completed,
        });
    }
    result.synthetic_request_bytes = result.offered * 64;
    result.synthetic_reply_bytes = result.offered * 64 * s.reply_ratio;
    result.cache_misses = if s.cache_misses { result.offered } else { 0 };
    debug_assert!(active.is_empty());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn models_conserve_events_and_release_all_resources() {
        for (family, range) in [
            ("TCP", 28..=32),
            ("UDP", 13..=14),
            ("ICMP", 13..=14),
            ("DNS", 17..=20),
            ("NTP", 7..=8),
            ("SIP", 9..=10),
            ("HTTP", 21..=34),
            ("TLS", 11..=12),
            ("SPECIAL", 1..=5),
            ("SPECIAL", 8..=10),
        ] {
            for number in range {
                let id = format!("{family}-{number:03}");
                let m = run(&id).unwrap();
                assert_eq!(m.offered, m.accepted + m.rejected, "{id}");
                assert_eq!(m.completed, m.accepted, "{id}");
                assert_eq!(m.ticks.last().unwrap().active_work, 0);
                assert_eq!(m, run(&id).unwrap());
                for groups in [&m.destinations, &m.protocols] {
                    assert_eq!(groups.iter().map(|g| g.offered).sum::<u64>(), m.offered);
                    assert_eq!(groups.iter().map(|g| g.accepted).sum::<u64>(), m.accepted);
                    assert_eq!(groups.iter().map(|g| g.rejected).sum::<u64>(), m.rejected);
                    assert!(groups.iter().all(|g| g.offered == g.accepted + g.rejected));
                }
            }
        }
        assert!(run("UNKNOWN-001").is_err());
    }
    #[test]
    fn mechanisms_affect_state_and_do_not_claim_real_defense_performance() {
        let slow = run("HTTP-025").unwrap();
        assert!(slow.rejected > run("HTTP-021").unwrap().rejected);
        let amplification = run("NTP-008").unwrap();
        assert_eq!(
            amplification.synthetic_reply_bytes,
            amplification.synthetic_request_bytes * 10
        );
        assert_eq!(run("DNS-020").unwrap().cache_misses, 40);
        let transition = run("SPECIAL-009").unwrap();
        assert_eq!(transition.ticks[3].capacity, 12);
        assert_eq!(transition.ticks[4].capacity, 6);
        assert_eq!(run("SPECIAL-002").unwrap().synthetic_destinations, 16);
        assert_eq!(run("SPECIAL-010").unwrap().ticks[4].offered, 0);
    }

    #[test]
    fn distribution_mixed_protocols_and_bursts_execute_distinct_events() {
        let distributed = run("SPECIAL-002").unwrap();
        assert_eq!(distributed.destinations.len(), 16);
        assert!(distributed.destinations.iter().all(|g| g.offered >= 2));
        for id in ["SPECIAL-001", "SPECIAL-008"] {
            let mixed = run(id).unwrap();
            assert_eq!(
                mixed
                    .protocols
                    .iter()
                    .map(|g| g.name.as_str())
                    .collect::<Vec<_>>(),
                ["TCP", "UDP", "HTTP"]
            );
            assert!(mixed.protocols.iter().all(|g| g.accepted > 0));
            assert!(mixed.rejected > 0);
        }
        let burst = run("HTTP-033").unwrap();
        for tick in &burst.ticks[..8] {
            assert_eq!(tick.offered, if tick.at % 2 == 0 { 16 } else { 0 });
        }
        let alternating = run("HTTP-031").unwrap();
        assert_eq!(
            alternating.protocols[0].offered,
            alternating.protocols[1].offered
        );
    }
}
