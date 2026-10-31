#!/usr/bin/env python3
"""Verify complete offline coverage and zero observed network activity in a lab report."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from generate_catalog import entries


def check(report):
    expected = Counter(row["id"] for row in entries() if row["mode"] == "lab_emulation")
    errors = []
    if report.get("mode") != "lab_emulation" or report.get("target") is not None:
        errors.append("expected an offline report with no target")
    if report.get("termination_reason") != "completed":
        errors.append("run did not complete")
    if Counter(report.get("vector_ids", [])) != expected:
        errors.append("plan does not contain every offline vector exactly once")
    observations = report.get("observations", [])
    if Counter(item.get("vector_id") for item in observations) != expected:
        errors.append("observations are missing, duplicated, or contain unexpected vectors")
    if any(item.get("outcome") != "simulated" or not item.get("simulated_events", 0)
           for item in observations):
        errors.append("every observation must contain a successful simulated event/fixture")
    metrics = report.get("metrics", {})
    for field in ("probes_started", "probes_completed"):
        if metrics.get(field) != sum(expected.values()):
            errors.append(f"incorrect {field}")
    for field in ("probes_cancelled", "timeouts", "network_errors", "protocol_errors", "remote_rejections",
                  "application_datagrams_sent", "application_datagrams_received", "application_bytes_sent",
                  "application_bytes_received", "raw_ip_packets_accepted", "raw_ip_bytes_accepted",
                  "responses_received", "tcp_handshake_successes", "http_responses_received"):
        if metrics.get(field) != 0:
            errors.append(f"expected zero {field}")
    if report.get("delivery") is not None or report.get("outbound_capture") is not None:
        errors.append("offline report must not contain delivery or capture evidence")
    if errors:
        raise ValueError("; ".join(errors))
    return {"verified_offline_vectors": sum(expected.values()), "termination_reason": "completed",
            "network_counters": 0, "scope": "offline execution coverage, not live-network validation"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(check(json.loads(args.report.read_text()))))
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, f"Lab report verification failed: {error}\n")
