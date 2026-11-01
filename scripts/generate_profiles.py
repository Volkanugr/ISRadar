#!/usr/bin/env python3
"""Generate bounded, unsigned YAML cases and curated preset selections."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
from generate_catalog import entries

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "external-agent/vectors/profiles"
ROWS = entries()
CA = ROOT / "external-agent/tests/fixtures/tls/ca.der"


def config(row):
    backend = row["backend"]
    live = row["mode"] == "live_validation"
    raw = backend.startswith("raw_")
    value = {
        "vectors": [row["id"]], "mode": row["mode"], "target": None,
        "limits": {"duration_seconds": 15, "probes_per_second": 1, "concurrency": 1,
                   "bandwidth_bytes_per_second": 8192, "max_probes": 1 if raw or not live or backend in ("sip_invite", "http_connect") else 3,
                   "timeout_ms": 2000},
        "kill_switch": "STOP", "controller_lease": None, "measurement": None,
        "health": {"consecutive_failures": 3, "max_latency_ms": 3000},
    }
    if not live:
        return value
    target = {"ip": "::1" if row["ip_version"] == 6 else "127.0.0.1", "port": 9001, "server_name": None}
    value["target"] = target
    options = {}
    if row["family"] == "UDP":
        target["port"] = 9004 if backend == "udp_closed_port" else 9000
    if backend in ("tcp_echo", "tcp_session", "tcp_half_close"):
        target["port"] = 9003
    if backend == "icmp_echo":
        target["port"] = 1
    if row["family"] == "DNS":
        target.update(port=9053, server_name="missing.example" if backend == "dns_nxdomain" else "host.example")
        if backend == "dnssec":
            # RFC 8032 public test key; replace with the DNSKEY of your test zone.
            options["dnssec"] = {"zone": "example", "flags": 257,
                "public_key_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"}
    if row["family"] == "NTP":
        target["port"] = 9123
    if row["family"] == "SIP":
        target["port"] = 9061 if backend == "sip_tls" else 9060
        if backend in ("sip_invite", "sip_register"):
            options["sip"] = {"test_user": "isradar-fixture", "dedicated_test_endpoint": True,
                "expected_status": 420 if backend == "sip_invite" else 200}
    if row["family"] == "HTTP":
        target["port"] = 9002
        http = {"path": "/", "body": "", "headers": {}, "expected_status": 200,
                "expected_headers": {}, "dedicated_test_endpoint": False}
        if backend in ("http_post", "http_put", "http_patch", "http_delete", "http_connect", "http_slow_body"):
            http.update(path="/isradar-test", dedicated_test_endpoint=True)
        if backend in ("http_post", "http_put", "http_patch", "http_slow_body"):
            http["body"] = "isradar-test"
        if backend == "http_headers":
            http.update(headers={"x-isradar-test": "fixture"}, expected_headers={"x-isradar-test": "fixture"})
        if backend == "http_health":
            http["path"] = "/health"
        if backend == "http_redirect":
            http.update(path="/redirect", expected_status=302)
        if backend == "http2_get":
            target["port"] = 9080
        if backend in ("https_get", "https_head", "http3_get"):
            target["port"] = 9443
        options["http"] = http
    if row["family"] == "TLS":
        target["port"] = {"tls_negotiation_failure": 9444, "tls_expired": 9445}.get(backend, 9443)
    if row["family"] == "TLS" or backend in ("https_get", "https_head", "http3_get", "sip_tls"):
        target["server_name"] = "other.example" if backend == "tls_name_mismatch" else "validator.example"
        options["tls_ca"] = {"file": "../../../tests/fixtures/tls/ca.der", "sha256": hashlib.sha256(CA.read_bytes()).hexdigest()}
    if backend == "udp_delivery":
        value["measurement"] = {"run_id": "00000000000000000000000000000001", "key_file": "measurement.key", "await_ack": False}
    if options:
        value["protocol"] = options
    return value


def yaml_lines(value, level=0):
    prefix = " " * level
    lines = []
    for key, item in value.items():
        if isinstance(item, dict) and item:
            lines.append(f"{prefix}{key}:")
            lines.extend(yaml_lines(item, level + 2))
        else:
            lines.append(f"{prefix}{key}: {json.dumps(item, ensure_ascii=False)}")
    return lines


def high_priority_ids():
    """Use the guide's importance ratings without changing catalog execution risk."""
    ratings = {}
    for line in (ROOT / "vectors.md").read_text().splitlines():
        match = re.match(r"^\| `([A-Z]+-\d{3})` \| (?:Live|Raw|Model|Fixture) \| (Low|Medium|High) \|", line)
        if match:
            vector_id, importance = match.groups()
            if vector_id in ratings:
                raise ValueError(f"duplicate importance rating in vectors.md: {vector_id}")
            ratings[vector_id] = importance
    expected = {row["id"] for row in ROWS}
    if set(ratings) != expected:
        raise ValueError(
            "vectors.md must rate every catalog ID exactly once; "
            f"missing={sorted(expected - set(ratings))}, unknown={sorted(set(ratings) - expected)}"
        )
    selected = [row["id"] for row in ROWS if ratings[row["id"]] == "High"]
    if not selected:
        raise ValueError("vectors.md has no High-importance vectors")
    return selected


def outputs():
    basic = {"TCP-001", "UDP-001", "UDP-010", "HTTP-001", "HTTP-003", "HTTP-007"}
    negative = {"UDP-002", "DNS-007", "SIP-002", "SIP-003", "HTTP-009", "HTTP-017", "TLS-006", "TLS-009", "TLS-010"}
    presets = {
        "basic": [r["id"] for r in ROWS if r["id"] in basic],
        "sophisticated": [r["id"] for r in ROWS if r["mode"] == "live_validation" and not r["backend"].startswith("raw_")],
        "researcher": [r["id"] for r in ROWS],
        "hacker": [r["id"] for r in ROWS if r["mode"] == "lab_emulation" or r["id"] in negative],
        "l4": [r["id"] for r in ROWS if r["layer"] == "L4"],
        "high-priority": high_priority_ids(),
    }
    configs = {row["id"]: config(row) for row in ROWS}
    result = {BASE / "bundle.json": json.dumps({"schema_version": 1, "presets": presets, "configs": configs}, indent=2) + "\n"}
    offline_rows = [row for row in ROWS if row["mode"] == "lab_emulation"]
    lab = config(offline_rows[0])
    lab["vectors"] = [row["id"] for row in offline_rows]
    lab["limits"].update(duration_seconds=30, probes_per_second=10,
                         bandwidth_bytes_per_second=65536, max_probes=len(offline_rows))
    result[BASE / "lab.yaml"] = (
        "# Generated by scripts/generate_profiles.py: every offline model/fixture, once each.\n"
        + "\n".join(yaml_lines(lab)) + "\n"
    )
    for row in ROWS:
        preamble = f"# Generated by scripts/generate_profiles.py: {row['name']}\n"
        if row["backend"] == "udp_delivery":
            preamble += "# Use profiles create to generate a fresh measurement key and run_id.\n"
        result[BASE / "cases" / f"{row['id']}.yaml"] = preamble + "\n".join(yaml_lines(configs[row["id"]])) + "\n"
    return presets, result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    presets, files = outputs()
    for path, content in files.items():
        if args.check:
            assert path.read_text() == content, f"stale generated profile: {path}"
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    print(json.dumps({"profile_cases": len(ROWS), "presets": {name: len(ids) for name, ids in presets.items()}}))
