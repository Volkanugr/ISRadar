#!/usr/bin/env python3
"""Prepare bounded L3/L4/L7 checks for a numeric target with HTTP/HTTPS services; no network I/O."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
import uuid

sys.dont_write_bytecode = True
from generate_profiles import ROWS, config as catalog_config, yaml_lines

PROBES_PER_CASE = 100
RAW_TCP_IDS = {row["id"] for row in ROWS
               if row["layer"] == "L4" and row["family"] == "TCP" and row["backend"].startswith("raw_")}
RAW_LIMITS = {"probes_per_second": 1, "concurrency": 1, "max_probes": 16}
SCENARIOS = {
    "baseline": ["http-80", "https-443"],
    "signature": ["unifi-signature-80"],
    "hacker-web": ["http-80", "https-443", "http-options-80", "http-trace-80",
                   "http-redirect-80", "unifi-signature-80", "http-after-80", "https-after-443"],
}
SCENARIOS["full-test"] = [
    "l3-icmp", "l4-tcp-80", "l4-tcp-443",
    "l4-syn-80", "l4-synack-80", "l4-syn-443", "l4-synack-443",
    *SCENARIOS["hacker-web"], "offline-slowloris",
]


def target_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Sayısal hedef IP gerekli") from error
    if (address.is_unspecified or address.is_multicast or address.is_link_local
            or "%" in value
            or (address.version == 4 and (address.packed[0] == 0 or int(address) == 0xffffffff))
            or (address.version == 6 and address.ipv4_mapped is not None)):
        raise argparse.ArgumentTypeError("Geçerli bir unicast hedef IP gerekli")
    return str(address)


def server_name(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if (len(value) <= 253 and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                                     for label in value.split("."))):
            return value
    raise argparse.ArgumentTypeError("URL yerine sertifikadaki DNS alan adını yazın")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-ip", required=True, type=target_ip)
    parser.add_argument("--server-name", required=True, type=server_name)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    run_id = uuid.uuid4().hex
    cases = [
        ("l3-icmp", "ICMP-001" if ipaddress.ip_address(args.target_ip).version == 4 else "ICMP-002", 1, {}),
        ("l4-tcp-80", "TCP-001", 80, {}),
        ("l4-tcp-443", "TCP-001", 443, {}),
        ("l4-syn-80", "TCP-002", 80, {}),
        ("l4-synack-80", "TCP-003", 80, {}),
        ("l4-syn-443", "TCP-002", 443, {}),
        ("l4-synack-443", "TCP-003", 443, {}),
        ("http-80", "HTTP-001", 80, {}),
        ("https-443", "HTTP-015", 443, {}),
        ("http-options-80", "HTTP-007", 80, {}),
        ("http-trace-80", "HTTP-008", 80, {}),
        ("http-redirect-80", "HTTP-017", 80, {}),
        ("unifi-signature-80", "HTTP-001", 80, {"user-agent": "BlackSun"}),
        ("http-after-80", "HTTP-001", 80, {}),
        ("https-after-443", "HTTP-015", 443, {}),
        ("offline-slowloris", "HTTP-025", None, {}),
    ]
    metadata, skipped = {}, []
    try:
        args.directory.mkdir(parents=True, exist_ok=False)
        for name, vector, port, headers in cases:
            row = next(row for row in ROWS if row["id"] == vector)
            if vector in RAW_TCP_IDS and ipaddress.ip_address(args.target_ip).version != row["ip_version"]:
                skipped.append({"case": name, "vector_id": vector,
                                "reason": "Bu katalog kaydı IPv4 gerektirir; IPv6 hedefe gönderilmez."})
                continue
            # TRACE's existing backend requires fixed headers and no per-run marker.
            request_headers = {} if vector == "HTTP-008" else {
                "x-isradar-test": f"{run_id}-{name}", **headers,
            }
            config = {
                "vectors": [vector], "mode": "live_validation",
                "target": {"ip": args.target_ip, "port": port,
                           "server_name": args.server_name if vector.startswith("HTTP-") else None},
                "limits": {"duration_seconds": 60, "probes_per_second": 10, "concurrency": 8,
                           "bandwidth_bytes_per_second": 65536, "max_probes": PROBES_PER_CASE,
                           "timeout_ms": 3000},
                "kill_switch": "../STOP", "controller_lease": None, "measurement": None,
                "health": {"consecutive_failures": 3, "max_latency_ms": 5000},
                "protocol": {"http": {"path": "/", "body": "",
                                      "headers": request_headers,
                                      "expected_status": None, "expected_headers": {},
                                      "dedicated_test_endpoint": False}},
            }
            if not vector.startswith("HTTP-"):
                config.pop("protocol")
            if vector in RAW_TCP_IDS:
                config["limits"].update(RAW_LIMITS)
            if row["mode"] == "lab_emulation":
                config = catalog_config(row)
                config["kill_switch"] = "../STOP"
            metadata[name] = {"vector_id": vector, "port": port, "layer": row["layer"],
                              "mode": config["mode"], "backend": row["backend"],
                              "limits": config["limits"], "target": config["target"]}
            (args.directory / f"{name}.yaml").write_text("\n".join(yaml_lines(config)) + "\n")
        (args.directory / "index.json").write_text(json.dumps({
            "run_id": run_id, "target_ip": args.target_ip, "server_name": args.server_name,
            "normal_live_limits": {"max_probes": PROBES_PER_CASE, "probes_per_second": 10},
            **{scenario: [f"{case}.yaml" for case in names if case in metadata]
               for scenario, names in SCENARIOS.items()},
            "cases": metadata, "skipped_cases": skipped,
            "scope": "Bounded ICMP/TCP/HTTP checks, IPv4 SYN/SYN-ACK samples and an offline Slowloris model. Raw sent means local socket acceptance; offline execution is not live validation. Not a DDoS capacity or packet delivery test.",
            "signature_reference": "https://help.ui.com/hc/en-us/articles/360006893234-UniFi-Gateway-Intrusion-Detection-and-Prevention-IDS-IPS",
        }, indent=2) + "\n")
    except OSError as error:
        parser.exit(1, f"Profil yazılamadı: {error}\n")
    print(f"Profiller hazır: {args.directory}")


if __name__ == "__main__":
    main()
