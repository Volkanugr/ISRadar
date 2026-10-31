#!/usr/bin/env python3
"""Plan every L4 vector against explicitly configured transport services; no network I/O."""
import argparse
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path
import secrets
import sys
import uuid

sys.dont_write_bytecode = True
from generate_profiles import ROWS, config, yaml_lines
from prepare_all_vectors import summarize
from prepare_web_test import RAW_LIMITS, target_ip


def port(value):
    try:
        number = int(value)
        if 1 <= number <= 65535:
            return number
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("Port 1..65535 arasında olmalı")


def endpoint(row, version, ports):
    if row["ip_version"] is not None and row["ip_version"] != version:
        return None, f"Bu kayıt IPv{row['ip_version']} hedef gerektirir."
    backend = row["backend"]
    if backend in {"tcp_echo", "tcp_half_close", "tcp_session"}:
        key, description = "tcp_echo", "TCP echo/half-close/session servisi (--tcp-echo-port)"
    elif row["family"] == "TCP":
        key, description = "tcp", "TCP hedef portu (--tcp-port)"
    elif backend == "udp_closed_port":
        key, description = "udp_closed", "Kapalı olduğu bilinen UDP portu (--udp-closed-port)"
    elif backend == "udp_delivery":
        key, description = "udp_measurement", "Sıra numaralı UDP gönderimi için hedef port (--udp-measurement-port)"
    else:
        key, description = "udp", "UDP echo/test servisi (--udp-port)"
    return (ports[key], None) if ports.get(key) is not None else (None, description + " gerekli.")


def prepare(ip, directory, ports):
    directory.mkdir(parents=True, exist_ok=False)
    version = ipaddress.ip_address(ip).version
    rows = [row for row in ROWS if row["layer"] == "L4"]
    offline = [row for row in rows if row["mode"] == "lab_emulation"]
    lab = config(offline[0])
    lab["vectors"] = [row["id"] for row in offline]
    lab["kill_switch"] = "../STOP"
    lab["limits"].update(max_probes=len(offline), probes_per_second=10,
                         duration_seconds=30, bandwidth_bytes_per_second=65536)
    (directory / "offline-l4.yaml").write_text("\n".join(yaml_lines(lab)) + "\n")
    selected = ["offline-l4.yaml"]
    cases = {"offline-l4": {"mode": "lab_emulation", "vector_ids": lab["vectors"],
                            "layer": "L4", "target": None, "limits": lab["limits"]}}
    catalog = []
    for row in rows:
        entry = {key: row[key] for key in ("id", "name", "layer", "mode", "backend")}
        if row["mode"] == "lab_emulation":
            entry.update(status="offline_ready", config="offline-l4.yaml", expected_observations=1)
        else:
            destination_port, reason = endpoint(row, version, ports)
            if reason:
                entry.update(status="needs_configuration", config=None, reason=reason)
                catalog.append(entry)
                continue
            value = config(row)
            value["target"] = {"ip": ip, "port": destination_port, "server_name": None}
            value["kill_switch"] = "../STOP"
            value["limits"].update(duration_seconds=60, probes_per_second=10, concurrency=8,
                                   max_probes=100, bandwidth_bytes_per_second=65536, timeout_ms=3000)
            raw_cost = 2 if row["backend"] == "raw_ipv4_fragments" else 1
            if row["backend"].startswith("raw_"):
                value["limits"].update(RAW_LIMITS)
                value["limits"]["max_probes"] //= raw_cost
            if row["backend"] == "udp_delivery":
                key_path = directory / "measurement.key"
                descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w") as key_file:
                    key_file.write(secrets.token_hex(32) + "\n")
                value["measurement"] = {"run_id": uuid.uuid4().hex,
                                        "key_file": key_path.name, "await_ack": False}
            name = row["id"]
            filename = name + ".yaml"
            (directory / filename).write_text("\n".join(yaml_lines(value)) + "\n")
            cases[name] = {"vector_id": name, "mode": row["mode"], "backend": row["backend"],
                           "layer": "L4", "target": value["target"], "port": destination_port,
                           "limits": value["limits"], "raw_packet_cost": raw_cost}
            selected.append(filename)
            entry.update(status="live_ready", config=filename,
                         expected_observations=value["limits"]["max_probes"])
        catalog.append(entry)
    manifest = {"run_id": uuid.uuid4().hex, "target_ip": ip, "ports": ports,
                "l4-test": selected, "cases": cases, "catalog": catalog,
                "counts": dict(Counter(entry["status"] for entry in catalog)),
                "scope": "Every L4 ID accounted for. Seven destructive families remain offline models. Raw sent is local socket acceptance, not downstream delivery or a firewall verdict."}
    (directory / "index.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    return manifest["counts"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-ip", type=target_ip)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--server-name", help=argparse.SUPPRESS)  # Shared Docker runner; unused at L4.
    parser.add_argument("--tcp-port", type=port, default=80)
    parser.add_argument("--tcp-echo-port", type=port)
    parser.add_argument("--udp-port", type=port)
    parser.add_argument("--udp-closed-port", type=port)
    parser.add_argument("--udp-measurement-port", type=port)
    parser.add_argument("--summarize", type=Path)
    args = parser.parse_args()
    if not args.summarize and (not args.target_ip or not args.directory):
        parser.error("--target-ip and --directory are required")
    ports = {"tcp": args.tcp_port, "tcp_echo": args.tcp_echo_port, "udp": args.udp_port,
             "udp_closed": args.udp_closed_port, "udp_measurement": args.udp_measurement_port}
    try:
        print(json.dumps(summarize(args.summarize) if args.summarize else
                         prepare(args.target_ip, args.directory, ports), ensure_ascii=False))
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, f"L4 plan failed: {error}\n")
