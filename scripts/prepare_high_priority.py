#!/usr/bin/env python3
"""Prepare every High-importance vector and account for missing services; no network I/O."""
import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import ipaddress
import json
from pathlib import Path
import sys
import uuid

sys.dont_write_bytecode = True
from generate_profiles import ROWS, config, high_priority_ids, yaml_lines
from prepare_all_vectors import TLS_BACKENDS, WEB_BACKENDS, pending_reason, summarize
from prepare_web_test import RAW_LIMITS, server_name, target_ip


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate settings key: {key}")
        result[key] = value
    return result


def load_services(path, rows):
    if path is None:
        return {}
    services = json.loads(path.read_text(), object_pairs_hook=unique_object)
    if not isinstance(services, dict):
        raise ValueError("services must be an object keyed by High-importance vector ID")
    live = {row["id"]: row for row in rows if row["mode"] == "live_validation"}
    for vector_id, endpoint in services.items():
        if vector_id not in live:
            raise ValueError(f"service override must select a live High-importance ID: {vector_id}")
        if not isinstance(endpoint, dict) or set(endpoint) - {"port", "server_name", "protocol"}:
            raise ValueError(f"{vector_id}: allowed endpoint fields are port, server_name, protocol")
        port = endpoint.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError(f"{vector_id}: an explicit integer port in 1..65535 is required")
        if endpoint.get("server_name") is not None:
            if not isinstance(endpoint["server_name"], str):
                raise ValueError(f"{vector_id}: server_name must be a DNS name")
            server_name(endpoint["server_name"])
        if live[vector_id]["family"] == "DNS" and not endpoint.get("server_name"):
            raise ValueError(f"{vector_id}: server_name must explicitly specify the query name")
        protocol = endpoint.get("protocol", {})
        if not isinstance(protocol, dict) or set(protocol) - {"http", "sip", "dnssec", "tls_ca"}:
            raise ValueError(f"{vector_id}: unsupported protocol settings")
        if any(not isinstance(value, dict) for value in protocol.values()):
            raise ValueError(f"{vector_id}: protocol settings must be objects")
    return services


def copy_ca(protocol, services_path, directory, vector_id):
    if "tls_ca" not in protocol:
        return
    ca = protocol["tls_ca"]
    if set(ca) - {"file", "sha256"} or not isinstance(ca.get("file"), str) or not ca["file"]:
        raise ValueError(f"{vector_id}: tls_ca requires a DER file and optional sha256")
    source = services_path.parent / ca["file"]
    with source.open("rb") as stream:
        data = stream.read(65537)
    if not data or len(data) > 65536:
        raise ValueError(f"{vector_id}: CA file must contain 1..65536 bytes")
    digest = hashlib.sha256(data).hexdigest()
    if "sha256" in ca and ca["sha256"] != digest:
        raise ValueError(f"{vector_id}: CA sha256 mismatch")
    filename = f"{vector_id}-ca.der"
    (directory / filename).write_bytes(data)
    protocol["tls_ca"] = {"file": filename, "sha256": digest}


def live_config(row, ip, hostname, run_id, endpoint):
    value = config(row)
    backend = row["backend"]
    port = 443 if backend in TLS_BACKENDS | {"https_get", "https_head"} else 80
    value["target"] = {"ip": ip, "port": port,
                       "server_name": hostname if row["family"] in {"HTTP", "TLS", "SIP"} else None}
    value["kill_switch"] = "../STOP"
    value["limits"].update(duration_seconds=60, probes_per_second=10, concurrency=8,
                           max_probes=100, bandwidth_bytes_per_second=65536, timeout_ms=3000)
    if backend.startswith("raw_") or backend in {"sip_invite", "http_connect"}:
        value["limits"].update(RAW_LIMITS)
    value["protocol"] = {}
    if backend in WEB_BACKENDS:
        value["protocol"]["http"] = {
            "path": "/", "body": "", "expected_status": None, "expected_headers": {},
            "dedicated_test_endpoint": False,
            "headers": {} if backend in {"http_trace", "http_reuse"} else
                       {"x-isradar-test": f"{run_id}-{row['id']}"},
        }
    if endpoint is not None:
        value["target"]["port"] = endpoint["port"]
        if "server_name" in endpoint:
            value["target"]["server_name"] = endpoint["server_name"]
        if "protocol" in endpoint:
            value["protocol"] = deepcopy(endpoint["protocol"])
    return value


def prepare(ip, hostname, directory, services_path=None):
    selected_ids = set(high_priority_ids())
    rows = [row for row in ROWS if row["id"] in selected_ids]
    services = load_services(services_path, rows)
    directory.mkdir(parents=True, exist_ok=False)
    run_id = uuid.uuid4().hex
    version = ipaddress.ip_address(ip).version
    offline = [row for row in rows if row["mode"] == "lab_emulation"]
    offline_name = "offline-high-priority"
    lab = config(offline[0])
    lab["vectors"] = [row["id"] for row in offline]
    lab["kill_switch"] = "../STOP"
    lab["limits"].update(duration_seconds=30, probes_per_second=10,
                         max_probes=len(offline), bandwidth_bytes_per_second=65536)
    (directory / f"{offline_name}.yaml").write_text("\n".join(yaml_lines(lab)) + "\n")
    selected = [f"{offline_name}.yaml"]
    cases = {offline_name: {"mode": "lab_emulation", "vector_ids": lab["vectors"],
                            "layer": "mixed", "target": None, "limits": lab["limits"]}}
    entries = []
    for row in rows:
        entry = {key: row[key] for key in ("id", "name", "layer", "mode", "backend")}
        entry["importance"] = "High"
        if row["mode"] == "lab_emulation":
            entry.update(status="offline_ready", config=selected[0], expected_observations=1)
        else:
            endpoint = services.get(row["id"])
            reason = pending_reason(row, version)
            wrong_version = row["ip_version"] is not None and row["ip_version"] != version
            if wrong_version or (reason and endpoint is None):
                entry.update(status="needs_configuration", config=None, reason=reason)
            else:
                value = live_config(row, ip, hostname, run_id, endpoint)
                copy_ca(value["protocol"], services_path, directory, row["id"])
                filename = row["id"] + ".yaml"
                (directory / filename).write_text("\n".join(yaml_lines(value)) + "\n")
                selected.append(filename)
                cases[row["id"]] = {
                    "mode": row["mode"], "vector_id": row["id"], "backend": row["backend"],
                    "layer": row["layer"], "target": value["target"], "limits": value["limits"],
                }
                entry.update(status="live_ready", config=filename,
                             expected_observations=value["limits"]["max_probes"])
        entries.append(entry)
    manifest = {
        "run_id": run_id, "target_ip": ip, "server_name": hostname,
        "high-priority": selected, "cases": cases, "catalog": entries,
        "counts": dict(Counter(entry["status"] for entry in entries)),
        "scope": "All High-importance IDs accounted for. Missing services remain pending. Offline entries do not transmit; sender results do not establish target passage.",
    }
    (directory / "index.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    return manifest["counts"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-ip", type=target_ip)
    parser.add_argument("--server-name", type=server_name)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--services", type=Path, help="JSON endpoint overrides keyed by live High ID")
    parser.add_argument("--summarize", type=Path)
    args = parser.parse_args()
    if not args.summarize and not all([args.target_ip, args.server_name, args.directory]):
        parser.error("--target-ip, --server-name and --directory are required")
    try:
        result = summarize(args.summarize) if args.summarize else prepare(
            args.target_ip, args.server_name, args.directory, args.services)
        print(json.dumps(result, ensure_ascii=False))
    except (OSError, ValueError, TypeError, KeyError, argparse.ArgumentTypeError) as error:
        parser.exit(1, f"High-priority plan failed: {error}\n")
