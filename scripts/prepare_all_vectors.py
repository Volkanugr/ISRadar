#!/usr/bin/env python3
"""Account for every catalog vector; prepare only checks supported by the supplied web endpoints."""
import argparse
from collections import Counter
import ipaddress
import json
from pathlib import Path
import uuid

from generate_profiles import ROWS, config, yaml_lines
from prepare_web_test import RAW_LIMITS, RAW_TCP_IDS, target_ip, server_name

WEB_BACKENDS = {"http_get", "http_head", "http_options", "http_trace", "http_redirect", "http_headers", "http_reuse",
                "https_get", "https_head"}
TLS_BACKENDS = {"tls12", "tls13", "tls_certificate", "tls_cipher", "tls_alpn", "tls_resume"}


def pending_reason(row, version):
    if row.get("ip_version") is not None and row["ip_version"] != version:
        return "Hedefin IP sürümü bu vektörle uyumlu değil; uygun IPv4/IPv6 hedef gerekli."
    backend = row["backend"]
    if row["id"] in RAW_TCP_IDS:
        return None
    if backend.startswith("raw_"):
        return "Linux raw örneği: CAP_NET_RAW, örneğe uygun hedef/port ve hedef tarafı paket gözlemi yapılandırılmalı."
    if backend in WEB_BACKENDS | TLS_BACKENDS | {"tcp_connect", "icmp_echo"}:
        return None
    return {
        "TCP": "TCP echo/session/half-close davranışını destekleyen servis ve port gerekli.",
        "UDP": "UDP echo/kapalı-port/ölçüm servisi ve portu gerekli; UDP-010 için ölçüm kimliği ve anahtarı da gerekir.",
        "DNS": "DNS sunucusu portu, sorgu adı ve gerekiyorsa DNSSEC anchor/özel yanıt davranışı gerekli.",
        "NTP": "NTP test servisi ve portu gerekli.",
        "SIP": "SIP test servisi/transport/port ve ilgili vektör için özel test kimliği gerekli.",
        "HTTP": "Bu HTTP vektörü özel metot endpoint'i, health path'i, h2c veya HTTP/3 servis yapılandırması gerektirir.",
        "TLS": "Negatif TLS testi için ilgili sürüm/sertifika/hostname koşulunu sağlayan test endpoint'i gerekli.",
    }.get(row["family"], "Vektöre uygun test endpoint'i yapılandırılmalı.")


def prepare(ip, hostname, directory):
    directory.mkdir(parents=True, exist_ok=False)
    run_id = uuid.uuid4().hex
    version = ipaddress.ip_address(ip).version
    entries, cases, selected = [], {}, ["offline-catalog.yaml"]
    offline = [row for row in ROWS if row["mode"] == "lab_emulation"]
    lab = config(offline[0])
    lab["vectors"] = [row["id"] for row in offline]
    lab["kill_switch"] = "../STOP"
    lab["limits"].update(duration_seconds=30, probes_per_second=10, max_probes=len(offline), bandwidth_bytes_per_second=65536)
    (directory / "offline-catalog.yaml").write_text("\n".join(yaml_lines(lab)) + "\n")
    cases["offline-catalog"] = {"mode": "lab_emulation", "vector_ids": lab["vectors"],
                                "layer": "mixed", "target": None, "limits": lab["limits"]}
    for row in ROWS:
        entry = {"id": row["id"], "name": row["name"], "layer": row["layer"], "mode": row["mode"], "backend": row["backend"]}
        if row["mode"] == "lab_emulation":
            entry.update(status="offline_ready", config="offline-catalog.yaml", expected_observations=1)
        elif reason := pending_reason(row, version):
            entry.update(status="needs_configuration", config=None, reason=reason)
        else:
            value = config(row)
            backend = row["backend"]
            port = 443 if backend in TLS_BACKENDS | {"https_get", "https_head"} else 80
            if backend == "icmp_echo":
                port = 1
            value["target"] = {"ip": ip, "port": port, "server_name": hostname if backend in WEB_BACKENDS | TLS_BACKENDS else None}
            value["kill_switch"] = "../STOP"
            value["limits"].update(duration_seconds=60, probes_per_second=10, concurrency=8,
                                   max_probes=100, bandwidth_bytes_per_second=65536, timeout_ms=3000)
            if row["id"] in RAW_TCP_IDS:
                value["limits"].update(RAW_LIMITS)
            value["protocol"] = {}
            if backend in WEB_BACKENDS:
                value["protocol"]["http"] = {"path": "/", "body": "", "expected_status": None,
                    "expected_headers": {}, "dedicated_test_endpoint": False,
                    "headers": {} if backend in {"http_trace", "http_reuse"} else {"x-isradar-test": f"{run_id}-{row['id']}"}}
            filename = row["id"] + ".yaml"
            (directory / filename).write_text("\n".join(yaml_lines(value)) + "\n")
            selected.append(filename)
            cases[row["id"]] = {"mode": row["mode"], "vector_id": row["id"], "port": port,
                                "layer": row["layer"], "target": value["target"],
                                "backend": backend, "limits": value["limits"]}
            entry.update(status="live_ready", config=filename, expected_observations=value["limits"]["max_probes"])
        entries.append(entry)
    manifest = {"run_id": run_id, "target_ip": ip, "server_name": hostname,
                "all-vectors": selected, "cases": cases, "catalog": entries,
                "counts": dict(Counter(entry["status"] for entry in entries)),
                "scope": "Every catalog ID accounted for. Offline models do not transmit. Missing services are not tested or counted as passed."}
    (directory / "index.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    return manifest["counts"]


def summarize(directory):
    manifest = json.loads((directory / "configs/index.json").read_text())
    reports = {}
    results = []
    for entry in manifest["catalog"]:
        result = dict(entry)
        if entry["config"]:
            name = Path(entry["config"]).stem
            path = directory / f"{name}-report.json"
            if name not in reports:
                try:
                    reports[name] = json.loads(path.read_text())
                except (OSError, ValueError):
                    reports[name] = None
            report = reports[name]
            expected = manifest["cases"][name]
            expected_ids = expected.get("vector_ids", [expected.get("vector_id")])
            result["report"] = str(path)
            if report is None:
                result["status"] = "no_complete_report"
            elif (report.get("mode") != entry["mode"] or report.get("vector_ids") != expected_ids
                  or report.get("target") != expected["target"]):
                result["status"] = "report_mismatch"
            else:
                observations = [item for item in report["observations"] if item["vector_id"] == entry["id"]]
                result["outcomes"] = dict(Counter(item["outcome"] for item in observations))
                result["observations"] = len(observations)
                result["termination_reason"] = report["termination_reason"]
                result["status"] = ("offline_completed" if entry["mode"] == "lab_emulation" else "live_completed") if (
                    report["termination_reason"] == "completed" and len(observations) == entry["expected_observations"]
                ) else "partial_or_stopped"
        results.append(result)
    result = {"target_ip": manifest["target_ip"], "catalog_vectors": len(results),
              "counts": dict(Counter(row["status"] for row in results)), "vectors": results,
              "note": "Completed means executed; inspect outcomes. No automatic UniFi blocking attribution."}
    (directory / "catalog-results.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    return result["counts"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-ip", type=target_ip)
    parser.add_argument("--server-name", type=server_name)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--summarize", type=Path)
    args = parser.parse_args()
    if not args.summarize and not all([args.target_ip, args.server_name, args.directory]):
        parser.error("--target-ip, --server-name and --directory are required")
    try:
        print(json.dumps(summarize(args.summarize) if args.summarize else prepare(args.target_ip, args.server_name, args.directory), ensure_ascii=False))
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, f"Catalog plan failed: {error}\n")
