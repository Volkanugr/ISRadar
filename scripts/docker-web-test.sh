#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "Kullanım: bash scripts/docker-web-test.sh HEDEF_IP SERTIFIKA_ALAN_ADI [baseline|signature|hacker-web|full-test|all-vectors|l4-test|high-priority]" >&2
    exit 2
fi
scenario="${3:-baseline}"
case "$scenario" in
    baseline|signature|hacker-web|full-test|all-vectors|l4-test|high-priority) ;;
    *) echo "Senaryo baseline, signature, hacker-web, full-test, all-vectors, l4-test veya high-priority olmalı." >&2; exit 2 ;;
esac
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
agent_image="${ISRADAR_IMAGE:-isradar-external-agent:local}"
command -v python3 >/dev/null || { echo "Python 3 gerekli." >&2; exit 1; }
command -v docker >/dev/null || { echo "Docker CLI bulunamadı." >&2; exit 1; }

mkdir -p "$project_dir/reports"
report_dir="$(mktemp -d "$project_dir/reports/docker-web-XXXXXX")"
profile_script=prepare_web_test.py
if [[ "$scenario" == "all-vectors" ]]; then profile_script=prepare_all_vectors.py; fi
if [[ "$scenario" == "l4-test" ]]; then profile_script=prepare_l4_test.py; fi
if [[ "$scenario" == "high-priority" ]]; then profile_script=prepare_high_priority.py; fi
profile_args=(--target-ip "$1" --server-name "$2" --directory "$report_dir/configs")
if [[ "$scenario" == "high-priority" && -n "${ISRADAR_HIGH_PRIORITY_SERVICES:-}" ]]; then
    profile_args+=(--services "$ISRADAR_HIGH_PRIORITY_SERVICES")
fi
if [[ "$scenario" == "l4-test" ]]; then
    profile_args+=(--tcp-port "${ISRADAR_TCP_PORT:-80}")
    if [[ -n "${ISRADAR_TCP_ECHO_PORT:-}" ]]; then profile_args+=(--tcp-echo-port "$ISRADAR_TCP_ECHO_PORT"); fi
    if [[ -n "${ISRADAR_UDP_PORT:-}" ]]; then profile_args+=(--udp-port "$ISRADAR_UDP_PORT"); fi
    if [[ -n "${ISRADAR_UDP_CLOSED_PORT:-}" ]]; then profile_args+=(--udp-closed-port "$ISRADAR_UDP_CLOSED_PORT"); fi
    if [[ -n "${ISRADAR_UDP_MEASUREMENT_PORT:-}" ]]; then profile_args+=(--udp-measurement-port "$ISRADAR_UDP_MEASUREMENT_PORT"); fi
fi
python3 "$project_dir/scripts/$profile_script" "${profile_args[@]}"
if [[ "$scenario" == "high-priority" ]]; then
    # Preserve an all-ID summary even after validation failure, STOP or a failed case.
    summarize_high_priority() {
        local run_status=$?
        trap - EXIT
        if ! python3 "$project_dir/scripts/$profile_script" --summarize "$report_dir"; then
            if [[ "$run_status" == "0" ]]; then run_status=1; fi
        fi
        printf 'Rapor ve loglar: %s\n' "$report_dir"
        exit "$run_status"
    }
    trap summarize_high_priority EXIT
fi
python3 - "$report_dir/configs/index.json" "$scenario" >"$report_dir/selected-cases.tsv" <<'PY'
import json
from pathlib import Path
import sys

manifest = json.loads(Path(sys.argv[1]).read_text())
for name in manifest[sys.argv[2]]:
    name = Path(name).stem
    case = manifest["cases"][name]
    kind = ("offline" if case["mode"] == "lab_emulation" else
            "raw" if case.get("backend", "").startswith("raw_") else
            "icmp" if case.get("backend") == "icmp_echo" else "live")
    print(name, kind, case["limits"]["max_probes"], case["limits"]["probes_per_second"], sep="\t")
if sys.argv[2] == "full-test":
    for case in manifest.get("skipped_cases", []):
        print(f"Atlandı: {case['case']} — {case['reason']}", file=sys.stderr)
for entry in manifest.get("catalog", []):
    if entry["status"] == "needs_configuration":
        print(f"Yapılandırma bekliyor: {entry['id']} — {entry['reason']}", file=sys.stderr)
PY
cases=()
needs_raw=0
while IFS=$'\t' read -r case_name case_kind case_count case_rate; do
    cases+=("$case_name")
    if [[ "$case_kind" == "raw" ]]; then needs_raw=1; fi
done <"$report_dir/selected-cases.tsv"
printf 'Senaryo: %s | adım: %s | live/icmp=canlı, raw=ham paket örneği, offline=çevrimdışı\n' "$scenario" "${#cases[@]}"
printf 'Rapor dizini: %s\nDurdurmak için: touch "%s/STOP"\n' "$report_dir" "$report_dir"
if [[ "$needs_raw" == "1" ]]; then
    # Raw-only containers use UID 0 with just NET_RAW. Give their primary group
    # read/traverse access to new configs and STOP; the mount stays read-only.
    chgrp "$(id -g)" "$report_dir" "$report_dir/configs" "$report_dir"/configs/*.yaml
    chmod g+rx "$report_dir" "$report_dir/configs"
    chmod g+r "$report_dir"/configs/*.yaml
fi
docker info >/dev/null
docker build --tag "$agent_image" "$project_dir"
docker_args=(--rm --cap-drop ALL --read-only --security-opt no-new-privileges=true
    --user "$(id -u):$(id -g)" --mount "type=bind,source=$report_dir,target=/data")

# Validate every selected case without network access before the first live request.
for case_name in "${cases[@]}"; do
    docker run "${docker_args[@]}" --network none "$agent_image" \
        validate --config "/data/configs/$case_name.yaml" >"$report_dir/$case_name-validation.log" 2>&1 || {
        cat "$report_dir/$case_name-validation.log" >&2
        exit 1
    }
done

while IFS=$'\t' read -r case_name case_kind case_count case_rate; do
    if [[ -e "$report_dir/STOP" ]]; then
        echo "STOP mevcut; sonraki teste geçilmedi." >&2
        exit 130
    fi
    printf 'Çalışıyor: %s | %s | en fazla %s deneme | hedef %s/s\n' "$case_name" "$case_kind" "$case_count" "$case_rate"
    # Bash 3.2 treats an empty array as unset under set -u. Keep one nonempty
    # argument array per invocation, with the ICMP-only option appended below.
    run_args=("${docker_args[@]}")
    if [[ "$case_kind" == "icmp" ]]; then
        # Permit ICMP echo datagram sockets only for this container's user group.
        run_args+=(--sysctl "net.ipv4.ping_group_range=$(id -g) $(id -g)")
    fi
    network_mode=bridge
    if [[ "$case_kind" == "offline" ]]; then network_mode=none; fi
    if [[ "$case_kind" == "raw" ]]; then
        # Export the actual report over stdout so no root-owned host files are
        # created. No extra DAC/CHOWN/SETUID capabilities or writable bind mount.
        if ! docker run --rm --cap-drop ALL --cap-add NET_RAW --read-only \
            --security-opt no-new-privileges=true --user "0:$(id -g)" --workdir /tmp \
            --mount "type=bind,source=$report_dir,target=/data,readonly" \
            --tmpfs /tmp:rw,noexec,nosuid,size=16m,mode=0700 --network bridge \
            --entrypoint /bin/sh "$agent_image" -c \
            'external-agent run --config "$1" --output /tmp/report.json >/tmp/summary.json && cat /tmp/report.json' \
            isradar-raw "/data/configs/$case_name.yaml" \
            >"$report_dir/$case_name-report.json" 2>"$report_dir/$case_name-audit.jsonl"; then
            cat "$report_dir/$case_name-audit.jsonl" >&2
            exit 1
        fi
    elif ! docker run "${run_args[@]}" --network "$network_mode" "$agent_image" \
        run --config "/data/configs/$case_name.yaml" --output "/data/$case_name-report.json" \
        >"$report_dir/$case_name-summary.json" 2>"$report_dir/$case_name-audit.jsonl"; then
        cat "$report_dir/$case_name-audit.jsonl" >&2
        exit 1
    fi
    python3 - "$report_dir/$case_name-report.json" "$report_dir/$case_name-summary.json" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

path = Path(sys.argv[1])
report = json.loads(path.read_text())
metrics = report["metrics"]
summary = {
    "report": str(path), "termination_reason": report["termination_reason"],
    "mode": report["mode"], "vector_ids": report["vector_ids"],
    "network_evidence": ("none: offline model/fixture" if report["mode"] == "lab_emulation" else
                         "sender observations; target delivery requires independent evidence"),
    "probes_planned": report["requested_limits"]["max_probes"],
    "probes_started": metrics["probes_started"], "probes_completed": metrics["probes_completed"],
    "probes_cancelled": metrics["probes_cancelled"],
    "target_probes_per_second": report["requested_limits"]["probes_per_second"],
    "actual_probes_per_second": metrics["actual_probes_per_second"],
    "responses_received": metrics["responses_received"],
    "tcp_handshake_successes": metrics["tcp_handshake_successes"],
    "raw_ip_packets_accepted": metrics.get("raw_ip_packets_accepted", 0),
    "tagged_http_probes": len(report.get("http_probes", [])),
    "http_responses_received": metrics["http_responses_received"],
    "http_statuses": dict(Counter(str(item["http_status"]) for item in report["observations"]
                                  if item.get("http_status") is not None)),
    "outcomes": dict(Counter(item["outcome"] for item in report["observations"])),
    "unifi_blocking": ("not tested: offline" if report["mode"] == "lab_emulation" else
                       "requires matching UniFi log evidence"),
}
serialized = json.dumps(summary, ensure_ascii=False)
Path(sys.argv[2]).write_text(serialized + "\n")
print(serialized)
if report["termination_reason"] in ("cancelled", "kill_switch", "kill_switch_unreadable"):
    sys.exit(130)
PY
done <"$report_dir/selected-cases.tsv"
if [[ "$scenario" == "all-vectors" || "$scenario" == "l4-test" ]]; then
    python3 "$project_dir/scripts/$profile_script" --summarize "$report_dir"
fi
if [[ "$scenario" != "high-priority" ]]; then printf 'Rapor ve loglar: %s\n' "$report_dir"; fi
