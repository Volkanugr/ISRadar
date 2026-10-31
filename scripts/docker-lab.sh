#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
agent_image="${ISRADAR_IMAGE:-isradar-external-agent:local}"

command -v docker >/dev/null || { echo "Docker CLI bulunamadı; Docker kurulumunu tamamlayın." >&2; exit 1; }
command -v python3 >/dev/null || { echo "Rapor kontrolü için Python 3 gerekli." >&2; exit 1; }
docker info >/dev/null
python3 "$project_dir/scripts/generate_profiles.py" --check

# A unique directory preserves earlier runs and keeps the container's STOP path writable.
mkdir -p "$project_dir/reports"
report_dir="$(mktemp -d "$project_dir/reports/docker-lab-XXXXXX")"
cp "$project_dir/external-agent/vectors/profiles/lab.yaml" "$report_dir/lab.yaml"
docker build --tag "$agent_image" "$project_dir"

if ! docker run --rm --network none --cap-drop ALL --read-only \
    --security-opt no-new-privileges=true --user "$(id -u):$(id -g)" \
    --mount "type=bind,source=$report_dir,target=/data" \
    "$agent_image" run --config /data/lab.yaml --output /data/report.json \
    >"$report_dir/summary.json" 2>"$report_dir/audit.jsonl"; then
    cat "$report_dir/audit.jsonl" >&2
    exit 1
fi
python3 "$project_dir/scripts/check_lab_report.py" "$report_dir/report.json"
printf 'Rapor ve loglar: %s\n' "$report_dir"
