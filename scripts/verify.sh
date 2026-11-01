#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
python3 scripts/check_project.py
python3 scripts/test_http_log_comparison.py
python3 scripts/test_docker_runner.py
python3 scripts/test_l4_profiles.py
python3 scripts/test_high_priority_profiles.py
python3 scripts/check_wire.py
if [[ ! -f Cargo.lock ]]; then cargo generate-lockfile; fi
build_options=(--workspace --locked)
if [[ "${ISRADAR_CAPTURE_CHECKS:-0}" == "1" ]]; then build_options+=(--features packet-capture); fi
cargo build "${build_options[@]}"
cargo test "${build_options[@]}" -- --include-ignored
cargo clippy --all-targets "${build_options[@]}"
