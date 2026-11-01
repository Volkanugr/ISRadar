# Working on ISRadar External Agent

## Purpose and scope

ISRadar is a Rust sender for bounded network protocol validation across L3, L4, and L7. It helps operators examine how configured services and network protections handle probes. This phase provides the sender, YAML profiles, offline models, and JSON reports. A target receiver, central controller, dashboard, database, and multi-node orchestration are outside the current phase.

Read [README.md](README.md) for usage, the [product specification](MazeBolt_DDoS_Trafik_Ajani_Promptu.md) for intended scope, and [docs/status.md](docs/status.md) for implementation and validation evidence. The specification's example directory tree is conceptual; the source map below describes the actual layout.

The catalog has 184 entries: 33 L3, 49 L4, and 102 L7. It contains 129 bounded live checks and 55 offline entries (41 event models and 14 packet/protocol fixtures). L4 contains 42 live implementations and 7 offline models. `implemented` means code exists for the declared mode; it does not mean live-network verification, an independent attack implementation, or vendor parity. Offline entries have no live-network implementation.

## Stack and source map

The workspace contains one Rust 2021 crate, `external-agent`, using stable Rust, Tokio, Clap, Serde, and Tracing. Linux is the primary runtime; macOS supports development and non-raw checks. Python scripts use the standard library. Default Cargo features are empty.

| Path | Responsibility |
| --- | --- |
| `external-agent/src/main.rs` | CLI, JSON output, report creation, and cancellation signals |
| `external-agent/src/config.rs` | YAML loading, configuration validation, and relative paths |
| `external-agent/src/settings.rs` | Protocol-specific settings and validation |
| `external-agent/src/engine/mod.rs` | Whole-plan validation, scheduling, workers, quotas, cancellation, and health stops |
| `external-agent/src/safety/` | Admission limits, kill switch, and controller heartbeat |
| `external-agent/src/vectors/registry.rs` | Metadata, backends, and catalog validation |
| `external-agent/src/vectors/mod.rs` and `protocols.rs` | `TrafficVector` interface and execution dispatch |
| `external-agent/src/vectors/event_models.rs` and `lab.rs` | Offline models and fixture dispatch |
| `external-agent/src/network/` | Protocol codecs, transports, raw sample builders, and optional capture |
| `external-agent/src/results/mod.rs` | Observations, metrics, and reports |
| `external-agent/src/measurement.rs` | Authenticated UDP frames and the feature-gated receiver prototype |
| `external-agent/src/profiles.rs` | CLI preset creation from the generated bundle |
| `external-agent/vectors/` | Generated catalog and profiles |
| `external-agent/tests/` | Integration tests and local protocol/certificate fixtures |
| `scripts/` | Generators, validators, planners, Docker runners, and log comparison |
| `.github/workflows/check.yml` | Linux CI |

`packet-capture` enables libpcap and requires its Linux development libraries. `experimental-receiver` exposes a prototype excluded from the default binary, Docker image, and current acceptance scope.

## Build and validation

Run commands from the repository root. Keep the existing `Cargo.lock`; use `--locked` for normal builds and tests.

```sh
cargo build --workspace --locked
cargo fmt --all -- --check
python3 scripts/check_project.py
python3 scripts/test_http_log_comparison.py
python3 scripts/test_docker_runner.py
python3 scripts/test_l4_profiles.py
python3 scripts/check_wire.py
cargo test --workspace --locked --lib --test profiles
cargo clippy --workspace --all-targets --locked -- -D warnings
```

For the complete suite on a machine with local TCP/UDP socket access:

```sh
bash scripts/verify.sh
```

On Linux with `libpcap-dev` and `pkg-config`, include capture validation:

```sh
ISRADAR_CAPTURE_CHECKS=1 bash scripts/verify.sh
```

Mock-Docker tests never contact Docker or a network; their synthetic reports are not live evidence. `check_wire.py` runs a subset of existing Rust tests, so do not double-count it as distinct coverage. Native raw validation on macOS is expected to reject execution because it requires Linux. If socket access, dependencies, or Docker access are unavailable, report affected checks as incomplete, not passed.

## Generated artifacts

Edit generator sources, then regenerate and check their outputs:

```sh
python3 scripts/generate_catalog.py
python3 scripts/generate_profiles.py
python3 scripts/check_project.py
```

- `scripts/generate_catalog.py` owns `external-agent/vectors/catalog.yaml` and `docs/vector-coverage.md`.
- `scripts/generate_profiles.py` owns `external-agent/vectors/profiles/bundle.json`, `lab.yaml`, and `cases/*.yaml`.
- `scripts/prepare_web_test.py`, `prepare_all_vectors.py`, and `prepare_l4_test.py` create per-run plans and manifests in new directories.

Do not hand-edit generated files as the only change. Catalog test references must name actual test functions. Keep backend mappings, preset membership, coverage counts, and documentation consistent. Metadata alone does not implement a protocol.

## Execution and profiles

The workflow is `run --config ... --output ...`; the engine validates the plan automatically. There is no operator approval, signature, authorization profile, or trusted-key workflow. Do not reintroduce one. UDP measurement HMAC keys and DNSSEC signatures validate protocol evidence and are separate from execution approval.

```sh
./target/debug/external-agent profiles list
./target/debug/external-agent profiles create --preset l4 --directory profiles/l4
./target/debug/external-agent vectors info TCP-002
./target/debug/external-agent validate --config profiles/l4/TCP-001.yaml
```

Presets are `basic`, `sophisticated`, `researcher`, `hacker`, and `l4`. They default to loopback. Service-dependent checks need matching endpoints; missing UDP/echo services must not be silently directed to HTTP ports. Configuration validation does not establish target availability.

The Docker runner supports `baseline`, `signature`, `hacker-web`, `full-test`, `all-vectors`, and `l4-test`. `hacker-web` differs from the CLI's `hacker` preset. See [profiles](docs/profiles.md), [L4 tests](docs/l4-test.md), and [UniFi tests](docs/unifi-test.md) for selection, ports, and current plan counts. [Native Linux deployment](deploy.md) is supported; Docker is optional.

## Existing execution contracts

- Targets are explicit numeric IP/port pairs. Hostnames supply protocol metadata such as Host, SNI, or DNS qname; they do not change the socket target.
- Normal engine limits are 600 seconds, 50 probes/second, 8 workers, 10,000 probes, and a 5-second probe timeout. Profile defaults can be lower.
- Raw execution requires Linux/CAP_NET_RAW and is limited to 1 probe/second, one worker, 16 total IP packet samples, and 60 seconds. Fragment probes consume two samples. Raw TCP checks reserve a fresh tuple rather than targeting existing sessions.
- SIP INVITE and HTTP CONNECT are limited to 1/second, one worker, at most 16 probes, and 60 seconds.
- Preserve cancellation, STOP, configured heartbeat expiry, and health-stop behavior. Live and offline vectors are not mixed in one engine plan.
- Preserve TLS certificate validation, fixed targets, and bounded protocol parsing. HTTP redirects are not followed.
- Disruptive families remain offline models or fixtures under the product specification. Do not relabel an offline model as a live implementation or a low-volume sample as a flood-capacity test.

Docker raw steps use only NET_RAW, a read-only configuration mount, and tmpfs report output transferred to the host user. Other steps do not inherit raw capabilities. Do not introduce `--privileged` as a workaround. Keep shell scripts compatible with macOS Bash 3.2, including its empty-array behavior under `set -u`.

## Reports and evidence

Use new report files and preserve historical runs under `reports/`. Audit events go to stderr. Exit code 0 means a report was written, not that every probe succeeded. Inspect `termination_reason`, observations, and counters.

`sent` and `raw_ip_packets_accepted` indicate local socket acceptance, not target delivery or firewall traversal. TCP connections, HTTP requests, and TLS handshakes are not individual packets. Do not invent wire counts or infer UniFi blocking from timeouts, resets, or missing responses. Delivery requires independent target evidence; UniFi attribution requires matching UniFi events.

Supported HTTP probes carry an engine-generated `X-Isradar-Probe` identity. Preserve admitted identities across timeout/cancellation and do not allow YAML to override the header. `scripts/compare_http_logs.py` supports documented JSONL/IIS W3C logs. See [measurement](docs/measurement.md) and [HTTP log correlation](docs/http-log-correlation.md) for exact fields and limitations.

## Documentation maintenance

Keep Markdown documentation in English. Preserve CLI flags, vector IDs, report field names, evidence paths, and protocol identifiers when editing prose. Update heading links when headings change. The English product specification retains its existing filename for link compatibility.

Document code availability, offline execution, local tests, and live-network validation separately. Consult [validation status](docs/status.md) before making completion claims. LLM integration remains a [proposal](docs/improvements.md), not an implemented runtime component.
