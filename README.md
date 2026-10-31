# ISRadar External Agent — Sender

A Rust agent for L3/L4/L7 protocol checks and offline event models. This phase covers only the sender; the target receiver belongs to a later phase. A YAML file is sufficient to run the agent; no operator approval, authorization profile, or signature file is required.

[Native Linux installation](deploy.md) · [Profile sets](docs/profiles.md) · [YAML configuration](docs/configuration.md) · [Validation status](docs/status.md) · [LLM / improvement TODO](docs/improvements.md) · [Development guide](CLAUDE.md)

[L4 test guide](docs/l4-test.md): the `l4` YAML set and `l4-test` Docker plan cover all 48 L4 entries, including TCP flag/option samples, session checks, and UDP variants.

The [UniFi test guide](docs/unifi-test.md) covers Docker tests against a real server on ports 80/443: `baseline`, `signature`, the eight-step `hacker-web`, the 16-step IPv4 `full-test`, and `all-vectors`, which accounts for 183 entries. Normal live steps use 100 probes at a target rate of 10 probes/second; SYN/SYN-ACK samples use 16 probes at 1 probe/second. `full-test` also runs one offline Slowloris model. HTTP probes can be [matched to target access logs](docs/http-log-correlation.md).

## Quick start

```sh
cargo build --release --workspace --locked
./target/release/external-agent profiles create --preset basic --directory profiles/basic
python3 scripts/local_servers.py --udp-echo
```

With the servers running, use another terminal:

```sh
./target/release/external-agent run --config profiles/basic/HTTP-001.yaml --output http-report.json
./target/release/external-agent report --input http-report.json --format json
```

To run a model without network access:

```sh
./target/release/external-agent run --config external-agent/vectors/profiles/cases/HTTP-025.yaml --output model-report.json
```

All 55 offline entries run together through `external-agent/vectors/profiles/lab.yaml`. `bash scripts/docker-lab.sh` runs the same profile in Docker and checks every result automatically. The Docker report obtained from the user's terminal recorded **55/55 completed**. [Combined lab profile](docs/profiles.md#all-55-offline-entries).

The output file must be new. `Ctrl+C`/SIGTERM stops execution, as does creating the file specified by `kill_switch` in the YAML.

## Profiles and catalog

| Set | YAML files | Contents |
| --- | ---: | --- |
| `basic` | 6 | TCP, UDP, HTTP, and the sequenced UDP sender |
| `sophisticated` | 90 | All non-raw live protocol checks, including L7 details |
| `researcher` | 183 | A separate YAML file for every catalog vector |
| `hacker` | 64 | 55 offline scenarios and 9 controlled rejection/policy checks |
| `l4` | 48 | Every TCP/UDP entry: 41 live implementations and 7 offline models |

```sh
./target/release/external-agent profiles list
./target/release/external-agent profiles create --preset researcher --directory profiles/researcher
./target/release/external-agent vectors list --layer L7
./target/release/external-agent vectors info DNS-008
./target/release/external-agent validate --config profiles/researcher/DNS-008.yaml
```

Profiles start with loopback targets. Basic TCP/UDP/HTTP fixtures are in `local_servers.py`; advanced protocols need their own test services. Edit the address, port, hostname, and protocol expectations in the YAML. [Service mappings and sequential execution](docs/profiles.md).

The catalog contains **183 entries**: L3=33, L4=48, L7=102. Of these, **128 are bounded live checks** and **55 are offline models/fixtures**; no entries contain only metadata. Some entries share a backend. Named disruptive families are offline models as specified in the project document; this is not a claim of 183 independent attack tools or vendor parity. [Per-ID matrix](docs/vector-coverage.md).

**These 55 entries have no live-network implementation.** `implemented` means that code exists for the selected mode: 41 entries are event models and 14 are packet/protocol fixtures. For example, `HTTP-025` does not open connections to a target; it calculates slot occupancy in a model. Passing an offline test says nothing about firewall behavior or actual server resilience. Linux network acceptance testing is also incomplete for the 128 entries with live code.

## Sending 1,000 UDP datagrams

```sh
./target/release/external-agent demo --directory local-demo
./target/release/external-agent run --config local-demo/delivery.yaml --output sender-report.json
```

The demo is configured for 1,000 datagrams of 64 bytes each at 10 probes/second. `await_ack: false` does not wait for a receiver. `sent` means local socket acceptance, not the number of packets observed at the target. Use a new `run_id` for each measurement; creating a new demo/profile directory generates one automatically. [Counter semantics](docs/measurement.md).

## Execution limits

Normal plans are limited to 600 seconds, 50 probes/second, 8 workers, 10,000 probes, and a 5-second probe timeout. The bandwidth field limits admission by reserving 4,096 bytes/probe; it is not actual wire traffic shaping. Raw samples require Linux/CAP_NET_RAW, 1 probe/second, one worker, and at most 16 IP samples. SIP INVITE and HTTP CONNECT are also limited to 1/second, one worker, and 16 probes.

The target is pinned to a numeric IP/port. HTTPS/TLS/QUIC certificates are validated; HTTP redirects are not followed. The engine handles cancellation, the kill switch, loss of a configured heartbeat, and health degradation. Additional protocol settings are read directly from YAML. See the [configuration guide](docs/configuration.md).

## Build and validation

```sh
python3 scripts/check_project.py
python3 scripts/check_wire.py
bash scripts/verify.sh
```

`Cargo.lock` is included. The default macOS build and tests that do not require network sockets have run; the Docker report for all 55 offline entries was also verified. Network integration tests encounter `Operation not permitted` when opening sockets in the agent environment; Linux live-network acceptance tests remain incomplete. The libpcap feature requires separate Linux validation. See the [status report](docs/status.md) for current results.

Use `python3 scripts/generate_catalog.py` and `python3 scripts/generate_profiles.py` to update the catalog and sample YAML files. An external catalog can be loaded with `--catalog`. New protocol behavior requires code and tests.
