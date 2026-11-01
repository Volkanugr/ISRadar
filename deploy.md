# Linux deployment — no Docker required

This guide covers installation directly from the Rust binary on Ubuntu 24.04 / Debian 12. Run commands from the project root (the directory containing `Cargo.toml`). A binary built on macOS will not run on Linux; copy the project to the Linux machine and build it there.

## 1. Prerequisites and build

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config ca-certificates curl python3 iputils-ping
```

If Rust is not installed on the Linux machine, install it as a normal user:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
rustup component add rustfmt clippy
```

If Rust is already installed, check it with `rustc --version` and `cargo --version`. Installation source: [official Rust guide](https://rust-lang.org/tools/install/).

```sh
cargo build --release --workspace --locked
./target/release/external-agent --version
./target/release/external-agent vectors coverage
bash scripts/verify.sh
```

`Cargo.lock` is included; do not regenerate it during release installation. The first build needs internet access to download dependencies. Tests open local TCP/UDP sockets and include the 1,000-datagram test. Do not consider the installation validated until `verify.sh` completes successfully.

Install the binary:

```sh
sudo install -m 0755 target/release/external-agent /usr/local/bin/external-agent
external-agent vectors list --layer L4
```

## 2. First run

Start by running the example models without network access:

```sh
report_dir="$(mktemp -d)"
external-agent run --config external-agent/vectors/profiles/lab.yaml --output "$report_dir/lab.json"
external-agent report --input "$report_dir/lab.json" --format json
```

For local TCP/UDP/HTTP checks, start the test servers in one terminal:

```sh
python3 scripts/local_servers.py --udp-echo
```

In a second terminal, create the loopback example:

```sh
demo_dir="$(mktemp -d)/demo"
external-agent demo --directory "$demo_dir"
external-agent validate --config "$demo_dir/http.yaml"
external-agent run --config "$demo_dir/http.yaml" \
  --output "$demo_dir/http-report.json" 2>"$demo_dir/http-audit.jsonl"
```

Use `delivery.yaml` in the same directory to send 1,000 sequenced UDP datagrams:

```sh
external-agent run --config "$demo_dir/delivery.yaml" \
  --output "$demo_dir/sender-report.json" 2>"$demo_dir/sender-audit.jsonl"
```

This profile uses 10 probes/second for about 100 seconds, with a total duration limit of 150 seconds. It does not wait for ACKs/a receiver. `sent` means the local socket accepted the datagram, not the number of packets delivered to the target. Generate a new `run_id`/key for each new UDP measurement. A new demo directory generates them automatically.

`Ctrl+C` stops execution. To use the kill switch, create `STOP` in the directory printed by the demo command from another terminal. Reports never overwrite existing files; use a new output filename for each run.

## 3. Select a profile and configure the target

```sh
external-agent profiles create --preset researcher --directory profiles/researcher
external-agent run --config profiles/researcher/HTTP-001.yaml --output report-001.json
```

Available sets are `basic`, `sophisticated`, `researcher`, `hacker`, and `l4`. `researcher` generates YAML for all 184 entries; `l4` covers all 49 L4 entries. Advanced protocols need suitable services; the [profile guide](docs/profiles.md) describes default ports and expectations.

For a real test, edit `target.ip`, `port`, and, where needed, `server_name` and `protocol` in the selected YAML. No separate operator approval, signature, authorization key, or authorization file is required:

```sh
external-agent validate --config test.yaml
external-agent run --config test.yaml --output report-001.json 2>audit-001.jsonl
external-agent report --input report-001.json --format json
```

Relative file paths in YAML are resolved against the YAML directory. [Configuration examples](docs/configuration.md).

## 4. Optional systemd installation

Each service start runs one bounded test. A persistent daemon or automatic restart is not required.

```sh
sudo useradd --system --user-group --home-dir /var/lib/isradar --shell /usr/sbin/nologin isradar
sudo install -d -o root -g isradar -m 0750 /etc/isradar
sudo install -d -o isradar -g isradar -m 0750 /var/lib/isradar
sudo install -o root -g isradar -m 0640 test.yaml /etc/isradar/
```

Skip `useradd` if the user already exists. Set `kill_switch` to `/var/lib/isradar/STOP` in the YAML. For UDP-010, also install the `measurement.key_file` under `/etc/isradar/` with the same permissions and set its path in YAML. If using a custom CA/heartbeat, ensure the service user can read the files. Demo YAML files contain absolute paths; moving them does not update paths automatically.

```sh
sudo tee /etc/systemd/system/isradar@.service >/dev/null <<'EOF'
[Unit]
Description=ISRadar bounded sender run %i
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=isradar
Group=isradar
WorkingDirectory=/var/lib/isradar
ExecStartPre=/usr/local/bin/external-agent validate --config /etc/isradar/test.yaml
ExecStart=/usr/local/bin/external-agent run --config /etc/isradar/test.yaml --output /var/lib/isradar/report-%i.json
TimeoutStartSec=650
TimeoutStopSec=10
Restart=no
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/isradar
CapabilityBoundingSet=
EOF
sudo systemctl daemon-reload
run_instance="$(cat /proc/sys/kernel/random/uuid)"
sudo systemctl start --no-block "isradar@$run_instance"
sudo journalctl -u "isradar@$run_instance" -f
```

The report is written to `/var/lib/isradar/report-<run_instance>.json`; JSON audit logs go to the journal. It is normal for the oneshot service to become `inactive` after completion. Use a new instance name for each run and a new `run_id` for each UDP measurement. [systemd service behavior](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html).

```sh
sudo systemctl stop "isradar@$run_instance"
# Alternatively, activate the kill switch shared by these agents.
sudo touch /var/lib/isradar/STOP
```

New tests also stop while `STOP` exists; remove it only when ready to resume. Exit code 0 alone does not indicate protocol success; inspect `termination_reason`, errors/timeouts, and observation outcomes in the report. This installation shares one configuration; do not start separate instances concurrently.

## 5. Raw packet and libpcap options

Standard TCP/UDP/HTTP/TLS checks do not require root. Raw samples require `CAP_NET_RAW` on Linux; the systemd service above does not have this capability by default. ICMP echo uses the system `ping` utility and depends on Linux ping socket permissions.

For raw samples or Linux packet capture, use `sudo systemctl edit isradar@.service` to add the following settings, then run `sudo systemctl daemon-reload`:

```ini
[Service]
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
```

This capability applies to all instances of the service. The YAML target, protocol settings, and raw sample quotas still apply. Raw runtime behavior must be validated separately on the relevant Linux test network.

To include libpcap egress observation in the binary:

```sh
sudo apt-get install -y libpcap-dev pkg-config
ISRADAR_CAPTURE_CHECKS=1 bash scripts/verify.sh
cargo build --release --workspace --locked --features packet-capture
sudo install -m 0755 target/release/external-agent /usr/local/bin/external-agent
```

Set the capture interface through `protocol.capture.interface`. Egress observation does not replace a target receiver. If copying the binary to another machine, its Linux architecture and runtime libraries must match the destination; building on the target Linux machine is the simplest approach.

Docker on Mac is not required for this workflow. The existing `Dockerfile` can also run Linux tests in a container on Mac; the installation described above uses the Linux binary directly. Current validation limitations: [status report](docs/status.md).

## 6. All 55 offline entries in Docker

With Docker Desktop installed and running, and Python 3 available on the host, run from the project root:

```sh
bash scripts/docker-lab.sh
```

The script builds an image from the existing Dockerfile and runs all 55 entries through `lab.yaml`. The first build uses the internet to download the base image/packages. The lab run starts with `--network none`; this Docker network mode creates only a loopback interface. [Docker network mode documentation](https://docs.docker.com/engine/network/drivers/none/).

Each run stores `lab.yaml`, `report.json`, `summary.json`, and `audit.jsonl` under `reports/docker-lab-XXXXXX/`. The container uses the host user's UID/GID so your normal user can read the reports. `check_lab_report.py` checks that all offline results are present and network counters are zero; otherwise the script fails. Cancel with `Ctrl+C` or create `STOP` in the report directory.

This command tests 41 event models and 14 fixtures; live protocol integrations are separate tests. The report from the user's Docker run on 2026-10-30 was checked: **55/55 completed** in **5.53 seconds**, with errors/timeouts and network counters at **0**. Evidence directory: `reports/docker-lab-ZE8HI2/`; details are in the [validation report](docs/status.md#docker-lab-result--2026-10-30). This result does not replace live protocol integration tests.

## 7. Live port 80/443 tests in Docker

```sh
bash scripts/docker-web-test.sh TARGET_IP test.example.com baseline
bash scripts/docker-web-test.sh TARGET_IP test.example.com signature
bash scripts/docker-web-test.sh TARGET_IP test.example.com hacker-web
bash scripts/docker-web-test.sh TARGET_IP test.example.com full-test
bash scripts/docker-web-test.sh TARGET_IP test.example.com all-vectors
bash scripts/docker-web-test.sh TARGET_IP test.example.com l4-test
```

Replace placeholders with your target. The first command targets 100 HTTP GETs followed by 100 HTTPS GETs; the second targets 100 GETs on port 80 with the documented UniFi User-Agent header. Normal live steps target 10 requests/second, at most 8 workers, and a 60-second duration; health checks may stop them early. Each run has a separate report directory. Docker bridge networking provides target access. For target placement, certificates, UniFi settings, and interpretation, see the [UniFi test guide](docs/unifi-test.md).

`hacker-web` runs eight steps sequentially: initial HTTP/HTTPS access, OPTIONS, TRACE, redirects, the User-Agent signature, and final HTTP/HTTPS access. It targets 100 requests per step, at most 800 total. It differs from the CLI's 64-entry `hacker` preset; this web scenario does not execute offline models.

IPv4 `full-test` runs 16 steps: 11 normal live steps (ICMP, TCP 80/443, eight web steps), four SYN/SYN-ACK sample steps (80/443), and one offline Slowloris model. Normal steps target at most 1,100 probes total; raw steps target 64 packet samples total. Each raw step is limited to 16 samples, 1/second, and one worker. On IPv6 targets, IPv4 raw entries are skipped with explicit reasons, leaving 12 steps.

`all-vectors` accounts for all 184 catalog IDs: for IPv4, 47 live checks (26 normal + 21 raw TCP) and 55 offline entries can run; the other 82 await configuration. IPv6 counts are 26/55/103. Raw TCP samples in this set target port 80; use `full-test` for SYN/SYN-ACK on both ports. Pending reasons are in `configs/index.json`, and results are in `catalog-results.json`. Offline steps use `--network none`. ICMP ping group permissions are set only inside the container's network namespace.

`l4-test` accounts for all 49 L4 IDs; TCP flag/option samples and connection checks default to port 80. TCP echo/UDP checks accept separate service ports. A fully configured IPv4 plan has 40 live entries, 7 offline entries, and 2 awaiting an IPv6 target. [L4 usage guide](docs/l4-test.md).

Raw steps run as container UID 0 with only the `NET_RAW` capability; the configuration directory is read-only, and the report is generated in temporary memory and transferred to a file owned by the host user. Other steps use the host UID/GID and `--cap-drop ALL`. `--privileged` is unnecessary. `sent`/`raw_ip_packets_accepted` mean local socket acceptance; target delivery requires a target packet capture. Slowloris is only an offline model here.

To count HTTP probes reaching the target, [match identities from the new report against server access logs](docs/http-log-correlation.md). Identities are not retroactively added to old reports.
