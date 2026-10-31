# Ready-to-use test profiles

```sh
external-agent profiles create --preset basic --directory profiles/basic
external-agent run --config profiles/basic/HTTP-001.yaml --output http-report.json
```

Creating a set only writes files. Each YAML in these sets runs one vector; inspect its name with `vectors info HTTP-001`. A new directory is required; existing files are not modified. All sets default to loopback targets; edit the YAML target/protocol fields to use your own test service. No signature or operator approval is required.

| Set | Files | Purpose |
| --- | ---: | --- |
| `basic` | 6 | TCP-001, UDP-001/010, HTTP-001/003/007 |
| `sophisticated` | 90 | All non-raw live checks: HTTP/1.1/2/3, TLS, DNS, NTP, SIP, and session variants |
| `researcher` | 183 | Every catalog entry, including Linux raw samples and offline scenarios |
| `hacker` | 64 | 55 offline event/malformed-packet scenarios; closed UDP port, NXDOMAIN, SIP policy, CONNECT/redirect, and negative TLS checks |
| `l4` | 48 | All L4 entries: 41 live TCP/UDP implementations and 7 offline models |

Set names select coverage; they do not increase rates or quotas. Normal files use 1 probe/second, one worker, and 3 probes; raw/INVITE/CONNECT and offline files use 1 probe. Each file runs for at most 15 seconds. For the 1,000-datagram UDP example, use `delivery.yaml` created by `external-agent demo --directory local-demo`.

For a real server on ports 80/443, `prepare_web_test.py` generates eight web YAML files, three ICMP/TCP files, four SYN/SYN-ACK files for IPv4 targets, and one offline Slowloris file. Select `baseline`, `signature`, `hacker-web`, or `full-test` in the Docker script. Normal live steps use 100 probes at a target rate of 10 probes/second; raw steps use at most 16 samples, 1 probe/second, and one worker. The Slowloris model runs once without networking. `hacker-web` has eight web steps; IPv4 `full-test` has 16 steps. For IPv6, the four IPv4 raw entries are skipped with reasons, leaving 12 steps. These scenarios differ from the CLI's 64-entry `hacker` preset.

`all-vectors` uses `prepare_all_vectors.py` to account for all 183 entries: an IPv4 web target has 46 live-ready entries (26 normal + 20 raw TCP), 55 offline entries, and 82 entries awaiting configuration. The IPv6 counts are 26/55/102. Pending entries are neither sent nor counted as passed. [Docker-based UniFi testing](unifi-test.md).

`l4-test` separately accounts for all 48 L4 entries. With the default IPv4 TCP port 80 target, it has 23 live entries, 7 offline entries, and 18 awaiting configuration. Supplying TCP echo and UDP service ports prepares 39 live IPv4 entries; two IPv6 entries remain pending. [L4 port configuration and scope](l4-test.md).

## All 55 offline entries

[lab.yaml](../external-agent/vectors/profiles/lab.yaml) selects all 41 event models and 14 byte/protocol fixtures in one run. Each entry executes once: 55 probes total, 10 probes/second, and a 30-second upper limit. The YAML is generated from the catalog; new offline entries are also included in this combined profile.

```sh
external-agent run --config external-agent/vectors/profiles/lab.yaml --output lab-report.json
python3 scripts/check_lab_report.py lab-report.json
```

The check requires every offline ID to appear exactly once in the report, all outcomes to be `simulated`, execution to complete, and network counters to remain zero. Missing/duplicate results or early termination fail the check. This report does not measure network packet delivery or actual appliance resilience.

When Docker is ready, run the same check with:

```sh
bash scripts/docker-lab.sh
```

The script builds the image, copies the shared YAML into a new report directory, runs it, and validates the report. See [Docker lab setup](../deploy.md#6-all-55-offline-entries-in-docker).

## Example services

`python3 scripts/local_servers.py --udp-echo` starts basic IPv4 services on TCP 9001, UDP 9000, and HTTP 9002. **Advanced profiles include protocols this small fixture does not support.** Provide suitable test services on the following ports or adapt the YAML to existing services.

| Default | Expected service / behavior |
| --- | --- |
| TCP 9001 | Connect/close; also the target for raw TCP/IP samples |
| TCP 9003 | Echo, a two-message session, bounded session workload, and echo/EOF after write-half shutdown |
| UDP 9000 | Echo, including the bounded random-datagram workload; UDP-010 does not wait for ACKs |
| UDP 9004 | Closed-port check; a timeout may occur without an OS response |
| TCP 9002 | HTTP/1.1; dedicated `/isradar-test`, `/health`, `/redirect`, header assertions, keep-alive, and complete partial-header/slow-body exchanges for advanced methods |
| TCP 9080 | HTTP/2 cleartext prior knowledge |
| TCP 9443 | HTTPS/TLS; `validator.example` certificate, TLS1.2/1.3, ALPN, session resumption |
| UDP 9443 | HTTP/3 QUIC, h3 ALPN, and the same hostname validation |
| TCP 9444 | TLS1.2 only; version rejection for a negative test requesting TLS1.3 |
| TCP 9445 | Expired test certificate |
| UDP/TCP 9053 | DNS; `host.example`, `missing.example` for NXDOMAIN, unique subdomains below the configured parent for DNS-022; configured zone key for DNSSEC |
| UDP 9123 | NTP v3/v4 with matching origin timestamps |
| UDP/TCP 9060 | SIP OPTIONS, including the bounded workload; dedicated INVITE/REGISTER endpoint |
| TCP 9061 | SIP TLS with certificate validation |
| ICMP / port field 1 | System ping; IPv4/IPv6 host reachability |

IPv6 entries target `::1`; the corresponding service must listen on IPv6. TLS profiles use the development fixture CA; change the hostname and CA for a real service, or remove `tls_ca` when system roots suffice. The bundled CA belongs to the test certificates in `external-agent/tests/fixtures/tls/`; creating a profile does not start a TLS server. The DNSSEC example public key is a test value and must be replaced with the target zone's DNSKEY. SIP INVITE defaults to expecting 420, and REGISTER to 200. Adjust these values to the endpoint's intended behavior.

## Selecting a set and running it sequentially

```sh
external-agent profiles create --preset researcher --directory profiles/researcher
external-agent profiles create --preset hacker --directory profiles/hacker
external-agent run --config profiles/hacker/HTTP-025.yaml --output slow-model.json
```

`HTTP-025` is an offline slot-occupancy model; it does not send Slowloris traffic to a target. Offline files need no network service. The source also includes [183 YAML files](../external-agent/vectors/profiles/cases). Use `profiles create` for UDP-010 so a fresh measurement key and run_id are generated.

To run the basic set sequentially once the basic services are ready:

```sh
mkdir reports-basic
for config in profiles/basic/*.yaml; do
  case_id="$(basename "$config" .yaml)"
  external-agent run --config "$config" --output "reports-basic/$case_id.json" \
    2>"reports-basic/$case_id.audit.jsonl" || break
done
```

Change the directory when selecting another set. Researcher files containing raw samples require Linux/CAP_NET_RAW. Do not reuse an output directory. Each YAML has its own execution budget; this loop is not a central aggregate quota or result evaluation engine. A run stopped by health checks may still return CLI exit code 0; inspect each report's termination reason and observations. To stop the set, create `STOP` in its selected profile directory.

## Developer checks

```sh
python3 scripts/generate_profiles.py --check
cargo test --test profiles --locked
bash scripts/verify.sh
```

Profile tests check configuration coverage for every catalog ID, target/protocol settings, measurement identity renewal, and CLI execution without an approval file. Profile validation does not establish that the target service is running or that all network integration tests passed.
