# Implementation and validation status

The scope is the **L3/L4/L7 sender agent** in the source specification. All 185 catalog entries map to executable source code: **130 bounded live checks, 41 offline event models, and 14 offline fixtures**. No `catalog_only` entries remain. `implemented` means source code exists; `verified` means validation is complete. Entries in this version are `implemented`, while vendor parity remains `unverified`.

The 55 offline entries have no live-network implementation. Their `implemented` status refers to model/fixture code; it would be incorrect to count them as implemented live attacks or tests performed against a target firewall.

The current source passed `bash scripts/verify.sh` on macOS with loopback socket access: **78 Rust tests** (including the ignored-by-default 1,000-datagram test), **12 Python tests**, and **21 wire tests**, plus build, format/generated-file checks, and Clippy. `check_wire.py` runs a dependency-free subset of the same Rust source; its 21 tests are not additional independent coverage. Profile tests check 39 raw entries against the expected Linux platform requirement and use normal engine validation for the remaining entries; no raw packets are sent. Linux raw runtime behavior and live libpcap capture remain unverified.

[Each ID's name, layer, mode, and backend mapping](vector-coverage.md) is generated alongside the catalog.

## Bounded live workload variants

Ten catalog IDs now provide separately selectable bounded live workloads: `TCP-033`, `UDP-015`, `DNS-021`, `DNS-022`, `SIP-011`, `HTTP-035`–`HTTP-038`, and `TLS-013`. They reuse the existing session, echo, DNS, SIP, HTTP, and TLS implementations, with new unique-subdomain behavior for DNS-022 and complete two-chunk exchanges for HTTP-037/038. The two HTTP variants wait 25 ms between chunks and preserve actual response and byte-count evidence; they do not claim Slowloris/RUDY equivalence or capacity exhaustion.

`bounded_live_variants_execute_real_protocol_exchanges` exercises all ten IDs through the engine against local protocol peers. It verifies distinct DNS-022 names and NXDOMAIN handling, SIP/HTTP/TLS response evidence, HTTP probe identity, slow-body validation, and application byte counters. The original 55 offline models/fixtures remain unchanged. These are real protocol exchanges on loopback, not evidence of target delivery, target resource impact, DDoS resilience, or firewall mitigation.

## Docker lab result — 2026-10-30

The `reports/docker-lab-ZE8HI2/` directory from the user's `bash scripts/docker-lab.sh` run was reviewed. `check_lab_report.py` was rerun against the actual `report.json`; `summary.json` and `audit.jsonl` agree with the result.

| Check | Result |
| --- | --- |
| Mode / target | `lab_emulation` / `null` |
| Start / end (UTC) | 20:51:01.105762 / 20:51:06.633474 |
| Duration | 5.5277 seconds |
| Started / completed entries | 55 / 55; each ID exactly once |
| Outcome / termination reason | All observations `simulated`; `completed` |
| Errors / timeouts / cancellations | 0 / 0 / 0 |
| Application datagram/byte and raw send counters | 0 |
| Audit log | 1 start, 55 completed probes, 6 statistics events, 1 end |

This evidence validates offline execution coverage. It does not validate live protocol integrations such as HTTP/2–3, TLS, DNS, NTP, or SIP, Linux raw transmission, or target packet observations. The container ran in the user's terminal because the agent session still lacked Docker socket access; report files were validated here.

## Docker web result — 2026-10-31 Turkey time

The user's `reports/docker-web-8BuTwG/` and `reports/docker-web-6xeYeP/` directories were reviewed. Counters, observations, summaries, validation output, and audit events in the three reports are consistent. All runs targeted `212.252.162.17` with hostname `online.solvitsoftware.com`; no report was found for the second external IP.

| Profile | Responses / probes | HTTP status | Average latency | Turkey time |
| --- | ---: | --- | ---: | --- |
| HTTP 80 | 3 / 3 | 301 | 134.83 ms | 00:13:09–00:13:11 |
| HTTPS 443 | 3 / 3 | 200 | 596.25 ms | 00:13:11–00:13:14 |
| UniFi User-Agent / HTTP 80 | 1 / 1 | 301 | 105.27 ms | 00:15:11 |

The UTC date was 2026-10-30, between 21:13:09 and 21:15:11. All runs ended with `completed`; timeout, network/protocol error, remote rejection, and cancellation counters were zero. HTTPS responses came from a backend with certificate validation enabled. The 301 redirects were not followed; their destinations are not recorded in these reports. The slowest HTTPS observation was 1,253.65 ms; that alone is not evidence of blocking or a load problem.

The signature YAML includes `User-Agent: BlackSun`, and this run also received an HTTP response. The sender report does not show UniFi blocking; without UniFi events or server access logs, alerts, traffic direction, and actual backend delivery require separate verification. Because the HTTP library is not included in byte counters, zero application bytes do not mean that no traffic was sent. These are 7 HTTP requests, not a packet count or DDoS resilience measurement.

This initial evidence comes from the old 1/3-request profiles. At the user's request, web profiles now use **100 requests, a target rate of 10 requests/second, 8 workers, a 65,536-byte/second admission budget, and a 60-second duration**. Results from subsequent user runs with these settings are below; historical reports were not modified.

The Docker script gained the `hacker-web` scenario: initial HTTP/HTTPS access, OPTIONS, TRACE, redirects, the BlackSun User-Agent check, and final HTTP/HTTPS access. Eight steps run sequentially, targeting at most 800 HTTP requests. The 16 YAML files generated for IPv4 and IPv6 passed network-free engine validation; manifest selection for three scenarios, TRACE's fixed-header requirement, and terminal summaries of existing reports were checked. Shell syntax and project consistency passed. Live HTTP results are below; UniFi blocking was not verified. The CLI's separate `hacker` set remains 55 offline + 9 live entries.

### Later user runs and expanded measurement scope

Two `hacker-web` runs using 100 probes / 10 probes-per-second were found in `reports/docker-web-rrTIZ5/` and `reports/docker-web-GbhQHK/`. In each run, seven steps completed with 100 successful responses each: five HTTP steps returned 301, and two HTTPS steps returned 200. TRACE admitted 4 probes and triggered the health threshold after three 405 responses. A 405 is HTTP method rejection, not classified as UniFi blocking. Completed steps achieved approximately 9.66–9.77 probes/second. These reports predate probe identities; no target log or UniFi event was supplied.

The first `full-test` version contained ICMP, TCP on 80/443, and eight web steps. The first `all-vectors` version accounted for all 173 IDs: 24 live-ready, 55 offline, and 94 awaiting configuration. In that version, 22 full-test YAML files and 50 catalog execution YAML files for IPv4/IPv6 passed engine validation. Current SYN/SYN-ACK and offline Slowloris additions are described below; the new sets have not yet been validated live in Docker.

An HTTP probe identity header, a list of admitted identities retained across errors/timeouts/cancellation, and JSONL/IIS W3C log comparison were added. Twenty-nine library tests and three Python evidence-counting tests passed; the default binary and all Rust test targets compiled. A new HTTP socket integration test checks the identity observed by the server during timeout/cancellation; it is not counted as executed in this environment because of the OS socket restriction. End-to-end matching against real target logs remains pending. [Measurement usage](http-log-correlation.md).

## Family coverage

| Family | Live | Offline | Implementation |
| --- | ---: | ---: | --- |
| TCP | 29 | 5 | Connect/close, timeout, echo, two-message session, half-close/EOF, bounded session workload; all listed flag combinations and raw window/MSS/timestamp/SACK and SYN-flood half-open samples |
| UDP | 13 | 2 | Echo to a connected peer; 0/64/128/1200 bytes, fixed/random payloads, closed-port classification, valid fragments, HMAC sequenced sender, bounded datagram workload |
| ICMP | 7 | 7 | Echo; Destination Unreachable, Time Exceeded, Parameter Problem, timestamp samples; MTU/redirect/quote checks offline |
| IP | 13 | 6 | IPv4 checksum/TTL/ECN/options/fragments; IPv6 reachability, Hop-by-Hop/Destination/SRH/fragments/No Next Header; malformed/overlap/tiny-fragment offline |
| DNS | 18 | 4 | A/AAAA/MX/TXT/CNAME/NS/SOA/ANY, NXDOMAIN, EDNS0, recursion policy, TC inspection, compression, framed TCP/fallback, cryptographic DNSSEC A RRset, bounded fixed/unique-name query workloads |
| NTP | 6 | 2 | v3/v4 mode-3→mode-4, origin nonce, leap/stratum, kiss-of-death classification |
| SIP | 8 | 3 | OPTIONS over UDP/TCP/TLS and bounded OPTIONS workload; INVITE/REGISTER with a dedicated test identity; Call-ID/CSeq/Via checks, INVITE ACK/CANCEL/BYE cleanup |
| HTTP/HTTPS | 25 | 14 | GET/POST/HEAD/PUT/PATCH/DELETE/OPTIONS/TRACE/CONNECT; HTTP/1.1/2/3; keep-alive/reuse, certificates, status, redirects, headers, health, bounded GET/POST/partial-header/slow-body/Slowloris workloads |
| TLS | 11 | 2 | 1.2/1.3 and bounded negotiation workload, certificate/hostname, secure cipher observation, ALPN, actual session resumption, version/expired/name-mismatch rejections |
| Specialized | 0 | 10 | Multi-vector, distribution, low-rate/long occupancy, volume, synthetic request/reply ratio, IKEv2 SA_INIT, SMTP HELO, correlation/transition/recovery |
| Total | **130** | **55** | **185** |

Multiple entries use the same protocol implementation with different policy/transport conditions. The 185 entries are not 185 different attack tools or an exact copy of MazeBolt's private list.

## Protocol details and limitations

The raw backend runs only on Linux against the configured target, using the actual local source IP selected by the OS. A source TCP port is reserved without connect/listen; no existing unrelated session is targeted. Limits are 1 probe/second, one worker, 16 total IP samples, and 60 seconds. Each IPv4/IPv6 fragment probe consumes two samples. IPv6 SRH uses Segments Left=0, with the configured target as its only segment. A `sent` outcome means local socket acceptance, not target observation.

DNSSEC cryptographically validates an RRSIG over a positive IN A RRset using a configured, pinned Ed25519 zone DNSKEY. It does not rely only on the AD bit. Root-to-zone DS/DNSKEY chains, wildcard, NSEC/NSEC3 denial-of-existence proofs, and other signature algorithms are unsupported and not counted as verified. DNS queries use a fixed configured qname except DNS-022, which generates a unique `isradar-` subdomain below the configured parent. Only the explicit recursion-policy check requests RD=1. TCP fallback adds at most one query to the same IP/port. The response codec limit is 4,096 bytes.

SIP REGISTER queries existing bindings without sending Contact. INVITE uses `Require: isradar-no-session`, `Expires: 0`, and `Max-Forwards: 0`, allowing only a configured dedicated `isradar-` identity. An unexpectedly successful dialog is closed with ACK/BYE on the same configured peer; Contact/Record-Route are not followed. INVITE is limited to 1/second, one worker, and 16 probes. SIP product integration requires the operator to supply a dedicated test endpoint.

HTTP mutation methods and the slow-body workload require configured dedicated test path/body/header settings. HTTP-037 and HTTP-038 each complete one real exchange per probe, split into two chunks with a 25 ms delay; they do not measure connection-exhaustion capacity or reproduce Slowloris/RUDY. TRACE uses fixed, nonsensitive headers. CONNECT authority is always the configured target's own numeric IP/port; there is no third-party tunnel or tunnel payload. CONNECT is also limited to 1/second, one worker, and 16 probes. HTTP/2 uses cleartext prior knowledge; HTTP/3 uses QUIC/TLS1.3 with h3 ALPN. HTTPS/TLS/QUIC certificate validation cannot be disabled. TLS resumption is reported from the second handshake of two actual TLS1.2 connections. Bodies are not downloaded and redirects are not followed.

## Offline models

The 41 event models have individual ID-to-mechanism mappings: queues, connection/state occupancy, CPU work budgets, long-held slots, cache-miss costs, synthetic fanout, capacity transitions, and recovery. Each model ends after 16 logical ticks; tests verify offered=accepted+rejected and release of all accepted resources. Values are illustrative work tokens, not actual defense-appliance capacity or effectiveness. Names such as MHDDOS/GoldenEye are retained as taxonomy labels; their tool behavior or protection-bypass techniques are not reproduced.

Fourteen fixtures perform actual byte/checksum/header classification. They cover malformed IP, overlaps, tiny fragments, ICMP redirect/MTU, invalid SIP CSeq, IKEv2 payload framing, and SMTP HELO. Fixture/model execution accepts no target and opens no network sockets. PCAP export produces one IPv4/ICMP record using documentation addresses; it does not replay traffic.

## Local model profiling

`python3 scripts/profile_models.py` runs the actual 41 event models 1,000 times in an optimized Rust binary. The 41,000 executions in that session took approximately 0.020 seconds; this is a microbenchmark on one development machine. It is not network throughput, actual protection capacity, or a product SLA result.

## Validation still required for acceptance

The `full-test` attempt in `reports/docker-web-HEOm6a/` was reviewed: its three ICMP observations ended with `Operation not permitted` while starting `/bin/ping`; the remote target's ICMP behavior was not observed. Bash 3.2 then stopped the script before the TCP step while expanding an empty `ping_args` array under `set -u`. Empty-array usage was fixed in the runner and `verify.sh`. The Docker image was updated to remove ping file capability/setuid bits and use the existing group permission, addressing a possible capability conflict consistent with the local `EPERM` log. New ICMP reports retain local startup context and process exit diagnostics.

The initial validation of that fix passed three mock-Docker regression tests on Mac `/bin/bash` 3.2: baseline, the old 11-step full-test continuing to TCP/HTTP after ICMP errors, and all-vectors transitioning from offline to live steps. Tests use synthetic reports in temporary directories and do not run Docker or networking. Thirty Rust library tests, shell syntax, project consistency, and Clippy `-D warnings` passed. Actual Docker validation of the ping image fix remains pending.

### SYN/SYN-ACK and offline Slowloris profile integration

Existing `TCP-002/003` raw backends were connected to separate IPv4 `full-test` steps on ports 80 and 443, each limited to 16 samples, 1/second, and one worker. The existing `HTTP-025` offline model runs once without a target and with Docker networking disabled. IPv4 full-test therefore has 16 steps. For IPv6, the four IPv4 raw steps are skipped with reasons, leaving 12 steps. All 21 raw TCP entries were added to the IPv4 `all-vectors` plan on port 80: the current plan has 47 live-ready, 55 offline, and 82 pending entries. IPv6 counts are 26/55/103.

Raw containers use only the `NET_RAW` capability and a read-only data mount; the host user writes the actual JSON report received over stdout. Other steps run without capabilities. Terminal/file summaries show the mode and raw socket acceptance count; offline steps are explicitly labeled `not tested: offline`.

Mock-Docker flow tests check that raw capabilities do not leak to other steps, offline networking is disabled, IPv6 skips are recorded, and report modes are correct. Actual Linux/Docker raw transmission and target delivery remain unverified.

### Planning every L4 entry

The `l4` CLI preset generates 49 YAML files: 42 live implementations and 7 offline models. The `l4-test` Docker plan accounts for every ID; its default IPv4 TCP target has 24 live / 7 offline / 18 pending entries. With TCP echo and UDP ports configured, IPv4 has 40 live / 7 offline / 2 awaiting IPv6; IPv6 has 17 live / 7 offline / 25 awaiting IPv4. UDP-005 produces two fragments per probe and is therefore limited to 8 probes. UDP-010 gets a fresh measurement key with 0600 permissions and does not wait for ACKs. Missing services are not automatically directed to web ports.

Validation: 30 Rust library tests and 5 profile tests passed; profile tests cover every L4 ID and actual model execution for all 55 offline entries. Two Python L4 plan tests cover the union of 42 live IDs across IPv4/IPv6, port mappings, the fragment budget, and measurement identity renewal. Seven mock-Docker flow tests (baseline, IPv4/IPv6 full-test, IPv4/IPv6 all-vectors, and default/fully configured L4 plans), formatting, shell syntax, static consistency, and Clippy `-D warnings` passed. Details and commands are in the [L4 guide](l4-test.md). Live Linux/Docker L4 acceptance testing remains incomplete.

Generated IPv4/IPv6 web/catalog/L4 YAML files were checked with the actual macOS agent: 107 normal/offline configurations validated, while 47 raw configurations were rejected with the expected Linux requirement. The CLI `l4` preset produced 49 YAML files. The new Slowloris profile's 1 observation and L4 model profile's 7 observations completed in actual offline engine runs with zero network counters. These checks sent no traffic to a remote target.

Initial Docker HTTP/HTTPS and 100-request / 10-probes-per-second results appear above. Live runtime validation of `full-test`, `all-vectors`, HTTP identity correlation, and UniFi event matching remains pending. Clippy `-D warnings` passed on the latest code. [Test scope and usage](unifi-test.md).

1. Complete `bash scripts/verify.sh` on Linux with loopback socket access. The lockfile is present; CI uses `cargo fetch --locked`.
2. Complete `ISRADAR_CAPTURE_CHECKS=1 bash scripts/verify.sh` on Linux with `libpcap-dev` and `pkg-config` installed.
3. Validate Linux raw checks on a dedicated test network with operator-provided CAP_NET_RAW, and validate the libpcap interface/Direction::Out in the relevant runtime environment. Docker is optional. Automated tests do not transmit raw packets.

libpcap egress observation is limited to the configured interface and target IP; it cannot distinguish other processes' traffic to the same target. Results are stored separately in `outbound_capture`; agent-originated wire packet counts are not invented. The bandwidth budget limits probe admission; it does not shape actual wire traffic including OS retransmission and TLS/QUIC overhead. [Counter semantics](measurement.md).

The target receiver and two-endpoint comparison belong to a later phase. The existing `experimental-receiver` prototype is excluded from the default binary/Docker image and from this phase's acceptance scope. Dashboards, databases, a central controller, and multi-node execution are outside this phase of the source specification.

## Fixes made during this review

- DNS EDNS extended RCODE is read, and OPT records are accepted only in the additional section. DNSSEC signature, altered A records, incorrect keys, and validity times were tested separately.
- NTP kiss-of-death responses with an alarm leap value are classified as the appropriate rejection; origin matching is required.
- SIP OPTIONS skips provisional responses and waits for the final status. TCP/TLS body limits and UDP Content-Length integrity are validated.
- Actual HTTP response/status evidence is retained on header/policy failure; duplicate expected headers and Location headers are rejected. Reuse checks distinguish coalesced 100/103 responses and final responses on the same stream.
- TLS 1.2/1.3, ALPN, resumption, expired/name mismatch, and version mismatch were tested using actual rustls connections in memory. These are not OS-socket or QUIC tests.
- Distribution and multi-protocol models now count admission/rejection per group; the burst model operates intermittently. All 55 offline entries are checked for inclusion in engine output.
- Incorrect test references in the catalog were fixed; unknown fixture IDs are not counted as implemented.
- The requested simplification removed operator signatures, authorization profiles, `auth` commands, and `--trusted-key`. Target/limit/protocol validation remains inside the engine. DNSSEC signatures and UDP measurement HMAC are protocol validation.
- Added 173 YAML files and five ready-to-use profile sets including `l4`. [Profile usage](profiles.md), [native Linux deployment](../deploy.md), [LLM improvements](improvements.md).
- Shared `lab.yaml` runs all 55 offline entries once each; the local CLI test and validation of the user's Docker report passed. Docker CLI 29.9.2 and the `desktop-linux` context are available. Direct agent access to the Docker socket was denied with `permission denied`; file permissions were not changed. Docker evidence is in the result table above.
