# External Agent Vectors and Traffic-Passage Reporting

This guide describes all **184 vectors** in `external-agent`, assigns an importance level to each scenario, and gives examples of reports based on whether the test traffic reached the protected destination.

**Scope:** the English descriptions reflect the current source code. The importance levels, report categories, and percentage thresholds below are **proposed reporting policy**. They do not add a receiver or scoring engine to the agent. Numerical examples are illustrative, not measurements from a remote assessment.

## Coverage

| Family | Layer | Total | Live | Offline |
| --- | --- | ---: | ---: | ---: |
| TCP | L4 | 34 | 29 | 5 |
| UDP | L4 | 15 | 13 | 2 |
| ICMP | L3 | 14 | 7 | 7 |
| IP | L3 | 19 | 13 | 6 |
| DNS | L7 | 22 | 18 | 4 |
| NTP | L7 | 8 | 6 | 2 |
| SIP | L7 | 11 | 8 | 3 |
| HTTP | L7 | 38 | 24 | 14 |
| TLS | L7 | 13 | 11 | 2 |
| SPECIAL | Cataloged as L7 | 10 | 0 | 10 |
| **Total** | | **184** | **129** | **55** |

Execution types:

- **Live:** `live_validation`; performs a bounded protocol exchange with the configured destination. There are 90 ordinary live entries.
- **Raw:** also `live_validation`; sends specific packet samples on Linux with `CAP_NET_RAW`. There are 39 raw entries.
- **Model:** `lab_emulation` / `offline_model`; runs an in-memory workload model without traffic. There are 41.
- **Fixture:** `lab_emulation` / `offline_policy_fixture` or `offline_packet`; constructs and checks bytes without sending them. There are 14.

Several IDs share a backend. `implemented` means a code path exists, not that every entry has passed live acceptance testing. Named attack-tool models do not execute those tools.

## What the report should answer

For each vector, report **what was sent, what was observed behind the protection system, what was expected, and how important a deviation is**.

Use explicit labels to avoid confusing successful delivery with successful protection:

| Expected behavior | Observation | Assessment result |
| --- | --- | --- |
| Block | Identified test traffic reaches the protected observation point | **Confirmed passage / policy deviation.** Rate the finding according to scenario importance and observed extent. |
| Block | Every eligible item has correlated drop evidence, with no contradictory destination observation | **Confirmed blocked for the measured sample.** |
| Block | Traffic is absent at the destination, but no conclusive drop evidence exists | **Not observed / inconclusive cause.** Loss, routing, capture, and service behavior remain possible explanations. |
| Allow | Traffic reaches the intended observation point | **Expected delivery.** Ordinary permitted traffic is a positive control. |
| Allow | Delivery or the required exchange fails | **Availability or compatibility deviation.** Investigate the path/service; passage itself is not a weakness. |
| Offline model or fixture | Local simulation/validation completes | **No live protection assessment.** No packet-passage percentage is available. |

A successful TCP connection, valid HTTP request, DNS response, or RST packet is not inherently malicious. Define the expected policy for the exact source, destination, port, direction, and vector before interpreting passage as a weakness. These entries include baseline checks, protocol validation, and offline scenarios; they are not 184 independently implemented attacks.

## Importance levels

The table's **Importance** is a proposed default assessment priority for the scenario, separate from the catalog's execution `risk`. It is not a measured vulnerability score. Apply it to a finding only when the expected control actually fails.

| Importance | Reporting interpretation |
| --- | --- |
| High | Prioritize a confirmed deviation involving a defined security boundary, identity/integrity control, unusual protocol-state handling, or important availability protection. |
| Medium | Investigate a confirmed protocol-policy, session-handling, or hardening deviation. Establish impact from the observed behavior. |
| Low | Baseline reachability or compatibility coverage. Expected successful delivery normally produces no security finding. |

Adjust the final finding to the target's documented policy and business impact. A Low-importance TCP reachability check can become High if it proves access to a prohibited service. A High-importance offline model produces no live security finding. Reserve **Critical** for independently confirmed severe impact on a critical asset; neither a vector label nor a passage percentage establishes that alone.

## Measuring passage

Use one vector, one target/path, one direction, one observation layer, and one stable policy per result. Keep each assessment window bounded and record its start/end time. Verify that the observed flow traversed the assessed boundary; receipt through an alternate path does not establish failure of that control.

| Quantity | Meaning |
| --- | --- |
| `planned` | Configured test budget; not the denominator by itself. |
| `offered_unique` | Unique test items confirmed as emitted toward the assessed boundary, preferably observed at its ingress. Record the evidence and observation point. |
| `received_unique` | Offered test items matched at the protected destination, after deduplication. |
| `confirmed_blocked_unique` | Offered items with attributable enforcement-drop evidence and no contradictory destination observation. |
| `unresolved_unique` | Remaining offered items with no conclusive arrival/drop outcome. |
| `conflicting_unique` | Items with incompatible evidence, such as both an asserted block and downstream receipt. Investigate before issuing a final score. |

```text
observed_passage_percent = 100 * received_unique / offered_unique
confirmed_block_percent = 100 * confirmed_blocked_unique / offered_unique
```

Require `offered_unique > 0`. A measured passage ratio describes the observed sample; it is not a probability that all future attacks will succeed. If the target capture/log is incomplete, label observed passage as a **confirmed lower bound**, retain the unresolved count, and do not claim the complement was blocked. A positive matched arrival remains evidence even when other outcomes are unknown.

For a conflict-free sample, keep the outcome groups disjoint:

```text
offered_unique = received_unique + confirmed_blocked_unique + unresolved_unique
```

**Count the correct unit.** Raw packet assessments count identified packet samples. HTTP assessments count unique requests. TCP/TLS checks count connections or exchanges. A probe can emit several packets, fragments, retransmissions, or application messages. Do not call 1,000 HTTP probes “1,000 packets,” or mix offline events into a delivery denominator.

### Proposed 40% reporting example

For a predeclared sample of **1,000 unique, evidenced test items that should be blocked**:

| Result | Proposed report |
| --- | --- |
| 400 or more reach the protected destination | **High — substantial traffic passage** under this example policy, with the measured count/percentage and evidence coverage. |
| 1–399 reach the destination | **Confirmed passage**; use the vector's importance and the boundary's impact. Do not suppress a valid finding merely because it is below 40%. |
| 0 arrive and all 1,000 have conclusive drop evidence | **Confirmed blocked for this sample.** |
| 0 arrive but some outcomes are unresolved | **Inconclusive for blocking.** |
| Fewer than 1,000 eligible items were offered | Report actual counts and the actual sample ratio; the specific 1,000-item threshold is **Not evaluated**. |
| Traffic was expected to pass | Report delivery/availability; the 40% weakness rule does not apply. |

**40% is an example reporting threshold chosen for this guide, not a universal security standard or an existing vendor score.** Report a forbidden arrival as soon as it is confirmed. The percentage describes extent and helps prioritize remediation. Produce one consolidated finding per vector/target/window, rather than one notification per packet.

### Worked finding: 400 of 1,000 get through

Assume a protected origin must not receive GET requests from the assessment source. In a fixed 10-minute collection window, correlated evidence shows:

| Evidence | Count |
| --- | ---: |
| Unique test requests observed at the boundary ingress | 1,000 |
| Matching unique request IDs at the protected origin | 400 |
| Attributable enforcement drops for the other requests | 600 |
| Unresolved or conflicting outcomes | 0 |

The report should say:

> **High — HTTP access-control policy deviation.** 400 of 1,000 evaluated GET requests reached the protected origin despite the configured deny expectation: **40% observed passage**. The remaining 600 have correlated drop evidence. Observation point: origin access log behind the assessed control. Unit: HTTP requests. Window: 10 minutes.

If the only target evidence is 400 matching log entries, the report can confirm those arrivals; it cannot call the other 600 “blocked.” If only local send acceptance is known, an actual passage ratio is unavailable.

This example is a report template. Completing the required sample depends on the actual execution budget and health stopping behavior; do not relax stopping safeguards to manufacture 1,000 observations.

## Practical packet example: TCP-005

**TCP-005 — TCP RST packet sample** sends an IPv4 TCP packet with RST set (`0x04`). It uses the OS-selected source IP and a freshly reserved source port. It does not target an established connection or verify that any session was terminated. The backend is `raw_tcp_flags` → `PacketKind::TcpFlags(4)`.

RST handling depends on TCP state and sequence validation, and RST also occurs during ordinary TCP operation. Arrival of a RST alone does not prove session disruption. [RFC 9293, section 3.5.3](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.5.3).

**Default importance: Medium.** Example expectation: the assessed boundary must drop this unsolicited out-of-state RST sample from the selected external source.

1. Start with [TCP-005.yaml](external-agent/vectors/profiles/cases/TCP-005.yaml). Its default target is `127.0.0.1:9001`, with one probe.
2. On a Linux sender with `CAP_NET_RAW`, configure the intended IPv4 target. Preserve the current limit: **at most 16 IP samples, 1 probe/second, one worker, and 60 seconds**, plus health checks and STOP.
3. Match offered samples and protected-side packet observations using tuples, the reported packet identifier/TCP sequence, and timestamps. Account for NAT, duplicate observations, retransmission, and capture loss.
4. Suppose 16 samples are independently confirmed offered and six match the protected-side capture. Report **6/16 observed passage (37.5%)**. If the other ten lack drop evidence, report ten unresolved outcomes.
5. Under the stated drop expectation, those six arrivals support a policy-deviation finding. Use Medium for this example unless the asset/boundary impact justifies High. They do not demonstrate an existing-session reset.
6. If the only evidence is 16 local `Sent` outcomes, report **Destination passage not measured**.

A 1,000-probe TCP-005 run is rejected by the current raw limits. Do not bypass those limits. The runnable 1,000-item example below uses HTTP requests. `TCP-020` shares TCP-005's RST implementation; `TCP-030` is an offline RST Flood model.

## Runnable example: bounded HTTP validation

This runs real HTTP exchanges against one known endpoint; host/port discovery is outside this example. Use the repository's loopback service to reproduce the execution workflow. For a protected remote endpoint, supply the actual numeric target and collect its origin/enforcement evidence.

From the repository root, build the agent and start the local fixture in a separate terminal:

```sh
cargo build --locked -p external-agent
python3 scripts/local_servers.py
```

Save as `http-1000.yaml` in the repository root:

```yaml
vectors: [HTTP-001]
mode: live_validation
target:
  ip: 127.0.0.1
  port: 9002
  server_name: null
limits:
  duration_seconds: 300
  probes_per_second: 10
  concurrency: 1
  bandwidth_bytes_per_second: 65536
  max_probes: 1000
  timeout_ms: 2000
kill_switch: STOP
health:
  consecutive_failures: 3
  max_latency_ms: 3000
protocol:
  http:
    path: /
    body: ""
    headers: {}
    expected_status: 200
    expected_headers: {}
    dedicated_test_endpoint: false
```

Validate without traffic, then run with fresh report/audit filenames:

```sh
./target/debug/external-agent validate --config http-1000.yaml
./target/debug/external-agent run --config http-1000.yaml --output http-1000-report.json 2>http-1000-audit.jsonl
./target/debug/external-agent report --input http-1000-report.json --format json
```

The budget is up to 1,000 probes at a target rate of 10/s. Healthy loopback responses should take roughly 100 seconds plus overhead. Duration, failed-health checks, cancellation, or STOP may end execution earlier. Use actual counts and `termination_reason`; exit code 0 means a report was written. Set `expected_status` to the intended service response when adapting the profile. It is a health expectation, not a firewall rule.

For an actual target, configure its access log to retain `X-Isradar-Probe` using the [HTTP log correlation guide](docs/http-log-correlation.md). Then compare a completed log collected locally:

```sh
python3 scripts/compare_http_logs.py --sender http-1000-report.json --target-log target-access.jsonl --output http-1000-comparison.json
```

The local fixture suppresses access logs, so this comparison requires a separately configured target log. The tool reports deduplicated origin observations and missing IDs; it does not generate the proposed ratings or prove blocks for missing requests. Its admitted-probe identities also do not prove emission. Correlate ingress/enforcement evidence before using `offered_unique` and a final blocking score.

## Evidence available in this version

| Evidence | Available now | What it establishes |
| --- | --- | --- |
| Local raw send counters | Yes | OS socket acceptance; destination passage is not measured. |
| UDP-010 sequence IDs and local send acceptance | Yes | Sender identity ledger; a target receiver is needed for independent delivery evidence. |
| Optional sender-side packet capture | Feature-gated | Outbound observations to the target IP; may include other traffic and is not a target receiver. |
| Tagged HTTP requests and log-comparison script | Supported backends | Arrival at the chosen log point when a trusted target log is supplied. |
| Integrated target packet receiver/capture and automatic passage scoring | Not implemented in the default sender workflow | Required evidence/scoring must be supplied externally or developed separately. |
| Offline model or fixture output | Yes | In-memory behavior only. |

A proxy log establishes receipt at that proxy; use an origin log/capture to claim receipt farther downstream. TRACE, CONNECT, HTTP reuse, and HTTP/3 are outside the current HTTP identity-correlation scope. For those, collect suitable independent evidence. [Measurement semantics](docs/measurement.md) and [HTTP correlation scope](docs/http-log-correlation.md).

## Vector reference

Every catalog ID appears once below. **Importance** is the proposed scenario importance, not proof of a finding. **Evidence** identifies the basis required for interpretation:

- **Packet:** independent offered-packet and protected-side observations.
- **Exchange:** protocol response/transaction evidence; use protected-side logs/capture for a passage claim through a specific control.
- **Trust:** certificate, identity, or signature outcome; packet arrival alone cannot assess this property.
- **Offline:** no live delivery or blocking conclusion.

## TCP — 34 vectors

Raw TCP samples use IPv4 and a fresh reserved source port. TCP-024 through TCP-027 carry their options on SYN packets. Packet passage is a separate measurement from session establishment or disruption.

| ID | Type | Importance | Evidence | What it does |
| --- | --- | --- | --- | --- |
| `TCP-001` | Live | Low | Exchange | Establishes and gracefully closes a standard TCP connection to check reachability. |
| `TCP-002` | Raw | Low | Packet | Sends a TCP SYN sample from a fresh source port. |
| `TCP-003` | Raw | Medium | Packet | Sends a standalone TCP SYN-ACK sample; it does not measure a server's reply to a SYN. |
| `TCP-004` | Raw | Medium | Packet | Sends an ACK-only sample without first establishing a TCP session. |
| `TCP-005` | Raw | Medium | Packet | Sends an RST-only sample from a fresh source port; existing sessions are not targeted. |
| `TCP-006` | Raw | Medium | Packet | Sends a FIN-only sample from a fresh source port. |
| `TCP-007` | Raw | Medium | Packet | Sends a PSH sample containing a small trace payload. |
| `TCP-008` | Raw | Medium | Packet | Sends a URG sample with an urgent pointer and trace payload. |
| `TCP-009` | Raw | High | Packet | Sends SYN and FIN flags together in one TCP sample. |
| `TCP-010` | Raw | Medium | Packet | Sends ACK and SYN flags together; the flag combination is identical to TCP-003. |
| `TCP-011` | Raw | Medium | Packet | Sends ACK and RST flags together in one sample. |
| `TCP-012` | Raw | Medium | Packet | Sends ACK and PSH flags together with a trace payload. |
| `TCP-013` | Raw | High | Packet | Sends RST and SYN flags together in one sample. |
| `TCP-014` | Raw | High | Packet | Sets all eight bits of the TCP flags byte (0xFF); this is the ALL FLAGS sample. |
| `TCP-015` | Raw | High | Packet | Clears the TCP flags byte (0x00); this is the NULL FLAGS sample. |
| `TCP-016` | Live | Medium | Exchange | Attempts a standard connection; the engine classifies timeout outcomes. Uses the same connect backend as TCP-001. |
| `TCP-017` | Live | Medium | Exchange | Sends data, shuts down the write half, then verifies matching echo data followed by EOF. |
| `TCP-018` | Live | Medium | Exchange | Sends a fixed message over an established connection and verifies an exact echo. |
| `TCP-019` | Live | Medium | Exchange | Verifies two consecutive echo exchanges on one TCP connection. |
| `TCP-020` | Raw | Medium | Packet | Sends a reset on a fresh reserved tuple; shares TCP-005's implementation. |
| `TCP-021` | Raw | Medium | Packet | Sends an out-of-state ACK on a fresh tuple; shares TCP-004's implementation. |
| `TCP-022` | Live | Low | Exchange | Checks TCP connection reachability over IPv4. |
| `TCP-023` | Live | Low | Exchange | Checks TCP connection reachability over IPv6. |
| `TCP-024` | Raw | Low | Packet | Sends a SYN with the TCP receive-window field set to 4096. |
| `TCP-025` | Raw | Low | Packet | Sends a SYN with an MSS option of 1200. |
| `TCP-026` | Raw | Low | Packet | Sends a SYN carrying a TCP timestamp option. |
| `TCP-027` | Raw | Low | Packet | Sends a SYN carrying the SACK-permitted option. |
| `TCP-028` | Model | High | Offline | SYN Flood model: represents resource occupancy by half-open connection state. |
| `TCP-029` | Model | High | Offline | ACK Flood model: represents the processing cost of ACK classification. |
| `TCP-030` | Model | High | Offline | RST Flood model: represents reset-related connection-state lookup work. |
| `TCP-031` | Model | High | Offline | FIN Flood model: represents resources retained in closing states. |
| `TCP-032` | Model | High | Offline | State-exhaustion model: represents prolonged connection-table occupancy. |
| `TCP-033` | Live | High | Exchange | Runs bounded TCP session work; each probe performs two echo exchanges on one connection, using TCP-019's backend. |
| `TCP-034` | Raw | High | Packet | Cataloged as SYN Flood live half-open sample: sends one raw SYN per probe without completing a handshake. Raw limits still apply. |

## UDP — 15 vectors

Echo checks require a service that returns the sent payload unchanged. UDP-010's authenticated measurement frame has different receiver semantics from ordinary echo.

| ID | Type | Importance | Evidence | What it does |
| --- | --- | --- | --- | --- |
| `UDP-001` | Live | Low | Exchange | Sends a fixed datagram and verifies an identical echo response. |
| `UDP-002` | Live | Medium | Exchange | Observes OS connection-refused behavior for an expected closed UDP port. Silence alone is inconclusive. |
| `UDP-003` | Live | Low | Exchange | Sends a fixed 128-byte payload and checks its echo. |
| `UDP-004` | Live | Low | Exchange | Sends a 1200-byte payload and checks its echo. |
| `UDP-005` | Raw | Medium | Packet | Splits one well-formed UDP datagram into two IPv4 fragments and sends both. |
| `UDP-006` | Live | Medium | Exchange | Sends a random 64-byte payload and verifies an identical echo. |
| `UDP-007` | Live | Medium | Exchange | Sends a zero-length datagram and expects a zero-length echo response. |
| `UDP-008` | Live | Low | Exchange | Performs UDP echo validation over IPv4. |
| `UDP-009` | Live | Low | Exchange | Performs UDP echo validation over IPv6. |
| `UDP-010` | Live | Medium | Packet | Sends authenticated, sequenced 64-byte measurement datagrams. Default await_ack=false records local acceptance, not target delivery. |
| `UDP-011` | Raw | Low | Packet | Sends an IPv4/UDP sample with a valid checksum covering the UDP pseudo-header. |
| `UDP-012` | Live | Medium | Exchange | Uses a connected UDP socket to constrain the response peer and verifies the echo payload. |
| `UDP-013` | Model | High | Offline | UDP Flood model: represents load on a datagram-processing queue. |
| `UDP-014` | Model | High | Offline | UDP amplification model: uses a synthetic response-to-request byte ratio of four. |
| `UDP-015` | Live | High | Exchange | Runs bounded repeated random 64-byte UDP echo exchanges using UDP-006's backend. |

## ICMP — 14 vectors

Echo responses establish an exchange with the replying endpoint. A gateway reply does not establish application availability or delivery to a different protected host.

| ID | Type | Importance | Evidence | What it does |
| --- | --- | --- | --- | --- |
| `ICMP-001` | Live | Low | Exchange | Sends an IPv4 Echo Request and validates an Echo Reply. |
| `ICMP-002` | Live | Low | Exchange | Sends an ICMPv6 Echo Request and validates an Echo Reply. |
| `ICMP-003` | Raw | Medium | Packet | Sends an IPv4 Destination Unreachable / Port Unreachable sample quoting a reserved test tuple. |
| `ICMP-004` | Raw | Medium | Packet | Sends an IPv4 Time Exceeded sample; it does not wait for an actual TTL-expiry event. |
| `ICMP-005` | Fixture | Medium | Offline | Builds a Fragmentation Needed fixture with MTU=1280 and checks headers, checksums, and the quoted packet. |
| `ICMP-006` | Live | Low | Exchange | Observes echo behavior using the shared ICMP backend; a missing response does not identify a blocking device. |
| `ICMP-007` | Fixture | High | Offline | Constructs and validates an ICMP Redirect fixture in memory. |
| `ICMP-008` | Raw | Medium | Packet | Sends an IPv4 Parameter Problem error sample. |
| `ICMP-009` | Fixture | Medium | Offline | Constructs an ICMPv6 Packet Too Big fixture and checks its MTU=1280 field and checksum. |
| `ICMP-010` | Raw | Medium | Packet | Sends an IPv4 Timestamp Request using milliseconds since UTC midnight. |
| `ICMP-011` | Fixture | Medium | Offline | Checks the original IP header and packet quotation carried inside an ICMP error fixture. |
| `ICMP-012` | Fixture | Low | Offline | Builds an IPv4/ICMP Echo fixture and verifies its IPv4 and ICMP checksums. |
| `ICMP-013` | Model | High | Offline | Ping Flood model: represents a large batch of echo-processing work. |
| `ICMP-014` | Model | High | Offline | Smurf-style model: represents eight synthetic destinations and an eightfold response-byte ratio. |

## IP — 19 vectors

Well-formed fragment and extension-header passage can be legitimate. Classify it against the configured policy. Malformed cases in this family are offline fixtures.

| ID | Type | Importance | Evidence | What it does |
| --- | --- | --- | --- | --- |
| `IP-001` | Raw | Low | Packet | Sends a UDP sample with a valid IPv4 header and checksums. |
| `IP-002` | Raw | Medium | Packet | Sends a UDP datagram as two well-formed IPv4 fragments. |
| `IP-003` | Live | Low | Exchange | Checks IPv6 reachability by opening a TCP connection. |
| `IP-004` | Raw | Medium | Packet | Sends UDP with an IPv6 Hop-by-Hop padding header. |
| `IP-005` | Raw | Medium | Packet | Sends the same two-fragment IPv4/UDP sample as IP-002; does not independently verify fragment delivery. |
| `IP-006` | Fixture | High | Offline | Corrupts the IP version field and classifies the fixture as an invalid IPv4 version. |
| `IP-007` | Fixture | High | Offline | Builds overlapping IPv4 fragments and detects their overlap. |
| `IP-008` | Fixture | High | Offline | Builds a tiny IPv4 fragment that cannot hold a complete TCP header and classifies it. |
| `IP-009` | Fixture | High | Offline | Detects an invalid IPv4 header-length field in a generated fixture. |
| `IP-010` | Fixture | High | Offline | Detects disagreement between the IPv4 total-length field and actual fixture length. |
| `IP-011` | Raw | Medium | Packet | Sends an IPv4/UDP sample with TTL=1. |
| `IP-012` | Raw | Low | Packet | Sends an IPv4/UDP sample with default DSCP and ECN ECT(0). |
| `IP-013` | Raw | Medium | Packet | Sends an IPv4/UDP sample containing NOP/EOL options. |
| `IP-014` | Raw | Medium | Packet | Sends a well-formed fragmented UDP sample using IPv6 Fragment headers. |
| `IP-015` | Raw | Medium | Packet | Sends an IPv6 Hop-by-Hop padding sample; shares IP-004's implementation. |
| `IP-016` | Raw | Medium | Packet | Sends UDP with an IPv6 Destination Options padding header. |
| `IP-017` | Raw | Medium | Packet | Sends a one-segment IPv6 routing header with Segments Left=0. |
| `IP-018` | Raw | Medium | Packet | Sends an IPv6 No Next Header sample. |
| `IP-019` | Fixture | High | Offline | Detects an IPv6 payload-length field that does not match the generated fixture. |

## DNS — 22 vectors

The query name comes from target.server_name. RD=0 is used except by DNS-012; DNS-022 generates a new name below the configured parent. Expected NXDOMAIN is valid for the relevant checks.

| ID | Type | Importance | Evidence | What it does |
| --- | --- | --- | --- | --- |
| `DNS-001` | Live | Low | Exchange | Queries the configured name for an A record over UDP. |
| `DNS-002` | Live | Low | Exchange | Queries an AAAA record over UDP. |
| `DNS-003` | Live | Low | Exchange | Queries an MX mail-server record over UDP. |
| `DNS-004` | Live | Low | Exchange | Queries a TXT record over UDP. |
| `DNS-005` | Live | Low | Exchange | Queries a CNAME alias record over UDP. |
| `DNS-006` | Live | Medium | Exchange | Issues an ANY query and validates the response; it does not guarantee that every record type is returned. |
| `DNS-007` | Live | Medium | Exchange | Queries A for the configured name and expects NXDOMAIN (RCODE=3). |
| `DNS-008` | Live | High | Trust | Cryptographically verifies a positive A RRset signature against a configured pinned Ed25519 zone key. Root-chain, wildcard, and negative-proof validation are unsupported. |
| `DNS-009` | Live | Medium | Exchange | Queries over UDP, then retries once over TCP to the same IP/port if TC=1 indicates truncation. |
| `DNS-010` | Live | Low | Exchange | Queries an NS authoritative-name-server record over UDP. |
| `DNS-011` | Live | Low | Exchange | Queries SOA zone-management information over UDP. |
| `DNS-012` | Live | High | Exchange | Requests recursion with RD=1 and observes the recursion-available flag. This alone does not establish successful arbitrary recursive resolution. |
| `DNS-013` | Live | Medium | Exchange | Advertises an EDNS0 UDP buffer of 1232 bytes and checks the response's EDNS information and size. |
| `DNS-014` | Live | Medium | Exchange | Queries TXT for the configured name and validates a truncated TC=1 response without switching to TCP. |
| `DNS-015` | Live | Medium | Exchange | Queries A, parses the answer, and requires observed name compression in the response. |
| `DNS-016` | Live | Medium | Exchange | Queries A directly over framed TCP and validates the response identity and question. |
| `DNS-017` | Model | High | Offline | DNS request-flood model: represents resolver work-queue load. |
| `DNS-018` | Model | High | Offline | DNS reflection model: uses a synthetic response-to-request byte ratio of three. |
| `DNS-019` | Model | High | Offline | DNS amplification model: uses a synthetic response-to-request byte ratio of eight. |
| `DNS-020` | Model | High | Offline | Water-torture model: represents unique-name cache misses and additional resolution work. |
| `DNS-021` | Live | High | Exchange | Runs bounded repeated A queries for the same name using DNS-001's backend. |
| `DNS-022` | Live | High | Exchange | Queries a unique isradar- subdomain beneath the configured parent on each probe; accepts validated NOERROR and NXDOMAIN responses. |

## NTP — 8 vectors

NTP-001 through NTP-005 share the ntp_basic implementation and emphasize different aspects of its response validation.

| ID | Type | Importance | Evidence | What it does |
| --- | --- | --- | --- | --- |
| `NTP-001` | Live | Low | Exchange | Sends a mode-3 client request and validates the mode-4 server response and origin timestamp. |
| `NTP-002` | Live | Low | Exchange | Observes service response/rejection through the same mode-3/mode-4 exchange. |
| `NTP-003` | Live | Medium | Exchange | Validates and reports the leap-indicator field in the NTP response. |
| `NTP-004` | Live | Medium | Exchange | Classifies stratum=0 as Kiss-of-Death and records the server's rejection code. |
| `NTP-005` | Live | Medium | Exchange | Verifies that the response's origin timestamp matches the request's transmitted timestamp. |
| `NTP-006` | Live | Low | Exchange | Sends an NTPv3 request and requires an NTPv3 response. |
| `NTP-007` | Model | High | Offline | NTP reflection model: uses a synthetic response-to-request byte ratio of two. |
| `NTP-008` | Model | High | Offline | Monlist-style amplification model: uses a synthetic tenfold response-byte ratio; sends no actual monlist query. |

## SIP — 11 vectors

Dedicated test identities are required for INVITE/REGISTER policy checks. A matched transaction rejection may be the desired policy result; interpret it against the configured expectation.

| ID | Type | Importance | Evidence | What it does |
| --- | --- | --- | --- | --- |
| `SIP-001` | Live | Low | Exchange | Sends OPTIONS over UDP and validates the final status and transaction identifiers. |
| `SIP-002` | Live | High | Exchange | Checks INVITE policy with a dedicated test identity, Require: isradar-no-session, and Max-Forwards: 0; uses bounded CANCEL/ACK/BYE cleanup when needed. |
| `SIP-003` | Live | High | Exchange | Sends REGISTER without Contact to query existing bindings and check policy; does not request a registration change. |
| `SIP-004` | Live | Medium | Exchange | Classifies OPTIONS response status using the same implementation as SIP-001. |
| `SIP-005` | Live | Medium | Exchange | Checks OPTIONS Call-ID, CSeq, and Via branch matching using the same implementation as SIP-001. |
| `SIP-006` | Fixture | Medium | Offline | Constructs a response with a nonnumeric CSeq and classifies it as malformed. |
| `SIP-007` | Live | Medium | Exchange | Performs an OPTIONS transaction over TCP and validates the final response. |
| `SIP-008` | Live | High | Trust | Performs OPTIONS over TLS with certificate-chain and hostname verification. |
| `SIP-009` | Model | High | Offline | OPTIONS Flood model: represents transaction-queue processing work. |
| `SIP-010` | Model | High | Offline | INVITE Flood model: represents transaction-state occupancy and processing work. |
| `SIP-011` | Live | High | Exchange | Runs bounded repeated UDP OPTIONS transactions using SIP-001's backend. |

## HTTP — 38 vectors

Live HTTP checks inspect status and headers without downloading the response body or following redirects. State-changing methods use an explicitly configured dedicated test path. HTTP-025/026 are offline models; HTTP-037/038 complete a real exchange with a 25 ms inter-chunk delay and do not establish capacity exhaustion.

| ID | Type | Importance | Evidence | What it does |
| --- | --- | --- | --- | --- |
| `HTTP-001` | Live | Low | Exchange | Sends GET and checks response status and headers. |
| `HTTP-002` | Live | Medium | Exchange | Sends POST and the configured body to an explicitly configured test path; checks the response. |
| `HTTP-003` | Live | Low | Exchange | Sends HEAD and checks response status and headers. |
| `HTTP-004` | Live | High | Exchange | Sends PUT to the configured dedicated test path and checks the response. |
| `HTTP-005` | Live | High | Exchange | Sends PATCH to the configured dedicated test path and checks the response. |
| `HTTP-006` | Live | High | Exchange | Sends DELETE to the configured dedicated test path and checks the response. |
| `HTTP-007` | Live | Low | Exchange | Sends OPTIONS with Max-Forwards: 0 and checks response status and headers. |
| `HTTP-008` | Live | Medium | Exchange | Sends TRACE with fixed nonsensitive headers and observes status/headers; it does not inspect an echoed response body. |
| `HTTP-009` | Live | High | Exchange | Checks CONNECT policy against the target's own numeric IP/port; sends no tunnel payload and does not test third-party proxying. |
| `HTTP-010` | Live | Low | Exchange | Checks HTTP/1.1 GET behavior using the same implementation as HTTP-001. |
| `HTTP-011` | Live | Medium | Exchange | Uses cleartext HTTP/2 prior knowledge for GET and requires an HTTP/2 response. |
| `HTTP-012` | Live | Medium | Exchange | Performs HTTP/3 GET over certificate-verified QUIC/TLS 1.3 with h3 ALPN. |
| `HTTP-013` | Live | Medium | Exchange | Sends two HEAD requests on one TCP connection, using keep-alive then close, and checks reuse. |
| `HTTP-014` | Live | Medium | Exchange | Checks the second HEAD response on the same TCP connection; shares HTTP-013's backend. |
| `HTTP-015` | Live | High | Trust | Performs HTTPS GET with certificate-chain and hostname verification. |
| `HTTP-016` | Live | High | Trust | Performs HTTPS HEAD with certificate-chain and hostname verification. |
| `HTTP-017` | Live | Medium | Exchange | Checks a redirect status and a single valid Location header without following it. |
| `HTTP-018` | Live | Medium | Exchange | Sends configured request headers and requires exact, single-valued expected response headers. |
| `HTTP-019` | Live | Medium | Exchange | Checks a configured API health path; expects HTTP 200 unless a different status is explicitly configured. |
| `HTTP-020` | Live | Low | Exchange | Classifies the GET response status using HTTP-001's implementation. |
| `HTTP-021` | Model | High | Offline | GET Flood model: represents a high-volume GET work queue. |
| `HTTP-022` | Model | High | Offline | POST Flood model: represents request-body processing work. |
| `HTTP-023` | Model | High | Offline | HEAD Flood model: represents a high-volume HEAD work queue. |
| `HTTP-024` | Model | High | Offline | Dynamic Flood model: represents cache misses and more expensive dynamic-response work. |
| `HTTP-025` | Model | High | Offline | Slowloris model: represents connection slots occupied by incomplete request headers. |
| `HTTP-026` | Model | High | Offline | Slow POST / RUDY model: represents long occupancy while a request body remains incomplete. |
| `HTTP-027` | Model | High | Offline | GoldenEye model: represents connection-reuse work and occupancy; does not run the named tool. |
| `HTTP-028` | Model | High | Offline | Tor's Hammer model: represents slow-POST processing and occupancy; does not run the named tool. |
| `HTTP-029` | Model | High | Offline | MHDDOS GET model: generates synthetic GET-labeled work. |
| `HTTP-030` | Model | High | Offline | MHDDOS HEAD model: generates synthetic HEAD-labeled work. |
| `HTTP-031` | Model | High | Offline | MHDDOS EVEN model: alternates synthetic GET and HEAD work. |
| `HTTP-032` | Model | High | Offline | MHDDOS CFB model: represents uncached work costs; does not perform a protection-bypass technique. |
| `HTTP-033` | Model | High | Offline | MHDDOS BRUST model: represents intermittent workload bursts. BRUST is the catalog spelling. |
| `HTTP-034` | Model | High | Offline | HTTPS MHDDOS GSB model: represents higher processing cost and occupancy for synthetic HTTPS work. |
| `HTTP-035` | Live | High | Exchange | Runs bounded repeated GET requests using HTTP-001's backend. |
| `HTTP-036` | Live | High | Exchange | Runs bounded repeated POST requests against the configured test path using HTTP-002's backend. |
| `HTTP-037` | Live | High | Exchange | Completes request headers in two parts separated by 25 ms, then checks the response; each probe is a complete exchange. |
| `HTTP-038` | Live | High | Exchange | Sends a POST body in two parts separated by 25 ms, then checks the response; each probe is a complete exchange. |

## TLS — 13 vectors

These checks assess negotiation or trust properties. Packet arrival alone does not establish a TLS policy failure. For TLS-006/009/010, the specific expected rejection is the desired result; a failed handshake is not automatically a weakness.

| ID | Type | Importance | Evidence | What it does |
| --- | --- | --- | --- | --- |
| `TLS-001` | Live | High | Trust | Performs a TLS 1.2-only handshake with certificate-chain and hostname validation. |
| `TLS-002` | Live | High | Trust | Performs a TLS 1.3-only handshake with certificate-chain and hostname validation. |
| `TLS-003` | Live | High | Trust | Validates the server's certificate chain and hostname and reports certificate metadata. |
| `TLS-004` | Live | Medium | Trust | Makes two TLS 1.2 connections with a shared session cache and checks resumption on the second handshake. |
| `TLS-005` | Live | Medium | Trust | Reports the negotiated suite from the client's supported safe suites; does not enumerate all server cipher suites. |
| `TLS-006` | Live | High | Trust | Attempts TLS 1.3 and expects a ProtocolVersion or HandshakeFailure rejection from the configured negative test service. |
| `TLS-007` | Live | High | Trust | Uses the configured SNI/hostname and verifies certificate-name matching; shares TLS-003's backend. |
| `TLS-008` | Live | Medium | Trust | Offers h2 and http/1.1 ALPN and requires a negotiated application protocol. |
| `TLS-009` | Live | High | Trust | Checks that an expired-certificate test service is rejected specifically for certificate expiry. Expected rejection is a passing negative check. |
| `TLS-010` | Live | High | Trust | Checks that a name-mismatched certificate is rejected specifically for hostname mismatch. Expected rejection is a passing negative check. |
| `TLS-011` | Model | High | Offline | THC-SSL-DOS-style model: represents synthetic handshake processing-budget consumption. |
| `TLS-012` | Model | High | Offline | Renegotiation-exhaustion model: represents repeated negotiation costs and occupancy without actual renegotiation. |
| `TLS-013` | Live | High | Trust | Runs bounded repeated certificate-verified TLS 1.3 handshakes using TLS-002's backend. |

## SPECIAL — 10 vectors

Every entry in this family is offline. No result in this table can supply target packet counts or a live mitigation score.

| ID | Type | Importance | Evidence | What it does |
| --- | --- | --- | --- | --- |
| `SPECIAL-001` | Model | High | Offline | Multi-vector model: distributes TCP, UDP, and HTTP work across three synthetic destinations with a shared work budget. |
| `SPECIAL-002` | Model | High | Offline | Carpet-bombing model: distributes work across 16 synthetic destinations. |
| `SPECIAL-003` | Model | High | Offline | Low-and-slow model: represents a small number of jobs holding resources for a long time. |
| `SPECIAL-004` | Model | High | Offline | Volumetric model: represents large batches of work and synthetic byte budgets. |
| `SPECIAL-005` | Model | High | Offline | Reflection/amplification model: uses a synthetic response-to-request byte ratio of six. |
| `SPECIAL-006` | Fixture | Medium | Offline | Constructs IKEv2 SA_INIT headers and SA/KE/Nonce payload framing; does not establish an IPsec tunnel. |
| `SPECIAL-007` | Fixture | Low | Offline | Checks SMTP HELO request and 250 reply syntax locally; does not contact an SMTP server. |
| `SPECIAL-008` | Model | High | Offline | Correlates TCP, UDP, and HTTP work across three synthetic destinations under a shared availability budget. |
| `SPECIAL-009` | Model | High | Offline | Mitigation-transition model: changes synthetic capacity over time and calculates accepted/rejected work. |
| `SPECIAL-010` | Model | Medium | Offline | Recovery-window model: stops synthetic arrivals and tracks completion and resource release. |

## Source and profile reference

Each example profile is at `external-agent/vectors/profiles/cases/<ID>.yaml`. Configure the service, numeric address, port, hostname, and expected result before execution.

- [Catalog: IDs, names, layers, modes, and backends](external-agent/vectors/catalog.yaml)
- [Per-ID implementation matrix](docs/vector-coverage.md)
- [Live protocol dispatch and DNS/NTP/SIP checks](external-agent/src/vectors/protocols.rs)
- [Raw packet sending and TCP flag mapping](external-agent/src/network/raw.rs)
- [Packet construction, options, and fragments](external-agent/src/network/packets.rs)
- [TCP sessions, HTTP reuse, and split writes](external-agent/src/network/sessions.rs)
- [HTTP response checks](external-agent/src/network/http_checks.rs)
- [TLS checks](external-agent/src/network/tls_checks.rs)
- [SIP INVITE/REGISTER policy checks](external-agent/src/network/sip_policy.rs)
- [Offline event models](external-agent/src/vectors/event_models.rs)
- [Offline protocol fixtures](external-agent/src/network/lab_fixtures.rs)
- [Offline result generation](external-agent/src/vectors/lab.rs)
- [Execution limits and raw admission](external-agent/src/engine/mod.rs)
- [YAML configuration](docs/configuration.md)
- [Counter and observation semantics](docs/measurement.md)
- [HTTP request correlation](docs/http-log-correlation.md)
- [HTTP log-comparison tool](scripts/compare_http_logs.py)
