# L4 catalog and batch execution

The L4 catalog contains **48 entries**: **41 live protocol implementations** and **7 offline event models**. The live implementations comprise 22 raw samples and 19 socket/protocol checks. Every L4 entry has source code; the seven models have no live attack implementation. Acceptance testing of all live paths on Linux/Docker remains incomplete.

| Entries | Implementation | Execution requirements |
| --- | --- | --- |
| TCP-001, 016, 022, 023 | Connect/close, timeout classification, IPv4/IPv6 reachability | TCP port and an IP version matching the entry |
| TCP-002–015, 020–021 | SYN, SYN-ACK, ACK, RST, FIN, PSH, URG, and flag combinations | IPv4, Linux, NET_RAW; a newly reserved source port |
| TCP-017–019, 033 | Half-close/EOF, echo, two messages on one connection, and bounded session occupancy | TCP echo service |
| TCP-024–027 | Window, MSS, timestamp, SACK options | IPv4, Linux, NET_RAW |
| TCP-028–032 | SYN/ACK/RST/FIN flood and state exhaustion | Offline event models only |
| UDP-001, 003–004, 006–009, 012, 015 | Echo, 0/64/128/1200 bytes, IPv4/IPv6, connected-peer validation, and bounded random-datagram workload | UDP echo service |
| UDP-002 | Observe the OS response for a closed UDP port | A separate UDP port known to be closed |
| UDP-005, 011 | Valid IPv4 fragment/checksum samples | IPv4 UDP test port, Linux, NET_RAW |
| UDP-010 | Authenticated, sequenced 64-byte UDP sender | Explicit UDP destination port; does not wait for ACKs in this phase |
| UDP-013–014 | UDP flood/amplification | Offline event models only |

Slowloris (`HTTP-025`) is an **L7** entry and is not part of the L4 set. Its offline model is included in `full-test`. It does not measure slow-connection behavior or Slowloris resilience on a real server.

## Generate every L4 YAML file

```sh
cargo build --release --workspace --locked
./target/release/external-agent profiles create --preset l4 --directory profiles/l4
```

This command creates a separate YAML file for each of the 48 entries and a new measurement key/identity for UDP-010; it sends no traffic. Examples start with loopback addresses. Executing raw samples requires Linux and NET_RAW. Inspect individual entries with commands such as `vectors info TCP-002`.

## L4 plan in Docker

```sh
bash scripts/docker-web-test.sh 212.252.162.17 online.solvitsoftware.com l4-test
```

The hostname is part of the shared script interface; L4 configurations do not use it. The default TCP port is 80. To use 443:

```sh
ISRADAR_TCP_PORT=443 bash scripts/docker-web-test.sh 212.252.162.17 online.solvitsoftware.com l4-test
```

The default IPv4 plan has 23 live entries, 7 offline models, and 18 entries awaiting configuration. All seven models run in one `offline-l4` step with networking disabled. UDP/echo ports are not guessed, and echo data is not sent to an HTTP port.

Specify service ports once suitable target services are ready. The following numbers are examples; their services are not assumed to exist on the current web server:

```sh
ISRADAR_TCP_PORT=80 \
ISRADAR_TCP_ECHO_PORT=9003 \
ISRADAR_UDP_PORT=9000 \
ISRADAR_UDP_CLOSED_PORT=9004 \
ISRADAR_UDP_MEASUREMENT_PORT=9005 \
bash scripts/docker-web-test.sh TARGET_IP test.example.com l4-test
```

The TCP echo service must return the sent bytes unchanged, support two messages on the same connection, and return EOF after the final echo when the client shuts down its write half. UDP echo must return 0–1200 bytes unchanged. The port specified for UDP-002 must be closed. UDP-010 sends without waiting for a receiver; it cannot measure loss/delivery counts alone. A measurement key is generated in the new run directory with `0600` permissions; it is not an operator approval key.

With all these ports configured, the IPv4 plan contains **39 live + 7 offline + 2 awaiting an IPv6 target**. The same ports with an IPv6 target produce **17 live + 7 offline + 24 awaiting an IPv4 target**. Combining the plans for both IP versions covers all 41 live entry paths; this does not mean the tests have executed successfully.

You can also generate a plan without running Docker:

```sh
python3 scripts/prepare_l4_test.py --target-ip TARGET_IP --directory l4-plan \
  --tcp-port 80 --tcp-echo-port 9003 --udp-port 9000 \
  --udp-closed-port 9004 --udp-measurement-port 9005
```

## Budgets and result semantics

Normal live steps use 100 probes, a target rate of 10/second, and at most 8 workers. Raw steps are limited to 1 probe/second, one worker, and at most 16 IP packets total. UDP-005 sends two fragments per probe, so it uses 8 probes. These budgets apply per step; the health threshold or STOP can end a step earlier.

`configs/index.json` records the mode, status, target, and pending reason for all 48 IDs. `catalog-results.json` matches each ID to its actual report. `live_completed` means execution completed; it does not mean the traffic traversed the firewall. Missing services are not counted as tested or successful.

`sent` and `raw_ip_packets_accepted` mean the local socket accepted the packet. A SYN-ACK sample is a standalone SYN-ACK packet, not a measurement of the response to a SYN. To verify target delivery, inspect target packet captures together with the source/destination tuple and packet identifier in the report; NAT can change the source address/port. Attributing blocking to UniFi also requires a matching UniFi record. Offline models produce none of this evidence.

Raw containers use only the NET_RAW capability, a read-only data mount, and tmpfs for reports. Other steps do not receive this capability. Docker raw transmission has not yet been validated in the current user environment; local structure/plan tests do not replace that validation.
