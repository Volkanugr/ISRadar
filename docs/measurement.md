# Measurement in the sender phase

The default agent is a sender. The UDP receiver and target-side packet capture belong to a later phase. HTTP probe identities can already be matched against existing server access logs; this does not start a separate receiver service. [HTTP log correlation](http-log-correlation.md).

## What is currently known

- The number of admitted, completed, and cancelled probes.
- UDP datagrams accepted by the operating system's local socket.
- Directly counted UDP and direct TCP application/frame bytes; bytes already sent are retained even after a timeout.
- Normal protocol responses, errors, timeouts, HTTP status codes, and observed latency.
- Requested limits, actual duration, and termination reason.

`measurement.await_ack: false` is the default. In the sequenced UDP check, `sent` means **local send acceptance**. It does not prove target receipt, firewall traversal, or service resilience. Without a receiver, target loss and delivery rates cannot be calculated. A datagram is not counted as sent if a local network error occurs.

A TCP connection, HTTP request, or TLS handshake is not a single network packet. `packets_sent` and `wire_bytes_sent` remain `null` because there is no observation that conclusively attributes actual wire packets to the agent. UDP application datagrams have a separate counter. IP fragmentation and kernel retransmissions cannot be inferred from that counter.

## Frame prepared for the next phase

UDP-010 produces a 64-byte authenticated frame:

| Offset | Length | Contents |
| --- | ---: | --- |
| 0 | 8 | `ISRDP001` request magic |
| 8 | 16 | Random measurement `run_id` |
| 24 | 8 | Big-endian sequence number |
| 32 | 32 | HMAC-SHA256 tag over the first 32 bytes |

Every new run needs a new run_id. The measurement HMAC key associates packet identities; it is not operator approval. Sender evidence stores the sequence numbers accepted by the local socket. The frame and sequence list are retained for matching in the later receiver phase.

Optional `await_ack: true` expects an `ISRDA001` frame from the future receiver protocol with the same run_id/sequence number and a valid HMAC. The default example does not use this. A normal UDP echo response is not a substitute for this ACK. A missing ACK alone does not prove that the target blocked the packet.

## Planned receiver-phase work

Unique sent sequence numbers will be compared with those observed behind the protection system. The comparison will distinguish packets not observed at the target, duplicates, and packets that reached the target but whose ACK did not return. Placement and observation loss will be included in the report. Resilience assessment will also be correlated with business-service latency and error rates.

References: [UDP — RFC 768](https://www.rfc-editor.org/rfc/rfc768), [HMAC — RFC 2104](https://www.rfc-editor.org/rfc/rfc2104).

## Raw samples and local egress observation

`raw_ip_packets_accepted` and `raw_ip_bytes_accepted` count bounded raw-socket sends accepted by the local operating system. They do not count physical wire/driver transmission, target observations, or responses. These values cannot be used to derive packet counts for standard TCP/HTTP/TLS traffic.

For a sender built with `packet-capture`, `protocol.capture.interface` enables libpcap. Capture opens before the first send, promiscuous mode is disabled, `Direction::Out` is required, and the BPF selects only the configured numeric target IP. Users cannot supply BPF expressions, other targets, or payload replay. Interface/filter setup errors reject execution before the first send. Capture runtime errors or the 100,000-observation limit stop execution; final kernel/interface drop counters are reported.

`outbound_capture.packets_observed` and `captured_packet_bytes` cover all outbound traffic observed on the selected interface to the target IP, potentially including fragments and other processes' traffic to the same target. Full packet contents are not retained; lengths are counted. Capture length does not represent full wire utilization including Ethernet preamble/FCS/IFG. Driver offload, interface selection, and capture drops affect the difference between observation and physical transmission. These values therefore do not replace `metrics.packets_sent` and do not count as target delivery.

`responses_received` and `tcp_handshake_successes` count **probes** with a validated response/successful TCP connection, not packets or every message within a probe. `http_responses_received`, `http_successes`, and `http_errors` count observed HTTP response statuses, including both HEAD responses in a reuse probe. Direct UDP datagram counters count datagrams actually observed. If a probe ends in an error or cancellation, intermediate protocol steps may not all become observation records; atomic application/raw send counters are retained.
