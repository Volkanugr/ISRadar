#!/usr/bin/env python3
"""Generate the independent catalog, not a vendor's proprietary vector list."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = {
    "TCP": ("tcp", "L4", "TCP", "https://www.rfc-editor.org/rfc/rfc9293"),
    "UDP": ("udp", "L4", "UDP", "https://www.rfc-editor.org/rfc/rfc768"),
    "ICMP": ("icmp", "L3", "ICMP", "https://www.rfc-editor.org/rfc/rfc792"),
    "IP": ("ip", "L3", "IP", "https://www.rfc-editor.org/rfc/rfc8200"),
    "DNS": ("dns", "L7", "DNS", "https://www.rfc-editor.org/rfc/rfc1035"),
    "NTP": ("ntp", "L7", "NTP", "https://www.rfc-editor.org/rfc/rfc5905"),
    "SIP": ("sip", "L7", "SIP", "https://www.rfc-editor.org/rfc/rfc3261"),
    "HTTP": ("http", "L7", "HTTP", "https://www.rfc-editor.org/rfc/rfc9110"),
    "TLS": ("tls", "L7", "TLS", "https://www.rfc-editor.org/rfc/rfc8446"),
    "SPECIAL": ("specialized", "L7", "MIXED", "https://www.rfc-editor.org/rfc/rfc4732"),
}

# C = metadata only; M = offline event model; P/F = offline protocol fixtures.
# A concrete backend name is an implemented bounded live protocol check.
ROWS = {
    "TCP": [
        ("TCP connection establishment and graceful close", "tcp_connect"),
        ("TCP SYN packet sample", "raw_tcp_flags", 4), ("TCP SYN-ACK packet sample", "raw_tcp_flags", 4),
        ("TCP ACK packet sample", "raw_tcp_flags", 4), ("TCP RST packet sample", "raw_tcp_flags", 4),
        ("TCP FIN packet sample", "raw_tcp_flags", 4), ("TCP PSH packet sample", "raw_tcp_flags", 4),
        ("TCP URG packet sample", "raw_tcp_flags", 4), ("TCP SYN-FIN packet sample", "raw_tcp_flags", 4),
        ("TCP ACK-SYN packet sample", "raw_tcp_flags", 4), ("TCP ACK-RST packet sample", "raw_tcp_flags", 4),
        ("TCP ACK-PSH packet sample", "raw_tcp_flags", 4), ("TCP RST-SYN packet sample", "raw_tcp_flags", 4),
        ("TCP ALL FLAGS packet sample", "raw_tcp_flags", 4), ("TCP NULL FLAGS packet sample", "raw_tcp_flags", 4),
        ("TCP connection timeout classification", "tcp_connect"), ("TCP half-close echo and EOF validation", "tcp_half_close"),
        ("TCP established-session echo data validation", "tcp_echo"), ("TCP established-session continuity", "tcp_session"),
        ("TCP reset sample on a fresh reserved tuple", "raw_tcp_flags", 4), ("TCP out-of-state ACK sample on a fresh tuple", "raw_tcp_flags", 4),
        ("TCP IPv4 connection reachability", "tcp_connect", 4),
        ("TCP IPv6 connection reachability", "tcp_connect", 6),
        ("TCP window-size sample", "raw_tcp_window", 4), ("TCP MSS=1200 option sample", "raw_tcp_mss", 4),
        ("TCP timestamp option sample", "raw_tcp_timestamp", 4), ("TCP SACK-permitted option sample", "raw_tcp_sack", 4),
        ("TCP SYN Flood", "M"), ("TCP ACK Flood", "M"), ("TCP RST Flood", "M"),
        ("TCP FIN Flood", "M"), ("TCP state exhaustion", "M"),
        ("Bounded live TCP session-occupancy workload", "tcp_session"),
        ("TCP SYN Flood live half-open sample", "raw_tcp_syn_flood", 4),
    ],
    "UDP": [
        ("UDP echo service reachability and response", "udp_echo"),
        ("UDP closed-port response observation", "udp_closed_port"), ("UDP fixed 128-byte payload echo", "udp_echo128"),
        ("UDP 1200-byte echo validation", "udp_echo1200"), ("UDP well-formed IPv4 fragment sample", "raw_ipv4_fragments", 4),
        ("UDP bounded random 64-byte payload echo", "udp_echo_random"), ("UDP zero-length echo validation", "udp_echo_zero"),
        ("UDP IPv4 echo response", "udp_echo", 4), ("UDP IPv6 echo response", "udp_echo", 6),
        ("UDP authenticated sequence sender", "udp_delivery"),
        ("UDP valid IPv4 pseudo-header checksum sample", "raw_ipv4_header", 4), ("UDP connected-peer response-source validation", "udp_echo"),
        ("UDP Flood", "M"), ("UDP amplification", "M"),
        ("Bounded live UDP datagram workload", "udp_echo_random"),
    ],
    "ICMP": [
        ("ICMP IPv4 Echo Request and Reply", "icmp_echo", 4),
        ("ICMPv6 Echo Request and Reply", "icmp_echo", 6),
        ("ICMP Destination Unreachable sample", "raw_icmp_unreachable", 4), ("ICMP Time Exceeded sample", "raw_icmp_time_exceeded", 4),
        ("ICMP fragmentation-needed error fixture", "F"), ("ICMP echo policy observation", "icmp_echo", 4),
        ("ICMP redirect offline fixture", "F"), ("ICMP parameter-problem sample", "raw_icmp_parameter", 4),
        ("ICMPv6 Packet Too Big offline fixture", "F"), ("ICMP timestamp request sample", "raw_icmp_timestamp", 4),
        ("ICMP error quotation offline validation", "F"), ("ICMP Echo offline checksum fixture", "P"),
        ("ICMP Flood (Ping Flood)", "M"), ("Smurf-style broadcast scenario", "M"),
    ],
    "IP": [
        ("IPv4 valid header and checksum packet sample", "raw_ipv4_header", 4),
        ("IPv4 well-formed two-fragment UDP sample", "raw_ipv4_fragments", 4), ("IPv6 TCP reachability", "tcp_connect", 6),
        ("IPv6 hop-by-hop padding header sample", "raw_ipv6_hop_by_hop", 6), ("IPv4 fragment delivery sample", "raw_ipv4_fragments", 4),
        ("Malformed IP offline classification", "F"), ("IPv4 overlapping-fragment offline fixture", "F"),
        ("IPv4 tiny-fragment offline fixture", "F"), ("IPv4 invalid-header-length offline fixture", "F"),
        ("IPv4 total-length-mismatch offline fixture", "F"), ("IPv4 TTL=1 sample", "raw_ipv4_ttl", 4),
        ("IPv4 default-DSCP ECT(0) sample", "raw_ipv4_ecn", 4), ("IPv4 NOP/EOL option sample", "raw_ipv4_options", 4),
        ("IPv6 well-formed fragment-header sample", "raw_ipv6_fragments", 6), ("IPv6 hop-by-hop padding sample", "raw_ipv6_hop_by_hop", 6),
        ("IPv6 destination-options padding sample", "raw_ipv6_destination", 6), ("IPv6 one-segment routing header with Segments Left=0", "raw_ipv6_routing", 6),
        ("IPv6 no-next-header sample", "raw_ipv6_no_next", 6), ("IPv6 invalid-payload-length offline fixture", "F"),
    ],
    "DNS": [
        ("DNS A authoritative-service query", "dns_a"), ("DNS AAAA authoritative-service query", "dns_aaaa"),
        ("DNS MX authoritative-service query", "dns_mx"), ("DNS TXT authoritative-service query", "dns_txt"),
        ("DNS CNAME authoritative-service query", "dns_cname"), ("DNS ANY authorized-service query", "dns_any"),
        ("DNS NXDOMAIN behavior for the configured qname", "dns_nxdomain"), ("DNSSEC response authenticity", "dnssec"),
        ("DNS UDP/TCP fallback", "dns_tcp_fallback"), ("DNS NS authoritative-service query", "dns_ns"),
        ("DNS SOA authoritative-service query", "dns_soa"), ("DNS recursion policy", "dns_recursion"),
        ("DNS EDNS0 1232-byte buffer policy", "dns_edns"), ("DNS truncated-response policy", "dns_truncation"),
        ("DNS compressed-name handling", "dns_compressed"), ("DNS TCP transaction-ID validation", "dns_tcp"),
        ("DNS request flood", "M"), ("DNS reflection", "M"),
        ("DNS amplification", "M"), ("DNS water-torture (random subdomain) scenario", "M"),
        ("Bounded live DNS query workload", "dns_a"),
        ("Bounded live unique-subdomain DNS workload", "dns_unique_a"),
    ],
    "NTP": [
        ("NTP basic mode-3 request and mode-4 response", "ntp_basic"),
        ("NTP mode-3/mode-4 service-policy observation", "ntp_basic"), ("NTP leap-indicator validation", "ntp_basic"),
        ("NTP kiss-of-death response classification", "ntp_basic"), ("NTP origin-timestamp validation", "ntp_basic"),
        ("NTPv3 request/response compatibility", "ntp_v3"), ("NTP reflection", "M"),
        ("NTP amplification (monlist-style)", "M"),
    ],
    "SIP": [
        ("SIP OPTIONS transaction check", "sip_options"), ("SIP INVITE policy", "sip_invite"),
        ("SIP REGISTER policy", "sip_register"), ("SIP OPTIONS response status classification", "sip_options"),
        ("SIP OPTIONS Call-ID/CSeq/branch validation", "sip_options"), ("SIP malformed-response offline fixture", "F"),
        ("SIP OPTIONS over TCP", "sip_tcp"), ("SIP OPTIONS over certificate-verified TLS", "sip_tls"),
        ("SIP OPTIONS Flood", "M"), ("SIP INVITE Flood", "M"),
        ("Bounded live SIP OPTIONS workload", "sip_options"),
    ],
    "HTTP": [
        ("HTTP GET status and headers", "http_get"), ("HTTP POST to an explicitly configured test path", "http_post"),
        ("HTTP HEAD status and headers", "http_head"), ("HTTP PUT to an explicitly configured test path", "http_put"),
        ("HTTP PATCH to an explicitly configured test path", "http_patch"), ("HTTP DELETE at an explicitly configured test path", "http_delete"),
        ("HTTP OPTIONS status and headers", "http_options"), ("HTTP TRACE with fixed non-sensitive headers", "http_trace"),
        ("HTTP CONNECT policy", "http_connect"), ("HTTP/1.1 status check", "http_get"),
        ("HTTP/2 cleartext prior-knowledge status check", "http2_get"), ("HTTP/3 policy", "http3_get"),
        ("HTTP HEAD keep-alive on one TCP connection", "http_reuse"), ("HTTP second-request connection reuse", "http_reuse"),
        ("HTTPS GET with certificate validation", "https_get"),
        ("HTTPS HEAD with certificate validation", "https_head"),
        ("HTTP redirect inspection without following Location", "http_redirect"), ("HTTP configured request/response header assertions", "http_headers"),
        ("API health-check at a configured path", "http_health"), ("HTTP status-code classification", "http_get"),
        ("HTTP GET Flood", "M"), ("HTTP POST Flood", "M"), ("HTTP HEAD Flood", "M"),
        ("HTTP Dynamic Flood", "M"), ("HTTP Slowloris", "M"), ("HTTP Slow POST (RUDY)", "M"),
        ("HTTP GoldenEye", "M"), ("HTTP Tor's Hammer", "M"),
        ("HTTP MHDDOS GET", "M"), ("HTTP MHDDOS HEAD", "M"), ("HTTP MHDDOS EVEN", "M"),
        ("HTTP MHDDOS CFB", "M"), ("HTTP MHDDOS BRUST", "M"), ("HTTPS MHDDOS GSB", "M"),
        ("Bounded live HTTP GET workload", "http_get"),
        ("Bounded live HTTP POST workload", "http_post"),
        ("Bounded live partial-header HTTP workload", "http_slow_headers"),
        ("Bounded live slow-body HTTP workload", "http_slow_body"),
    ],
    "TLS": [
        ("TLS 1.2 certificate-verified handshake", "tls12"),
        ("TLS 1.3 certificate-verified handshake", "tls13"),
        ("TLS certificate-chain and hostname validation", "tls_certificate"), ("TLS 1.2 session-resumption observation", "tls_resume"),
        ("TLS safe cipher-suite negotiation observation", "tls_cipher"), ("TLS negotiation-failure policy", "tls_negotiation_failure"),
        ("TLS configured SNI and hostname validation", "tls_certificate"), ("TLS h2/http1.1 ALPN negotiation", "tls_alpn"),
        ("TLS expired-certificate policy", "tls_expired"), ("TLS hostname-mismatch policy", "tls_name_mismatch"),
        ("SSL/TLS negotiation flood (THC-SSL-DOS style)", "M"),
        ("TLS renegotiation resource exhaustion", "M"),
        ("Bounded live TLS negotiation workload", "tls13"),
    ],
    "SPECIAL": [
        ("Multi-vector DDoS simulation", "M"), ("Carpet-bombing simulation", "M"),
        ("Low-and-slow DDoS simulation", "M"), ("Volumetric DDoS simulation", "M"),
        ("Reflection/amplification simulation", "M"),
        ("IPsec IKEv2 SA_INIT syntax offline fixture", "F"), ("SMTP HELO exchange offline fixture", "F"),
        ("Offline multi-protocol availability event correlation", "M"),
        ("Multi-stage mitigation transition", "M"), ("Synthetic recovery-window model", "M"),
    ],
}


def entries():
    result = []
    for family, rows in ROWS.items():
        category, layer, protocol, reference = FAMILIES[family]
        for index, row in enumerate(rows, 1):
            name, backend, *version = row
            marker = backend
            mode = "catalog_only" if marker == "C" else "lab_emulation" if marker in ("M", "P", "F") else "live_validation"
            backend = {"C": "catalog", "M": "offline_model", "P": "offline_packet", "F": "offline_policy_fixture"}.get(marker, marker)
            description = {
                "catalog_only": "Registry metadata only; no executable implementation. Protocol reference is not evidence of vendor parity.",
                "lab_emulation": "Offline only. Finite family-specific state/event fixture; no attack traffic and no measured mitigation efficacy.",
                "live_validation": "Bounded protocol check against an exact configured numeric destination. No inference about security-appliance blocking.",
            }[mode]
            if marker == "P":
                description = "Offline IPv4/ICMP documentation-address fixture; validates header and ICMP checksum. Never transmitted or replayed."
            if marker == "F":
                description = "Concrete offline protocol fixture with byte-level generation and classification. No sockets, replay, real attack traffic or destination delivery claims."
            if backend == "udp_delivery":
                description = "Sender-only authenticated, sequence-numbered 64-byte UDP datagrams. Default await_ack=false records local socket acceptance as sent, not destination delivery. Optional authenticated ACK handling follows the future receiver protocol."
            if backend == "tcp_connect":
                description += " Uses standard TCP connect and close only; does not validate arbitrary TCP flag policy."
            if backend.startswith("dns_"):
                if backend == "dns_unique_a":
                    description += " Generates a unique isradar- subdomain below the configured parent qname for each probe; RD=0; validated NOERROR and NXDOMAIN responses are accepted. UDP only."
                else:
                    description += " Fixed configured qname; RD=0 except the explicit recursion-policy check; no random-subdomain requests."
                    description += " One TCP retry to the same IP/port on TC=1; response capped at 4096 bytes." if backend == "dns_tcp_fallback" else " Framed TCP response capped at 4096 bytes." if backend == "dns_tcp" else " UDP only."
            if backend == "dnssec":
                description += " Positive IN A RRset RRSIG is cryptographically verified with a configured pinned Ed25519 zone anchor; wildcard, negative proofs and recursive root-chain validation are unsupported."
            if backend in ("sip_invite", "sip_register"):
                description += " Configured dedicated isradar- test identity required. REGISTER queries bindings without Contact. INVITE requires an unsupported no-session extension, Max-Forwards:0 and bounded cleanup; 1 probe/second, one worker and 16 probes maximum."
            if backend == "http_connect":
                description += " CONNECT authority is the configured target IP/port itself; no tunnel payload. Dedicated endpoint grant, 1 probe/second, one worker and 16 probes maximum."
            if backend == "http3_get":
                description += " QUIC with certificate-verified TLS1.3 and h3 ALPN, pinned destination; status and headers only."
            if backend.startswith("raw_"):
                description = "Linux low-volume raw packet sample. Execution requires an explicit target, an OS-owned source address and a fresh reserved source port. At most 1 probe/second, one worker, 16 total IP samples and 60 seconds. Existing TCP connections are never targeted; no spoofing, reflection or delivery inference."
            if backend in ("http_post", "http_put", "http_patch", "http_delete", "http_headers", "http_health", "http_slow_body"):
                description += " HTTP path/body/headers are read from the validated protocol settings. State-changing methods require an explicitly attested dedicated test endpoint."
            if backend in ("http_slow_headers", "http_slow_body"):
                description += " Sends one complete exchange per probe, split into two chunks with a 25 ms delay; no capacity-exhaustion or Slowloris/RUDY equivalence claim."
            tests = ["catalog_integrity"]
            if marker == "M": tests += ["offline_vectors_do_not_send", "models_conserve_events_and_release_all_resources"]
            elif marker == "P": tests += ["ipv4_fixture_checksums"]
            elif marker == "F": tests += ["required_unsafe_packet_cases_are_real_offline_fixtures"]
            elif marker != "C": tests += ["backend_contracts"]
            if f"{family}-{index:03}" in ("TCP-033", "UDP-015", "DNS-021", "DNS-022", "SIP-011", "HTTP-035", "HTTP-036", "HTTP-037", "HTTP-038", "TLS-013"):
                tests += ["bounded_live_variants_execute_real_protocol_exchanges"]
            if backend in ("tcp_connect", "udp_echo", "http_get", "http_head", "http_options"):
                tests += ["live_protocol_smoke"]
            if backend == "udp_delivery": tests += ["sender_datagrams_without_listener_ack", "sender_frame_matches_golden_vector"]
            if backend in ("tcp_echo", "udp_echo_zero", "udp_echo1200", "dns_tcp_fallback", "http2_get"):
                tests += ["extended_live_protocols"]
            if backend.startswith("raw_"): 
                tests += ["raw_sample_admission_is_stricter_than_normal_traffic"]
                if backend == "raw_tcp_flags":
                    tests += ["all_tcp_flag_samples_have_valid_headers_and_checksums"]
                elif backend == "raw_tcp_syn_flood":
                    tests += ["syn_flood_sample_is_a_bounded_raw_syn_burst"]
                elif backend.startswith("raw_ipv6_"):
                    tests += ["ipv6_extensions_and_fragments_keep_the_authorized_destination"]
                elif backend == "raw_ipv4_fragments":
                    tests += ["ipv4_fragments_reassemble_to_one_valid_udp_datagram"]
                elif backend in ("raw_icmp_unreachable", "raw_icmp_time_exceeded"):
                    tests += ["icmp_error_samples_quote_only_the_reserved_probe_tuple"]
                else:
                    tests += ["tcp_options_ipv4_options_and_icmp_timestamps_are_real_wire_fields"]
            if backend in ("udp_closed_port", "udp_echo128", "udp_echo_random"):
                tests += ["additional_protocol_transports"]
            if backend in ("http_post", "http_put", "http_patch", "http_delete", "http_trace", "http_redirect", "http_headers", "http_health", "http_reuse"):
                tests += ["configured_http_operations_and_connection_reuse"]
            if backend.startswith(("http_", "https_")) or backend in ("http2_get", "http3_get"):
                if backend == "http_reuse":
                    tests += ["http_reuse_handles_coalesced_informational_responses_in_memory"]
                else:
                    tests += ["http_policy_failures_preserve_observed_status_and_response"]
            if backend == "http_redirect": tests += ["redirects_require_one_location_and_bounded_headers"]
            if backend in ("tls_certificate", "tls_cipher", "tls_alpn", "tls_resume"):
                tests += ["verified_tls_negotiation_and_resumption"]
            if backend in ("sip_tcp", "ntp_v3", "tcp_session", "tcp_half_close"):
                tests += ["additional_protocol_transports"]
            if backend in ("sip_options", "sip_tcp", "sip_tls"):
                tests += ["sip_transactions_reject_duplicate_headers_and_branch_confusion"]
            if backend in ("sip_tcp", "sip_tls"):
                tests += ["sip_options_waits_for_final_status_in_memory"]
            if backend == "sip_tls": tests += ["verified_tls_negotiation_and_resumption"]
            if backend in ("ntp_basic", "ntp_v3"):
                tests += ["ntp_kiss_of_death_accepts_alarm_leap_but_requires_matching_origin"]
            if backend in ("sip_invite", "sip_register"):
                tests += ["sip_policy_uses_dedicated_identity_and_matching_transactions"]
            if backend in ("dns_any", "dns_nxdomain", "dns_edns", "dns_tcp", "dns_recursion", "dns_truncation", "dns_compressed", "dnssec"):
                tests += ["dns_policy_and_signed_rrset_validation"]
            if backend.startswith("dns_") or backend == "dnssec":
                tests += ["edns_extended_errors_are_not_reported_as_success", "edns_opt_must_be_in_the_additional_section"]
            if backend == "dnssec": tests += ["dnssec_verifies_signed_rrsets_and_rejects_tampering_even_with_ad"]
            if (family == "SPECIAL" and marker == "M") or f"{family}-{index:03}" in ("HTTP-031", "HTTP-033"):
                tests += ["distribution_mixed_protocols_and_bursts_execute_distinct_events"]
            if backend in ("tls12", "tls13", "tls_negotiation_failure", "tls_expired", "tls_name_mismatch"):
                tests += ["verified_tls_negotiation_and_resumption"]
            if backend.startswith("tls") or backend == "sip_tls":
                tests += ["tls_negotiation_and_expected_errors_in_memory"]
            if backend == "http_connect": tests += ["connect_authority_is_the_configured_target_only"]
            if backend == "http3_get": tests += ["http3_uses_verified_quic_to_the_configured_peer"]
            result.append(dict(
                id=f"{family}-{index:03}", name=name, family=family, category=category,
                layer=layer, protocol=protocol, mode=mode, risk="low" if mode == "live_validation" else "offline" if mode == "lab_emulation" else "not_executable",
                enabled=marker != "C", requires_lab=mode == "lab_emulation",
                implementation_status="unverified" if marker == "C" else "implemented", backend=backend,
                description=description, references=[reference],
                supported_parameters=[] if marker == "C" else ["limits"] if mode == "lab_emulation" else ["target", "limits"] + (["measurement"] if backend == "udp_delivery" else []) + (["protocol"] if backend.startswith(("http", "tls", "sip")) or backend == "dnssec" else []),
                automated_tests=tests, vendor_parity="unverified", ip_version=version[0] if version else None,
            ))
    return result


def render(rows):
    text = ["# Generated by scripts/generate_catalog.py. Protocol taxonomy; vendor parity unverified.", "schema_version: 1", "vectors:"]
    for row in rows:
        first = True
        for key, value in row.items():
            text.append(f"{'  - ' if first else '    '}{key}: {json.dumps(value, ensure_ascii=False)}")
            first = False
    return "\n".join(text) + "\n"


def coverage(rows):
    lines = ["# Vector implementation matrix", "",
             "This file is generated by `scripts/generate_catalog.py`. `implemented` means a source execution path exists; it does not indicate a successful build/test or vendor parity.", "",
             "Live checks use configured targets and limits. Offline models/fixtures do not transmit packets. Named attack models are not implementations of the actual attack tools.", "",
             "| ID | Layer | Check / scenario | Mode | Code path |", "| --- | --- | --- | --- | --- |"]
    for row in rows:
        lines.append(f"| {row['id']} | {row['layer']} | {row['name']} | {row['mode']} | `{row['backend']}` |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rows = entries()
    output = render(rows)
    path = ROOT / "external-agent/vectors/catalog.yaml"
    coverage_path = ROOT / "docs/vector-coverage.md"
    if args.check:
        assert path.read_text() == output, "catalog is stale; regenerate it"
        assert coverage_path.read_text() == coverage(rows), "coverage document is stale"
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output)
        coverage_path.write_text(coverage(rows))
    counts = {mode: sum(v["mode"] == mode for v in rows) for mode in ("live_validation", "lab_emulation", "catalog_only")}
    print(json.dumps({"total": len(rows), **counts}))
