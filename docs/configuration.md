# YAML configuration

Edit the file and run `external-agent run --config test.yaml --output report.json`. No operator approval or signature is required. `validate --config test.yaml` checks the target, vectors, protocol settings, and limits without using the network; `run` performs the same checks automatically.

```yaml
vectors: [HTTP-001]
mode: live_validation
target:
  ip: 127.0.0.1
  port: 9002
  server_name: null
limits:
  duration_seconds: 15
  probes_per_second: 1
  concurrency: 1
  bandwidth_bytes_per_second: 8192
  max_probes: 3
  timeout_ms: 2000
kill_switch: STOP
health:
  consecutive_failures: 3
  max_latency_ms: 3000
```

The target IP is numeric. `server_name` is the qname for DNS and the certificate hostname/SNI for HTTPS/TLS/HTTP3; the connection remains pinned to `target.ip`. The configuration port for ICMP echo is 1. Offline vectors require `mode: lab_emulation` and `target: null`. Live and offline vectors cannot be mixed in a single plan.

Multiple IDs can run sequentially with the same target/settings. `max_probes` is their combined budget and must be at least the number of vectors. Duration and quotas are shared across workers. If the health threshold or duration limit is reached, later vectors may not run; use the report as the source of truth.

## Protocol settings

HTTP POST/PUT/PATCH example:

```yaml
protocol:
  http:
    path: /isradar-test
    body: test
    headers: {x-isradar-test: fixture}
    expected_status: 200
    expected_headers: {x-isradar-test: fixture}
    dedicated_test_endpoint: true
```

`dedicated_test_endpoint` identifies the test endpoint in configuration; it does not introduce a separate approval step. POST/PUT/PATCH/DELETE require a test path other than the root path. Other methods require an empty body. TRACE and reuse use fixed headers. CONNECT uses its own target's numeric IP/port as the authority and sends no tunnel payload.

Limits are 512 bytes for the path, 1,024 bytes for the body, 256 bytes per header value, and 8 configurable headers. Queries, escapes, dot segments, and credential/transport headers are rejected. An expected response header must match exactly one value; multiple values with the same name are ambiguous. HTTP header evaluation is limited to 64 headers / 4,096 bytes; reqwest's network read buffer operates separately.

Other options; include only the fields you need:

```yaml
protocol:
  tls_ca:
    file: ca.der
    sha256: "64-character lowercase SHA256 digest of the DER file"
  dnssec:
    zone: example
    public_key_hex: "64-character lowercase hex encoding of the zone Ed25519 DNSKEY"
    flags: 257
  sip:
    test_user: isradar-fixture
    dedicated_test_endpoint: true
    expected_status: 420
  capture:
    interface: eth0
```

The TLS CA file must be DER and no larger than 64 KiB. Its hash validates file contents; it is not an operator signature. System roots are retained and certificate validation is never disabled. DNSSEC supports the positive A RRset/Ed25519 subset. SIP INVITE/REGISTER use a dedicated `isradar-` test identity. Capture is available only in binaries built with the `packet-capture` feature.

## UDP measurement, stopping, and output

`x-isradar-probe` is the engine's HTTP probe identity header; it cannot be set in YAML. For supported HTTP backends, admitted probes are added to the report's `http_probes` list. [Matching target access logs](http-log-correlation.md).

```yaml
measurement:
  run_id: "32-character hex encoding of a new random 16-byte identity"
  key_file: measurement.key
  await_ack: false
controller_lease:
  heartbeat_file: /run/isradar/controller.heartbeat
  max_age_seconds: 5
```

These snippets illustrate the format. `measurement` is used only in a single-vector UDP-010 plan. `profiles create` or `demo` generates a valid key/identity automatically. To generate them manually, use the output of `external-agent measurement-keygen --key-file new.key` as `run_id`. HMAC associates packets with their test stream; it is not execution approval. Use a new identity for each measurement.

The heartbeat is optional; no controller is needed when it is not configured. If configured, a missing or stale heartbeat file stops execution. Relative paths for the kill switch, measurement key, custom CA, and heartbeat are resolved against the YAML directory. The report path is relative to the CLI working directory.

JSON audit events are written to stderr; save them with `2>audit.jsonl`. Exit code 0 means a report was written, not that all probes succeeded. Inspect `termination_reason`, observations, and error/timeout counters. The output file must be new.

When migrating from an earlier version, remove `authorization`/`signature` from YAML and `requires_authorization` from custom catalogs. The `auth` command and `--trusted-key` CLI option have been removed. Generate new examples with `profiles create`.
