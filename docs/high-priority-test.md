# High-priority Bash test

Run the High-only assessment through the existing Docker runner:

```sh
bash scripts/docker-web-test.sh TARGET_IP certificate.example.com high-priority
```

Run from the repository root. Supply a numeric target IP and the hostname expected by its HTTPS/TLS certificate. The script requires Python 3, Docker CLI, and a running Docker engine. It builds the current agent image, prepares a fresh report directory, validates every selected configuration with networking disabled, and then runs the selected cases sequentially.

The selection contains all **81 High-importance IDs** from [vectors.md](../vectors.md). Every ID appears in the final report. A missing service remains `needs_configuration`; it is not sent or marked successful.

## Default web target

| Target | Live-ready IDs | Offline-ready IDs | Awaiting configuration |
| --- | ---: | ---: | ---: |
| IPv4, HTTP 80 / HTTPS 443 | 13 | 47 | 21 |
| IPv6, HTTP 80 / HTTPS 443 | 8 | 47 | 26 |

The default IPv4 plan runs 14 steps: one combined offline step containing 47 IDs, followed by 13 live checks. Five live checks are raw TCP samples: TCP-009, TCP-013, TCP-014, TCP-015, and TCP-034. The other eight are HTTP-015/016/035 and TLS-001/002/003/007/013. IPv6 keeps those five IPv4-only raw samples pending.

Normal live checks use up to **100 probes at 10 probes/second**, at most 8 workers, and a 60-second duration. Raw samples use at most **16 packets at 1/second with one worker**. Explicitly configured SIP INVITE and HTTP CONNECT checks also retain their 16-probe / 1-per-second / one-worker limit. Health conditions, duration, and STOP may end a case before its budget is reached.

Offline IDs execute once each in `offline-high-priority.yaml`, with Docker `--network none`. Only raw steps receive `NET_RAW`; their configuration mount remains read-only and their reports are exported from container tmpfs. Other steps do not receive this capability.

## Configure the remaining services

The [service example](../examples/high-priority-services.json) supplies endpoint settings for the 21 additional live entries. It uses the repository's development-service ports, DNS test key, and fixture CA. Adapt it to actual matching test services before using it against a target; the file does not start those services.

```sh
ISRADAR_HIGH_PRIORITY_SERVICES=examples/high-priority-services.json \
bash scripts/docker-web-test.sh TARGET_IP certificate.example.com high-priority
```

With matching services configured, an IPv4 plan contains **34 live + 47 offline IDs**, executed in 35 steps. An IPv6 plan contains **29 live + 47 offline + 5 pending IPv4-only IDs**. `live_ready` means configuration is available; it does not mean a service has already responded successfully.

The JSON object is keyed by live High-importance vector ID. For example, to add just TCP echo and UDP echo:

```json
{
  "TCP-033": {"port": 9003},
  "UDP-015": {"port": 9000}
}
```

Each override accepts:

| Field | Meaning |
| --- | --- |
| `port` | Required integer in 1–65535 for the explicitly selected service. |
| `server_name` | Optional hostname/SNI; required explicitly for DNS as the query name. TCP/UDP services normally do not need it. |
| `protocol` | The agent's `http`, `sip`, `dnssec`, or `tls_ca` settings. When supplied, this replaces the generated protocol settings for that case. |

Overrides keep the command's numeric target IP, execution mode, limits, and shared STOP path. Unknown fields, duplicate JSON keys, non-High IDs, and offline IDs are rejected. An override cannot make an IPv4-only raw vector run against IPv6.

Important service requirements:

- TCP-033 requires an echo service that handles two consecutive messages on one connection. UDP-015 requires exact 64-byte echo behavior.
- DNS-008 needs the actual pinned Ed25519 zone key and query name. DNS-012 requests recursion; DNS-021/022 need a configured DNS service and parent/query name.
- SIP INVITE/REGISTER require the dedicated test identity and expected status in `protocol.sip`. SIP-008 needs a certificate-validating TLS service; SIP-011 uses UDP OPTIONS.
- HTTP PUT/PATCH/DELETE/POST and slow-body checks require a dedicated test path in `protocol.http`. CONNECT also requires dedicated endpoint settings and sends no tunnel payload. A body is required for HTTP-038.
- TLS-006 needs a version-rejection test service, TLS-009 an expired-certificate service, and TLS-010 the deliberately mismatched certificate hostname. These are distinct negative test conditions.

For a private test CA, use `protocol.tls_ca.file` pointing to a DER certificate. Relative paths are resolved beside the services JSON. The planner copies the CA into the new configuration directory and records its SHA-256 for portable Docker validation. An optional supplied `sha256` must match. The example uses the public development fixture CA; replace it for your own services. Certificate verification remains enabled.

All selected YAML files must pass the agent's validation before the first run. Missing protocol settings or invalid paths/expectations therefore stop the batch before traffic begins. Standard configuration details are in [configuration.md](configuration.md).

## Reports and stopping

The script prints a new directory such as `reports/docker-web-ABC123` and the exact STOP command:

```sh
touch reports/docker-web-ABC123/STOP
```

Reports include:

- `configs/index.json`: all 81 IDs, their High importance, execution mode, endpoint, and readiness or pending reason.
- `selected-cases.tsv`: the actual execution steps and budgets.
- `*-validation.log`: preflight result for each selected YAML.
- `*-report.json`, `*-summary.json`, `*-audit.jsonl`: results and diagnostics for attempted steps.
- `catalog-results.json`: all 81 IDs matched to completed, partial, missing, or mismatched reports, with pending configurations retained.

The high-priority exit handler writes `catalog-results.json` on normal completion, preflight/runtime failure, or STOP once plan creation has succeeded. A preflight failure prevents all execution; STOP prevents admission of subsequent steps. An interrupted or failed step is not silently counted as successful. A forcibly killed host/process may require manual summarization:

```sh
python3 scripts/prepare_high_priority.py --summarize reports/docker-web-ABC123
```

`live_completed` and `offline_completed` mean the planned observations were produced; inspect their outcomes and termination reason. Local raw send acceptance does not establish packet passage. Use protected-side captures or [HTTP log correlation](http-log-correlation.md) for the passage report described in [vectors.md](../vectors.md). The runner does not invent a blocking percentage or issue a High rating from sender counters alone.

## Prepare without Docker or traffic

```sh
python3 scripts/prepare_high_priority.py \
  --target-ip TARGET_IP --server-name certificate.example.com \
  --directory high-priority-plan \
  --services examples/high-priority-services.json
```

The output directory must be new. Omit `--services` to prepare the default web-only subset while accounting for the remaining IDs.

## Verification

```sh
bash -n scripts/docker-web-test.sh
python3 scripts/test_high_priority_profiles.py
python3 scripts/test_docker_runner.py
```

The planner tests check exact coverage, IPv4/IPv6 selection, endpoint routing, CA copying, and limits. Bash tests use a fake Docker CLI, including full-service selection, preflight failure, and STOP; their synthetic reports are not live network evidence. Real Docker/raw-path and target-service acceptance remain separate checks.
