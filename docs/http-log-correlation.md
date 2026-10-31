# Measuring HTTP requests observed at the target

The updated sender adds a unique `X-Isradar-Probe` header to supported HTTP probes. Each identity combines a new random prefix for the run with the probe sequence number. The `http_probes` list records admitted probes; completed observations also include `protocol_details.http_request_id`. Timeout or cancellation does not remove an admitted identity from the list. Assigning an identity does not prove that the request was written to a socket.

Identities can be compared when the server access log **behind the protection system** records this header. A reverse proxy log proves that the request reached that proxy; observing an application further downstream requires an application-side log. State the logging location alongside the result.

## Log formats

The tool reads JSONL and IIS W3C formats. Each JSONL line must be an object with these fields:

```json
{"request_id":"0123456789abcdef0123456789abcdef-0","status":200}
```

This is a format example, not evidence of a real request. `request_id` is the received header value. For ordinary requests without the header, the field may be empty or `-`. `status` is optional. A missing identity column or malformed JSON produces an error.

For Nginx, define a log format in the `http` context and an additional access log in the relevant site's `server`/`location` context:

```nginx
log_format isradar escape=json
  '{"request_id":"$http_x_isradar_probe","status":$status,"time":"$time_iso8601"}';

# Add to the relevant site behind the protection system.
access_log /var/log/nginx/isradar-access.jsonl isradar;
```

Reload only after the server's standard configuration validation passes. JSON escaping and log contexts are described in the [Nginx documentation](https://nginx.org/en/docs/http/ngx_http_log_module.html). If a proxy is involved, verify that it forwards the header to the observation point.

For IIS 8.5+, use the site's **Logging → W3C → Select Fields → Add Field** controls to add field name `isradar-probe`, source type **Request Header**, and source name `X-Isradar-Probe`. Use the actual column name in the log's `#Fields:` line; specify `--id-field COLUMN_NAME` when needed. [Microsoft documentation on custom W3C fields](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/site/logfile/customfields/add).

## Comparison

Run the Docker script again; older reports have no probe identities. Once the new report and a log from the target server are available locally:

```sh
python3 scripts/compare_http_logs.py \
  --sender reports/DOCKER_DIRECTORY/http-80-report.json \
  --target-log target-access.jsonl --output http-comparison.json
```

For IIS, add `--format w3c --id-field isradar-probe`. `--sender` accepts multiple live reports; do not supply the same report twice. The output file must be new. Use a fully written log covering the entire test. Log rotation/sampling, a proxy stripping the header, or logs from the wrong server can reduce the observation count.

| Field | Meaning |
| --- | --- |
| `tagged_http_probes_started` | Admitted HTTP probes with assigned identities |
| `observed_at_log_point` | Number of unique identities found in the log |
| `not_observed_at_log_point` | Identities absent from the log; this does not mean they were blocked |
| `duplicate_matching_log_records` | Repeated records for the same identity; these do not increase the delivery count |
| `sender_outcomes_for_observed_ids` | Outcomes including probes observed by the server but timed out/cancelled at the sender |
| `unifi_blocked` | `null`; no count is inferred without UniFi evidence |

TRACE, CONNECT, and HTTP reuse retain their fixed-header contracts; HTTP/3 is outside this initial correlation scope. ICMP/TCP/raw packets have no HTTP identity. These are listed separately in `untagged_probes_started`. Other HTTP backends that make a single request through reqwest carry an identity. Users cannot set `x-isradar-probe` in YAML; the engine generates it.

The comparison relies on trusted server logs. An HTTP request is not a network packet; the result must not be labeled as packet loss, firewall bypass, or DDoS capacity measurement.
