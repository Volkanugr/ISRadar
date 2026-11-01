# UniFi HTTP/HTTPS observations with Docker

This workflow uses existing HTTP vectors to check access on ports 80/443, HTTP method/redirect behavior, and detection of an IDS/IPS signature. It does not measure packet loss, DDoS capacity, or validation of every IDS/IPS rule.

## Target and traffic direction

Provide a numeric target IP and the DNS name covered by the port 443 certificate. The hostname is used for HTTP Host and TLS SNI; socket connections remain pinned to the supplied IP. Redirects are not followed. A server using a private CA requires a manually prepared YAML file with the [TLS CA setting](configuration.md); the short command below expects a certificate that trusted roots can validate.

To examine traffic arriving from the internet at a server behind UniFi, run the sender on another internet connection. Accessing a WAN IP from the same LAN may use a different NAT/routing path. Record which WAN or server each external IP maps to, and run separately for each IP. Two target IPs do not imply two separate senders.

## Running the tests

From the project root, replace the placeholders with your IP and hostname. Python 3 and a running Docker installation are required.

```sh
bash scripts/docker-web-test.sh TARGET_IP test.example.com baseline
```

`baseline` targets 100 HTTP GETs on port 80, then 100 HTTPS GETs on port 443. Each profile uses 10 probes/second, at most 8 concurrent workers, and an admission budget of 65,536 bytes/second. If responses are fast enough, sends are admitted in about 10 seconds; total duration is capped at 60 seconds per profile. Slow responses can reduce the actual rate. Three consecutive failures stop that profile early; cancelled and completed counts are separate in the report. Normal GET requests may be expected to pass; that result alone does not establish an IPS fault.

For the documented UniFi signature check:

```sh
bash scripts/docker-web-test.sh TARGET_IP test.example.com signature
```

This option sends **100 GETs at a target rate of 10 requests/second** to port 80 with the same `User-Agent: BlackSun` header; early-stop rules still apply. Ubiquiti's official test requires the **Malicious User Agents** category to be enabled and describes a single outbound HTTP request from a client inside the UniFi network; 100 repetitions are this project's test setting. Our internet-to-internal direction is not guaranteed to trigger the same signature; rule direction and selected networks matter. Use **Notify and Block** for IPS or **Notify** for IDS. Record the mode and enabled category with the test. [Ubiquiti IDS/IPS and test documentation](https://help.ui.com/hc/en-us/articles/360006893234-UniFi-Gateway-Intrusion-Detection-and-Prevention-IDS-IPS).

The signature check uses plain HTTP. The User-Agent inside HTTPS cannot be inspected without decrypting TLS; access on port 443 does not prove this header was inspected.

## Combined execution: hacker-web

```sh
bash scripts/docker-web-test.sh TARGET_IP test.example.com hacker-web
```

This option runs the following eight steps sequentially. **Each step uses 100 requests at a target rate of 10 requests/second, for at most 800 HTTP requests total.** Steps do not start concurrently; the overall send rate is not multiplied by the number of steps. Early health stops and response-dependent actual rates still apply.

| Order / file | Vector | Check |
| --- | --- | --- |
| 1. `http-80` | HTTP-001 | Initial HTTP GET access |
| 2. `https-443` | HTTP-015 | Initial HTTPS GET access with certificate validation |
| 3. `http-options-80` | HTTP-007 | OPTIONS method response |
| 4. `http-trace-80` | HTTP-008 | TRACE method response with fixed headers |
| 5. `http-redirect-80` | HTTP-017 | Redirect and Location validation on `/`; redirects are not followed |
| 6. `unifi-signature-80` | HTTP-001 | Documented BlackSun User-Agent check |
| 7. `http-after-80` | HTTP-001 | HTTP access after the checks |
| 8. `https-after-443` | HTTP-015 | HTTPS access after the checks |

`hacker-web` is this Docker script's web scenario. The CLI's `profiles create --preset hacker` is a different set of 55 offline models/fixtures and 9 live negative/policy checks. Those 64 entries are not executed by the Docker web command. Directing every example requiring DNS/SIP services, expired test certificates, or a dedicated CONNECT endpoint to ports 80/443 would not provide meaningful validation.

OPTIONS/TRACE and redirect checks observe HTTP policy behavior; triggering an attack signature is not assumed. TRACE status 405/501 may mean method rejection; do not label it as UniFi blocking. The redirect check fails if `/` does not redirect. If the server redirects every method on port 80, the observed behavior belongs to the first HTTP endpoint. A difference between before/after access does not independently prove the source of a block. `hacker-web` is not a complete attacker simulation or DDoS generator.

Each command creates a new `reports/docker-web-XXXXXX/` directory. Selected YAML files first undergo network-free `validate`; requests then use `--network bridge`. Docker bridge uses address translation for external access; correlate the actual source IP on the network path in UniFi rather than the container's private IP. [Docker bridge documentation](https://docs.docker.com/engine/network/drivers/bridge/).

These web steps do not require root or raw-socket privileges. Cancel with `Ctrl+C` or the printed `touch ".../STOP"` command; the script does not advance to the next profile when STOP exists. Exit code 0 means reports were produced, not that access succeeded or IPS blocked traffic.

To generate only YAML without Docker or network access:

```sh
python3 scripts/prepare_web_test.py --target-ip TARGET_IP \
  --server-name test.example.com --directory profiles/unifi-ip1
```

A new directory is required. It contains 16 YAML files for IPv4 or 12 for IPv6; the breakdown is below. `index.json` records the run identity, step modes/budgets, and file order for each scenario. The Docker script runs only the selected scenario and records the selection in `selected-cases.tsv`. Web requests other than TRACE include `x-isradar-test`; configuring the server access log to record it makes profile correlation easier. Per-probe correlation uses `X-Isradar-Probe`, described below. TRACE uses fixed headers as required by its backend and must be correlated by time, source IP, and method. Do not assume standard access logs record custom headers automatically. The kill switch is `STOP` one directory above the configuration directory.

## L3/L4/L7 together: full-test

```sh
bash scripts/docker-web-test.sh 212.252.162.17 online.solvitsoftware.com full-test
```

An IPv4 target uses 16 steps:

| Steps | Mode | Per-step upper limit |
| --- | --- | --- |
| ICMP echo, TCP connections on 80/443, the eight web steps above | Live, 11 steps total | 100 probes, target 10/second |
| `TCP-002` SYN and `TCP-003` SYN-ACK, separately on 80/443 | Live raw samples, 4 steps total | 16 samples, 1/second, one worker |
| `HTTP-025`, `offline-slowloris` | Offline event model, 1 step | 1 execution, no target, `--network none` |

Normal steps target at most 1,100 probes total; raw steps target 64 IP packet samples. Model execution is not network traffic. ICMPv4/ICMPv6 is selected from the target IP version. Catalog entries `TCP-002/003` are IPv4-specific: on IPv6 targets, the four raw steps are listed with reasons in `skipped_cases`, and 12 steps run. A missing ICMP response does not show that HTTP is also blocked. A gateway may answer ICMP; this is not target-application evidence.

The SYN-ACK step sends a standalone sample with SYN-ACK flags; it does not measure a SYN-ACK response to a SYN request. `raw_ip_packets_accepted` counts only packets accepted by the local raw socket, not downstream delivery or UniFi blocking. Target captures and UniFi events must be correlated for that evidence. Live delivery through Docker bridge/NAT has not yet been validated in this version.

Only raw steps use container UID 0 with `--cap-drop ALL --cap-add NET_RAW`. The configuration/STOP directory is mounted read-only; the report is transferred from container tmpfs over stdout into a host-user-owned file. Other steps use the host UID/GID without extra capabilities. No step uses `--privileged`.

`HTTP-025` runs the existing slot-occupancy model; it does not send slow headers or hold connections open on a real server. Output fields `mode: lab_emulation`, `network_evidence`, and `unifi_blocking: not tested: offline` distinguish it from live checks. Completing the offline model is not an actual Slowloris resilience test.

For ICMP, `net.ipv4.ping_group_range` is set only to the container user's GID inside Docker's network namespace; the host setting is unchanged. This permits ICMP echo sockets without root. [Linux ping group range](https://kernel.org/doc/html/latest/networking/ip-sysctl.html). ICMP/TCP results are separate response/handshake counts, not packet delivery rates.

The Docker image removes the `ping` package's file capability/setuid bits; echo-socket permission comes from the group setting above. This avoids conflicts between package-installed privilege markers and `--cap-drop ALL` during program startup. Linux can return `EPERM` from `execve` for some file capability/bounding-set mismatches. [Linux capabilities documentation](https://man7.org/linux/man-pages/man7/capabilities.7.html). `failed to start local ICMP helper` is a local startup error, not evidence that the target blocked traffic. If a running `ping` returns an error, new reports include `icmp_exit_code` and bounded `icmp_stdout`/`icmp_stderr` fields.

The empty-array / `set -u` incompatibility in Mac's Bash 3.2 has been fixed. If an older run shows `ping_args[@]: unbound variable`, rerun the command with the updated script; it rebuilds the image and creates a new report directory. Previous reports are retained.

## All 184 catalog entries: all-vectors

```sh
bash scripts/docker-web-test.sh 212.252.162.17 online.solvitsoftware.com all-vectors
```

This option accounts for every ID and executes only live checks configurable with the available web services:

| Status | Count | Behavior |
| --- | ---: | --- |
| Live-ready | 47 | 26 normal ICMP/TCP/UDP/HTTP/HTTPS/TLS checks: 100 probes/ID, target 10/second. Also 21 raw TCP flag/option/syn-flood samples on port 80: 16 samples/ID, 1/second |
| Offline-ready | 55 | Each ID once through shared `offline-catalog.yaml`; Docker `--network none` |
| Awaiting configuration | 82 | Missing service, different IP version, other raw packet conditions, or a special test requirement; not sent or counted as passed |

`configs/index.json` records each ID's status and pending reason. After execution, `catalog-results.json` matches each ID to its report. `live_completed`/`offline_completed` mean execution completed, not that every outcome succeeded or UniFi blocked traffic. Inspect error outcomes separately. After an early cancellation, summarize existing results for the report directory with:

```sh
python3 scripts/prepare_all_vectors.py --summarize reports/DOCKER_DIRECTORY
```

`all-vectors` does not claim to send 184 live attacks. Knowing ports 80/443 does not provide DNS, NTP, SIP, UDP echo, special HTTP-method endpoints, or other raw-packet requirements. Remaining entries can run only after their requirements are configured. The table applies to a single IPv4 target; IPv6 has 26 live entries, 55 offline entries, and 103 pending entries. A probe can include multiple messages/connections for backends such as TLS resumption or HTTP reuse; 10 probes/second is not a wire packet count. `all-vectors` runs catalog vectors; the non-catalog `BlackSun` header variation belongs to `signature`/`hacker-web`/`full-test`.

Use `l4-test` to select only the L4 catalog and configure TCP echo/UDP services on separate ports. Coverage of all 49 IDs and commands are in the [L4 test guide](l4-test.md).

Use `high-priority` to account for all 80 High-importance IDs. The default IPv4 web plan has 13 live checks, 47 offline entries, and 20 awaiting service configuration. The [High-priority guide](high-priority-test.md) includes the Bash command and endpoint overrides for all 33 live checks.

## Reading results

For each selected profile, the report directory contains `*-report.json`, `*-summary.json`, `*-audit.jsonl`, and `*-validation.log`. The terminal summary shows planned, started, completed, and cancelled counts along with target/actual rates. Evaluate HTTP status, timeout, TLS errors, and termination reason separately. A new command generates new settings; YAML files in old report directories are retained as records of past runs.

The updated binary adds an `X-Isradar-Probe` identity to supported HTTP probes. If the target server logs the header, [log comparison](http-log-correlation.md) counts which probes reached the observation point behind the protection system. The sender report alone does not provide that evidence.

| Observation | Supported conclusion |
| --- | --- |
| HTTP 2xx/3xx with a matching server access record | The request reached the application; a 3xx redirect was not followed |
| HTTP 403/429 | An HTTP component rejected/rate-limited the request; identify the source using logs |
| TLS certificate error | Inspect the certificate/hostname/trust chain; do not count it as IPS blocking |
| Timeout or connection reset | Cause unknown; possible firewall, NAT, server, or network-path issue |
| UniFi block event matching time, source/destination, port, and signature | Evidence of UniFi blocking for that traffic |
| IDS alert only | Evidence of detection, not blocking |

Obtain the matching UniFi event from **System Log → Threats** or **Insights → Traffic Flows → Threats**. Menus can vary by model/version. The **Blocked** view in Traffic Flows, applied policy, and ports can help; some models log only blocked flows. A missing flow record therefore does not prove that the packet failed to pass. [Traffic Flows and model limitations](https://help.ui.com/hc/en-us/articles/32201256219799-Traffic-Flows-and-Traffic-Logging-in-UniFi-Network).

Convert server and UniFi times to the same time zone and compare them with the report's UTC start/end timestamps. An HTTP probe is not a network packet; target packet counts require server-side capture/a receiver.

The initial Docker run returned HTTP 301 for HTTP 3/3 and signature 1/1, and HTTP 200 for HTTPS 3/3. In two later `hacker-web` runs, seven steps completed with 100 responses each; TRACE stopped at the health threshold after three 405 responses. [Reviewed reports](status.md#docker-web-result--2026-10-31-turkey-time). Live Docker validation of the new `full-test`, `all-vectors`, and HTTP identity/log correlation is still pending. IDS/IPS detection and blocking remain unverified because no UniFi event record was provided.
