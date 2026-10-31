# PROJECT: External DDoS Traffic Generator Agent (MazeBolt RADAR-Aligned)

You are a senior Rust systems engineer specializing in networking, Linux packet processing, TCP/IP protocols, and security validation.

Build a standalone, production-quality **External DDoS Traffic Generator Agent**: an independently developed alternative to the traffic-validation component of **MazeBolt RADAR™**.

Like RADAR, the agent's purpose is **continuous, non-disruptive DDoS defense validation**: it simulates 150+ known attack vectors across OSI layers 3, 4, and 7 so defenders can find misconfigurations **before** real attackers do — without downtime and without endangering production systems.

**Scope (this phase):** Build ONLY the traffic generation agent. Do NOT build a SaaS dashboard, database, internal sensor, firewall integration, analytics backend, or central controller UI yet. Design the codebase so a future central controller can orchestrate it.

---

## 0. Safety Boundaries (Non-Negotiable)

These boundaries are part of the product specification — the same class of constraints that make MazeBolt RADAR a legitimate enterprise security product. They are enforced in the execution layer, not just documentation.

- **No unrestricted flooding.** Every execution is bounded by rate, duration, concurrency, and bandwidth limits.
- **No reflection or amplification toward third parties.** Reflection/amplification scenarios run only against lab-owned echo servers; never direct third-party systems toward any target.
- **No Internet source-address spoofing.** Source IPs must be real, routable addresses owned by the test operator (or lab-reserved ranges).
- **No resource-exhaustion attacks against production targets.** Disruptive families (SYN Flood, Slowloris, etc.) exist as lab-only emulation or catalog entries.
- **No protection-bypass/evasion tooling** designed to overwhelm or circumvent mitigation systems on live networks.
- **Explicit target configuration.** Live checks use the numeric IP/port and protocol settings in the YAML file. No operator approval, signing key, signature file, or authorization profile is required.

Every vector is classified into exactly one of three execution modes:

- `live_validation` — bounded protocol checks against explicitly configured targets.
- `lab_emulation` — executable only inside a verified, isolated laboratory environment.
- `catalog_only` — documented in the registry, not executable until safely implemented.

Never claim a vector is implemented when it only has registry metadata.

---

## 1. Technology Stack

- Rust (stable), Tokio async runtime
- Linux primary target (VPS and physical machines)
- Standard TCP/UDP sockets
- libpcap for packet capture
- Restricted raw-packet support, only for low-volume protocol validation
- Clap (CLI), Serde (JSON/YAML), Tracing (structured logging)
- Unit + integration tests
- Native binary and Docker deployment

## 2. Project Structure

```text
external-agent/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── cli.rs
│   ├── config.rs
│   ├── engine/
│   │   ├── scheduler.rs
│   │   ├── executor.rs
│   │   ├── worker.rs
│   │   └── lifecycle.rs
│   ├── vectors/
│   │   ├── registry.rs
│   │   ├── tcp.rs
│   │   ├── udp.rs
│   │   ├── icmp.rs
│   │   ├── ip.rs
│   │   ├── dns.rs
│   │   ├── ntp.rs
│   │   ├── sip.rs
│   │   ├── http.rs
│   │   ├── tls.rs
│   │   └── lab.rs
│   ├── network/
│   │   ├── sockets.rs
│   │   ├── capture.rs
│   │   └── interfaces.rs
│   ├── safety/
│   │   ├── limits.rs
│   │   └── kill_switch.rs
│   ├── results/
│   │   ├── metrics.rs
│   │   └── json.rs
│   └── utils/
├── vectors/
│   ├── catalog.yaml
│   └── profiles/
├── tests/
└── README.md
```

## 3. Vector Registry

Every vector has a unique ID and complete metadata:

```yaml
id: TCP-001
name: TCP SYN Validation
category: TCP
layer: L4
protocol: TCP
mode: live_validation        # live_validation | lab_emulation | catalog_only
risk: low
enabled: true
requires_lab: false
implementation_status: planned  # planned | implemented | verified | unverified
```

Requirements:

- Dynamic vector discovery from `vectors/catalog.yaml` + code-registered vectors.
- Every vector implements a common interface, adapted to idiomatic async Rust:

```rust
trait TrafficVector {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn category(&self) -> &str;
    fn validate(&self) -> Result<()>;
    fn execute(&self, context: &TestContext) -> Result<TestResult>;
}
```

- Every vector is independently executable.
- The catalog must scale beyond 150 entries with zero changes to the execution engine.

## 4. Vector Families (L3 / L4 / L7, MazeBolt-Aligned Taxonomy)

### A. TCP — Layer 4

Register:

- TCP SYN, SYN-ACK, ACK, RST, FIN, PSH, URG
- TCP SYN-FIN, ACK-SYN, ACK-RST, ACK-PSH, RST-SYN
- TCP ALL FLAGS, NULL FLAGS
- TCP connection timeout, session establishment, session teardown
- TCP established-session data, handshake validation
- TCP connection reset validation, out-of-state validation

Named attack families (lab-only): **TCP SYN Flood, ACK Flood, RST Flood, FIN Flood, TCP state exhaustion.**

Implement: bounded TCP connection and packet-policy checks for live validation.

### B. UDP — Layer 4

Register:

- UDP service reachability, response validation, closed-port behavior
- UDP payload policy validation, packet-size classification
- UDP fragmentation policy, random-payload classification

Named families (lab-only): **UDP Flood, UDP amplification.**

Implement: standard UDP request/response validation.

### C. ICMP — Layer 3

Register:

- ICMP Echo Request / Echo Reply
- ICMP Destination Unreachable, Time Exceeded
- ICMP fragmentation-related error validation, policy validation

Named family (lab-only): **ICMP Flood (Ping Flood), Smurf-style broadcast scenario.**

Implement: low-rate ICMP reachability and policy tests.

### D. IP — Layer 3

Register:

- IPv4 header validation, IPv4 fragmentation handling
- IPv6 reachability, IPv6 extension-header validation
- Fragmented-packet policy, malformed IP packet classification

Malformed/disruptive scenarios use isolated fixtures or offline PCAP analysis unless a safe live implementation explicitly exists.

### E. DNS — Layer 7

Register:

- DNS A, AAAA, MX, TXT, CNAME requests
- DNS ANY policy, NXDOMAIN behavior, DNSSEC response validation
- DNS UDP/TCP fallback

Named families (lab-only): **DNS request flood, DNS reflection, DNS amplification, DNS water-torture (random subdomain) scenario.**

Implement: compliant DNS queries to explicitly authorized DNS services. Reflection scenarios may only target lab-owned reflectors.

### F. NTP — Layer 7

Register:

- NTP basic request, response validation, service policy

Named families (lab-only): **NTP reflection, NTP amplification (monlist-style).**

Live validation uses standard bounded requests to authorized servers only.

### G. SIP — Layer 7

Register:

- SIP OPTIONS, INVITE policy, REGISTER policy, response validation

Named family (lab-only): **SIP OPTIONS Flood, SIP INVITE Flood.**

Use authorized, dedicated SIP test endpoints.

### H. HTTP / HTTPS — Layer 7

Register:

- HTTP GET, POST, HEAD, PUT, PATCH, DELETE, OPTIONS, TRACE policy, CONNECT policy
- HTTP/1.1, HTTP/2, HTTP/3, keep-alive, connection reuse
- HTTPS certificate validation, status validation, redirect validation
- Request-header validation, API health-check

Named attack families (lab-only / catalog-only):

- **HTTP GET Flood, POST Flood, HEAD Flood, Dynamic Flood**
- **HTTP Slowloris, Slow POST (RUDY), GoldenEye, Tor's Hammer**
- **HTTP MHDDOS GET / HEAD / EVEN / CFB / BRUST, HTTPS MHDDOS GSB**

### I. TLS — Layer 7

Register:

- TLS 1.2 / 1.3 handshake validation, certificate validation
- Session resumption, cipher compatibility, negotiation-failure handling

Named families (lab-only): **SSL/TLS negotiation flood (THC-SSL-DOS style), TLS renegotiation resource exhaustion.**

### J. Multi-Vector & Specialized

Register (lab-only simulation models):

- Multi-vector DDoS simulation
- Carpet-bombing simulation
- Low-and-slow DDoS simulation
- Volumetric DDoS simulation
- Reflection/amplification simulation
- IPsec IKE protocol validation
- SMTP HELO validation

All of J runs offline/lab-only; nothing here generates destructive traffic against public systems.

## 5. Catalog Expansion

- MazeBolt publicly describes 150+ vectors across L3/L4/L7; the catalog system must grow past 150 entries without engine changes.
- Each entry includes: unique ID, family, protocol + OSI layer, description, references, implementation mode, safety classification, supported parameters, implementation status, automated tests.
- Where public documentation is incomplete, mark the vector `unverified` — never invent names or claim full MazeBolt parity.
- Do not copy proprietary source code or implementations.

## 6. Test Execution Engine

The user must be able to:

1. List available vectors
2. Inspect vector metadata
3. Choose a vector
4. Supply an explicit numeric target
5. Select execution mode
6. Run the vector
7. See real-time statistics
8. Cancel execution instantly
9. Export structured results (JSON)

Support individual and sequential execution. Initial release is single-agent and local — no multi-node orchestration or distributed amplification.

## 7. Traffic Controls (Enforced in the Execution Layer)

- Explicit numeric target IP/port per configuration
- Maximum test duration, request/packet rate, connection concurrency, bandwidth
- Aggregate limits across workers + per-vector limits
- Global emergency stop (kill switch)
- Immediate cancellation
- Automatic shutdown on controller disconnection
- Automatic stop on health-check degradation
- Complete execution audit logs
- The agent validates the whole plan and rejects invalid targets, unsupported modes, and excessive limits in the execution layer, not only the CLI. No separate approval step is required.

## 8. Metrics

Record per execution:

- Vector ID, target + destination port
- Start/end timestamps, requested vs. actual duration
- Packets sent, bytes sent, responses received
- Errors, timeouts, TCP handshake success
- HTTP success/error counts, response latency
- Actual packets/sec and bytes/sec
- Termination reason

Distinguish network errors, remote rejection, timeouts, and protection-system decisions. The external agent alone must NOT assert that an unacknowledged packet was blocked by a specific security appliance.

## 9. CLI

```bash
external-agent vectors list
external-agent vectors list --category tcp
external-agent vectors info TCP-001
external-agent validate --config test.yaml
external-agent run --config test.yaml --output report.json
external-agent report --input report.json --format json
external-agent profiles list
external-agent profiles create --preset researcher --directory profiles/researcher
```

Ship a safe example config targeting loopback or a dedicated local test server.

Execution uses `run --config test.yaml --output report.json`. Provide `basic`, `sophisticated`, `researcher`, `hacker`, and `l4` preset collections, with a separate YAML case for each selected vector. The researcher collection covers the complete implemented catalog; l4 covers every TCP/UDP catalog entry and keeps live implementations distinct from offline models. The l4-test Docker plan accepts explicit TCP, TCP echo, UDP echo, closed UDP and sequence-sender ports, accounting for missing services and IP-version mismatches without counting them as tested. Presets select coverage without increasing execution limits; disruptive families remain offline models. No operator key or approval workflow is required.

## 10. Offline & Laboratory Testing

- Local controllable TCP/UDP/HTTP test server
- Unit tests: vector registration, execution limits, timeout handling, cancellation
- Local TCP handshake, UDP request/response, and HTTP tests
- Offline PCAP fixtures for nonstandard protocol behavior
- Emulated attack-event fixtures for disruptive vector families
- Lab-only behavior is explicitly separated from public-network traffic generation.

## 11. Development Order

**Phase 1** — Rust scaffold, CLI, vector registry, execution limit controller, TCP connection validation, JSON reporting.

**Phase 2** — UDP, ICMP, HTTP/HTTPS, DNS, TLS, protocol test fixtures.

**Phase 3** — IP, NTP, SIP, TCP flag validation, offline packet generation + replay fixtures, complete public-vector taxonomy.

**Phase 4** — Lab-only DDoS simulation models, performance profiling, test coverage, documentation, production packaging.

## 12. Acceptance Criteria

- Rust binary compiles and runs on Linux.
- All publicly verified vector families are represented in the registry.
- Each implemented live vector executes independently.
- Unsupported vectors are clearly marked (`catalog_only` / `unverified`).
- Execution statistics are accurate; rate/duration limits enforced; cancellation is immediate.
- Local integration tests pass.
- Docker + native Linux installation instructions exist.
- Codebase is modular and ready for a future central controller.

---

**Start implementing now.** Do not stop at architecture documentation: create the actual source files, implement the first executable modules, add tests, run the build, fix compilation errors, and report which vectors are implemented versus catalog-only.
