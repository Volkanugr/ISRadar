# Improvement TODO — L7 and optional LLM

This file contains development proposals; the items below are not implemented features. The current phase is the sender. The most useful initial role for an LLM is explaining measurement results to the operator and suggesting the next check.

## Complete L7 validation

- [ ] Complete real TCP/UDP integration tests on Linux with `bash scripts/verify.sh`. HTTP/2, QUIC/HTTP/3, TLS, DNS fallback, and SIP tests require an environment that can open loopback sockets.
- [ ] Extend the L7 test matrix with delayed/incomplete responses, peer resets, oversized headers, incorrect transaction IDs, and certificate rotation. Validate each vector's error classification and cancellation behavior over real transports.
- [ ] For HTTP/2–3, validate stream resets, GOAWAY, and connection/driver shutdown after cancellation on Linux. Distinguish header limits evaluated after the client library reads headers from actual bytes received over the network.
- [ ] On a dedicated SIP test endpoint, validate INVITE provisional/final responses and CANCEL/ACK/BYE cleanup, and confirm that the REGISTER binding query does not change registrations. Do not claim that remote state is conclusively closed after a timeout/cancellation.
- [ ] If required by product scope, add DNSSEC DS/DNSKEY chains, additional algorithms, and NSEC/NSEC3 denial-of-existence support with separate acceptance criteria. Currently, only a positive A RRset is validated using a pinned Ed25519 key.
- [ ] Complete sender/receiver matching by `run_id`/sequence in the later receiver phase, keeping application events, socket acceptance, and libpcap egress observations separate in the sender report.

## What advantages could an LLM provide?

| Priority | Proposal | Operator benefit | Required data |
| --- | --- | --- | --- |
| P0 | Explained post-test report | Quickly identifies significant issues, uncertainties, and next steps among hundreds of observations | JSON report, vector catalog, validation limitations |
| P1 | L7 diagnostic suggestions | Explains different outcomes such as HTTP 503, TLS certificate errors, DNS SERVFAIL, and SIP 403, and suggests suitable follow-up checks | Actual status/error fields and relevant protocol details |
| P1 | Coverage gaps and draft test plans | Shows which existing checks have not run against which authorized services | Operator service inventory, configured targets, previous tests |
| P1 | Baseline change explanations | Prioritizes possible causes of changes in latency, timeout, or rejection rates | Comparable reports using the same target, vector, settings, and version |
| P2 | Correlation of evidence from both endpoints | Once a receiver exists, explains sent/observed sequence numbers alongside application results | Verified sender/receiver evidence with the same `run_id` |

The expected benefits are faster diagnosis and clearer customer reports. This is a design hypothesis, not a measured improvement in the current product. An LLM does not measure packet delivery, replace the protocol validator, or independently establish that a firewall blocked traffic or a defense is resilient. Without a target receiver, adding AI does not answer how many of 1,000 packets passed through.

## Proposed architecture

```text
Rust agent → unchanged JSON report
                  ↓
       deterministic summary / data reduction
                  ↓
       optional LLM report writer
                  ↓
       separate explanation + evidence paths + recommendations
```

Initially, the LLM should run in a separate process after the test completes. The agent's send loop, timeouts, kill switch, and quotas must not depend on the model's response. Measurement and the raw report must still complete when the model is unavailable. A model provider or local model can be selected later; no cloud SDK, API key, or automatic model invocation has been added in this version.

## Implementation TODO

- [ ] P0: Define a versioned JSON schema with `summary`, `findings`, `evidence_paths`, `uncertainties`, and `suggested_checks`. Every finding must point to an actual report field; reject nonexistent evidence paths.
- [ ] Calculate counts, percentages, p95, and comparisons in code, then give the results to the model. Reject outputs that turn failed/cancelled observations into successes or change raw counters.
- [ ] Separate observations from hypotheses in TLS/DNS/SIP/HTTP error explanations. For example, “HTTP 503 was received” is an observation; “upstream capacity may be insufficient” is a hypothesis requiring additional evidence.
- [ ] Restrict proposed plans to existing catalog IDs and the operator inventory. Validate draft configurations with the existing Rust validator; live execution must pass existing numeric-target, protocol, and limit checks. The model must not discover new targets, raise quotas, or generate and execute packet code.
- [ ] Do not send private keys, measurement keys, access tokens, cookies, or raw customer payloads to the LLM. Let the operator select fields sent to a remote model; mask target names where needed and provide a local model option.
- [ ] Treat network responses and error messages as untrusted data. Instructions inside responses must not turn into model tool/shell/network calls; the report writer must not have authority to control the live agent.
- [ ] Bound input size, call duration, and token budgets; cache explanations for the same report. Record the model, prompt, and summary-schema versions in the explanation output.
- [ ] Prepare a golden test set: HTTP 200/302/503, duplicate headers, TLS expired/name mismatch, DNS BADVERS/SERVFAIL, SIP provisional/final responses, timeout, cancellation, and evidence of local sending only. Evaluate evidence grounding and unsupported certainty claims.
- [ ] In pilot use, measure time to understand a report, the proportion of findings corrected by operators, unsupported-claim rates, and model cost per report. Compare against the version without a model.

Recommended first delivery: **post-test report explanation only**. Add test-plan suggestions and historical report comparisons after measuring the report writer's accuracy.
