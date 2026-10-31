#!/bin/sh
set -eu
# A supplied lockfile is preserved. The development tree may not yet have one.
if [ ! -f Cargo.lock ]; then cargo generate-lockfile; fi
if [ -n "${AGENT_FEATURES:-}" ]; then
    cargo build --release --locked --package external-agent --features "$AGENT_FEATURES"
else
    cargo build --release --locked --package external-agent
fi
