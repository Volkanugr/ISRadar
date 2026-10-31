#!/usr/bin/env python3
"""Dependency-free consistency checks. This does not compile or execute Rust."""
import hashlib
import hmac
import importlib.util
import json
import re
import struct
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("catalog", ROOT / "scripts/generate_catalog.py")
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)
rows = catalog.entries()
assert (ROOT / "external-agent/vectors/catalog.yaml").read_text() == catalog.render(rows)
assert len(rows) > 150
assert len({v["id"] for v in rows}) == len(rows)
tests = set()
for path in list((ROOT / "external-agent/tests").rglob("*.rs")) + list((ROOT / "external-agent/src").rglob("*.rs")):
    tests.update(re.findall(r"\bfn\s+(\w+)\s*\(", path.read_text()))
registry_source = (ROOT / "external-agent/src/vectors/registry.rs").read_text()
enum_text = registry_source.split("pub enum Backend {", 1)[1].split("}", 1)[0]
backends = set(re.findall(r"\b[A-Z][A-Za-z0-9]+\b", enum_text))
camel = lambda name: "".join(part.capitalize() for part in name.split("_"))
for row in rows:
    assert camel(row["backend"]) in backends, row
    assert set(row["automated_tests"]) <= tests, row
    assert row["vendor_parity"] == "unverified"
    if row["mode"] == "catalog_only":
        assert not row["enabled"] and row["backend"] == "catalog"
        assert row["implementation_status"] == "unverified"
    elif row["mode"] == "lab_emulation":
        assert row["backend"] in ("offline_model", "offline_packet", "offline_policy_fixture") and row["requires_lab"]
    else:
        assert not row["requires_lab"]
    if row["id"] == "UDP-010":
        assert row["backend"] == "udp_delivery"

for manifest in [ROOT / "Cargo.toml", ROOT / "external-agent/Cargo.toml"]:
    tomllib.loads(manifest.read_text())
package = tomllib.loads((ROOT / "external-agent/Cargo.toml").read_text())
assert package["features"]["default"] == []
assert "experimental-receiver" in package["features"]
cli = (ROOT / "external-agent/src/main.rs").read_text()
for declaration in ["Receiver {", "Compare {"]:
    assert f'#[cfg(feature = "experimental-receiver")]\n    {declaration}' in cli
assert "await_ack: false" in cli
for source in (ROOT / "scripts").glob("*.py"):
    compile(source.read_text(), str(source), "exec")

# Independently specify the interoperable fixed-size authenticated frame.
key, run_id, sequence = bytes([7]) * 32, bytes([3]) * 16, 999
prefix = b"ISRDP001" + run_id + struct.pack("!Q", sequence)
golden = prefix + hmac.new(key, prefix, hashlib.sha256).digest()
assert len(golden) == 64
fixture_path = ROOT / "external-agent/tests/fixtures/measurement-golden.json"
fixture = json.loads(fixture_path.read_text())
assert fixture == {"key": key.hex(), "run_id": run_id.hex(), "sequence": sequence, "request_hex": golden.hex()}

subprocess.run([sys.executable, str(ROOT / "scripts/generate_catalog.py"), "--check"], check=True)
subprocess.run([sys.executable, str(ROOT / "scripts/generate_profiles.py"), "--check"], check=True)
print(json.dumps({"check": "static consistency only; Rust build/tests not executed", "layers": dict(Counter(v["layer"] for v in rows)),
                  "referenced_test_functions": len({name for v in rows for name in v["automated_tests"]}), "golden_frame_bytes": len(golden)}))
