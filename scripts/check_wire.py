#!/usr/bin/env python3
"""Compile and run the actual dependency-free Rust protocol parsers and models."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
rustc = shutil.which("rustc") or str(Path.home() / ".cargo/bin/rustc")
modules = ["dns_wire", "dnssec_wire", "http_head", "sip_wire", "packets", "lab_fixtures"]
with tempfile.TemporaryDirectory(prefix="isradar-wire-") as directory:
    work = Path(directory)
    source = "\n".join(f"#[path = {json.dumps(str(ROOT / 'external-agent/src/network' / (name + '.rs')))}] mod {name};" for name in modules)
    source += f"\n#[path = {json.dumps(str(ROOT / 'external-agent/src/vectors/event_models.rs'))}] mod event_models;\n"
    harness = work / "wire.rs"
    harness.write_text(source)
    binary = work / "wire-tests"
    subprocess.run([rustc, "--edition=2021", "--test", str(harness), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
