#!/usr/bin/env python3
"""Profile actual offline event models; this measures neither network capacity nor defenses."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("catalog", ROOT / "scripts/generate_catalog.py")
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)
ids = [row["id"] for row in catalog.entries() if row["backend"] == "offline_model"]
with tempfile.TemporaryDirectory(prefix="isradar-profile-") as directory:
    work = Path(directory)
    source = '#[path = ' + json.dumps(str(ROOT / "external-agent/src/vectors/event_models.rs")) + '] mod event_models;\n'
    source += "fn main() { let ids = " + json.dumps(ids) + ";\n"
    source += '''let start = std::time::Instant::now();
        for _ in 0..1000 { for id in ids { std::hint::black_box(event_models::run(std::hint::black_box(id)).unwrap()); } }
        let elapsed = start.elapsed().as_secs_f64();
        println!("scope=offline_models_only model_executions={} seconds={:.6} models_per_second={:.0}",
            ids.len()*1000, elapsed, ids.len() as f64*1000.0/elapsed);
    }'''
    path = work / "profile.rs"
    path.write_text(source)
    binary = work / "profile"
    subprocess.run([shutil.which("rustc") or str(Path.home() / ".cargo/bin/rustc"), "--edition=2021", "-O", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
