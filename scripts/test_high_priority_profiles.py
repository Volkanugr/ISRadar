#!/usr/bin/env python3
"""Check High-only planning, endpoint configuration, and limits without network I/O."""
import json
from pathlib import Path
import tempfile
import unittest

from generate_profiles import ROWS, high_priority_ids
from prepare_high_priority import prepare

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/high-priority-services.json"


class HighPriorityProfiles(unittest.TestCase):
    def test_default_plans_account_for_every_high_id_and_keep_missing_services_pending(self):
        with tempfile.TemporaryDirectory() as temporary:
            for version, ip in [(4, "198.51.100.10"), (6, "2001:db8::10")]:
                directory = Path(temporary) / f"v{version}"
                counts = prepare(ip, "web.example", directory)
                self.assertEqual(counts, {"live_ready": 13 if version == 4 else 8,
                                          "offline_ready": 47,
                                          "needs_configuration": 20 if version == 4 else 25})
                manifest = json.loads((directory / "index.json").read_text())
                self.assertEqual({entry["id"] for entry in manifest["catalog"]}, set(high_priority_ids()))
                self.assertEqual(len(manifest["catalog"]), 80)
                self.assertEqual(manifest["high-priority"][0], "offline-high-priority.yaml")
                self.assertTrue(all(entry["importance"] == "High" for entry in manifest["catalog"]))
                for entry in manifest["catalog"]:
                    if entry["status"] == "needs_configuration":
                        self.assertIsNone(entry["config"])
                        self.assertTrue(entry["reason"])
                        self.assertFalse((directory / f"{entry['id']}.yaml").exists())
                offline = manifest["cases"]["offline-high-priority"]
                self.assertIsNone(offline["target"])
                self.assertEqual(len(offline["vector_ids"]), 47)
                self.assertEqual(offline["limits"]["max_probes"], 47)
                self.assertNotIn("TLS-009", manifest["cases"])
                self.assertFalse(list(directory.glob("*.der")))

    def test_explicit_services_cover_all_live_entries_with_their_protocols_and_limits(self):
        rows = {row["id"]: row for row in ROWS}
        with tempfile.TemporaryDirectory() as temporary:
            for version, ip in [(4, "198.51.100.10"), (6, "2001:db8::10")]:
                directory = Path(temporary) / f"v{version}"
                counts = prepare(ip, "web.example", directory, EXAMPLE)
                expected = {"live_ready": 33 if version == 4 else 28, "offline_ready": 47}
                if version == 6:
                    expected["needs_configuration"] = 5
                self.assertEqual(counts, expected)
                manifest = json.loads((directory / "index.json").read_text())
                for name, case in manifest["cases"].items():
                    source = (directory / f"{name}.yaml").read_text()
                    self.assertIn('kill_switch: "../STOP"', source)
                    if case["mode"] == "lab_emulation":
                        continue
                    self.assertEqual(case["target"]["ip"], ip)
                    backend = rows[name]["backend"]
                    restricted = backend.startswith("raw_") or backend in {"sip_invite", "http_connect"}
                    self.assertEqual(case["limits"]["max_probes"], 16 if restricted else 100)
                    self.assertEqual(case["limits"]["probes_per_second"], 1 if restricted else 10)
                    self.assertEqual(case["limits"]["concurrency"], 1 if restricted else 8)
                    self.assertLessEqual(case["limits"]["duration_seconds"], 60)
                self.assertEqual(manifest["cases"]["TCP-033"]["target"]["port"], 9003)
                self.assertEqual(manifest["cases"]["UDP-015"]["target"]["port"], 9000)
                self.assertEqual(manifest["cases"]["DNS-008"]["target"]["server_name"], "host.example")
                self.assertEqual(manifest["cases"]["TLS-010"]["target"]["server_name"], "other.example")
                self.assertIn("dnssec:", (directory / "DNS-008.yaml").read_text())
                self.assertIn("dedicated_test_endpoint: true", (directory / "HTTP-004.yaml").read_text())
                self.assertIn("expected_status: 420", (directory / "SIP-002.yaml").read_text())
                for vector_id in ["SIP-008", "TLS-006", "TLS-009", "TLS-010"]:
                    self.assertEqual((directory / f"{vector_id}-ca.der").read_bytes(),
                                     (ROOT / "external-agent/tests/fixtures/tls/ca.der").read_bytes())
                    self.assertIn(f'file: "{vector_id}-ca.der"', (directory / f"{vector_id}.yaml").read_text())
                before = (directory / "index.json").read_bytes()
                with self.assertRaises(FileExistsError):
                    prepare(ip, "web.example", directory, EXAMPLE)
                self.assertEqual((directory / "index.json").read_bytes(), before)

    def test_overrides_reject_wrong_ids_target_changes_unknown_fields_and_duplicate_keys(self):
        invalid = [
            [], {"TCP-001": {"port": 80}}, {"TCP-028": {"port": 80}},
            {"TCP-033": {"port": True}}, {"TCP-033": {"port": 0}},
            {"TCP-033": {"port": 80, "ip": "203.0.113.10"}},
            {"TCP-033": {"port": 80, "limits": {"max_probes": 1000}}},
            {"DNS-008": {"port": 53}},
            {"DNS-008": {"port": 53, "server_name": "host.example", "protocol": {"dnssec": []}}},
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "services.json"
            for item in invalid:
                path.write_text(json.dumps(item))
                with self.subTest(item=item), self.assertRaises(ValueError):
                    prepare("198.51.100.10", "web.example", root / "plan", path)
                self.assertFalse((root / "plan").exists())
            path.write_text('{"TCP-033":{"port":9003,"port":80}}')
            with self.assertRaisesRegex(ValueError, "duplicate settings key"):
                prepare("198.51.100.10", "web.example", root / "plan", path)

    def test_private_ca_hash_is_checked_before_preparing_a_runnable_case(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            services = {"TLS-009": {"port": 9445, "protocol": {"tls_ca": {
                "file": str(ROOT / "external-agent/tests/fixtures/tls/ca.der"), "sha256": "0" * 64,
            }}}}
            path = root / "services.json"
            path.write_text(json.dumps(services))
            with self.assertRaisesRegex(ValueError, "sha256 mismatch"):
                prepare("198.51.100.10", "web.example", root / "plan", path)
            self.assertFalse((root / "plan/index.json").exists())
            self.assertFalse((root / "plan/TLS-009.yaml").exists())


if __name__ == "__main__":
    unittest.main()
