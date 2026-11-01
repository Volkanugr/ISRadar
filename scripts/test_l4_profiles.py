#!/usr/bin/env python3
"""Validate L4 plan coverage, endpoint routing and budgets without sending traffic."""
import json
from pathlib import Path
import tempfile
import unittest

from generate_profiles import ROWS
from prepare_l4_test import prepare


class L4Profiles(unittest.TestCase):
    def test_dual_stack_plans_cover_all_ids_and_route_to_explicit_services(self):
        rows = {row["id"]: row for row in ROWS if row["layer"] == "L4"}
        ports = {"tcp": 443, "tcp_echo": 9003, "udp": 9000, "udp_closed": 9004,
                 "udp_measurement": 9005}
        live_ids = set()
        identities = []
        with tempfile.TemporaryDirectory() as temporary:
            for version, ip in [(4, "198.51.100.10"), (6, "2001:db8::10")]:
                directory = Path(temporary) / f"v{version}"
                counts = prepare(ip, directory, ports)
                self.assertEqual(counts, {"live_ready": 40 if version == 4 else 17,
                                         "offline_ready": 7, "needs_configuration": 2 if version == 4 else 25})
                manifest = json.loads((directory / "index.json").read_text())
                self.assertEqual({entry["id"] for entry in manifest["catalog"]}, rows.keys())
                self.assertEqual(len(manifest["catalog"]), 49)
                for name, case in manifest["cases"].items():
                    source = (directory / f"{name}.yaml").read_text()
                    if case["mode"] == "lab_emulation":
                        self.assertIsNone(case["target"])
                        self.assertEqual(len(case["vector_ids"]), 7)
                        self.assertIn('target: null', source)
                        continue
                    live_ids.add(name)
                    row = rows[name]
                    self.assertEqual(case["target"]["ip"], ip)
                    self.assertIsNone(case["target"]["server_name"])
                    backend = row["backend"]
                    expected_port = (9003 if backend in {"tcp_echo", "tcp_half_close", "tcp_session"} else
                                     443 if name.startswith("TCP-") else
                                     9004 if name == "UDP-002" else 9005 if name == "UDP-010" else 9000)
                    self.assertEqual(case["target"]["port"], expected_port)
                    self.assertIn(f'  port: {expected_port}', source)
                    if backend.startswith("raw_"):
                        self.assertEqual(case["limits"]["probes_per_second"], 1)
                        self.assertEqual(case["limits"]["concurrency"], 1)
                        expected_probes = 8 if name == "UDP-005" else 16
                        self.assertEqual(case["limits"]["max_probes"], expected_probes)
                        self.assertIn(f'  max_probes: {expected_probes}', source)
                key_path = directory / "measurement.key"
                self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(len(bytes.fromhex(key_path.read_text().strip())), 32)
                identities.append((key_path.read_text(), (directory / "UDP-010.yaml").read_text()))
            self.assertNotEqual(identities[0][0], identities[1][0])
            self.assertNotEqual(identities[0][1], identities[1][1])
        self.assertEqual(live_ids, {key for key, row in rows.items() if row["mode"] == "live_validation"})

    def test_missing_services_stay_pending_and_do_not_create_a_measurement_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "default"
            counts = prepare("198.51.100.10", directory, {"tcp": 80})
            self.assertEqual(counts, {"live_ready": 24, "offline_ready": 7, "needs_configuration": 18})
            manifest = json.loads((directory / "index.json").read_text())
            for entry in manifest["catalog"]:
                if entry["status"] == "needs_configuration":
                    self.assertIsNone(entry["config"])
                    self.assertTrue(entry["reason"])
                    self.assertFalse((directory / f"{entry['id']}.yaml").exists())
            self.assertFalse((directory / "measurement.key").exists())


if __name__ == "__main__":
    unittest.main()
