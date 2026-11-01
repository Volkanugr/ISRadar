#!/usr/bin/env python3
"""Exercise Bash orchestration with a fake Docker CLI; never contact Docker or a network."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MOCK_DOCKER = r'''
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
with open(os.environ["ISRADAR_TEST_CALLS"], "a") as stream:
    stream.write(json.dumps(args) + "\n")
if args[0] in ("info", "build"):
    sys.exit(0)
assert args[0] == "run", args
mount = args[args.index("--mount") + 1]
directory = Path(mount.split("source=", 1)[1].split(",target=", 1)[0])
raw = "--entrypoint" in args
config = Path(args[-1] if raw else args[args.index("--config") + 1]).name
name = Path(config).stem
manifest = json.loads((directory / "configs/index.json").read_text())
case = manifest["cases"][name]
ids = case.get("vector_ids", [case.get("vector_id")])
if "validate" in args:
    if name == os.environ.get("ISRADAR_TEST_FAIL_VALIDATION"):
        print("synthetic preflight failure", file=sys.stderr)
        sys.exit(1)
    print(json.dumps({"valid": True, "vectors": ids}))
    sys.exit(0)
# Synthetic failures reproduce the reported ICMP -> TCP transition.
icmp = name == "l3-icmp" or name.startswith("ICMP-")
offline = case["mode"] == "lab_emulation"
count = 3 if icmp else case["limits"]["max_probes"]
observations = [{"vector_id": ids[i] if offline else ids[0],
                 "outcome": "simulated" if offline else "network_error" if icmp else "sent" if raw else "success",
                 "http_status": None} for i in range(count)]
report = {"fixture": "FAKE Docker response, not network evidence",
          "mode": "lab_emulation" if offline else "live_validation",
          "target": case.get("target"), "vector_ids": ids,
          "termination_reason": "health_degradation" if icmp else "completed",
          "requested_limits": case["limits"],
          "metrics": {"probes_started": count, "probes_completed": count, "probes_cancelled": 0,
                      "actual_probes_per_second": case["limits"]["probes_per_second"],
                      "raw_ip_packets_accepted": count * case.get("raw_packet_cost", 1) if raw else 0,
                      "responses_received": 0 if offline or icmp or raw else count,
                      "tcp_handshake_successes": 0, "http_responses_received": 0},
          "observations": observations}
if raw:
    print(json.dumps(report))
else:
    output = directory / Path(args[args.index("--output") + 1]).name
    output.write_text(json.dumps(report))
    print(json.dumps({"fixture": True}))
if name == os.environ.get("ISRADAR_TEST_STOP_AFTER"):
    (directory / "STOP").write_text("stop fixture\n")
'''


class RunnerTests(unittest.TestCase):
    def run_scenario(self, scenario, ip="198.51.100.10", ports=None, fail_validation=None, stop_after=None):
        with tempfile.TemporaryDirectory(prefix="isradar-bash-") as temporary:
            base = Path(temporary)
            project = base / "project with spaces"
            scripts = project / "scripts"
            scripts.mkdir(parents=True)
            for name in ("docker-web-test.sh", "prepare_web_test.py", "prepare_all_vectors.py", "prepare_l4_test.py", "prepare_high_priority.py",
                         "generate_profiles.py", "generate_catalog.py"):
                shutil.copyfile(ROOT / "scripts" / name, scripts / name)
            shutil.copyfile(ROOT / "vectors.md", project / "vectors.md")
            ca = Path("external-agent/tests/fixtures/tls/ca.der")
            (project / ca).parent.mkdir(parents=True)
            shutil.copyfile(ROOT / ca, project / ca)
            commands = base / "bin"
            commands.mkdir()
            executable = commands / "docker"
            executable.write_text(f"#!{sys.executable}\n" + MOCK_DOCKER)
            executable.chmod(0o755)
            calls = base / "calls.jsonl"
            environment = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"],
                               ISRADAR_TEST_CALLS=str(calls))
            for key in ("ISRADAR_TCP_PORT", "ISRADAR_TCP_ECHO_PORT", "ISRADAR_UDP_PORT",
                        "ISRADAR_UDP_CLOSED_PORT", "ISRADAR_UDP_MEASUREMENT_PORT",
                        "ISRADAR_HIGH_PRIORITY_SERVICES", "ISRADAR_TEST_FAIL_VALIDATION", "ISRADAR_TEST_STOP_AFTER"):
                environment.pop(key, None)
            environment.update(ports or {})
            if fail_validation:
                environment["ISRADAR_TEST_FAIL_VALIDATION"] = fail_validation
            if stop_after:
                environment["ISRADAR_TEST_STOP_AFTER"] = stop_after
            result = subprocess.run(["/bin/bash", str(scripts / "docker-web-test.sh"),
                                     ip, "web.example", scenario],
                                    env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1 if fail_validation else 130 if stop_after else 0,
                             result.stdout + result.stderr)
            recorded = [json.loads(line) for line in calls.read_text().splitlines()]
            runs = [args for args in recorded if args[0] == "run" and "validate" not in args]
            validations = [args for args in recorded if args[0] == "run" and "validate" in args]
            self.assertTrue(all(args[args.index("--network") + 1] == "none" for args in validations))
            directory = next((project / "reports").iterdir())
            manifest = json.loads((directory / "configs/index.json").read_text())
            if fail_validation or stop_after:
                catalog = json.loads((directory / "catalog-results.json").read_text())
                self.assertEqual(catalog["catalog_vectors"], 80)
                if fail_validation:
                    self.assertFalse(runs)
                    self.assertEqual(catalog["counts"], {"no_complete_report": 60, "needs_configuration": 20})
                else:
                    self.assertEqual(len(runs), 1)
                    self.assertEqual(len(validations), 14)
                    self.assertEqual(catalog["counts"], {"offline_completed": 47, "no_complete_report": 13,
                                                       "needs_configuration": 20})
                return []
            self.assertEqual(len(validations), len(runs))
            names = []
            for args in runs:
                is_raw = "--entrypoint" in args
                name = Path(args[-1] if is_raw else args[args.index("--config") + 1]).stem
                names.append(name)
                case = manifest["cases"][name]
                self.assertEqual(is_raw, case.get("backend", "").startswith("raw_"))
                is_offline = case["mode"] == "lab_emulation"
                is_icmp = name == "l3-icmp" or name.startswith("ICMP-")
                self.assertEqual("--sysctl" in args, is_icmp, name)
                if is_icmp:
                    self.assertEqual(args[args.index("--sysctl") + 1],
                                     f"net.ipv4.ping_group_range={os.getgid()} {os.getgid()}")
                self.assertEqual(args[args.index("--network") + 1], "none" if is_offline else "bridge")
                self.assertEqual(args[args.index("--cap-drop") + 1], "ALL")
                self.assertEqual("--cap-add" in args, is_raw)
                if is_raw:
                    self.assertEqual(args[args.index("--cap-add") + 1], "NET_RAW")
                    self.assertEqual(args[args.index("--user") + 1], f"0:{os.getgid()}")
                    self.assertTrue(args[args.index("--mount") + 1].endswith(",readonly"))
                    self.assertIn("--tmpfs", args)
                    raw_cost = case.get("raw_packet_cost", 1)
                    self.assertEqual(case["limits"]["max_probes"] * raw_cost, 16)
                    self.assertEqual(case["limits"]["probes_per_second"], 1)
                    self.assertEqual(case["limits"]["concurrency"], 1)
                    self.assertEqual((directory / "configs").stat().st_gid, os.getgid())
                    self.assertEqual(directory.stat().st_mode & 0o050, 0o050)
                else:
                    self.assertEqual(args[args.index("--user") + 1], f"{os.getuid()}:{os.getgid()}")
                self.assertNotIn("--privileged", args)
                summary = json.loads((directory / f"{name}-summary.json").read_text())
                self.assertEqual(summary["mode"], case["mode"])
                self.assertEqual(summary["probes_planned"], case["limits"]["max_probes"])
                if is_offline:
                    self.assertIsNone(case["target"])
                    self.assertEqual(summary["unifi_blocking"], "not tested: offline")
                    self.assertEqual(summary["raw_ip_packets_accepted"], 0)
                if is_raw:
                    self.assertEqual(summary["raw_ip_packets_accepted"], 16)
                    self.assertEqual(summary["responses_received"], 0)
                    self.assertEqual(summary["tcp_handshake_successes"], 0)
                    self.assertEqual(summary["outcomes"], {"sent": case["limits"]["max_probes"]})
            self.assertEqual(len(list(directory.glob("*-report.json"))), len(runs))
            if ip == "2001:db8::10" and scenario == "full-test":
                self.assertEqual(len(manifest["skipped_cases"]), 4)
                self.assertIn("Atlandı: l4-syn-80", result.stderr)
            if scenario == "all-vectors":
                catalog = json.loads((directory / "catalog-results.json").read_text())
                self.assertEqual(catalog["catalog_vectors"], 184)
                for entry in catalog["vectors"]:
                    if entry["id"] in {"TCP-002", "TCP-003"}:
                        self.assertEqual(entry["status"], "live_completed" if ":" not in ip else "needs_configuration")
            if scenario == "l4-test":
                catalog = json.loads((directory / "catalog-results.json").read_text())
                self.assertEqual(catalog["catalog_vectors"], 49)
                self.assertEqual(catalog["counts"]["offline_completed"], 7)
                self.assertEqual(catalog["counts"]["live_completed"], 40 if ports else 24)
                self.assertEqual(catalog["counts"]["needs_configuration"], 2 if ports else 18)
            if scenario == "high-priority":
                catalog = json.loads((directory / "catalog-results.json").read_text())
                self.assertEqual(catalog["catalog_vectors"], 80)
                self.assertEqual(catalog["counts"]["offline_completed"], 47)
                live = (33 if ports else 13) - (5 if ":" in ip else 0)
                self.assertEqual(catalog["counts"]["live_completed"], live)
                self.assertEqual(catalog["counts"].get("needs_configuration", 0), 33 - live)
                self.assertTrue(all(entry["importance"] == "High" for entry in catalog["vectors"]))
            return names

    def test_baseline_without_any_optional_arguments(self):
        self.assertEqual(self.run_scenario("baseline"), ["http-80", "https-443"])

    def test_full_test_continues_after_icmp_and_does_not_leak_its_arguments(self):
        cases = self.run_scenario("full-test")
        self.assertEqual(cases[:3], ["l3-icmp", "l4-tcp-80", "l4-tcp-443"])
        self.assertEqual(len(cases), 16)
        self.assertEqual(cases[3:7], ["l4-syn-80", "l4-synack-80", "l4-syn-443", "l4-synack-443"])
        self.assertEqual(cases[-1], "offline-slowloris")

    def test_ipv6_skips_ipv4_raw_samples_but_includes_offline_model(self):
        cases = self.run_scenario("full-test", ip="2001:db8::10")
        self.assertEqual(len(cases), 12)
        self.assertFalse(any(name.startswith(("l4-syn-", "l4-synack-")) for name in cases))
        self.assertEqual(cases[-1], "offline-slowloris")

    def test_catalog_starts_offline_and_reaches_live_cases(self):
        cases = self.run_scenario("all-vectors")
        self.assertEqual(cases[0], "offline-catalog")
        self.assertEqual(len(cases), 48)
        self.assertIn("ICMP-001", cases)
        self.assertIn("TCP-001", cases)
        self.assertIn("TCP-002", cases)
        self.assertIn("TCP-003", cases)

    def test_ipv6_catalog_leaves_ipv4_samples_pending(self):
        cases = self.run_scenario("all-vectors", ip="2001:db8::10")
        self.assertEqual(len(cases), 27)
        self.assertNotIn("TCP-002", cases)
        self.assertNotIn("TCP-003", cases)

    def test_l4_default_does_not_guess_udp_or_echo_services(self):
        cases = self.run_scenario("l4-test")
        self.assertEqual(len(cases), 25)
        self.assertEqual(cases[0], "offline-l4")
        self.assertIn("TCP-027", cases)
        self.assertNotIn("TCP-017", cases)
        self.assertFalse(any(name.startswith("UDP-") for name in cases))

    def test_l4_with_explicit_services_and_bounded_fragment_samples(self):
        cases = self.run_scenario("l4-test", ports={
            "ISRADAR_TCP_PORT": "443", "ISRADAR_TCP_ECHO_PORT": "9003",
            "ISRADAR_UDP_PORT": "9000", "ISRADAR_UDP_CLOSED_PORT": "9004",
            "ISRADAR_UDP_MEASUREMENT_PORT": "9005",
        })
        self.assertEqual(len(cases), 41)
        self.assertIn("TCP-017", cases)
        self.assertIn("UDP-005", cases)
        self.assertIn("UDP-010", cases)

    def test_high_priority_runs_only_high_ids_and_reports_missing_services(self):
        cases = self.run_scenario("high-priority")
        self.assertEqual(len(cases), 14)
        self.assertEqual(cases[0], "offline-high-priority")
        self.assertIn("TCP-009", cases)
        self.assertIn("TLS-013", cases)
        self.assertNotIn("TCP-005", cases)
        self.assertNotIn("TCP-033", cases)

    def test_high_priority_ipv6_keeps_ipv4_samples_pending(self):
        cases = self.run_scenario("high-priority", ip="2001:db8::10")
        self.assertEqual(len(cases), 9)
        self.assertNotIn("TCP-009", cases)

    def test_high_priority_with_explicit_services_runs_all_33_live_entries(self):
        cases = self.run_scenario("high-priority", ports={
            "ISRADAR_HIGH_PRIORITY_SERVICES": str(ROOT / "examples/high-priority-services.json"),
        })
        self.assertEqual(len(cases), 34)
        self.assertIn("SIP-002", cases)
        self.assertIn("HTTP-009", cases)
        self.assertIn("TLS-009", cases)

    def test_high_priority_preflight_failure_sends_nothing_and_still_summarizes(self):
        self.run_scenario("high-priority", fail_validation="TCP-009")

    def test_high_priority_stop_prevents_next_case_and_preserves_partial_summary(self):
        self.run_scenario("high-priority", stop_after="offline-high-priority")


if __name__ == "__main__":
    unittest.main()
