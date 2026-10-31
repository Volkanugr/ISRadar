#!/usr/bin/env python3
"""Regression checks for evidence counting; all data is synthetic, no network I/O."""
import copy
from pathlib import Path
import tempfile
import unittest

from compare_http_logs import compare, log_rows


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.ids = ["a" * 32 + f"-{i}" for i in range(3)]
        self.report = {"mode": "live_validation", "vector_ids": ["HTTP-001"],
                       "metrics": {"probes_started": 3},
                       "http_probes": [{"request_id": id, "sequence": i, "vector_id": "HTTP-001"}
                                       for i, id in enumerate(self.ids)],
                       "observations": [{"outcome": "timeout", "protocol_details": {"http_request_id": self.ids[0]}}]}

    def test_duplicates_timeouts_and_cancelled_requests_are_not_loss_or_blocking(self):
        rows = [{"request_id": self.ids[0], "status": 200}, {"request_id": self.ids[0], "status": 200},
                {"request_id": self.ids[1], "status": 499}, {"request_id": "other-run"}, {"request_id": "-"}]
        result = compare([self.report], rows)
        self.assertEqual(result["observed_at_log_point"], 2)
        self.assertEqual(result["not_observed_at_log_point"], 1)
        self.assertEqual(result["duplicate_matching_log_records"], 1)
        self.assertEqual(result["sender_outcomes_for_observed_ids"], {"timeout": 1, "no_completed_observation": 1})
        self.assertIsNone(result["unifi_blocked"])
        self.assertEqual(result["missing_request_ids"], [self.ids[2]])

    def test_missing_and_ambiguous_sender_evidence_fail(self):
        for mutation in (lambda r: r.pop("http_probes"),
                         lambda r: r["http_probes"].append(r["http_probes"][0]),
                         lambda r: r["http_probes"][0].update(sequence=99)):
            report = copy.deepcopy(self.report)
            mutation(report)
            with self.assertRaises(ValueError):
                compare([report], [])
        with self.assertRaises(ValueError):
            compare([self.report, self.report], [])

    def test_w3c_column_order_and_jsonl_missing_id_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.log"
            path.write_text(f"#Fields: sc-status isradar-probe\n200 {self.ids[0]}\n#Fields: isradar-probe sc-status\n{self.ids[1]} 301\n")
            result = compare([self.report], log_rows(path, "w3c", "isradar-probe"))
            self.assertEqual(result["observed_at_log_point"], 2)
            path.write_text('{"status":200}\n')
            with self.assertRaises(ValueError):
                list(log_rows(path, "jsonl", "request_id"))
            path.write_text('{"request_id":""}\n')
            self.assertEqual(compare([self.report], log_rows(path, "jsonl", "request_id"))["log_records_without_id"], 1)


if __name__ == "__main__":
    unittest.main()
