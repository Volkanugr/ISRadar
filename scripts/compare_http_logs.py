#!/usr/bin/env python3
"""Match admitted HTTP probe IDs to supplied target logs, without inferring firewall blocking."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re


def log_rows(path, log_format, id_field):
    fields = None
    with path.open(encoding="utf-8-sig") as stream:
        for number, line in enumerate(stream, 1):
            if len(line) > 65536:
                raise ValueError(f"{path}:{number}: log line exceeds 64 KiB")
            if not line.strip():
                continue
            if log_format == "w3c":
                if line.startswith("#Fields:"):
                    fields = line.split()[1:]
                    if id_field not in fields or len(set(fields)) != len(fields):
                        raise ValueError(f"{path}:{number}: missing or ambiguous ID column")
                    continue
                if line.startswith("#"):
                    continue
                values = line.split()
                if fields is None or len(values) != len(fields):
                    raise ValueError(f"{path}:{number}: missing #Fields or incorrect column count")
                row = dict(zip(fields, values))
                yield {"request_id": row[id_field], "status": row.get("sc-status")}
            else:
                row = json.loads(line)
                if not isinstance(row, dict) or id_field not in row:
                    raise ValueError(f"{path}:{number}: JSON object with {id_field} required")
                yield {"request_id": row[id_field], "status": row.get("status")}


def compare(reports, rows):
    ids, outcomes = {}, {}
    total_started = 0
    for report in reports:
        if report.get("mode") != "live_validation":
            raise ValueError("only live sender reports can be compared")
        started = report["metrics"]["probes_started"]
        if type(started) is not int or not 0 <= started <= 10000:
            raise ValueError("invalid sender probe count")
        total_started += started
        probes = report.get("http_probes", [])
        sequences = set()
        if len(probes) > started:
            raise ValueError("more IDs than started probes")
        for probe in probes:
            request_id, sequence = probe["request_id"], probe["sequence"]
            if (not isinstance(request_id, str) or not re.fullmatch(r"[0-9a-f]{32}-[0-9]{1,20}", request_id)
                    or request_id in ids or type(sequence) is not int or not 0 <= sequence < started
                    or sequence in sequences or request_id.rsplit("-", 1)[1] != str(sequence)
                    or probe["vector_id"] not in report["vector_ids"]):
                raise ValueError("duplicate or invalid sender probe ID/sequence")
            ids[request_id] = probe
            sequences.add(sequence)
        report_ids = {probe["request_id"] for probe in probes}
        for observation in report["observations"]:
            request_id = observation.get("protocol_details", {}).get("http_request_id")
            if request_id is not None:
                if request_id not in report_ids or request_id in outcomes:
                    raise ValueError("unknown or repeated observation ID")
                outcomes[request_id] = observation["outcome"]
    if not ids:
        raise ValueError("no HTTP correlation IDs: use a new build/report; TRACE, ICMP and TCP are not tagged")
    seen, statuses = Counter(), Counter()
    unmatched = without_id = 0
    for row in rows:
        request_id = row["request_id"]
        if request_id in (None, "", "-"):
            without_id += 1
            continue
        if not isinstance(request_id, str):
            raise ValueError("log request_id must be a string")
        if request_id not in ids:
            unmatched += 1
            continue
        status = row.get("status")
        if status not in (None, "", "-"):
            if not re.fullmatch(r"[1-5][0-9]{2}", str(status)):
                raise ValueError("invalid HTTP status in matching log record")
            statuses[str(status)] += 1
        seen[request_id] += 1
    missing = sorted(set(ids) - set(seen))
    return {
        "scope": "unique HTTP requests observed at the supplied log point; not packet delivery or DDoS capacity",
        "total_probes_started": total_started, "tagged_http_probes_started": len(ids),
        "untagged_probes_started": total_started - len(ids),
        "observed_at_log_point": len(seen), "not_observed_at_log_point": len(missing),
        "observed_fraction_of_tagged_probes": len(seen) / len(ids),
        "duplicate_matching_log_records": sum(seen.values()) - len(seen),
        "unmatched_log_records": unmatched, "log_records_without_id": without_id,
        "matching_log_statuses": dict(statuses),
        "sender_outcomes_for_observed_ids": dict(Counter(outcomes.get(id, "no_completed_observation") for id in seen)),
        "missing_request_ids": missing, "unifi_blocked": None,
        "note": "IDs identify started attempts, not confirmed transmissions. Missing logs can reflect non-transmission, loss, filtering or logging gaps; UniFi blocking needs separate evidence.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sender", type=Path, nargs="+", required=True)
    parser.add_argument("--target-log", type=Path, required=True)
    parser.add_argument("--format", choices=["jsonl", "w3c"], default="jsonl")
    parser.add_argument("--id-field", help="default: request_id for JSONL, isradar-probe for W3C")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        reports = [json.loads(path.read_text()) for path in args.sender]
        field = args.id_field or ("isradar-probe" if args.format == "w3c" else "request_id")
        result = compare(reports, log_rows(args.target_log, args.format, field))
        result["sender_reports"] = [str(path) for path in args.sender]
        result["target_log"] = str(args.target_log)
        output = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            with args.output.open("x") as stream:
                stream.write(output)
        print(output, end="")
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, f"HTTP log comparison failed: {error}\n")


if __name__ == "__main__":
    main()
