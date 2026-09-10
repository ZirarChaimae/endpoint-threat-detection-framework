import json
import csv
import re
from pathlib import Path
from datetime import datetime, timedelta

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = REPO_ROOT / "detections" / "chainsaw-output"
PATTERNS_FILE = REPO_ROOT / "correlation" / "attack-patterns.json"
OUTPUT_DIR = REPO_ROOT / "correlation" / "incidents"


def find_latest_folder(prefix):
    matching = sorted(
        [d for d in DETECTIONS_DIR.iterdir() if d.is_dir() and d.name.startswith(prefix)],
        key=lambda d: d.stat().st_mtime,
        reverse=True
    )
    return matching[0] if matching else None


def load_all_detections():
    """Combine rows from the sysmon (custom + community) AND security (custom +
    adopted) hunts into one list. Security-log rules -- Failed Logon, Account
    Tampering -- live in security-custom-*/security-adopted-* folders, not the
    sysmon-* ones, so both families have to be read for any pattern that uses
    a Security-log detection to ever have a chance of matching."""
    rows = []
    for prefix in ["sysmon-community-", "sysmon-custom-", "security-custom-", "security-adopted-"]:
        folder = find_latest_folder(prefix)
        if not folder:
            continue
        csv_path = folder / "sigma.csv"
        if not csv_path.exists():
            continue
        with open(csv_path, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                rows.append(row)
    return rows


def parse_timestamp(ts_string):
    # Chainsaw timestamps look like: 2026-08-16T16:21:54.824220+00:00
    return datetime.fromisoformat(ts_string.replace("Z", "+00:00"))


def extract_user(event_data_text):
    match = re.search(r"^User:\s*(.+)$", event_data_text or "", re.MULTILINE)
    return match.group(1).strip() if match else "unknown"


def build_incident(pattern, matched, start_ts, last_ts):
    """Assemble the incident dict from a list of (index, timestamp, row) tuples."""
    matched_rows = [m[2] for m in matched]
    computers = sorted(set(r.get("Computer", "unknown") for r in matched_rows))
    users = list(set(extract_user(r.get("Event Data", "")) for r in matched_rows))
    stages = pattern["stages"]

    return {
        "pattern_id": pattern["id"],
        "pattern_name": pattern["name"],
        "description": pattern["description"],
        "start_time": start_ts.isoformat(),
        "end_time": last_ts.isoformat(),
        "computer": computers[0] if len(computers) == 1 else "MULTIPLE (" + ", ".join(computers) + ")",
        "users": users,
        "severity": pattern.get("severity", "medium"),
        "confidence": pattern.get("confidence", "medium"),
        "stage_count": len(matched_rows),
        "mitre_techniques": [
            {"id": s["mitre"], "tactic": s.get("tactic", "")} for s in stages
        ],
        "events": [
            {
                "timestamp": r.get("timestamp"),
                "detection": r.get("detections"),
                "event_id": r.get("Event ID"),
                "user": extract_user(r.get("Event Data", ""))
            }
            for r in matched_rows
        ]
    }


def match_single_event_pattern(pattern, parsed, used):
    """
    'single_event' patterns don't chain -- every matching, not-yet-used event
    becomes its own standalone incident (e.g. 'Security Event Log Cleared' is
    meaningful on its own, it doesn't need a second stage to matter).
    """
    incidents = []
    stage = pattern["stages"][0]
    needle = stage["match_contains"].lower()

    for idx, ts, row in parsed:
        if idx in used:
            continue
        if needle not in row.get("detections", "").lower():
            continue
        incidents.append(build_incident(pattern, [(idx, ts, row)], ts, ts))
        used.add(idx)

    return incidents


def match_chain_pattern(pattern, parsed, used):
    """
    Multi-stage pattern: find stages[0], then look forward (within
    time_window_minutes of stage 0) for stages[1], stages[2], etc., in order.

    Dedup: events already claimed by an earlier-processed pattern (or an
    earlier accepted match of this same pattern) are skipped entirely, via
    the shared `used` set. This prevents the same handful of raw events from
    being sliced into multiple overlapping/duplicate incidents.

    Entity check: if require_same_computer is true (default), a match is
    only accepted when every stage happened on the same Computer. A match
    that fits the time window but spans multiple hosts is discarded WITHOUT
    consuming its events, so they remain available to other patterns.

    Known limitation: matching is greedy and chronological. Patterns earlier
    in attack-patterns.json get first claim on any event they match. This is
    a deliberate simplification, not a full constraint solver -- worth a
    sentence in the report, not a hidden bug.
    """
    incidents = []
    window = timedelta(minutes=pattern["time_window_minutes"])
    stages = pattern["stages"]
    require_same_computer = pattern.get("require_same_computer", True)

    for start_pos, (start_idx, start_ts, start_row) in enumerate(parsed):
        if start_idx in used:
            continue
        if stages[0]["match_contains"].lower() not in start_row.get("detections", "").lower():
            continue

        matched = [(start_idx, start_ts, start_row)]
        last_ts = start_ts
        all_stages_found = True

        for stage in stages[1:]:
            needle = stage["match_contains"].lower()
            found = False
            for pos in range(start_pos + 1, len(parsed)):
                idx, ts, row = parsed[pos]
                if ts - start_ts > window:
                    break
                if idx in used:
                    continue
                if needle in row.get("detections", "").lower():
                    matched.append((idx, ts, row))
                    last_ts = ts
                    found = True
                    break
            if not found:
                all_stages_found = False
                break

        if not all_stages_found:
            continue

        if require_same_computer:
            computers = set(m[2].get("Computer", "unknown") for m in matched)
            if len(computers) > 1:
                continue  # timing fits, but it's not one coherent host-level incident

        incidents.append(build_incident(pattern, matched, start_ts, last_ts))
        for idx, _, _ in matched:
            used.add(idx)

    return incidents


def match_patterns(rows, patterns):
    parsed = []
    for i, r in enumerate(rows):
        try:
            ts = parse_timestamp(r["timestamp"])
            parsed.append((i, ts, r))
        except Exception:
            continue
    parsed.sort(key=lambda x: x[1])

    used = set()
    incidents = []

    # Pattern order matters: patterns are evaluated top-to-bottom as listed in
    # attack-patterns.json, and whichever pattern claims an event first keeps
    # it. Put your most specific / highest-value chain patterns before more
    # generic ones.
    for pattern in patterns:
        pattern_type = pattern.get("type", "chain")
        if pattern_type == "single_event":
            incidents.extend(match_single_event_pattern(pattern, parsed, used))
        else:
            incidents.extend(match_chain_pattern(pattern, parsed, used))

    return incidents


def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    with open(PATTERNS_FILE, encoding="utf-8") as f:
        config = json.load(f)

    rows = load_all_detections()
    print(f"Loaded {len(rows)} total detection events")

    incidents = match_patterns(rows, config["patterns"])
    print(f"Found {len(incidents)} correlated incident(s)")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = OUTPUT_DIR / f"incidents_{timestamp}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=2)

    print(f"Saved to {output_file}")
    for inc in incidents:
        print(f"  - {inc['pattern_name']} ({inc['stage_count']} stage(s), {inc['computer']})")


if __name__ == "__main__":
    main()
