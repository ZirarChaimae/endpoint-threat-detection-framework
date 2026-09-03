import json
import csv
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
    """Combine rows from the custom + community sysmon hunts into one list."""
    rows = []
    for prefix in ["sysmon-community-", "sysmon-custom-"]:
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


def match_patterns(rows, patterns):
    incidents = []

    # Sort all events chronologically first
    parsed = []
    for r in rows:
        try:
            ts = parse_timestamp(r["timestamp"])
            parsed.append((ts, r))
        except Exception:
            continue
    parsed.sort(key=lambda x: x[0])

    for pattern in patterns:
        window = timedelta(minutes=pattern["time_window_minutes"])
        stages = pattern["stages"]

        # Try every possible starting event as a candidate "stage 1"
        for start_idx, (start_ts, start_row) in enumerate(parsed):
            if stages[0]["match_contains"].lower() not in start_row.get("detections", "").lower():
                continue

            matched_events = [start_row]
            search_from = start_idx + 1
            last_ts = start_ts
            all_stages_found = True

            for stage in stages[1:]:
                found = False
                for ts, row in parsed[search_from:]:
                    if ts - start_ts > window:
                        break
                    if stage["match_contains"].lower() in row.get("detections", "").lower():
                        matched_events.append(row)
                        last_ts = ts
                        found = True
                        break
                if not found:
                    all_stages_found = False
                    break

            if all_stages_found:
                incidents.append({
                    "pattern_id": pattern["id"],
                    "pattern_name": pattern["name"],
                    "description": pattern["description"],
                    "start_time": start_ts.isoformat(),
                    "end_time": last_ts.isoformat(),
                    "computer": start_row.get("Computer", "unknown"),
                    "stage_count": len(matched_events),
                    "mitre_techniques": [s["mitre"] for s in stages],
                    "events": [
                        {
                            "timestamp": e.get("timestamp"),
                            "detection": e.get("detections"),
                            "event_id": e.get("Event ID"),
                        }
                        for e in matched_events
                    ]
                })

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
        print(f"  - {inc['pattern_name']} ({inc['stage_count']} stages, {inc['computer']})")


if __name__ == "__main__":
    main()