"""
Response Orchestrator (SOAR-lite), command-line version.

Config-driven, same philosophy as correlation/attack-patterns.json: which
patterns trigger a response, and what that response is, lives in
attack-patterns.json under a "response_action" field per pattern -- not
hardcoded here. A pattern with no "response_action" simply gets no automated
response, which is a deliberate config choice.

This does the same job as the dashboard's "Respond" button, just from the
command line and for every incident in the latest file at once, rather than
one at a time by hand. Useful for batch-testing multiple incidents quickly.

Usage:
    python response\\response_engine.py --guest-password "<pw>"          (dry-run, default)
    python response\\response_engine.py --guest-password "<pw>" --live   (actually executes)
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent))
from actions import kill_process, block_ip, verify_process_killed, verify_ip_blocked

REPO_ROOT = Path(__file__).resolve().parent.parent
INCIDENTS_DIR = REPO_ROOT / "correlation" / "incidents"
PATTERNS_FILE = REPO_ROOT / "correlation" / "attack-patterns.json"
AUDIT_LOG = REPO_ROOT / "response" / "audit-log.jsonl"


def find_latest_incidents_file():
    files = sorted(INCIDENTS_DIR.glob("incidents_*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
    return files[0] if files else None


def load_response_rules():
    with open(PATTERNS_FILE, encoding="utf-8") as f:
        config = json.load(f)
    rules = {}
    for pattern in config["patterns"]:
        if "response_action" in pattern:
            rules[pattern["id"]] = pattern["response_action"]
    return rules


def append_audit_log(entry):
    AUDIT_LOG.parent.mkdir(exist_ok=True)
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def find_target_event(incident, target_stage_contains):
    for event in incident["events"]:
        if target_stage_contains.lower() in (event.get("detection") or "").lower():
            return event
    return None


def process_incident(incident, rules, guest_user, guest_password, dry_run):
    rule = rules.get(incident["pattern_id"])
    if not rule:
        return  # no response configured for this pattern -- a deliberate config choice

    target_event = find_target_event(incident, rule["target_stage_contains"])
    if not target_event:
        return

    timestamp = datetime.now().isoformat()
    action_type = rule["type"]

    if action_type == "kill_process":
        pid = target_event.get("process_id")
        success, output = kill_process(pid, guest_user, guest_password, dry_run=dry_run)
        verified = verify_process_killed(pid, guest_user, guest_password, dry_run=dry_run)
        entry = {
            "timestamp": timestamp, "pattern_id": incident["pattern_id"],
            "incident_start": incident.get("start_time"), "action": "kill_process",
            "target": pid, "dry_run": dry_run, "success": success,
            "verified": verified, "output": output
        }

    elif action_type == "block_ip":
        ip = target_event.get("source_ip")
        success, output = block_ip(ip, guest_user, guest_password, dry_run=dry_run)
        verified = verify_ip_blocked(ip, guest_user, guest_password, dry_run=dry_run)
        entry = {
            "timestamp": timestamp, "pattern_id": incident["pattern_id"],
            "incident_start": incident.get("start_time"), "action": "block_ip",
            "target": ip, "dry_run": dry_run, "success": success,
            "verified": verified, "output": output
        }

    else:
        return  # unknown action type in config -- fail safe, do nothing

    append_audit_log(entry)
    mode = "DRY RUN" if dry_run else "LIVE"
    print(f"  [{mode}] {entry['action']}({entry['target']}) on '{incident['pattern_name']}' "
          f"-> success={entry['success']}, verified={entry['verified']}")


def main():
    parser = argparse.ArgumentParser(description="Argus SOAR-lite response orchestrator")
    parser.add_argument("--live", action="store_true",
                         help="Actually execute actions. Without this flag, everything is dry-run.")
    parser.add_argument("--guest-user", default="soc")
    parser.add_argument("--guest-password", required=True,
                         help="Needed for kill_process (reaches into the VM). Not used by block_ip.")
    args = parser.parse_args()

    dry_run = not args.live

    incidents_file = find_latest_incidents_file()
    if not incidents_file:
        print("No incidents file found -- run correlation/correlate.py first.")
        return

    with open(incidents_file, encoding="utf-8") as f:
        incidents = json.load(f)

    rules = load_response_rules()
    print(f"Loaded {len(incidents)} incident(s) from {incidents_file.name}")
    print(f"Mode: {'LIVE -- actions will actually execute' if not dry_run else 'DRY RUN -- no actions will execute'}")
    print(f"Response rules configured for: {list(rules.keys())}")
    print()

    for incident in incidents:
        process_incident(incident, rules, args.guest_user, args.guest_password, dry_run)


if __name__ == "__main__":
    main()
