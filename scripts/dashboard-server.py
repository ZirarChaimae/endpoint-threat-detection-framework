from flask import Flask, jsonify, request
import subprocess
import csv
import json
import threading
import time
import sys
from pathlib import Path
from datetime import datetime

app = Flask(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = REPO_ROOT / "detections" / "chainsaw-output"
SCRIPT_PATH = REPO_ROOT / "scripts" / "export-and-copy.ps1"
CORRELATE_SCRIPT = REPO_ROOT / "correlation" / "correlate.py"
PATTERNS_FILE = REPO_ROOT / "correlation" / "attack-patterns.json"

VMX_PATH = r"C:\Users\Zirar\Documents\Virtual Machines\Victim-Win10-v2\Victim-Win10.vmx"
VMRUN_PATH = r"C:\Program Files\VMware\VMware Workstation\vmrun.exe"

sys.path.insert(0, str(REPO_ROOT / "response"))
from actions import kill_process, block_ip, unblock_ip, verify_process_killed, verify_ip_blocked  # noqa: E402

# In-memory only. Never written to disk, never committed.
_auto_hunt_state = {
    "enabled": False,
    "interval_minutes": 15,
    "password": None,
    "thread": None,
    "last_run": None,
    "last_error": None,
}


def read_latest_csv(prefix):
    if not DETECTIONS_DIR.exists():
        return {"folder": None, "rows": [], "mtime": None}
    matching = sorted(
        [d for d in DETECTIONS_DIR.iterdir() if d.is_dir() and d.name.startswith(prefix)],
        key=lambda d: d.stat().st_mtime,
        reverse=True
    )
    if not matching:
        return {"folder": None, "rows": [], "mtime": None}

    latest = matching[0]
    csv_path = latest / "sigma.csv"
    if not csv_path.exists():
        return {"folder": latest.name, "rows": [], "mtime": latest.stat().st_mtime}

    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    return {"folder": latest.name, "rows": rows, "mtime": latest.stat().st_mtime}


def compute_last_hunt_time(results):
    mtimes = [r["mtime"] for r in results if r.get("mtime")]
    if not mtimes:
        return None
    return datetime.fromtimestamp(max(mtimes)).strftime("%Y-%m-%d %H:%M:%S")


def load_response_rules():
    """Pull the 'response_action' block out of any pattern that defines one."""
    with open(PATTERNS_FILE, encoding="utf-8") as f:
        config = json.load(f)
    return {p["id"]: p["response_action"] for p in config["patterns"] if "response_action" in p}


def find_target_event(incident, target_stage_contains):
    for event in incident.get("events", []):
        if target_stage_contains.lower() in (event.get("detection") or "").lower():
            return event
    return None


@app.route("/api/latest")
def latest():
    try:
        sysmon = read_latest_csv("sysmon-custom-")
        sysmon_community = read_latest_csv("sysmon-community-")
        security_custom = read_latest_csv("security-custom-")
        security_adopted = read_latest_csv("security-adopted-")
        weblog = read_latest_csv("weblog-")
        last_hunt = compute_last_hunt_time([sysmon, sysmon_community, security_custom, security_adopted, weblog])

        return jsonify({
            "sysmon": sysmon,
            "sysmon_community": sysmon_community,
            "security_custom": security_custom,
            "security_adopted": security_adopted,
            "weblog": weblog,
            "last_hunt": last_hunt,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/incidents")
def incidents():
    try:
        incidents_dir = REPO_ROOT / "correlation" / "incidents"
        if not incidents_dir.exists():
            return jsonify({"incidents": [], "file": None})

        files = sorted(incidents_dir.glob("incidents_*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not files:
            return jsonify({"incidents": [], "file": None})

        with open(files[0], encoding="utf-8") as f:
            data = json.load(f)
        return jsonify({"incidents": data, "file": files[0].name})
    except Exception as e:
        return jsonify({"error": str(e), "incidents": []}), 500


@app.route("/api/response-rules")
def response_rules():
    """Tells the frontend which incident patterns have an automated response
    action configured, and what type -- used to decide whether to show a
    Respond button on an incident card, and what to label it."""
    try:
        return jsonify(load_response_rules())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def generate_incident_report_markdown(incident):
    """Builds a markdown report from a real incident, in the same style as
    the project's earlier hand-written interim reports (Case 001/002)."""
    lines = []
    lines.append(f"# Incident Report — {incident.get('pattern_name', 'Unknown Pattern')}")
    lines.append("")
    lines.append(f"**Severity:** {incident.get('severity', 'unknown').upper()}  ")
    lines.append(f"**Confidence:** {incident.get('confidence', 'unknown')}  ")
    lines.append(f"**Host:** {incident.get('computer', 'unknown')}  ")
    lines.append(f"**User(s)/Source(s):** {', '.join(incident.get('users', []))}  ")
    lines.append(f"**Start:** {incident.get('start_time', '')}  ")
    lines.append(f"**End:** {incident.get('end_time', '')}  ")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(incident.get("description", ""))
    lines.append("")
    lines.append("## MITRE ATT&CK Techniques")
    lines.append("")
    for t in incident.get("mitre_techniques", []):
        lines.append(f"- **{t.get('id')}** — {t.get('tactic')}")
    lines.append("")
    lines.append(f"## Timeline ({incident.get('stage_count', 0)} stage(s))")
    lines.append("")
    lines.append("| Timestamp | Detection | User/Source |")
    lines.append("|---|---|---|")
    for e in incident.get("events", []):
        lines.append(f"| {e.get('timestamp','')} | {e.get('detection','')} | {e.get('user','')} |")
    lines.append("")
    lines.append("## Response Action")
    lines.append("")
    rules = load_response_rules()
    rule = rules.get(incident.get("pattern_id"))
    if rule:
        lines.append(f"Configured response: `{rule['type']}`, targeting the stage matching \"{rule['target_stage_contains']}\".")
    else:
        lines.append("No automated response is configured for this incident type.")
    lines.append("")
    lines.append("---")
    lines.append(f"*Generated by Argus SOC Prototype on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
    return "\n".join(lines)


@app.route("/api/generate-report", methods=["POST"])
def generate_report():
    try:
        data = request.get_json(force=True)
        incident = data.get("incident")
        if not incident:
            return jsonify({"success": False, "error": "No incident provided"}), 400
        markdown = generate_incident_report_markdown(incident)
        return jsonify({"success": True, "markdown": markdown})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/respond", methods=["POST"])
def respond():
    """Manually trigger the response action for a specific incident, from
    the dashboard itself. Defaults to dry-run; the frontend must explicitly
    set live=true (after the analyst confirms) to actually execute."""
    try:
        data = request.get_json(force=True)
        pattern_id = data.get("pattern_id")
        incident = data.get("incident")
        live = bool(data.get("live", False))
        password = data.get("password", "")

        rules = load_response_rules()
        rule = rules.get(pattern_id)
        if not rule:
            return jsonify({"success": False, "error": "No response action configured for this incident type."}), 400

        target_event = find_target_event(incident, rule["target_stage_contains"])
        if not target_event:
            return jsonify({"success": False, "error": "Could not find the matching stage in this incident."}), 400

        dry_run = not live

        if rule["type"] == "kill_process":
            pid = target_event.get("process_id")
            success, output = kill_process(pid, "soc", password, dry_run=dry_run)
            verified = verify_process_killed(pid, "soc", password, dry_run=dry_run)
            return jsonify({"success": success, "action": "kill_process", "target": pid,
                             "dry_run": dry_run, "verified": verified, "output": output})

        elif rule["type"] == "block_ip":
            ip = target_event.get("source_ip")
            success, output = block_ip(ip, "soc", password, dry_run=dry_run)
            verified = verify_ip_blocked(ip, "soc", password, dry_run=dry_run)
            return jsonify({"success": success, "action": "block_ip", "target": ip,
                             "dry_run": dry_run, "verified": verified, "output": output})

        else:
            return jsonify({"success": False, "error": f"Unknown action type: {rule['type']}"}), 400

    except Exception as e:
        return jsonify({"success": False, "error": "Server error: " + str(e)}), 500


@app.route("/api/unblock-ip", methods=["POST"])
def unblock_ip_route():
    """Convenience endpoint for repeated testing -- removes an IP from
    OPNsense's block alias so the same attacker machine can be used again."""
    try:
        data = request.get_json(force=True)
        ip = data.get("ip")
        live = bool(data.get("live", False))
        success, output = unblock_ip(ip, dry_run=not live)
        return jsonify({"success": success, "output": output, "dry_run": not live})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/vm-status")
def vm_status():
    try:
        result = subprocess.run(
            [VMRUN_PATH, "-T", "ws", "list"],
            capture_output=True,
            text=True,
            timeout=15
        )
        is_running = VMX_PATH in result.stdout
        return jsonify({"running": is_running})
    except Exception as e:
        return jsonify({"running": False, "error": str(e)})


def quick_auth_check(password):
    """Fast (~5s) credential check. Does NOT run the full pipeline.
    Returns True if credentials are valid, False if invalid, None if undetermined."""
    try:
        result = subprocess.run(
            [
                VMRUN_PATH, "-T", "ws", "-gu", "soc", "-gp", password,
                "runProgramInGuest", VMX_PATH,
                "C:\\Windows\\System32\\cmd.exe", "/c", "exit"
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30
        )
        combined = (result.stdout or "") + (result.stderr or "")
        if "Invalid user name or password" in combined:
            return False
        return True
    except Exception:
        return None  # couldn't determine; don't block on this


def run_pipeline(password):
    """Runs the full export -> hunt -> correlate pipeline once. Always returns a dict, never raises."""
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-ExecutionPolicy", "Bypass",
                "-File", str(SCRIPT_PATH),
                "-GuestPassword", password
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "auth_error": False, "error": "Hunt timed out after 10 minutes."}
    except Exception as e:
        return {"success": False, "auth_error": False, "error": "Unexpected error launching pipeline: " + str(e)}

    combined_output = (result.stdout or "") + (result.stderr or "")

    if "AUTH_ERROR" in combined_output or "Invalid user name or password" in combined_output:
        return {"success": False, "auth_error": True, "error": "Incorrect VM password."}

    if result.returncode != 0:
        return {"success": False, "auth_error": False, "error": combined_output[-800:] or "Unknown error"}

    try:
        subprocess.run(["python", str(CORRELATE_SCRIPT)], capture_output=True, text=True, timeout=60)
    except Exception:
        pass

    return {"success": True, "auth_error": False, "stdout": result.stdout}


@app.route("/api/run-hunt", methods=["POST"])
def run_hunt():
    try:
        data = request.get_json(force=True)
        password = data.get("password", "")
        if not password:
            return jsonify({"success": False, "error": "Password required"}), 400

        result = run_pipeline(password)
        status_code = 200 if result["success"] else 400
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({"success": False, "error": "Server error: " + str(e)}), 500


def _auto_hunt_loop():
    while _auto_hunt_state["enabled"]:
        password = _auto_hunt_state["password"]
        if password:
            result = run_pipeline(password)
            _auto_hunt_state["last_run"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _auto_hunt_state["last_error"] = None if result["success"] else result.get("error")
            if result.get("auth_error"):
                _auto_hunt_state["enabled"] = False
                break
        interval_seconds = _auto_hunt_state["interval_minutes"] * 60
        for _ in range(interval_seconds):
            if not _auto_hunt_state["enabled"]:
                return
            time.sleep(1)


@app.route("/api/auto-hunt/start", methods=["POST"])
def auto_hunt_start():
    try:
        data = request.get_json(force=True)
        password = data.get("password", "")
        interval = int(data.get("interval_minutes", 15))
        if not password:
            return jsonify({"success": False, "error": "Password required"}), 400

        # Fast check only -- does NOT run the heavy pipeline.
        auth_ok = quick_auth_check(password)
        if auth_ok is False:
            return jsonify({"success": False, "auth_error": True, "error": "Incorrect VM password."}), 400

        _auto_hunt_state["enabled"] = True
        _auto_hunt_state["interval_minutes"] = interval
        _auto_hunt_state["password"] = password
        _auto_hunt_state["last_run"] = None
        _auto_hunt_state["last_error"] = None

        t = threading.Thread(target=_auto_hunt_loop, daemon=True)
        _auto_hunt_state["thread"] = t
        t.start()

        return jsonify({"success": True, "interval_minutes": interval})
    except Exception as e:
        return jsonify({"success": False, "error": "Server error: " + str(e)}), 500


@app.route("/api/auto-hunt/stop", methods=["POST"])
def auto_hunt_stop():
    _auto_hunt_state["enabled"] = False
    _auto_hunt_state["password"] = None
    return jsonify({"success": True})


@app.route("/api/auto-hunt/status")
def auto_hunt_status():
    return jsonify({
        "enabled": _auto_hunt_state["enabled"],
        "interval_minutes": _auto_hunt_state["interval_minutes"],
        "last_run": _auto_hunt_state["last_run"],
        "last_error": _auto_hunt_state["last_error"],
    })


@app.route("/")
def serve_dashboard():
    dashboard_path = REPO_ROOT / "docs" / "soc-dashboard.html"
    return dashboard_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    print(f"Repo root detected as: {REPO_ROOT}")
    print(f"Watching detections in: {DETECTIONS_DIR}")
    # threaded=True so a long-running hunt doesn't block VM-status/incident polling
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)
