from flask import Flask, jsonify, request
import subprocess
import csv
import os
from pathlib import Path

app = Flask(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = REPO_ROOT / "detections" / "chainsaw-output"
SCRIPT_PATH = REPO_ROOT / "scripts" / "export-and-copy.ps1"


def read_latest_csv(prefix):
    """Find the most recent folder starting with `prefix` and read its sigma.csv."""
    matching = sorted(
        [d for d in DETECTIONS_DIR.iterdir() if d.is_dir() and d.name.startswith(prefix)],
        key=lambda d: d.stat().st_mtime,
        reverse=True
    )
    if not matching:
        return {"folder": None, "rows": []}

    latest = matching[0]
    csv_path = latest / "sigma.csv"
    if not csv_path.exists():
        return {"folder": latest.name, "rows": []}

    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    return {"folder": latest.name, "rows": rows}


@app.route("/api/latest")
def latest():
    return jsonify({
        "sysmon": read_latest_csv("sysmon-custom-"),
        "sysmon_community": read_latest_csv("sysmon-community-"),
        "security_custom": read_latest_csv("security-custom-"),
        "security_adopted": read_latest_csv("security-adopted-"),
    })

VMX_PATH = r"C:\Users\Zirar\Documents\Virtual Machines\Windows 10 (Log Source)\Windows 10 (Log Source).vmx"
VMRUN_PATH = r"C:\Program Files\VMware\VMware Workstation\vmrun.exe"


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
@app.route("/api/run-hunt", methods=["POST"])
def run_hunt():
    data = request.get_json()
    password = data.get("password", "")
    if not password:
        return jsonify({"success": False, "error": "Password required"}), 400

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
        return jsonify({"success": False, "error": "Hunt timed out after 10 minutes — community ruleset may be too slow on this machine."}), 500  

    return jsonify({
        "success": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr
    })


@app.route("/")
def serve_dashboard():
    dashboard_path = REPO_ROOT / "docs" / "soc-dashboard.html"
    return dashboard_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    print(f"Repo root detected as: {REPO_ROOT}")
    print(f"Watching detections in: {DETECTIONS_DIR}")
    app.run(host="127.0.0.1", port=5000, debug=True)