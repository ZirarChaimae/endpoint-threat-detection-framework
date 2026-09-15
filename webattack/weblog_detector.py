"""
weblog_detector.py -- parses an Apache access log (combined format) and flags
SQL Injection, Path Traversal, Cross-Site Scripting, and Command Injection
attempts, writing output in the exact same CSV schema Chainsaw already
produces (timestamp, detections, path, count, Event.System.Provider,
Event ID, Record ID, Computer, Event Data). This lets correlate.py read web
detections through the identical code path it already uses for Sysmon/
Security-log detections -- no changes needed there beyond adding the output
folder's prefix to the list it already scans.

IMPORTANT, DOCUMENTED LIMITATION: Apache's default log format never records
POST request bodies, only the request line (method + path + protocol). DVWA's
Command Injection form submits via POST, so the actual injected payload
(e.g. "127.0.0.1 & whoami") is invisible to this detector -- it can only see
that a POST was made to the known vulnerable endpoint. This detector
therefore flags Command Injection based on the REQUEST PATH matching a known
vulnerable endpoint, not on inspecting the payload, which is a real,
acknowledged simplification -- not a bug. A production system would need
Apache configured to log POST bodies (e.g. via mod_security) to close this
gap; that's out of scope here.

Usage:
    python weblog_detector.py --log "C:\\xampp\\apache\\logs\\access.log" --computer DESKTOP-JC89B03
"""

import argparse
import csv
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = REPO_ROOT / "detections" / "chainsaw-output"

# Apache combined log format:
# %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
LOG_LINE_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d+) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<useragent>[^"]*)"$'
)

# Signatures, applied to the URL-decoded path (method + query string combined
# for detection purposes -- Command Injection is checked separately below).
SIGNATURES = [
    {
        "name": "SQL Injection Attempt",
        "mitre": "T1190",
        "tactic": "Initial Access",
        "severity": "high",
        "pattern": re.compile(
            r"('.*or.*'.*=.*')|(\bunion\b.*\bselect\b)|(\bselect\b.*\bfrom\b)|(--\s)|(;\s*drop\b)",
            re.IGNORECASE,
        ),
    },
    {
        "name": "Path Traversal Attempt",
        "mitre": "T1083",
        "tactic": "Discovery",
        "severity": "high",
        "pattern": re.compile(r"(\.\./)|(\.\.\\)|(etc/passwd)|(windows[/\\]win\.ini)", re.IGNORECASE),
    },
    {
        "name": "Cross-Site Scripting (XSS) Attempt",
        "mitre": "T1059.007",
        "tactic": "Execution",
        "severity": "medium",
        "pattern": re.compile(r"(<script)|(onerror\s*=)|(onload\s*=)|(javascript:)", re.IGNORECASE),
    },
]

# Command Injection: detected by endpoint path alone, per the documented
# limitation above -- payload is invisible in a POST body.
COMMAND_INJECTION_PATH = re.compile(r"/vulnerabilities/exec/?", re.IGNORECASE)


def parse_apache_time(time_str):
    # Example: 15/Sep/2026:19:56:21 +0100
    dt = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
    return dt


def classify(method, decoded_path):
    """Return a list of (name, mitre, tactic, severity) tuples -- a single
    request could theoretically match more than one signature."""
    hits = []
    for sig in SIGNATURES:
        if sig["pattern"].search(decoded_path):
            hits.append((sig["name"], sig["mitre"], sig["tactic"], sig["severity"]))
    if COMMAND_INJECTION_PATH.search(decoded_path):
        hits.append((
            "Command Injection Attempt (endpoint-based, payload not visible in GET/POST log)",
            "T1190", "Initial Access", "high"
        ))
    return hits


def parse_log_file(log_path):
    detections = []
    record_id = 0
    with open(log_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            match = LOG_LINE_PATTERN.match(line.strip())
            if not match:
                continue
            record_id += 1
            g = match.groupdict()

            # Skip localhost/setup traffic -- not attacker-relevant noise
            if g["ip"] == "::1":
                continue

            decoded_path = unquote_plus(g["path"])
            hits = classify(g["method"], decoded_path)
            if not hits:
                continue

            try:
                ts = parse_apache_time(g["time"])
            except ValueError:
                continue

            for name, mitre, tactic, severity in hits:
                detections.append({
                    "timestamp": ts.isoformat(),
                    "name": name,
                    "mitre": mitre,
                    "tactic": tactic,
                    "severity": severity,
                    "source_ip": g["ip"],
                    "method": g["method"],
                    "path": g["path"],
                    "status": g["status"],
                    "useragent": g["useragent"],
                    "record_id": record_id,
                })
    return detections


def write_output(detections, computer):
    if not detections:
        print("No web-attack detections found in this log.")
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = DETECTIONS_DIR / f"weblog-{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "sigma.csv"

    fieldnames = ["timestamp", "detections", "path", "count",
                  "Event.System.Provider", "Event ID", "Record ID",
                  "Computer", "Event Data"]

    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in detections:
            event_data = (
                f"SourceIp: {d['source_ip']}\n"
                f"User: {d['source_ip']}\n"
                f"HttpMethod: {d['method']}\n"
                f"HttpPath: {d['path']}\n"
                f"HttpStatus: {d['status']}\n"
                f"UserAgent: {d['useragent']}"
            )
            writer.writerow({
                "timestamp": d["timestamp"],
                "detections": d["name"],
                "path": "apache/access.log",
                "count": 1,
                "Event.System.Provider": "Apache-WebLog",
                "Event ID": "HTTP",
                "Record ID": d["record_id"],
                "Computer": computer,
                "Event Data": event_data,
            })

    print(f"Found {len(detections)} web-attack detection(s)")
    print(f"Saved to {out_file}")
    for d in detections:
        print(f"  - {d['name']} from {d['source_ip']} ({d['method']} {d['path']})")
    return out_file


def main():
    parser = argparse.ArgumentParser(description="Detect web attacks in an Apache access log")
    parser.add_argument("--log", required=True, help="Path to Apache's access.log")
    parser.add_argument("--computer", required=True,
                         help="Computer name to tag detections with (must match the Sysmon Computer field for correlation to work, e.g. DESKTOP-JC89B03)")
    args = parser.parse_args()

    detections = parse_log_file(args.log)
    write_output(detections, args.computer)


if __name__ == "__main__":
    main()
