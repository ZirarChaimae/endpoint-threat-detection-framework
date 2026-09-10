# Argus SOC Prototype — Detection & Correlation Console

A from-scratch endpoint detection and correlation prototype, built as a PFA (end-of-year
academic project). Originally scoped as an endpoint threat detection and investigation
framework using Sysmon and Sigma rules; the scope was later revised, in agreement with
the project supervisor, toward strengthening multi-event correlation and adding automated
response to a set of common web attacks.

## What this is

A lightweight SIEM prototype that:

1. Captures endpoint telemetry from a Windows host using Sysmon.
2. Detects suspicious activity using Sigma rules evaluated through Chainsaw.
3. Correlates isolated alerts into multi-stage incidents using a custom, JSON-configurable
   correlation engine.
4. Presents both raw detections and correlated incidents through a browser dashboard.

## Current status

The endpoint detection and correlation layer is functionally complete. Work in progress:
finishing correlation coverage (more attack patterns, deduplication, entity checks) before
starting the second phase of the project — adding a web-attack lab (SQL Injection, Command
Injection, Path Traversal, XSS), automated response actions, and a benchmark against Wazuh.

See `mitre-mapping/techniques-covered.md` for exactly what is and isn't detected today.

## How it works

```
Windows Endpoint (Sysmon)
   → Log export (.evtx)
   → Chainsaw + Sigma rules (custom / adopted / community)
   → Detection CSVs
   → Correlation engine (correlation/correlate.py)
   → Incident records (correlation/incidents/)
   → Dashboard (docs/soc-dashboard.html + scripts/dashboard-server.py)
```

## Repository structure

| Path | Purpose |
|---|---|
| `sysmon-config/` | Sysmon configuration used on the victim VM |
| `sigma-rules/` | Detection rules: `custom/` (authored for this project), `adopted/` (SigmaHQ), `community/` (SigmaHQ process-creation set) |
| `mappings/` | Chainsaw's field-mapping reference file |
| `simulations/` | Log of every attack technique simulated, with exact commands and results |
| `detections/chainsaw-output/` | Raw, timestamped Chainsaw hunt output |
| `correlation/` | The correlation engine (`correlate.py`), its pattern config (`attack-patterns.json`), and its output (`incidents/`) |
| `scripts/` | Pipeline automation (`export-and-copy.ps1`) and the dashboard backend (`dashboard-server.py`) |
| `docs/` | The dashboard frontend, lab setup notes, and the running project log |
| `mitre-mapping/` | Technique coverage reference |
| `incident-reports/` | Written incident write-ups (interim reports now, full case studies once the web-attack phase is complete) |

## Setup

See `docs/lab-setup.md` for the full lab environment (VM, Sysmon install, log export process).

## Running the pipeline

From the repository root, in PowerShell:

```powershell
.\scripts\export-and-copy.ps1 -GuestPassword "<vm-password>"
python scripts\dashboard-server.py
```

Then open `http://127.0.0.1:5000`.

## Author

Zirar Chaimae
