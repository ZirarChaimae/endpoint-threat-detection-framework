## Week 6 — Chainsaw Detection Engine
- Re-exported full Sysmon and Security logs after Week 4-5 simulations (sysmon_export_full.evtx, security_export_full.evtx)
- Installed Chainsaw on host, using built-in mapping/sigma-event-logs-all.yml
- Ran chainsaw hunt against custom rules (sigma-rules/custom) and adopted rule (sigma-rules/adopted)
- Detections confirmed 
- Output saved as CSV in detections/chainsaw-output/

### Finding: T1070.001 destroyed evidence of the earlier failed-logon simulation) destroyed the evidence of the earlier T1110-
## Week 6 — Chainsaw Detection Engine

### Finding: T1070.001 destroyed evidence of the earlier failed-logon simulation
Simulating T1070.001 (clear Windows event logs via `wevtutil cl Security`) permanently destroyed the evidence of the earlier T1110-style failed logon simulation (Event ID 4625), since both events lived in the same Security log and no pre-clear backup was preserved in this run. This is a faithful, if unintentional, reproduction of a real-world SOC problem — an attacker covering their tracks by clearing logs after the fact, resulting in genuine loss of evidence. It reinforces why exporting/backing up logs *before* investigating a suspected incident is standard practice, and shows the real consequence when that step is skipped.

##  Full Pipeline Automation
- Built scripts/export-and-copy.ps1: single-command pipeline using vmrun to:
  1. Export Sysmon and Security logs remotely inside the VM
  2. Copy both exports to host automatically
  3. Run Chainsaw hunts against custom + adopted Sigma rules
- Verified end-to-end: single command produced 3 real detection output folders
  (sysmon-<timestamp>, security-custom-<timestamp>, security-adopted-<timestamp>)
- Credentials passed as a runtime parameter, never hardcoded or committed
- Resolved PowerShell execution policy restriction via Set-ExecutionPolicy -Scope CurrentUser

## Finding: SigmaHQ adopted rule too narrow for manual bad-password tests
The adopted rule (win_security_susp_failed_logon_reasons.yml) targets uncommon failure codes
(disabled accounts, unauthorized workstations, outside-hours logons) and did not match manual
bad-password attempts, which produce Status 0xC000006D — a code not covered by that rule.
Wrote a new custom rule (failed_logon_bad_password.yml) specifically for this common case.
Kept the adopted rule in the project as a demonstration of a different, more targeted detection
pattern used by real SOC teams for account-tampering scenarios.