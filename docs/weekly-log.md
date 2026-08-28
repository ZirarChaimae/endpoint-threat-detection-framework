## Week 6 — Chainsaw Detection Engine
- Re-exported full Sysmon and Security logs after Week 4-5 simulations (sysmon_export_full.evtx, security_export_full.evtx)
- Installed Chainsaw on host, using built-in mapping/sigma-event-logs-all.yml
- Ran chainsaw hunt against custom rules (sigma-rules/custom) and adopted rule (sigma-rules/adopted)
- Detections confirmed 
- Output saved as CSV in detections/chainsaw-output/

### Finding: T1070.001 destroyed evidence of the earlier failed-logon simulation
Simulating T1070.001 (clear Windows event logs via `wevtutil cl Security`) destroyed the evidence of the earlier T1110-style failed logon simulation, since both events lived in the same Security log. This is a faithful reproduction of a real-world SOC problem — an attacker covering their tracks by clearing logs after the fact — and demonstrates exactly why exporting/backing up logs *before* investigating a suspected incident is standard practice. A backup taken deliberately beforehand (`security_export_before_clear.evtx`) preserved the failed-logon evidence that the live/post-clear log lost.