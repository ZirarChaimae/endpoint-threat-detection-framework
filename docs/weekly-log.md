## Week 6 — Chainsaw Detection Engine
- Re-exported full Sysmon and Security logs after Week 4-5 simulations (sysmon_export_full.evtx, security_export_full.evtx)
- Installed Chainsaw on host, using built-in mapping/sigma-event-logs-all.yml
- Ran chainsaw hunt against custom rules (sigma-rules/custom) and adopted rule (sigma-rules/adopted)
- Detections confirmed 
- Output saved as CSV in detections/chainsaw-output/