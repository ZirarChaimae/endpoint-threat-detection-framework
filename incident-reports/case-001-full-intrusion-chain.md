# Case 001 — Full Intrusion Chain (Reconnaissance to Execution to Persistence)

**Status:** Objective 1 validation evidence (interim report — endpoint prototype phase)
**Date of activity:** September 2, 2026
**Host:** DESKTOP-JC89B03
**User context:** DESKTOP-JC89B03\soc
**Severity:** High
**Correlation confidence:** High
**Pattern matched:** `full-intrusion-chain`

## Summary

Four separate detections, spread across roughly one minute, were grouped by the correlation
engine into a single incident representing a coherent attack progression: the attacker first
fingerprinted the host and enumerated running processes, then executed an obfuscated
PowerShell command, then established persistence via the registry Run key. Each stage was
detected independently by a distinct Sigma rule; none of the four alerts would indicate a
serious compromise on its own, but their sequence and timing turn them into a single,
higher-confidence story.

## Timeline

| Time (local, UTC+1) | Time (UTC) | Detection | MITRE Technique | Tactic |
|---|---|---|---|---|
| 14:20:42 | 13:20:42 | System Information Discovery via systeminfo.exe | T1082 | Discovery |
| 14:20:52 | 13:20:52 | Process Discovery via tasklist.exe | T1057 | Discovery |
| 14:21:11 | 13:21:11 | Suspicious Encoded PowerShell Command | T1059.001 | Execution |
| 14:21:36 | 13:21:36 | Registry Run Key Persistence via reg.exe | T1547.001 | Persistence |

Total elapsed time: 54 seconds from first to last stage.

## Detection logic

Each stage was flagged independently by a dedicated custom Sigma rule against Sysmon
telemetry (Event ID 1, process creation):

- `system_info_discovery.yml` — flags execution of `systeminfo.exe`
- `process_discovery.yml` — flags execution of `tasklist.exe`
- `encoded_powershell_command.yml` — flags PowerShell invoked with an encoded/obfuscated
  command-line argument
- `registry_run_key_persistence.yml` — flags `reg.exe` writing to a
  `CurrentVersion\Run` registry key

## Correlation logic

The `full-intrusion-chain` pattern in `attack-patterns.json` requires all four stages to
occur, in this order, on the same host, within a 15-minute window. All four conditions were
met (54 seconds total, single host, single user), so the correlation engine grouped the four
independent alerts into one incident rather than reporting them as four unrelated events.

## Analysis

Taken individually, each of these four actions has legitimate, everyday explanations —
`systeminfo` and `tasklist` are routine administrative commands, and PowerShell obfuscation
alone is not proof of malicious intent. What makes this sequence notable is the combination
and the timing: host/process enumeration immediately followed by obfuscated code execution
and persistence, all within under a minute, is consistent with an attacker (or a testing
simulation of one) first assessing the environment before establishing a durable foothold.
This is the correlation engine doing exactly what it is meant to do — surfacing a pattern
that individual, isolated alerts would not.

## Response taken

No automated response exists at this stage of the project (automated response is scoped for
the next phase, alongside the web-attack lab). Manual remediation for a real occurrence of
this chain would involve: reviewing the created registry Run key for legitimacy, removing it
if unauthorized, reviewing the decoded PowerShell command content, and checking for further
persistence mechanisms established by the same process tree.

## Notes

This incident was generated as part of a deliberate, authorized simulation on an isolated
lab VM (no production or third-party systems involved), for the purpose of validating the
correlation engine's ability to chain related endpoint alerts into a single incident.
