# Case 002 — Scheduled Task Persistence to Encoded PowerShell Execution

**Status:** Objective 1 validation evidence (interim report — endpoint prototype phase)
**Date of activity:** September 2, 2026
**Host:** DESKTOP-JC89B03
**User context:** DESKTOP-JC89B03\soc
**Severity:** Medium
**Correlation confidence:** Medium
**Pattern matched:** `compromise-to-staging`

## Summary

Two detections, nine seconds apart, were correlated into a single incident: a scheduled
task was created, immediately followed by an obfuscated PowerShell execution. The scheduled
task itself triggered three separate community Sigma rules simultaneously, all describing
the same underlying event from different angles (task creation, schedule type, and the
parent-child process relationship).

## Timeline

| Time (local, UTC+1) | Time (UTC) | Detection | MITRE Technique | Tactic |
|---|---|---|---|---|
| 14:23:41 | 13:23:41 | Scheduled Task Creation via Schtasks.EXE; Suspicious Schtasks Schedule Types; Windows Shell/Scripting Processes Spawning Suspicious Programs | T1053.005 | Persistence |
| 14:23:50 | 13:23:50 | Suspicious Encoded PowerShell Command | T1059.001 | Execution |

Total elapsed time: 9 seconds.

## Detection logic

- `scheduled_task_persistence.yml` (custom rule) plus two community SigmaHQ rules fired on
  the same underlying `schtasks.exe` process-creation event — the task name, schedule type
  (`onlogon`), and the fact that a scripting-capable process was the one creating it, all
  independently matched separate detection logic against the same single event.
- `encoded_powershell_command.yml` (custom rule) flagged the subsequent PowerShell
  invocation.

## Correlation logic

The `compromise-to-staging` pattern requires a Scheduled Task detection followed by an
Encoded PowerShell detection, on the same host, within a 15-minute window. Both conditions
were met well inside the window (9 seconds), so the two alerts were grouped into one
incident.

## Analysis

A scheduled task configured to run `onlogon`, created seconds before an obfuscated
PowerShell command, is consistent with an attacker staging persistence and preparing to
execute a payload on every subsequent logon — a common pattern for maintaining access
across reboots. The fact that three separate community rules fired on the single task-
creation event is worth noting for report purposes: it demonstrates rule-set redundancy
(multiple independent detections corroborating the same event) rather than three distinct
behaviors, and should be read as one strong signal, not three.

## Response taken

No automated response exists at this stage of the project. Manual remediation for a real
occurrence of this chain would involve: reviewing the scheduled task definition and its
target command, deleting it if unauthorized (`schtasks /delete`), and reviewing the decoded
PowerShell command for further indicators.

## Notes

This incident was generated as part of a deliberate, authorized simulation on an isolated
lab VM (no production or third-party systems involved), for the purpose of validating the
correlation engine against a persistence-first attack ordering, distinct from the
execution-first ordering shown in Case 001.
