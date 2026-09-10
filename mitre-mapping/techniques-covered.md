# MITRE ATT&CK Techniques Covered

This table lists every technique currently detected by this prototype, the Sigma rule
that detects it, and the correlation pattern(s) it feeds into. Updated as of the
endpoint-detection phase; a second table will be added once the web-attack rules
(Objective 2) exist.

## Detected techniques

| Technique ID | Technique Name | Tactic | Sigma Rule | Rule Type |
|---|---|---|---|---|
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Persistence | `registry_run_key_persistence.yml` | Custom |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | `scheduled_task_persistence.yml` | Custom |
| T1057 | Process Discovery | Discovery | `process_discovery.yml` | Custom |
| T1082 | System Information Discovery | Discovery | `system_info_discovery.yml` | Custom |
| T1018 | Remote System Discovery | Discovery | `remote_system_discovery.yml` | Custom |
| T1071.004 | Application Layer Protocol: DNS | Command and Control | `dns_query_demo.yml` | Custom (demonstration only, not a real C2 detection) |
| T1112 | Modify Registry (Hide File Extensions) | Defense Evasion | `hide_file_extensions.yml` | Custom |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Defense Evasion | `event_log_cleared.yml` | Custom |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | `encoded_powershell_command.yml` | Custom |
| T1110 | Brute Force (bad password) | Credential Access | `failed_logon_bad_password.yml` | Custom |
| T1078 | Valid Accounts (suspicious failure reasons) | Initial Access / Persistence | `win_security_susp_failed_logon_reasons.yml` | Adopted (SigmaHQ, Florian Roth) — intentionally narrow, does not match ordinary bad-password attempts by design |

Community rule set: ~1,183 SigmaHQ `process_creation` rules, providing broad execution-technique
coverage beyond the 10 custom rules above. Not individually mapped here since they cover the
full SigmaHQ process-creation catalog rather than techniques hand-picked for this project.

## Correlation patterns (technique chains)

| Pattern ID | Techniques Chained | Tactic Progression |
|---|---|---|
| `full-intrusion-chain` | T1082 → T1057 → T1059.001 → T1547.001 | Discovery → Discovery → Execution → Persistence |
| `phishing-to-persistence` | T1059.001 → T1547.001 | Execution → Persistence |
| `execution-to-lateral-movement` | T1059.001 → T1110 → T1082 → T1018 | Execution → Credential Access → Discovery → Discovery |
| `compromise-to-staging` | T1053.005 → T1059.001 | Persistence → Execution |
| `reconnaissance-sweep` | T1082 → T1057 → T1018 | Discovery → Discovery → Discovery |
| `evasion-preparation` | T1112 → T1059.001 | Defense Evasion → Execution |
| `discovery-before-scheduled-persistence` | T1057 → T1053.005 | Discovery → Persistence |
| `discovery-before-registry-persistence` | T1082 → T1547.001 | Discovery → Persistence |
| `credential-access-to-log-clearing` | T1110 → T1070.001 | Credential Access → Defense Evasion |
| `evasion-to-persistence` | T1112 → T1547.001 | Defense Evasion → Persistence |
| `account-tampering-alone` | T1078 | Initial Access / Persistence (standalone) |
| `event-log-cleared-alone` | T1070.001 | Defense Evasion (standalone) |

## Not yet covered (blocked on Objective 2 — web attack lab)

| Attack Type | Status |
|---|---|
| SQL Injection | Not started — requires Apache access log detector |
| Command Injection (flagship scenario) | Not started — requires Apache access log detector + cross-schema correlation |
| Path Traversal / LFI | Not started — requires Apache access log detector |
| Cross-Site Scripting (XSS) | Not started — requires Apache access log detector |

## Known limitations

- T1018 (Remote System Discovery) has never been conclusively confirmed firing through
  Chainsaw, despite the Sigma rule and simulation both existing. Documented, not fixed.
- The adopted rule (T1078) is deliberately narrow — it will not match a simple bad-password
  attempt. This is a documented finding about detection-rule specificity, not a bug.
