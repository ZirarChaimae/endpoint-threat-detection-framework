# MITRE ATT&CK Techniques Covered

This table lists every technique currently detected by this prototype, the rule that
detects it, and the correlation pattern(s) it feeds into. Updated to include the web
attack detection layer (Objective 2) alongside the original endpoint-detection layer
(Objective 1).

## Detected techniques — endpoint (Sysmon + Sigma + Chainsaw)

| Technique ID | Technique Name | Tactic | Rule | Rule Type |
|---|---|---|---|---|
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Persistence | `registry_run_key_persistence.yml` | Custom |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | `scheduled_task_persistence.yml` | Custom |
| T1057 | Process Discovery | Discovery | `process_discovery.yml` | Custom |
| T1082 | System Information Discovery | Discovery | `system_info_discovery.yml` | Custom |
| T1018 | Remote System Discovery | Discovery | `remote_system_discovery.yml` | Custom |
| T1071.004 | Application Layer Protocol: DNS | Command and Control | `dns_query_demo.yml` | Custom (demonstration only) |
| T1112 | Modify Registry (Hide File Extensions) | Defense Evasion | `hide_file_extensions.yml` | Custom |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Defense Evasion | `event_log_cleared.yml` | Custom |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | `encoded_powershell_command.yml` | Custom |
| T1110 | Brute Force (bad password) | Credential Access | `failed_logon_bad_password.yml` | Custom |
| T1078 | Valid Accounts (suspicious failure reasons) | Initial Access / Persistence | `win_security_susp_failed_logon_reasons.yml` | Adopted (SigmaHQ) |
| **T1190 / T1059** | **Exploit Public-Facing Application → Command and Scripting Interpreter** | **Initial Access → Execution** | **`web_server_spawns_shell.yml`** | **Custom, NEW** — detects a shell or system utility spawned with `httpd.exe` as its parent process, the endpoint-side signature of a successful web application command injection |

Community rule set: ~1,183 SigmaHQ `process_creation` rules, providing broad execution-technique
coverage beyond the custom rules above.

## Detected techniques — web application (Apache access log + `weblog_detector.py`)

| Technique ID | Technique Name | Tactic | Detection method |
|---|---|---|---|
| T1190 | Exploit Public-Facing Application (SQL Injection) | Initial Access | Request-line pattern matching against known SQLi syntax |
| T1190 | Exploit Public-Facing Application (Path Traversal / LFI) | Initial Access | Request-line pattern matching against directory-traversal sequences |
| T1190 (via T1059.007-style reflected script) | Exploit Public-Facing Application (Cross-Site Scripting) | Initial Access | Request-line pattern matching against script/event-handler injection |
| T1190 | Exploit Public-Facing Application (Command Injection) | Initial Access | Request-path matching against the known vulnerable endpoint — **payload itself is not visible** (see Known Limitations) |

**Verified against real, authenticated attack traffic**, not synthetic test data — all
four confirmed genuinely successful (not just logged) against DVWA on 2026-09-15:
Path Traversal leaked real `win.ini` contents; XSS reflected the payload unescaped; SQLi
returned all rows instead of one; Command Injection executed `whoami` and returned
`nt authority\system`, confirmed independently via the matching Sysmon process-creation
event (`cmd.exe` spawned by `httpd.exe`, running as SYSTEM).

## Correlation patterns (technique chains)

| Pattern ID | Techniques Chained | Tactic Progression | Response Action |
|---|---|---|---|
| `full-intrusion-chain` | T1082 → T1057 → T1059.001 → T1547.001 | Discovery → Discovery → Execution → Persistence | — |
| `phishing-to-persistence` | T1059.001 → T1547.001 | Execution → Persistence | `kill_process` |
| `execution-to-lateral-movement` | T1059.001 → T1110 → T1082 → T1018 | Execution → Credential Access → Discovery → Discovery | — |
| `compromise-to-staging` | T1053.005 → T1059.001 | Persistence → Execution | — |
| `reconnaissance-sweep` | T1082 → T1057 → T1018 | Discovery → Discovery → Discovery | — |
| `evasion-preparation` | T1112 → T1059.001 | Defense Evasion → Execution | — |
| `discovery-before-scheduled-persistence` | T1057 → T1053.005 | Discovery → Persistence | — |
| `discovery-before-registry-persistence` | T1082 → T1547.001 | Discovery → Persistence | — |
| `credential-access-to-log-clearing` | T1110 → T1070.001 | Credential Access → Defense Evasion | — |
| `evasion-to-persistence` | T1112 → T1547.001 | Defense Evasion → Persistence | — |
| `account-tampering-alone` | T1078 | Initial Access / Persistence (standalone) | — |
| **`command-injection-web-to-endpoint`** | **T1190 → T1059** | **Initial Access (web) → Execution (endpoint)** | **`kill_process`** — the flagship cross-schema pattern, the only one correlating web-log evidence with endpoint (Sysmon) evidence |
| **`sql-injection-alone`** | **T1190** | **Initial Access (standalone)** | **`block_ip`** |
| **`path-traversal-alone`** | **T1190** | **Initial Access (standalone)** | **`block_ip`** |
| **`xss-alone`** | **T1190** | **Initial Access (standalone)** | **`block_ip`** |
| `event-log-cleared-alone` | T1070.001 | Defense Evasion (standalone) | — |

## Known limitations

- T1018 (Remote System Discovery) has never been conclusively confirmed firing through
  Chainsaw, despite the Sigma rule and simulation both existing. Documented, not fixed.
- The adopted rule (T1078) is deliberately narrow — it will not match a simple bad-password
  attempt. Documented finding, not a bug.
- T1078 (Suspicious Account Tampering) was verified correct at the raw Windows Security
  log level (`Sub Status: 0xC0000072`) but is still not surfaced by Chainsaw. Accepted as
  a tool-level limitation, not pursued further.
- **`weblog_detector.py` cannot see Command Injection's actual payload.** Apache's
  default logging never records POST request bodies, and DVWA's Command Injection form
  submits via POST. Detection is based on the request reaching a known vulnerable
  endpoint, not on inspecting what was actually injected — an honest, documented
  simplification. The endpoint-side detection (`web_server_spawns_shell.yml`), by
  contrast, sees the real, executed command directly, since Sysmon watches process
  creation regardless of what triggered it.
- `block_ip`'s response action currently executes via `netsh` on the victim endpoint
  itself, not at the network perimeter (OPNsense). Functionally correct for
  demonstration purposes; blocking at the firewall instead is the intended final design,
  not yet implemented.
