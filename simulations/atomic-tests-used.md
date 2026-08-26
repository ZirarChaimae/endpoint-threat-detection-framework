# Atomic Red Team & Windows Security Simulations Log

| # | Technique ID | Test # | Timestamp (UTC) | Status | Evidence |
|---|---|---:|---|---|---|
| 0 | T1059.001 - PowerShell (Mimikatz) | 1 | — | BLOCKED | Mimikatz test required Internet access. Host-only network isolation prevented download. No execution occurred. |
| 1 | T1053.005 - Scheduled Task | 1 | 2026-08-16 16:21:54 | VERIFIED | Sysmon Event ID 1 detected `schtasks.exe`. Created `T1053_005_OnLogon` and `T1053_005_OnStartup`. |
| 2 | T1547.001 - Registry Run Keys | 1 | 2026-08-16 18:07:58 | VERIFIED | Sysmon Event ID 13 detected registry modification. Event ID 1 detected `reg.exe`. |
| 3 | Manual - Failed Logon | N/A | 2026-08-16 20:15:38–20:15:47 | VERIFIED | Windows Security Event ID 4625 detected 3 failed logon attempts for account `soc`. |
| 4| T1057 - Process Discovery | N/A | 2026-08-19 13:08:56 | VERIFIED | Sysmon Event ID 1 detected `tasklist.exe`. |
| 5 | T1082 - System Information Discovery | N/A | 2026-08-19 15:00:11 | VERIFIED | Sysmon Event ID 1 detected `systeminfo.exe`. |
| 6 | T1018 - Remote System Discovery | N/A | 2026-08-15 20:54:40 | VERIFIED | Sysmon Event ID 3 detected outbound TCP connection probe to default gateway. |
| 7 | T1071.004 - DNS Query (demo) | N/A | 2026-08-15 22:16:21 | VERIFIED | Sysmon Event ID 22 detected DNS query for `www.example.com`. |
| 8 | T1112 - Modify Registry (Hide File Extensions) | N/A | 2026-08-25 11:46:05 | VERIFIED | Sysmon Event ID 13 detected `HideFileExt` value set under Explorer\Advanced. |
| 9 | T1070.001 - Clear Windows Event Logs | N/A | 2026-08-19 09:07:25 | VERIFIED | Security Event ID 1102 detected log clear action. Backup exported prior to clearing. |
| 10 | T1059.001 - Encoded PowerShell Command | N/A | 2026-08-26 1:51:15 | VERIFIED | Sysmon Event ID 1 detected `powershell.exe` with `-EncodedCommand` flag decoding to `whoami`. |

# Test Details

## 0. T1059.001 - PowerShell (Mimikatz)

**Test:** T1059.001-1 - Mimikatz
**Status:** BLOCKED
**Timestamp:** N/A
**Verification:** Not applicable

**Reason:**
- The test requires Internet access.
- It downloads Mimikatz from an external GitHub repository.
- The Windows VM uses host-only network isolation.
- The payload could not be downloaded.
- No actual Mimikatz execution occurred.

**Case Study:** Not used.
**Action:** Replaced with a safe, self-built encoded PowerShell test (see #11) that requires no Internet access.

---

## 1. T1053.005 - Scheduled Task

**Test:** T1053.005-1 - Scheduled Task Startup Script
**Status:** VERIFIED
**Timestamp:** 2026-08-16 16:21:54 UTC
**Verification:** Sysmon Event ID 1

**Activity:**
- Created scheduled task `T1053_005_OnLogon`.
- Trigger: `ONLOGON`.
- Created scheduled task `T1053_005_OnStartup`.
- Trigger: `ONSTART`.
- Runs as: `SYSTEM`.
- Payload: `cmd.exe /c calc.exe`.

**Purpose:**
Demonstrates Scheduled Task persistence/execution using a harmless `calc.exe` payload.

**MITRE ATT&CK:**
T1053.005 - Scheduled Task/Job: Scheduled Task

**Sigma Rule:** `sigma-rules/custom/scheduled_task_persistence.yml`

---

## 2. T1547.001 - Registry Run Keys / Startup Folder

**Test:** T1547.001-1 - Reg Key Run
**Status:** VERIFIED
**Timestamp:** 2026-08-16 18:07:58 UTC
**Verification:** Sysmon Event ID 13 and Event ID 1

**Activity:**
- Modified the registry using `reg.exe`.
- Registry path: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`.
- Value name: `Atomic Red Team`.
- Configured value: `C:\Path\AtomicRedTeam.exe`.

**Purpose:**
Demonstrates Registry Run Key persistence.

**MITRE ATT&CK:**
T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

**Sigma Rule:** `sigma-rules/custom/registry_run_key_persistence.yml`

---

## 3. Manual - Failed Logon

**Test:** Manual failed authentication attempts
**Status:** VERIFIED
**Timestamp:** 2026-08-16 20:15:38–20:15:47 UTC
**Verification:** Windows Security Event ID 4625

**Activity:**
- 3 failed logon attempts.
- Account: `soc`.
- Logon Type: `2` (Interactive).
- Status: `0xC000006D`.
- Failure reason: Bad password.

**Purpose:**
Demonstrates failed authentication telemetry for detecting repeated login attempts.

**MITRE ATT&CK Context:**
Valid Accounts / Credential Access context

**Sigma Rule:** `sigma-rules/adopted/<failed_logon_filename>.yml`

---

## 4. T1057 - Process Discovery

**Test:** Manual - tasklist
**Status:** VERIFIED
**Timestamp:** 2026-08-19 13:08:56 UTC
**Verification:** Sysmon Event ID 1

**Activity:**
- Ran `tasklist` to enumerate running processes.

**Purpose:**
Demonstrates Process Discovery — attackers commonly enumerate processes to identify security tools to avoid or disable.

**MITRE ATT&CK:**
T1057 - Process Discovery

**Sigma Rule:** `sigma-rules/custom/process_discovery.yml`

---

## 5. T1082 - System Information Discovery

**Test:** Manual - systeminfo
**Status:** VERIFIED
**Timestamp:** 2026-08-19 15:00:11 UTC
**Verification:** Sysmon Event ID 1

**Activity:**
- Ran `systeminfo` to enumerate OS version, patch level, and hardware.

**Purpose:**
Demonstrates System Information Discovery, used by attackers to fingerprint the host and check for VM/sandbox indicators.

**MITRE ATT&CK:**
T1082 - System Information Discovery

**Sigma Rule:** `sigma-rules/custom/system_info_discovery.yml`

---

## 6. T1018 - Remote System Discovery

**Test:** Manual - Test-NetConnection to default gateway
**Status:** VERIFIED
**Timestamp:** 2026-08-15 20:54:40  UTC
**Verification:** Sysmon Event ID 3

**Activity:**
- Ran `Test-NetConnection -ComputerName <gateway_ip> -Port 80`.
- Generated an outbound TCP connection attempt.

**Purpose:**
Demonstrates Remote System Discovery — probing other hosts on the network to plan lateral movement.

**MITRE ATT&CK:**
T1018 - Remote System Discovery

**Sigma Rule:** `sigma-rules/custom/remote_system_discovery.yml`

---

## 7. T1071.004 - DNS Query (Demonstration)

**Test:** Manual - ping www.example.com
**Status:** VERIFIED
**Timestamp:** 2026-08-15 22:16:21 UTC 
**Verification:** Sysmon Event ID 22

**Activity:**
- Ran `ping www.example.com`, triggering a DNS resolution attempt.

**Purpose:**
Demonstrates DNS query telemetry (Event ID 22). Used as a simplified stand-in for DNS-based C2 detection concepts, not a real C2 detection.

**MITRE ATT&CK:**
T1071.004 - Application Layer Protocol: DNS

**Sigma Rule:** `sigma-rules/custom/dns_query_demo.yml`

---

## 8. T1112 - Modify Registry (Hide File Extensions)

**Test:** Manual - reg add HideFileExt
**Status:** VERIFIED
**Timestamp:** 2026-08-25 11:46:05 UTC 
**Verification:** Sysmon Event ID 13

**Activity:**
- Set `HideFileExt` to `1` under `HKCU\...\Explorer\Advanced`, hiding file extensions in Explorer.
- Reverted afterward for cleanup.

**Purpose:**
Demonstrates a known technique for disguising malicious files (e.g. `invoice.pdf.exe` appearing as `invoice.pdf`).

**MITRE ATT&CK:**
T1112 - Modify Registry

**Sigma Rule:** `sigma-rules/custom/hide_file_extensions.yml`

---

## 9. T1070.001 - Clear Windows Event Logs

**Test:** Manual - wevtutil cl Security
**Status:** VERIFIED
**Timestamp:** 2026-08-19 09:07:25 UTC 
**Verification:** Security Event ID 1102

**Activity:**
- Exported Security log as backup before clearing.
- Ran `wevtutil cl Security`.
- The clearing action itself generated Event ID 1102.

**Purpose:**
Demonstrates Indicator Removal via clearing event logs, and shows that the cleanup action itself is detectable.

**MITRE ATT&CK:**
T1070.001 - Indicator Removal: Clear Windows Event Logs

**Sigma Rule:** `sigma-rules/custom/event_log_cleared.yml`

---

## 10. T1059.001 - Encoded PowerShell Command

**Test:** Manual - self-built -EncodedCommand (whoami)
**Status:** VERIFIED
**Timestamp:** 2026-08-26 1:51:15 UTC 
**Verification:** Sysmon Event ID 1

**Activity:**
- Base64-encoded the command `whoami` and executed it via `powershell.exe -EncodedCommand`.
- Replaces the earlier blocked Mimikatz test with a safe, fully transparent equivalent.

**Purpose:**
Demonstrates obfuscated command execution, a technique used to hide malicious intent from casual inspection and simple string-based detection.

**MITRE ATT&CK:**
T1059.001 - Command and Scripting Interpreter: PowerShell

**Sigma Rule:** `sigma-rules/custom/encoded_powershell_command.yml`