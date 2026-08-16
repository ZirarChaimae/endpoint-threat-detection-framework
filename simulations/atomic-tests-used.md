# Atomic Red Team & Windows Security Simulations Log

| # | Technique ID | Test # | Timestamp (UTC) | Status | Evidence |
|---|---|---:|---|---|---|
| 1 | T1059.001 - PowerShell | 1 | — | BLOCKED | Mimikatz test required Internet access. Host-only network isolation prevented download. No execution occurred. |
| 2 | T1053.005 - Scheduled Task | 1 | 2026-08-16 16:21:54 | VERIFIED | Sysmon Event ID 1 detected `schtasks.exe`. Created `T1053_005_OnLogon` and `T1053_005_OnStartup`. |
| 3 | T1547.001 - Registry Run Keys | 1 | 2026-08-16 18:07:58 | VERIFIED | Sysmon Event ID 13 detected registry modification. Event ID 1 detected `reg.exe`. |
| 4 | Manual - Failed Logon | N/A | 2026-08-16 20:15:38–20:15:47 | VERIFIED | Windows Security Event ID 4625 detected 3 failed logon attempts for account `soc`. |

# Test Details

## 1. T1059.001 - PowerShell

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
**Action:** Replace with a safe PowerShell test that does not require Internet access.

---

## 2. T1053.005 - Scheduled Task

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

---

## 3. T1547.001 - Registry Run Keys / Startup Folder

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

---

## 4. Manual - Failed Logon

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