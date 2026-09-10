# Scenario Playbook — Exact Trigger Commands

This file maps every detection you have to the exact command that fires it, and every
correlation pattern in `correlation/attack-patterns.json` to the exact sequence of
commands needed to produce it end-to-end. Run all commands inside the victim VM
(current-user PowerShell, not the host), then run the normal pipeline
(`scripts\export-and-copy.ps1`) to pull logs, hunt, and correlate.

**Rule of thumb:** run one scenario, then pipeline + correlate + confirm it shows up
in the Incidents tab, before starting the next one. Cleaner for screenshots, and
avoids two scenarios' events landing inside each other's time windows by accident.

---

## Single-technique trigger commands (building blocks)

| Code | Technique | Rule title matched | Exact command |
|---|---|---|---|
| A | T1059.001 Encoded PowerShell | Suspicious Encoded PowerShell Command | `$b=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami')); powershell -EncodedCommand $b` |
| B | T1547.001 Registry Run Key | Registry Run Key Persistence via reg.exe | `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestPersist /t REG_SZ /d "calc.exe" /f` |
| C | T1053.005 Scheduled Task | Scheduled Task Creation via schtasks.exe | `schtasks /create /tn "TestTask_Recon" /tr "cmd.exe /c calc.exe" /sc onlogon /f` |
| D | T1057 Process Discovery | Process Discovery via tasklist.exe | `tasklist` |
| E | T1082 System Info Discovery | System Information Discovery via systeminfo.exe | `systeminfo` |
| F | T1018 Remote System Discovery | Outbound Network Connection Probe | `Test-NetConnection -ComputerName <default-gateway-ip> -Port 443` — **unreliable, Known Issue, low priority, use only if you want to re-test it** |
| G | T1112 Hide File Extensions | File Extensions Hidden via Registry Modification | `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 1 /f` |
| H | T1070.001 Event Log Cleared | Security Event Log Cleared | `wevtutil epl Security C:\logs\security_backup_beforeclear.evtx` then `wevtutil cl Security` — **destroys Security-log evidence, always back up first** |
| I | T1110 Failed Logon (bad password) | Multiple Failed Logon Attempts (Bad Password) | `runas /user:soc cmd` and type a wrong password 3 times in a row |
| J | T1078 Account Tampering (adopted rule) | Account Tampering - Suspicious Failed Logon Reasons | `net user reconTest Test123! /add` then `net user reconTest /active:no` then `runas /user:reconTest cmd` and type any password once (fails because the account is disabled → Status 0xC0000072) |

Cleanup after testing (run once you're done with a batch, so the VM doesn't accumulate junk):
```
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestPersist /f
schtasks /delete /tn "TestTask_Recon" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f
net user reconTest /delete
```

---

## Every pattern in attack-patterns.json → exact command sequence

### 1. full-intrusion-chain (NEW) — Recon → Execution → Persistence
Run E, then D, then A, then B, each a few seconds apart:
```
systeminfo
tasklist
$b=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami')); powershell -EncodedCommand $b
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestPersist /t REG_SZ /d "calc.exe" /f
```

### 2. phishing-to-persistence (existing) — Execution → Persistence
Run A, then B, within ~1 minute:
```
$b=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami')); powershell -EncodedCommand $b
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestPersist /t REG_SZ /d "calc.exe" /f
```

### 3. execution-to-lateral-movement (existing) — Execution → Credential Access → Discovery → Discovery
Run A, then I, then E, then F, spaced within ~15 minutes:
```
$b=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami')); powershell -EncodedCommand $b
runas /user:soc cmd            # type wrong password 3 times
systeminfo
Test-NetConnection -ComputerName <default-gateway-ip> -Port 443
```

### 4. compromise-to-staging (existing) — Persistence → Execution
Run C, then A:
```
schtasks /create /tn "TestTask_Recon" /tr "cmd.exe /c calc.exe" /sc onlogon /f
$b=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami')); powershell -EncodedCommand $b
```

### 5. reconnaissance-sweep (existing) — Discovery → Discovery → Discovery
Run E, then D, then F:
```
systeminfo
tasklist
Test-NetConnection -ComputerName <default-gateway-ip> -Port 443
```

### 6. evasion-preparation (existing) — Defense Evasion → Execution
Run G, then A:
```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 1 /f
$b=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami')); powershell -EncodedCommand $b
```

### 7. discovery-before-scheduled-persistence (NEW) — Discovery → Persistence
Run D, then C:
```
tasklist
schtasks /create /tn "TestTask_Recon" /tr "cmd.exe /c calc.exe" /sc onlogon /f
```

### 8. discovery-before-registry-persistence (NEW) — Discovery → Persistence
Run E, then B:
```
systeminfo
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestPersist /t REG_SZ /d "calc.exe" /f
```

### 9. credential-access-to-log-clearing (NEW) — Credential Access → Anti-Forensics
Run I, then H (back up the log first, this one is destructive):
```
runas /user:soc cmd            # type wrong password 3 times
wevtutil epl Security C:\logs\security_backup_beforeclear.evtx
wevtutil cl Security
```

### 10. evasion-to-persistence (NEW) — Defense Evasion → Persistence
Run G, then B:
```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestPersist /t REG_SZ /d "calc.exe" /f
```

### 11. account-tampering-alone (NEW, single_event) — uses the adopted rule
Run J only:
```
net user reconTest Test123! /add
net user reconTest /active:no
runas /user:reconTest cmd      # type any password once, it will fail
```
This is the scenario that finally gives the adopted rule (`win_security_susp_failed_logon_reasons.yml`)
something to legitimately catch — it's designed to ignore plain bad-password attempts, so
your existing 3x-wrong-password test (I) will never trigger it. This one will.

### 12. event-log-cleared-alone (existing, single_event)
Run H only:
```
wevtutil epl Security C:\logs\security_backup_beforeclear.evtx
wevtutil cl Security
```

---

## Notes

- F (Remote System Discovery) is still the one detection never conclusively confirmed
  firing through Chainsaw (Known Issue, low priority). It's included above for
  completeness, but don't spend time chasing it right now if it doesn't fire — it's
  already documented as an open issue, not a new problem.
- Every command above is safe and reversible in your isolated lab — no real payloads,
  no external network calls.
