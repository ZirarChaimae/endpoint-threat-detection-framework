# Lab Setup

## Hypervisor
- VMware® Workstation Pro 26H1, version 26.0.0.25388281

## Victim VM
- Name: Windows 10 (Log Source) <!-- NEEDS CONFIRMATION: previous version of this file said "Victim-Win10" — confirm which is the actual current VM name and I'll correct this line. -->
- OS: Windows 10
- Local account: `soc`
- RAM: 4 GB
- CPU cores: 2
- Disk: 40GB, single file
- Network: Host-only (VMnet2)
- Isolation confirmed: `Test-NetConnection` to 8.8.8.8:443 failed as expected — no internet access from the guest

## Snapshots
- `clean-baseline` (w10_victim) — taken immediately after OS install + VMware Tools + auto-update disabled
- `post-cleanup-week4` — taken after the Mimikatz cleanup (process killed, downloaded script removed from Temp, PowerShell/PSReadLine history cleared)

## Sysmon
- Version: v15.21
- Config used: SwiftOnSecurity `sysmonconfig-export.xml` (saved as `sysmon-config/sysmonconfig.xml`)
- Install command: `.\Sysmon64.exe -accepteula -i sysmonconfig.xml`
- Verified running: `Get-Service Sysmon64` → Status Running
- Verified logging: `Get-WinEvent` confirmed Event ID 1 entries present

## Log Export Process
- Sysmon log exported via: `wevtutil epl Microsoft-Windows-Sysmon/Operational C:\logs\sysmon_export.evtx`
- Security log exported via: `wevtutil epl Security C:\logs\security_export.evtx`
- Exports transferred host-side automatically by `scripts\export-and-copy.ps1` via `vmrun`
  (guest credentials passed as a runtime parameter, never stored on disk or committed)

## Chainsaw
- Version: v2.16.5
- Runs **inside the VM**, not on the host — the host blocks Chainsaw entirely via Windows
  Smart App Control (no exclusion, unblock, or admin-rights workaround succeeded). All
  Chainsaw execution happens via `vmrun runProgramInGuest`; only the resulting `sigma.csv`
  files are copied back to the host, never the raw `.evtx` logs.
- Installed inside the VM at: `C:\Tools\Chainsaw\`
- Sigma rules copied inside the VM at: `C:\Tools\SigmaRules\`

## Account Lockout Policy
- Repeated deliberate bad-password testing can trigger Windows' own account lockout policy
  on the `soc` account. If this happens, wait ~30 minutes for it to clear, or disable the
  policy permanently for lab purposes: `net accounts /lockoutthreshold:0`
