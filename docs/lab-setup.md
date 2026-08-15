# Lab Setup

## Hypervisor
- VMware Workstation Player, version: 26.0.0.25388281

## Victim VM
- Name: Victim-Win10
- OS: Windows 10 
- RAM: 4 GB
- CPU cores: 2git 
- Disk: 40GB, single file
- Network: Host-only (VMnet2)
- Isolation confirmed: Test-NetConnection to 8.8.8.8:443 failed as expected

## Snapshots
- clean-baseline(w10_victim) — taken immediately after OS install + VMware Tools + auto-update disabled

## Sysmon
- Version: v15.21
- Config used: SwiftOnSecurity sysmonconfig-export.xml (saved as sysmon-config/sysmonconfig.xml)
- Install command: .\Sysmon64.exe -accepteula -i sysmonconfig.xml
- Verified running: Get-Service Sysmon64 → Status Running
- Verified logging: Get-WinEvent confirmed Event ID 1 entries present

## Log Export Process
- Sysmon log exported via: wevtutil epl Microsoft-Windows-Sysmon/Operational C:\logs\sysmon_export.evtx
- Security log exported via: wevtutil epl Security C:\logs\security_export.evtx
- Exports transferred host-side via VMware shared folder, stored locally in logs-samples/ (not committed — see .gitignore)