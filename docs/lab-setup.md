# Lab Setup

## Hypervisor
- VMware Workstation Pro 26H1, version 26.0.0.25388281

## Victim / Web Application VM
- Name: Victim-Win10 (VMX: `Victim-Win10-v2`, rebuilt during Phase 2 after VMX corruption -- see Week 9 in `docs/weekly-log.md`)
- OS: Windows 10
- Local account: `soc`
- RAM: 4 GB
- CPU cores: 2
- Disk: 40GB, single file
- Network: VMnet4 (Custom), static IP `192.168.20.41/24`, gateway `192.168.20.128` (OPNsense LAN)
- A second, dead network adapter exists on VMnet2 (`192.168.100.10/24`, no gateway) -- harmless, intentionally left connected, confirmed fine to leave as-is.
- No longer network-isolated in the Phase 1 sense (host-only, no internet) -- this VM now sits behind OPNsense as part of the Phase 2 segmented network. See `docs/architecture.md` for the full current topology.

## Snapshots
- `clean-baseline` (w10_victim) -- taken immediately after OS install + VMware Tools + auto-update disabled
- `post-cleanup-week4` -- taken after the Mimikatz cleanup (process killed, downloaded script removed from Temp, PowerShell/PSReadLine history cleared)
- Recommended: snapshot again once Phase 2's full stack (DVWA + Wazuh agent + OPNsense route) is confirmed working, before making further changes.

## Sysmon
- Version: v15.21
- Config used: SwiftOnSecurity `sysmonconfig-export.xml` (saved as `sysmon-config/sysmonconfig.xml`)
- Install command: `.\Sysmon64.exe -accepteula -i sysmonconfig.xml`
- Verified running: `Get-Service Sysmon64` -> Status Running
- Verified logging: `Get-WinEvent` confirmed Event ID 1 entries present

## Log Export Process
- Sysmon log exported via: `wevtutil epl Microsoft-Windows-Sysmon/Operational C:\logs\sysmon_export.evtx`
- Security log exported via: `wevtutil epl Security C:\logs\security_export.evtx`
- Exports transferred host-side automatically by `scripts\export-and-copy.ps1` via `vmrun`
  (guest credentials passed as a runtime parameter, never stored on disk or committed)

## Chainsaw
- Version: v2.16.5
- Runs **inside the VM**, not on the host -- the host blocks Chainsaw entirely via Windows
  Smart App Control (no exclusion, unblock, or admin-rights workaround succeeded). All
  Chainsaw execution happens via `vmrun runProgramInGuest`; only the resulting `sigma.csv`
  files are copied back to the host, never the raw `.evtx` logs.
- Installed inside the VM at: `C:\Tools\Chainsaw\`
- Sigma rules copied inside the VM at: `C:\Tools\SigmaRules\`

## Account Lockout Policy
- Repeated deliberate bad-password testing can trigger Windows' own account lockout policy
  on the `soc` account. If this happens, wait ~30 minutes for it to clear, or disable the
  policy permanently for lab purposes: `net accounts /lockoutthreshold:0`

---

## Phase 2 Infrastructure

### Kali-Attacker
- OS: Kali Linux 2026.2
- Network: VMnet8 (NAT), DHCP-assigned (`192.168.250.x`, changes if the VM is recreated -- always confirm with `ip a` before assuming an address is still current)
- **Required manual route** to reach the victim subnet through OPNsense instead of VMware's own NAT gateway:
  ```bash
  sudo ip route add 192.168.20.0/24 via 192.168.250.141
  ```
- This route is **not persistent by default**. Make it survive a reboot:
  ```bash
  sudo nmcli connection modify "Wired connection 1" +ipv4.routes "192.168.20.0/24 192.168.250.141"
  sudo nmcli connection up "Wired connection 1"
  ```
- Before any test session, verify the route is actually in place:
  ```bash
  ip route get 192.168.20.41
  ```
  Must show `via 192.168.250.141`. If it shows `via 192.168.250.2` instead, re-run the two commands above -- this exact silent reversion was the root cause of a multi-session `block_ip` enforcement investigation (see `docs/benchmark-results.md` and `docs/architecture.md`).

### OPNsense-Firewall
- Version: 26.7 (amd64)
- WAN (`em1`): `192.168.250.141/24`, **static** (deliberately set via the console interface wizard, not DHCP -- a leased address is not guaranteed to survive a reboot, and Kali's route above depends on this exact address staying fixed)
- LAN (`em0`): `192.168.20.128/24`
- Web GUI: `http://192.168.20.128` (plain HTTP, confirmed intentional for this lab)
- Firewall objects to recreate if this instance is ever rebuilt:
  - Alias `SOC_Blocked_IPs`, type Host(s)
  - A `block` rule on WAN: Direction In, IPv4, Protocol any, Source = `SOC_Blocked_IPs`, positioned above the allow rule
  - A `pass` rule on WAN allowing inbound TCP/80 to `192.168.20.41`
- API credentials (`OPNSENSE_API_KEY` / `OPNSENSE_API_SECRET`) are generated under System -> Access -> Users -> API keys, and loaded on the host via:
  ```powershell
  [System.Environment]::SetEnvironmentVariable("OPNSENSE_API_KEY", "YOUR_KEY", "User")
  [System.Environment]::SetEnvironmentVariable("OPNSENSE_API_SECRET", "YOUR_SECRET", "User")
  ```
  Never hardcoded in `response/actions.py`, since that file is git-tracked.

### DVWA (on Victim-Win10)
- XAMPP (Apache 2.4.58, PHP 8.0.30, MariaDB 10.4.32), DVWA installed under `/DVWA/`
- Requires a dedicated MySQL user/database (`dvwa` / a set password) rather than `root` -- created via phpMyAdmin
- Security level must be "Low" for the scripted attacks to succeed -- **resets to a stricter level after a MySQL restart or VM reboot**; always re-verify before assuming an attack "isn't working." Exact authenticated re-login and security-level-reset commands are in `webattack/scenario-playbook.md`.

### Wazuh (benchmark comparison target)
- Wazuh manager VM: Ubuntu, dual-homed -- one NIC on VMnet8 (NAT, for the manager's own internet access/updates), a second NIC added specifically on VMnet4 so the manager is directly reachable from Victim-Win10 without routing through OPNsense (no security reason for the monitoring platform itself to sit behind the firewall being tested).
- Second NIC static IP, set via netplan (`/etc/netplan/00-installer-config.yaml`):
  ```yaml
  network:
    version: 2
    ethernets:
      ens33:
        dhcp4: no
        addresses:
          - 192.168.20.50/24
      ens32:
        dhcp4: yes
  ```
  Applied with `sudo netplan apply`.
- Dashboard: `https://192.168.20.50` (self-signed certificate, accept the browser warning)
- Admin password recovery, if lost: extract from the install-time archive:
  ```bash
  sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
  ```
  Or reset directly:
  ```bash
  sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p "NewPassword.1"
  ```
  (Password must include upper/lowercase, a number, and one of `. * + ? -` specifically -- other symbols are rejected.)
- **Agent enrollment is separate from network reachability.** Pointing an existing agent's `ossec.conf` at the manager's address is not sufficient by itself -- the agent must be enrolled with a key generated at install time. Use the dashboard's "Deploy new agent" wizard to generate a fresh install command (includes the manager address and enrollment key together) rather than hand-editing an existing install's config.
- Since Victim-Win10 has no direct internet access, download the agent MSI on the host and push it in via `vmrun`:
  ```powershell
  Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi -OutFile "C:\Users\Zirar\Downloads\wazuh-agent.msi"
  & "C:\Program Files\VMware\VMware Workstation\vmrun.exe" -T ws -gu soc -gp "<password>" copyFileFromHostToGuest "C:\Users\Zirar\Documents\Virtual Machines\Victim-Win10-v2\Victim-Win10.vmx" "C:\Users\Zirar\Downloads\wazuh-agent.msi" "C:\Users\soc\Desktop\wazuh-agent.msi"
  ```
  Then, on Victim-Win10:
  ```powershell
  msiexec.exe /i "C:\Users\soc\Desktop\wazuh-agent.msi" /q WAZUH_MANAGER='192.168.20.50' WAZUH_AGENT_NAME='DESKTOP-JC89B03' WAZUH_REGISTRATION_SERVER='192.168.20.50'
  NET START WazuhSvc
  ```
- By default, the Wazuh agent only watches the Windows `Application`, `Security`, and `System` event channels -- it does **not** watch Apache's log or integrate with Sysmon out of the box. To let it see web attacks at all, add to `ossec.conf` (inside `<ossec_config>`):
  ```xml
  <localfile>
    <log_format>apache</log_format>
    <location>C:\xampp\apache\logs\access.log</location>
  </localfile>
  ```
  Restart the service after editing.
- **Known infrastructure gotcha:** the host and Victim-Win10 have been observed drifting exactly one hour out of sync (likely an asynchronous DST transition). Always check `Get-Date` on both machines before any test where exact timing matters -- see `docs/architecture.md` and `docs/benchmark-results.md` for the full incident this caused.
