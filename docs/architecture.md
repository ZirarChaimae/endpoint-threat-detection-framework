# Architecture

This document describes the full technical architecture of the Argus SOC Prototype: the network topology, every component and what it runs, the complete detection-to-response data flow, and the infrastructure details that aren't visible in the diagram alone. See `architecture.png` / `architecture.svg` in this same folder for the visual companion to this document.

---

## 1. Network Topology

The lab runs three VMs under VMware Workstation, on two separate virtual networks, plus the host machine itself.

```
Kali-Attacker                         OPNsense-Firewall                    Windows-DVWA
(VMnet8, NAT)                         (dual-homed)                         (VMnet4)
192.168.250.134                       WAN: 192.168.250.141/24 (static)     192.168.20.41/24
DHCP-assigned                         LAN: 192.168.20.128/24               gateway 192.168.20.128
                                                                            (also has a second, dead
                                                                            adapter on VMnet2,
                                                                            192.168.100.10/24 -- harmless,
                                                                            intentionally left as-is)

Host machine (DESKTOP-D7KLC3D)
192.168.20.1 on VMnet4
```

**Default gateways, and the one non-obvious fact that matters most:**
- Kali's actual default gateway is **192.168.250.2** — VMware's own built-in NAT router for the VMnet8 segment, **not** OPNsense. VMnet8 is a "NAT"-type virtual network, which always ships with its own hidden gateway device; this is a VMware lab artifact, not something present in a real network.
- To force traffic destined for the victim subnet through OPNsense instead of that hidden shortcut, Kali has a manually-added static route:
  ```
  ip route add 192.168.20.0/24 via 192.168.250.141
  ```
  **This route is not persistent by default** and must be made permanent via `nmcli` (see Section 6). If it silently reverts to the VMware NAT gateway, all traffic reaches the victim directly, completely bypassing OPNsense's firewall with no error of any kind — this was the root cause of a multi-session debugging investigation into why `block_ip` appeared not to work.
- Windows-DVWA's gateway is correctly OPNsense's LAN interface (192.168.20.128) — this one requires no manual override, since VMnet4 has no competing built-in router the way VMnet8 does.

---

## 2. Components

### 2.1 Kali-Attacker
- **Role:** Attacker / red-team machine, used to fire all 4 web attacks (SQLi, XSS, Path Traversal, Command Injection) via authenticated `curl` requests.
- **OS:** Kali Linux 2026.2.
- **Network:** VMnet8 (NAT), 192.168.250.134 (DHCP-leased, changes if the VM is recreated — always verify with `ip a` before assuming it's still the same address).
- **Key dependency:** the persistent static route described above.

### 2.2 OPNsense-Firewall
- **Role:** Network perimeter. Every packet from Kali to the victim must physically transit this VM's WAN interface — this is what makes `block_ip` a genuine network-level control rather than an endpoint-level one.
- **Version:** OPNsense 26.7 (amd64).
- **Interfaces:**
  - `em1` (WAN): 192.168.250.141/24, **static** (deliberately not DHCP — see Section 6 for why).
  - `em0` (LAN): 192.168.20.128/24.
- **Web GUI:** `http://192.168.20.128` (plain HTTP, confirmed intentional for this lab, not a misconfiguration).
- **Firewall objects:**
  - Alias `SOC_Blocked_IPs` (type: Host(s)) — the dynamic block list that `response/actions.py` adds/removes IPs from via the REST API.
  - A `block` rule on WAN, Direction In, source = `SOC_Blocked_IPs`, positioned above the general allow rule.
  - A `pass` rule on WAN allowing inbound TCP/80 to 192.168.20.41 (DVWA), so normal traffic still reaches the victim when not blocked.
- **API:** OPNsense's REST API (`/api/firewall/alias_util/add|delete|list/SOC_Blocked_IPs`), authenticated via an API key/secret pair, read from the host's `OPNSENSE_API_KEY`/`OPNSENSE_API_SECRET` environment variables — never hardcoded in `actions.py`, since that file is git-tracked.

### 2.3 Windows-DVWA ("Victim-Win10")
- **Role:** The monitored victim host — runs both the vulnerable web application and the endpoint detection stack.
- **OS:** Windows 10, local account `soc`.
- **VMX path:** `C:\Users\Zirar\Documents\Virtual Machines\Victim-Win10-v2\Victim-Win10.vmx`.
- **Network:** VMnet4, 192.168.20.41/24, gateway 192.168.20.128. A second adapter on VMnet2 (192.168.100.10/24) exists but is dead/unused — confirmed harmless, intentionally left connected.
- **Software running on this host:**
  - **XAMPP** (Apache 2.4.58, PHP 8.0.30, MariaDB 10.4.32) hosting **DVWA** (Damn Vulnerable Web Application) at `/DVWA/`.
  - **Sysmon** (SwiftOnSecurity configuration) — captures process creation, registry, network, and DNS telemetry at the OS level.
  - **Chainsaw v2.16.5** — runs Sigma rules against Sysmon/Security event logs. Runs **inside this VM**, not on the host, because Windows Smart App Control blocks Chainsaw's unsigned binary on the host machine with no workaround.
  - Sigma rules deployed to `C:\Tools\SigmaRules\` (custom, adopted, and community folders — 1,194 `.yml` files total).
  - Chainsaw binary at `C:\Tools\Chainsaw\`.

### 2.4 Host Machine (DESKTOP-D7KLC3D)
- **Role:** Orchestrates everything — runs the dashboard, drives the automation pipeline, and holds the response credentials.
- **Network:** 192.168.20.1 on VMnet4 (shares this segment with Windows-DVWA and OPNsense's LAN side).
- **Software running here:**
  - **Argus Dashboard** (`scripts/dashboard-server.py`, Flask, port 5000) — the analyst-facing web UI.
  - **`vmrun`** (`C:\Program Files\VMware\VMware Workstation\vmrun.exe`) — used both by the automation pipeline (to run Chainsaw remotely inside Windows-DVWA) and by `response/actions.py`'s `kill_process` (to terminate a malicious process on the victim by PID).
  - **`response/actions.py`** — the response logic itself: `kill_process` (via `vmrun`), `block_ip`/`unblock_ip` (via OPNsense's REST API).
  - Python 3, running `correlation/correlate.py` and `webattack/weblog_detector.py`.

---

## 3. Detection Pipeline

Two independent detection paths feed into one correlation engine, because Sysmon and Apache observe two entirely different things — an important architectural point, not just an implementation detail: **Sysmon can never see SQL Injection, XSS, or Path Traversal**, since these attacks only ever exist as HTTP request text that never touches the OS process/registry/network layer Sysmon monitors. **Command Injection is the one exception** — since a successful injection spawns a real child process (`cmd.exe`) under `httpd.exe`, it is visible on *both* sides simultaneously, which is exactly why it's the project's flagship "cross-schema correlation" scenario.

### 3.1 Endpoint path
```
Sysmon (captures events)
   → exported via wevtutil (scripts/export-and-copy.ps1)
   → Chainsaw, run inside the VM via `vmrun runProgramInGuest`
   → evaluated against 3 Sigma rule sets:
        - custom/     (11 rules, hand-written for this project)
        - adopted/    (1 rule from SigmaHQ, intentionally narrow scope)
        - community/  (~1,183 SigmaHQ process_creation rules)
   → CSV output copied back to host only (raw .evtx never leaves the VM)
```

### 3.2 Web-attack path
```
Apache access.log (on Windows-DVWA)
   → pulled to host via vmrun copyFileFromGuestToHost
   → webattack/weblog_detector.py
   → pattern-matches for SQLi, XSS, Path Traversal (by payload),
     and Command Injection (by endpoint path only --
     Apache does not log POST bodies, a documented detection limitation)
   → output written in the same CSV schema as Chainsaw's output,
     so the correlation engine can treat both sources identically
```

### 3.3 Correlation
```
correlation/correlate.py + correlation/attack-patterns.json
   → 16 patterns total: multi-stage endpoint chains, single-event
     web-attack patterns, and the cross-schema
     "command-injection-web-to-endpoint" pattern
   → deduplication (an event, once used in an incident, cannot be reused)
   → same-computer entity check between chain stages
   → output: correlation/incidents/incidents_<timestamp>.json
```

Each correlated incident carries: a MITRE ATT&CK mapping, a severity (High/Medium/Low, guessed from the detection name), a confidence level, the affected host, the source IP(s)/user(s), and a full event timeline.

---

## 4. Response Orchestration

`response/actions.py` exposes four functions, all defaulting to `dry_run=True` — nothing executes for real unless the dashboard explicitly passes `live=True` after analyst confirmation.

| Function | Mechanism | Target |
|---|---|---|
| `kill_process(pid, ...)` | `vmrun runProgramInGuest` → `taskkill /PID <pid> /F` | The Windows-DVWA VM, by process ID |
| `verify_process_killed(pid, ...)` | `vmrun runProgramInGuest` → `tasklist /FI "PID eq <pid>"` | Confirms the PID no longer appears |
| `block_ip(ip, ...)` | POST to OPNsense's `/api/firewall/alias_util/add/SOC_Blocked_IPs` | The `SOC_Blocked_IPs` alias on OPNsense |
| `unblock_ip(ip, ...)` | POST to OPNsense's `/api/firewall/alias_util/delete/SOC_Blocked_IPs` | Same alias, reverses the block |

Verification is deliberately independent of the action's own reported success — `block_ip` is confirmed by attempting the actual blocked connection and observing it fail (a `curl --max-time 8` timeout), not merely by trusting the OPNsense API's `{'status': 'done'}` response.

Every response attempt (dry-run or live, success or failure) is persisted to `correlation/incidents/response-log.json`, keyed by `pattern_id|start_time|computer` — a key stable across hunt re-runs, since a fresh hunt regenerates the incidents file but the underlying event timestamps don't change.

---

## 5. Dashboard

`scripts/dashboard-server.py` (Flask) serves `docs/soc-dashboard.html` and exposes:

| Route | Purpose |
|---|---|
| `/api/latest` | Latest Chainsaw/weblog CSV rows per category |
| `/api/incidents` | Latest correlated incidents, enriched with response history |
| `/api/response-rules` | Which incident patterns have an automated response configured |
| `/api/respond` | Triggers `kill_process` or `block_ip` for a specific incident |
| `/api/unblock-ip` | Reverses a `block_ip` action |
| `/api/generate-report` | Produces a Markdown incident report from a live incident |
| `/api/run-hunt` | Runs the full pipeline (export → Chainsaw → weblog_detector → correlate) |
| `/api/auto-hunt/start`, `/stop`, `/status` | Scheduled automatic hunting, password held in memory only |
| `/api/vm-status` | Whether the Victim-Win10 VM is currently running |

The dashboard has 6 tabs: Sysmon (Custom), Sysmon (Community), Security (Custom), Security (Adopted), Web Attacks, and Incidents. The Incidents and Web Attacks tabs both render correlated incidents as cards with MITRE badges, a timeline, a Respond button (labeled by action type), an Unblock IP button (once a block has succeeded), and a Download Report button.

---

## 6. Infrastructure Facts Worth Preserving

These are hard-won operational details that are easy to silently break and hard to re-diagnose — kept here so they don't have to be rediscovered.

- **Kali's route is not persistent by default.** Made permanent via:
  ```
  sudo nmcli connection modify "Wired connection 1" +ipv4.routes "192.168.20.0/24 192.168.250.141"
  sudo nmcli connection up "Wired connection 1"
  ```
  Verify before any `block_ip` testing session with `ip route get 192.168.20.41` — must show `via 192.168.250.141`, not `via 192.168.250.2`.

- **OPNsense's WAN is static, not DHCP, by deliberate design.** A DHCP-leased address is not guaranteed to survive a reboot, and Kali's route depends on this exact address — a changed lease would silently break the entire response pipeline again with no obvious error.

- **DVWA's login session and security level (must be "Low") reset after MySQL restarts or VM reboots.** Always re-authenticate and re-verify the security level before assuming an attack "isn't working" (see `webattack/scenario-playbook.md` for the exact re-authentication commands).


- **Windows Smart App Control blocks Chainsaw entirely on the host** — this is why Chainsaw runs inside the VM via `vmrun runProgramInGuest` rather than on the host machine directly; no exclusion or unblock workaround succeeded.

- **Only 15.3GB RAM on the host.** Running all three VMs plus normal desktop applications can push free RAM below 1GB, causing intermittent, misleading network symptoms that look like configuration bugs. Check free RAM before any multi-VM debugging session:
  ```powershell
  Get-CimInstance Win32_OperatingSystem | Select-Object @{N="FreeRAM(GB)";E={[math]::Round($_.FreePhysicalMemory/1MB,1)}}
  ```

---

## 7. Technology Stack Summary

| Layer | Technology |
|---|---|
| Hypervisor | VMware Workstation |
| Attacker OS | Kali Linux 2026.2 |
| Firewall | OPNsense 26.7 (amd64) |
| Victim OS | Windows 10 |
| Web stack | XAMPP (Apache 2.4.58, PHP 8.0.30, MariaDB 10.4.32) + DVWA |
| Endpoint telemetry | Sysmon (SwiftOnSecurity config) |
| Detection engine | Chainsaw v2.16.5 + Sigma rules |
| Web-attack detection | Custom Python (`weblog_detector.py`) |
| Correlation | Custom Python (`correlate.py`), JSON-config-driven |
| Response orchestration | Custom Python (`actions.py`), OPNsense REST API + `vmrun` |
| Dashboard backend | Python Flask |
| Dashboard frontend | Vanilla HTML/CSS/JS + Chart.js |
| VM automation | PowerShell + `vmrun` |
| Version control | Git + GitHub |
| Planned benchmark comparison | Wazuh (not yet integrated — see project roadmap) |
