# Weekly Project Log

## Weeks 1–5 (summary)
Lab built, Sysmon installed and verified, log export process established. Simulated the
first attack techniques (scheduled task, registry persistence, failed logons) and hit a
real safety incident: the first Atomic Red Team test filed under "T1059.001" turned out
to be Mimikatz, not a safe example. First run was blocked automatically by the VM's
network isolation. A second, apparently successful run produced real credential-dump
output, which was deliberately not analyzed or discussed — cleanup only (kill process,
remove downloaded script, clear PowerShell/PSReadLine history, confirm no `mimikatz`
process remained, fresh snapshot `post-cleanup-week4`). Replaced with a safe, self-built
encoded PowerShell example for all further testing. Expanded from 2 to 10 custom Sigma
rules across 6 MITRE tactics, added 1 adopted SigmaHQ rule, and added the full SigmaHQ
`process_creation` community rule set (~1,183 rules). Full detail in `docs/lab-setup.md`
and `simulations/atomic-tests-used.md`.

## Week 6 — Chainsaw Detection Engine
- Re-exported full Sysmon and Security logs after Week 4-5 simulations.
- Installed Chainsaw, initially attempted on the host.
- Ran Chainsaw hunts against custom rules and the adopted rule; detections confirmed,
  output saved as CSV in `detections/chainsaw-output/`.
- **Finding:** simulating T1070.001 (`wevtutil cl Security`) permanently destroyed the
  evidence of the earlier T1110 failed-logon simulation, since both events lived in the
  same Security log and no pre-clear backup was preserved in that run. A faithful, if
  unintentional, reproduction of a real SOC problem — reinforces why exporting/backing up
  logs before investigating is standard practice.
- Built `scripts/export-and-copy.ps1`: single-command pipeline using `vmrun` to export
  logs, copy them to host, and run Chainsaw hunts. Credentials passed as a runtime
  parameter, never hardcoded or committed. Resolved a PowerShell execution-policy block
  via `Set-ExecutionPolicy -Scope CurrentUser`.
- **Finding:** the adopted rule (`win_security_susp_failed_logon_reasons.yml`) targets
  uncommon failure codes and did not match manual bad-password attempts (Status
  `0xC000006D`). Wrote `failed_logon_bad_password.yml` to cover that common case
  specifically, and kept the adopted rule as a deliberate example of detection-rule
  specificity.
- **Blocker resolved:** Chainsaw could not run on the host at all — Windows Smart App
  Control blocked it unconditionally, with no working exclusion or admin-rights bypass.
  Moved all Chainsaw execution inside the VM via `vmrun runProgramInGuest`, copying back
  only the resulting `sigma.csv` files (Decision #002).

## Week 7 — Dashboard, Correlation Engine v1, Supervisor Pivot
- Built the first version of the correlation engine (`correlation/correlate.py`,
  `correlation/attack-patterns.json`) — generic and JSON-config-driven by design, so new
  attack scenarios mean editing config rather than rewriting code (Decision #003).
  Proved it working on real data: a genuine "Phishing/PowerShell to Registry Persistence"
  correlated incident.
- Built the first browser SOC dashboard (`docs/soc-dashboard.html`,
  `scripts/dashboard-server.py`): multi-tab layout, KPI cards, severity chart, sortable
  table, an Incidents tab with MITRE badges and timelines, a "Run New Hunt" button, and an
  auto-hunt scheduler.
- Fixed several real bugs along the way: a `$args` reserved-variable collision silently
  breaking `vmrun` calls (renamed to `$cmdArgs`); a folder-prefix ambiguity
  (`"sysmon-"` matching both custom and community folders) breaking correlation matching;
  a data-loss bug where a wrong VM password silently produced empty output folders that
  shadowed good prior data (fixed by verifying credentials before creating any folders);
  and a Flask-crash-to-HTML bug breaking the auto-hunt feature's JSON parsing (fixed by
  wrapping all routes in try/except and using a dedicated fast credential check instead of
  running the full pipeline as "validation").
- The VM's `soc` account was genuinely locked out by Windows' own account lockout policy
  after repeated deliberate bad-password testing — not a code bug. Resolved by waiting it
  out; permanent fix given (`net accounts /lockoutthreshold:0`).
- **Major pivot point:** the supervisor reviewed the project and stated that building
  "another SIEM" was not a strong enough problématique/contribution on its own, despite
  approving of the from-scratch approach. Redirected the project toward: strengthening
  correlation, adding automated response to four well-known web attacks (SQL Injection,
  Command Injection, Path Traversal, XSS — Command Injection as the flagship, since it
  uniquely allows correlating web-log evidence with Sysmon endpoint evidence), documenting
  one full security process, and benchmarking against an existing SIEM (Wazuh). An
  AI-assistant extension was explicitly demoted to an unapproved, optional future item.
  Produced a project-definition document matching the supervisor's own official scope
  (see `mitre-mapping/` for the resulting technique-coverage framing).
- Gave full DVWA + XAMPP installation steps for the same VM (chosen so the Command
  Injection scenario can correlate web-log and endpoint evidence on one machine). Paused
  deliberately — endpoint prototype quality comes first, per the supervisor's own stated
  priority order.

## Week 8 — Dashboard Rename, Correlation Engine v2
- Dashboard went blank after a manual edit attempting to rename it to "Argus SOC
  Prototype — Detection & Correlation Console" and hide a debug subtitle line. Root cause
  found: a broken closing `</title>` tag (missing the `<`) meant the browser had no way to
  find the end of the title element, so it silently absorbed the entire rest of the
  document — all CSS and body content — as title text. Fixed; "Argus" is now styled larger
  than the rest of the title, and the debug subtitle is hidden via CSS while staying in the
  DOM so the dashboard's JavaScript doesn't null-reference it.
- Rewrote `correlation/correlate.py` to fix two real, verified problems:
  - **Deduplication:** confirmed, using real repo data, that the old engine reused a
    single Registry Run Key event across two different "incidents" (paired with two
    different PowerShell events). The new engine marks every event "used" once it's
    claimed by an accepted match, so this can no longer happen.
  - **Same-computer entity check:** chain patterns now reject a match whose stages land on
    different hosts (`require_same_computer`, default true) — not a problem yet on a
    single VM, but required before web-log correlation is added.
  - Added a `single_event` pattern type for incidents that don't need chaining (e.g.
    "Security Event Log Cleared" alone).
- Expanded `attack-patterns.json` from 3 patterns to 12: kept and tightened the three
  original patterns (one bare `"Discovery"` match string was ambiguous and narrowed to
  `"System Information Discovery"`), and added 8 new ones covering every remaining
  meaningful combination of the 10 custom rules and the adopted rule, plus a
  `simulations/scenario-playbook.md` mapping each pattern to the exact commands needed to
  produce it.
- Repo hygiene: removed stale duplicate `correlation/incidents/` output and redundant
  `detections/chainsaw-output/` folders, keeping the latest of each real category.
## Week 9 — Network Architecture Upgrade, DVWA, and Web-Attack Detection

### Architecture decision
Proposed and adopted a segmented network architecture for Phase 2: a Kali attacker VM,
an OPNsense firewall/router, and the existing Windows victim VM (now also hosting DVWA),
managed initially through GNS3. Chose OPNsense over a commercial alternative (Fortinet)
specifically for licensing simplicity and its scriptable REST API. Given the real time
cost this ended up incurring (see below), this was a deliberate trade-off: a more
realistic architecture and a better story for the final report, in exchange for
significant infrastructure risk this close to the deadline.

### The infrastructure crisis (the bulk of this week's time)
GNS3's own switch nodes turned out to be actively conflicting with the VMs' already-
correct, directly-assigned VMware network adapters, causing repeated "no VMnet
available" failures — resolved by deleting GNS3's switches entirely and using GNS3
purely as a VM start/stop/console launcher going forward, never for networking.

Both OPNsense and the Windows victim VM subsequently suffered serious `.vmx`
configuration corruption — traced to an invalid network adapter type
(`ethernet0.virtualdev = "vmxnet2"`) that crashed VMware's own config parser and caused
it to silently disable every device on the VM, including the disk. This produced a
frightening "Operating System not found" state on both machines. In both cases, the
actual disk and its data were confirmed completely intact (verified directly via file
sizes and, for Windows, via the UEFI firmware's own file browser showing the real
`bootmgfw.efi`) — the damage was entirely in the hardware-description file, not the
data. Both VMs were recovered by building a clean new VM shell around the existing,
undamaged virtual disk rather than continuing to hand-patch the corrupted config file.
The Windows VM additionally required switching its firmware from BIOS to UEFI, since its
disk is GPT-partitioned and legacy BIOS cannot boot a GPT disk at all — this, not boot
order, was the actual root cause of that VM's extended troubleshooting.

**Lesson, now a standing rule for the rest of the project:** never hand-edit a `.vmx`
file in Notepad in response to an error message — use VMware's own Settings GUI
exclusively, and snapshot before touching any VM configuration.

### DVWA installation
Installed XAMPP and DVWA on the Windows victim VM. This DVWA version requires a
dedicated MySQL user/database (`dvwa` / `p@ssw0rd`) rather than using MySQL `root` —
created via phpMyAdmin. A misleading "config file not found" error, despite the config
file existing correctly, turned out to be a stale Apache/PHP cache, resolved by fully
restarting Apache.

### Proving all four web attacks are real, not just logged
Initial attack attempts via `curl` all returned HTTP 302 (redirect to login), not 200 —
DVWA requires an authenticated session, and plain `curl` doesn't carry one by default.
Built a proper authenticated attack workflow: fetch the login page's CSRF token, POST
real credentials with that token, and reuse the resulting session cookie for every
subsequent attack request. Also had to correct the security level, which had reverted to
"Impossible" (all vulnerabilities properly mitigated at that level) at some point during
the VM rebuild work, back to "Low."

With a real authenticated session and the security level corrected, all four attacks
were confirmed genuinely successful against real evidence, not just a 200 status code:

- **Path Traversal / LFI:** leaked the real contents of the Windows server's
  `C:\windows\win.ini` (the first attempt targeted `/etc/passwd`, a Linux path that
  doesn't exist on the Windows target — corrected once noticed).
- **Reflected XSS:** the injected `<script>alert(1)</script>` payload was reflected back
  completely unescaped in the response.
- **SQL Injection:** an `id=1' OR '1'='1` payload returned all five rows of DVWA's user
  table instead of the intended single row.
- **Command Injection:** required correcting the payload syntax twice — the initial
  attempt used a Unix-style `;` command separator, which doesn't work on Windows
  `cmd.exe` (needs `&`), and the initial GET-based attempt never reached DVWA's handler
  at all, since its form is hardcoded to POST. Once sent correctly as an authenticated
  POST with `&` as the separator, the injected `whoami` command executed and returned
  `nt authority\system` — meaning the web server (Apache, running as a Windows service)
  executed attacker-controlled commands with full SYSTEM privileges. Confirmed directly
  in Sysmon: a `cmd.exe` process, command line `cmd.exe /s /c "ping 127.0.0.1 & whoami"`,
  spawned by `C:\xampp\apache\bin\httpd.exe`, running as `NT AUTHORITY\SYSTEM`. This is
  strong, realistic evidence for the report — a genuine privilege-escalation-relevant
  finding, not a toy example.

### New detection and correlation capability
Discovered that none of the existing 10 Sigma rules would ever catch the Command
Injection event above — they were all written for endpoint-only threats (PowerShell,
registry persistence, scheduled tasks), with nothing watching for a process spawned by
the web server itself. Wrote a new custom rule,
`web_server_spawns_shell.yml`, detecting any shell or system utility spawned with
`httpd.exe` as its parent process.

Built `weblog_detector.py`, a new component (Apache access-log parser) that flags SQL
Injection, Path Traversal, Cross-Site Scripting, and Command Injection attempts, writing
output in the exact same CSV schema Chainsaw already produces — this lets it plug into
the existing correlation pipeline without any changes needed to how `correlate.py` reads
its input, only which folders it reads from. Extended `correlate.py` to also extract a
request's source IP and HTTP method/path, needed for both correlation and response.

**Important, deliberately documented limitation:** Apache's default logging never
records POST request bodies, only the request line. Since DVWA's Command Injection form
submits via POST, the actual injected payload is invisible to a log-only detector no
matter what regex is used — `weblog_detector.py` flags Command Injection based on the
request path matching the known vulnerable endpoint, not on inspecting the payload. This
is an honest, acknowledged simplification, not a bug — closing it fully would require
Apache configured to log POST bodies (e.g. via mod_security), out of scope here.

Added a new correlation pattern, `command-injection-web-to-endpoint`, chaining the
web-log detection with the new Sysmon rule's detection within a 2-minute window on the
same host — the actual cross-schema correlation the project's Objective 2 was designed
around from the start. Added three further patterns (`sql-injection-alone`,
`path-traversal-alone`, `xss-alone`) so all four web attacks now produce visible,
correlated incidents, not just Command Injection.

Wired automated response to all four: `kill_process` (targeting the spawned shell) for
Command Injection, and `block_ip` (targeting the attacker's source IP) for the other
three. All verified working in dry-run against real captured attack data, extracting the
genuine PID (`10132`) and source IP (`192.168.20.1`) from the actual incidents.

### Repository hygiene
Discovered several days' worth of uncommitted `detections/chainsaw-output/` and
`correlation/incidents/` clutter had accumulated since the last cleanup pass — cleared
using the existing `cleanup-old-hunts.ps1` script before committing this week's real
work, to keep today's genuine deliverables from being buried in noise.

### Still open going into next week
- A dashboard "Web Attacks" tab, showing all four use cases distinctly for the
  supervisor/analyst, plus a button to manually trigger a response action from the
  dashboard itself rather than only via command line — requested, not yet built,
  pending the current `soc-dashboard.html`/`dashboard-server.py` content being reviewed.
- `block_ip` still executes via `netsh` on the endpoint rather than through OPNsense's
  own firewall API — functionally correct for demonstration purposes, but blocking at
  the actual network perimeter (OPNsense) rather than the victim host is the more
  realistic, intended final design.
- Wazuh benchmark not yet started.
