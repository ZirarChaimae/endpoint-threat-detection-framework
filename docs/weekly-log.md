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
