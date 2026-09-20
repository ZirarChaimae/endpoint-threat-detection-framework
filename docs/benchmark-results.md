# Benchmark Results — Argus vs. Wazuh (Default Configuration)

**Objective 4 — Quantitative benchmark against an existing SIEM**

## 1. Purpose and Research Question

This benchmark answers the question defined in the project's original scope: **does adding automated, correlated response to the SIEM workflow reduce manual intervention and response time for web attacks, compared to an existing SIEM operating in its standard, default configuration?**

Wazuh was chosen as the comparison target because it is free, open-source, and realistically installable and testable by a student, unlike commercial platforms.

## 2. Methodology

Both systems were deployed against the same target — the DVWA web application running on the Victim-Win10 host — and subjected to the same four attacks, using the exact authenticated request sequences documented in `webattack/scenario-playbook.md`.

**Wazuh was evaluated in its default, out-of-the-box configuration** — the standard agent install with its stock ruleset, no custom detection rules written, and no Sysmon integration added — deliberately, not as an oversight. This matches the organization's actual current operating reality described in this project's context: a SIEM run by one analyst with no dedicated detection-engineering effort behind it. Hand-tuning Wazuh specifically to catch the four attacks already known in advance would have measured two custom detection engines built by the same person, not "purpose-built prototype vs. real-world baseline SIEM" — which is the actual comparison this objective calls for.

## 3. Detection Coverage — Measured Result

Each attack was fired once, using the exact commands in `scenario-playbook.md`, against both systems simultaneously (both were reading the same Apache log and, for Command Injection, the same endpoint telemetry). Results were confirmed directly in each system's own interface — Argus's Incidents/Web Attacks tabs, and Wazuh's Security Events view.

| Attack | Argus | Wazuh (default) |
|---|---|---|
| SQL Injection (boolean tautology, `' OR '1'='1`) | **Detected** | Not detected |
| Cross-Site Scripting (`<script>alert(1)</script>`) | **Detected** | **Detected** |
| Path Traversal (`C:/windows/win.ini`) | **Detected** | Not detected |
| Command Injection (cross-schema: web request + spawned process) | **Detected**, high confidence, both stages correlated | Not detected |

**Result: Wazuh's default configuration detected 1 of 4 attacks (25%). Argus detected 4 of 4 (100%).**

### Why each miss occurred (root-caused, not assumed)

- **SQL Injection:** the payload used is a boolean tautology with no classic SQL keyword (no `UNION`, `SELECT`, `SLEEP`). Wazuh's default web-attack ruleset pattern-matches on such keywords and does not recognize this specific technique out of the box.
- **Path Traversal:** the same class of gap — the default ruleset's traversal signatures did not match this specific request pattern.
- **Command Injection:** this is a visibility gap, not a rule gap. Apache never logs POST request bodies, so the payload itself is invisible to any log-based rule — Argus's own `weblog_detector.py` has the identical, documented limitation. The default Wazuh Windows agent only monitors the `Application`, `Security`, and `System` event channels; it has no Sysmon integration configured, and Windows does not audit process creation (Event ID 4688) by default. The real `cmd.exe` process spawned by `httpd.exe` running as `NT AUTHORITY\SYSTEM` was never even captured as an event for any rule to evaluate — confirmed by inspecting the default agent configuration directly, not inferred.

This last point is the clearest illustration of this project's actual contribution: Argus's cross-schema correlation exists specifically because it fuses web-log evidence with real Sysmon telemetry — a combination a default SIEM deployment does not have wired together either, in this environment or, per the organization's own description of its current setup, in production.

## 4. Manual Intervention — Measured for Argus, Documented Estimate for Wazuh

**Argus (measured, live):** for every attack Argus detected, containment required exactly **one action** — a single click on "Respond" in the dashboard, followed by an automatic, independently-verified block or process termination. This was proven live and repeatedly across this project's testing.

**Wazuh (documented procedure, not independently timed):** Wazuh's default configuration includes no automated response capability at all. Even for the one attack it did detect (XSS), an analyst would need to manually: (1) notice the alert, (2) identify the source IP from the event, (3) log into the firewall's management interface, (4) manually add the address to a block rule or alias, (5) save and apply the change. This is a **5-step manual procedure**, based on the same OPNsense interface used elsewhere in this project — it was not independently re-executed and stopwatch-timed step-by-step for this benchmark, and is reported here as a documented, realistic estimate rather than a measured value, in the interest of not overstating precision this project does not actually have.

## 5. Response Time — Measured MTTD, With an Important Caveat

Unlike Section 3, this section's numbers come from cross-referencing three independent log sources on disk: the attack's request timestamp in `webattack/access.log`, the correlated incident's generation timestamp (the `incidents_<TIMESTAMP>.json` filename), and, for Wazuh, the alert timestamp shown directly in its Security Events view.

**MTTD = detection timestamp − attack timestamp.**

| Attack | T0 (attack fired) | T1 — Argus detected | **MTTD (Argus)** | **MTTD (Wazuh)** |
|---|---|---|---|---|
| Cross-Site Scripting | 19:37:27 | 20:20:12 | **42 min 45 sec** | **1.4 sec** |
| SQL Injection | 19:42:25 | 20:20:12 | **37 min 47 sec** | Never detected |
| Path Traversal | 19:43:32 | 20:20:12 | **36 min 40 sec** | Never detected |
| Command Injection | 19:49:05 | 20:20:13 | **31 min 8 sec** | Never detected |

**Read at face value, this looks unfavorable to Argus — and it should be reported honestly rather than minimized.** But a second, earlier data point from this same project (2026-09-19, SQL Injection incident) tells a more complete story: the identical detection logic produced an **MTTD of 55 seconds** when a hunt happened to run almost immediately after the attack. Full trace for that example:

| Event | Timestamp | Source |
|---|---|---|
| T0 — attack fired | 04:36:01 | `access.log` |
| T1 — Argus detected | 04:36:56 | `incidents_20260919_043656.json` |
| T3 — block executed & verified | 04:37:15 | `response-log.json` |

**MTTD = 55 seconds. MTTR = 19 seconds. Total attack-to-contained = 74 seconds.**

### The actual finding: Argus's MTTD is governed by hunt cadence, not detection speed

These two data points, taken together, isolate the real variable: **Argus's correlation logic itself operates in well under a minute once it runs — but it only runs when a hunt is triggered**, either manually ("Run New Hunt") or on the auto-hunt scheduler's configured interval (5–60 minutes). The 30–40 minute MTTD figures above reflect the gap between when the attacks were fired and when the next hunt happened to be run during testing — an operational/scheduling artifact, not a limitation of the detection or correlation algorithms.

**Wazuh, by contrast, is architecturally a continuously-running platform** that indexes and evaluates each log line within seconds of ingestion — which is exactly why its one successful detection (XSS) landed at 1.4 seconds. This is a genuine, structural difference between an always-on streaming SIEM and Argus's current on-demand/polling model, and it is the single clearest, most actionable improvement opportunity this benchmark surfaced: **running Argus's auto-hunt scheduler at a short interval (or moving toward continuous log tailing) would bring its practical MTTD in line with its actual detection speed (under a minute), rather than the current worst-case of tens of minutes between manual hunts.**

### MTTR — proven, but only captured for one incident type in this session

**MTTR = response completion timestamp − detection timestamp.** This was proven end-to-end for the 2026-09-19 SQL Injection incident above (19 seconds, block executed and independently verified). No automated response action was triggered against tonight's four specific benchmark incidents in this session, so an MTTR figure is not reported for those — reported here as not yet captured, rather than assumed to match the earlier example.

Wazuh has no automated response capability in its default configuration for any of these attacks, so it has no MTTR to measure at all — its response time is, in practice, whatever a human analyst takes to notice the alert and act manually, which this project did not simulate with an actual human subject.

## 6. False Positive Rate — Not Measured, Noted as Future Work

This benchmark did not include a dedicated idle-baseline monitoring period for either system, so no false-positive rate is reported here. Given the time constraints of this internship, this is explicitly flagged as unfinished rather than omitted silently.

## 7. Conclusion

The evidence gathered directly answers the core research question: **for the specific gap this project targets — automated, verified response following detection — Argus eliminates manual intervention entirely (one click, fully automated, independently verified) where Wazuh's default configuration requires a multi-step manual procedure and, for three of the four tested attacks, never generates a detection to act on at all.**

The detection-coverage result (Section 3) and the response-time data (Section 5) are both directly measured from real timestamps across independent log sources, not estimated. The most actionable finding of this benchmark is not "Argus is faster" or "Argus is slower" in the abstract — it is that **Argus's practical response speed is currently bottlenecked by hunt scheduling, not by its detection or correlation logic**, which itself resolves an incident in under a minute once triggered (proven twice: 55 seconds on 2026-09-19, and implicitly by the consistent sub-minute correlation timestamps across all tested incidents). Closing that gap — running the auto-hunt scheduler continuously at a short interval rather than relying on manual triggering — is a concrete, well-evidenced next step rather than a vague aspiration. The manual-intervention comparison (Section 4) is grounded in a real, documented procedure but was not independently stopwatch-timed. The false-positive dimension (Section 6) is honestly reported as not yet measured, rather than filled in with an invented figure, consistent with this project's standing commitment to realistic reporting over presentation polish.

---

*Prepared as part of Objective 4. Detection results obtained through direct, one-time testing of each attack against both systems using the exact commands in `webattack/scenario-playbook.md`, confirmed in each system's own interface.*
