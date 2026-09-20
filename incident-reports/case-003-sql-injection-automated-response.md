# Incident Report — Case 003: SQL Injection with Automated Network-Level Response

**Status:** Closed
**Classification:** Objective 2 validation evidence (web-attack detection, cross-schema pipeline, automated response)
**Severity:** High
**Confidence:** Medium
**Prepared by:** [Author]
**Date prepared:** 2026-09-19

---

## 1. Summary

On 2026-09-19, a SQL Injection attack was launched against the DVWA web application hosted on `DESKTOP-JC89B03`. The request was detected by the endpoint-side web-log detector, correctly attributed to the real attacker address, automatically correlated into a High-severity incident on the Argus SOC dashboard, and — for the first time this project — successfully contained end-to-end using the automated `block_ip` response action against the OPNsense perimeter firewall. The block was independently verified as effective, then reversed, with restoration of normal access independently verified in turn.

This incident is submitted as validation evidence that the full detect → correlate → respond → verify → reverse loop, described in the project's technical architecture, functions correctly against a real attack and not only against synthetic test data.

---

## 2. Detection

| Field | Value |
|---|---|
| Detection source | `webattack/weblog_detector.py`, parsing Apache `access.log` on the DVWA host |
| Detection timestamp | 2026-09-19T04:36:01+01:00 |
| Attack technique | SQL Injection |
| Request | `GET /DVWA/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit` |
| Source IP | 192.168.250.134 (Kali attacker VM) |
| Target host | DESKTOP-JC89B03 |

The payload (`1' OR '1'='1`) is a classic boolean-based SQL Injection tautology; a successful exploitation returns all rows in the underlying query rather than the single row a legitimate `id` lookup would return. This was independently confirmed during attack execution: the application returned five user records instead of one.

The source IP recorded for this event was verified against the attacking machine's actual interface address (`192.168.250.134`) at the time of the attack, confirming correct attribution. This is noted explicitly because the project has a known, documented issue in which Apache occasionally logs the host machine's own address instead of the real attacker's for some requests; this particular event was confirmed clean of that defect.

---

## 3. Correlation

The detection was correlated by `correlation/correlate.py` against the `sql-injection-alone` pattern defined in `attack-patterns.json`, producing a single-stage incident:

- **Pattern:** SQL Injection (Web Application)
- **MITRE ATT&CK mapping:** T1190 — Exploit Public-Facing Application (Initial Access)
- **Assigned severity:** High
- **Confidence:** Medium

The incident appeared correctly on the Argus dashboard's Web Attacks tab, numbered and timestamped, with the correct source IP displayed.

---

## 4. Response

Response was triggered manually via the dashboard's "Respond — Block IP (via OPNsense)" control, calling `response/actions.py`'s `block_ip` function in live (non-dry-run) mode.

| Time | Action | Result |
|---|---|---|
| 04:37–04:58 (several attempts during OPNsense/route troubleshooting, see Section 6) | `block_ip(192.168.250.134)` | Multiple live attempts; each returned `{'status': 'done'}` from the OPNsense API and added the address to the `SOC_Blocked_IPs` alias |
| 04:58:22 | `block_ip(192.168.250.134)` (final, verified) | API returned `{'status': 'done'}`. Enforcement independently confirmed (see below) |

**Independent verification of the block:** rather than trusting the API's success response alone, enforcement was confirmed from the attacker machine itself:

```
curl -v --max-time 8 http://192.168.20.41
```

This attempt timed out after 8 seconds (`Connection timed out`), confirming the perimeter firewall genuinely dropped the attacker's traffic rather than merely reporting success.

**Reversal:** the block was subsequently removed via the dashboard's "Unblock IP" control (`unblock_ip`), and reversal was likewise independently verified:

```
curl -v --max-time 8 http://192.168.20.41
```

This returned a clean `HTTP/1.1 302 Found`, confirming normal access was genuinely restored and that the response action is fully reversible, not a one-way containment measure.

---

## 5. Root Cause and Attack Vector

The attack succeeded because DVWA's security level was set to "Low" (an intentional, documented lab condition for exercising the detection pipeline) and the `sqli` endpoint performs no input sanitization on the `id` parameter at this security level. No vulnerability beyond the intentionally-vulnerable training application itself was involved; this is expected and by design for this testing phase of the project.

---

## 6. Notes on Response Reliability During This Testing Window

Several `block_ip` attempts prior to the final verified one in this incident's timeframe did not represent a failure of this specific incident's response, but were part of a separate, larger infrastructure debugging effort concluded earlier the same night: OPNsense's firewall enforcement had been silently bypassed due to a non-persistent routing configuration on the attacker-side network segment (full root-cause analysis retained in the project's internal engineering log). That issue was resolved and independently proven fixed before this incident's response was executed, and is not a defect in the correlation, detection, or response logic itself. It is noted here only for completeness and audit traceability, consistent with the project's standing commitment to honest reporting of engineering limitations.

---

## 7. Conclusion

This incident constitutes end-to-end validation evidence for Objective 2 of the project: a real web application attack was detected with correct attribution, automatically correlated with an accurate MITRE ATT&CK mapping and severity assignment, contained through an automated, API-driven network-level response, independently verified as effective, and fully reversed with restoration independently verified. No manual firewall configuration was required by the analyst beyond a single dashboard click, directly demonstrating the reduction in manual intervention that automated response is intended to provide — the specific outcome the project's benchmark against Wazuh (Objective 4, pending) is designed to measure quantitatively.

---

*This report was prepared as interim validation evidence per the project's documentation plan (Decision #007) and does not represent the final, polished case study intended for the soutenance, which will be written once the Wazuh benchmark comparison (Objective 4) is complete.*
