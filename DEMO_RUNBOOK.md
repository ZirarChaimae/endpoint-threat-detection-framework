# Argus SOC Prototype — Live Demo Runbook

Use this exact sequence every time you need to demo the pipeline end-to-end:
simulate an attack, see it detected and correlated, then trigger both automated
response actions (kill_process and block_ip) from the dashboard.

---

## 0. Pre-Demo Checklist (run this every time, before anything else)

Things that do NOT automatically survive a host/VM reboot — verify all three
before starting, or the demo will fail partway through with a confusing error.

**A. Confirm the OPNsense API credentials are set on the host:**
```powershell
echo $env:OPNSENSE_API_KEY
echo $env:OPNSENSE_API_SECRET
```
Both must print real values. If either is blank, run:
```powershell
[System.Environment]::SetEnvironmentVariable("OPNSENSE_API_KEY", "YOUR_KEY", "User")
[System.Environment]::SetEnvironmentVariable("OPNSENSE_API_SECRET", "YOUR_SECRET", "User")
```
then open a **new** PowerShell window and re-check.

**B. Confirm Kali's route to the victim subnet is still via OPNsense (not the
VMware NAT gateway):**
```bash
ip route get 192.168.20.41
```
Must show `via 192.168.250.141`. If it instead shows `via 192.168.250.2`,
re-add it:
```bash
sudo ip route add 192.168.20.0/24 via 192.168.250.141
```
(It should already be persistent via `nmcli` — this is just a safety check.)

**C. Confirm DVWA's security level is still "Low"** (resets after MySQL
restarts or VM reboots — see Step 2 below to reset it if needed).

**D. Make sure all three VMs are running** (Windows-DVWA, Kali, OPNsense) and
the dashboard is started **from a PowerShell window that has the env vars
above set**:
```powershell
cd "C:\Users\Zirar\Documents\endpoint-threat-detection-framework"
python scripts\dashboard-server.py
```
Open `http://127.0.0.1:5000` and confirm the dashboard loads.

---

## 1. Authenticate to DVWA (Kali terminal)

```bash
curl -c cookies.txt -o login.html http://192.168.20.41/DVWA/login.php
cat login.html | grep user_token
```
Copy the token value, then:
```bash
curl -b cookies.txt -c cookies.txt -d "username=admin&password=password&user_token=PASTE_TOKEN_HERE&Login=Login" http://192.168.20.41/DVWA/login.php
```
Confirm login worked:
```bash
curl -b cookies.txt http://192.168.20.41/DVWA/index.php | grep -i "logout"
```
Should show a "Logout" link.

## 2. Confirm/reset security level to Low

```bash
curl -b cookies.txt http://192.168.20.41/DVWA/index.php | grep -i "security level"
```
If it doesn't say `low`:
```bash
curl -b cookies.txt -o security.html http://192.168.20.41/DVWA/security.php
cat security.html | grep user_token
```
Copy the token, then:
```bash
curl -b cookies.txt -c cookies.txt -d "security=low&seclev_submit=Submit&user_token=PASTE_TOKEN_HERE" http://192.168.20.41/DVWA/security.php
```

## 3. Simulate the web attack you want to demo

**For a `block_ip` demo** (SQLi, XSS, or Path Traversal — pick one):
```bash
curl -b cookies.txt -G "http://192.168.20.41/DVWA/vulnerabilities/sqli/" --data-urlencode "id=1' OR '1'='1" --data-urlencode "Submit=Submit"
```
Confirm success: response should show 5 rows of user data, not 1.

**For a `kill_process` demo** (use a long-running process, not the real
Command Injection attack, since a real cmd.exe process from DVWA exits almost
instantly and won't still be alive by the time you click Respond):

On the Windows-DVWA VM, in a PowerShell window:
```powershell
$sleepcmd = 'Start-Sleep -Seconds 900'
$sleepbytes = [System.Text.Encoding]::Unicode.GetBytes($sleepcmd)
$encodedsleep = [Convert]::ToBase64String($sleepbytes)
powershell -EncodedCommand $encodedsleep
```
No output at all = correct. In a second window, get its PID:
```powershell
Get-Process powershell | Select-Object Id, StartTime
```
Then generate the correlating registry-persistence event with a fresh,
never-used-before value name:
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v DemoKillN /t REG_SZ /d "calc.exe" /f
```
(increment `N` each time you demo this)

## 4. Pull logs and correlate

Click **"Run New Hunt"** on the dashboard, or run manually:
```powershell
cd "C:\Users\Zirar\Documents\endpoint-threat-detection-framework"
.\scripts\export-and-copy.ps1 -GuestPassword "<password>"
& "C:\Program Files\VMware\VMware Workstation\vmrun.exe" -T ws -gu soc -gp "<password>" copyFileFromGuestToHost "C:\Users\Zirar\Documents\Virtual Machines\Victim-Win10-v2\Victim-Win10.vmx" "C:\xampp\apache\logs\access.log" "webattack\access.log"
python webattack\weblog_detector.py --log "webattack\access.log" --computer DESKTOP-JC89B03
python correlation\correlate.py
```

## 5. Verify the incident in the dashboard

Open the **Web Attacks** tab (SQLi/XSS/Path Traversal) or **Incidents** tab
(kill_process demo). Before responding, confirm the source IP shown is
Kali's real current IP (`ip a | grep 192.168.250`) — Apache occasionally
logs the host's own IP instead. Re-run Steps 3–4 if the incident shows the
wrong address.

## 6. Respond — Kill Process

Click **Respond — Kill Process**. Confirm on Windows-DVWA:
```powershell
Get-Process -Id <the PID from Step 3>
```
Should return nothing.

## 7. Respond — Block IP (via OPNsense)

Click **Respond — Block IP (via OPNsense)**.

**Verify enforcement, from Kali:**
```bash
curl -v --max-time 8 http://192.168.20.41
```
Should time out.

**Dashboard behavior:** only the single most recent successful response is
shown on the incident card — repeated demo attempts do not stack up as
duplicates. Failed live attempts are not shown on the card, but are still
logged for audit in `correlation/incidents/response-log.json`; a failure
instead triggers an immediate on-screen alert.

## 8. Unblock (to re-run the demo, or restore access)

Click **Unblock IP**. A successful unblock does not currently produce a
visible on-screen confirmation (a known, cosmetic-only, deprioritized gap —
the action itself works correctly). Verify directly instead:

```bash
curl -v --max-time 8 http://192.168.20.41
```
Should return a clean `302 Found` again.

Fallback via OPNsense directly if needed: Firewall → Aliases →
`SOC_Blocked_IPs` → remove the IP → Save → Apply, then `pfctl -k <ip>` on
the console.

---

## Quick Reference — Common Failure Points

| Symptom | Likely Cause | Fix |
|---|---|---|
| `block_ip` returns `401`, or nothing visibly happens on click | API env vars not set in the dashboard's PowerShell window | Re-check checklist item A; a live failure now triggers an alert — if you see nothing at all, hard-refresh the browser (`Ctrl+Shift+R`) |
| Attack "succeeds" but curl gets a login redirect | DVWA session/security level reset | Redo Steps 1–2 |
| Attack simulated but no incident appears | Correlation event already "used," or hunt wasn't re-run | Use a fresh value/PID/payload; confirm Step 4 ran |
| `block_ip` says "done" but curl still succeeds | Kali's route reverted to the VMware NAT gateway | Re-check checklist item B |
| Incident shows source IP `192.168.20.1` instead of Kali's real IP | Known Apache logging bug (cosmetic) | Re-run the attack; use whichever attempt logs correctly |
| `kill_process` says "no such process" | Test process already exited | Always use the `Start-Sleep -Seconds 900` method |
| Unblock succeeds (curl confirms) but no on-screen message appears | Known, cosmetic-only display gap — deprioritized | Verify with curl instead; don't expect a popup |
