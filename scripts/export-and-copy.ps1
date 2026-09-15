param(
    [Parameter(Mandatory=$true)]
    [string]$GuestPassword
)

$vmx = "C:\Users\Zirar\Documents\Virtual Machines\Victim-Win10-v2\Victim-Win10.vmx"
$vmrun = "C:\Program Files\VMware\VMware Workstation\vmrun.exe"
$repo = "C:\Users\Zirar\Documents\endpoint-threat-detection-framework"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

function Run-InGuest($exe, $cmdArgs) {
    & $vmrun -T ws -gu soc -gp $GuestPassword runProgramInGuest $vmx $exe @cmdArgs
}

# --- Step 1: Verify credentials FIRST, before touching anything ---
# This is a trivial, near-instant command. If the password is wrong, we stop
# here and exit, so no empty/broken output folders ever get created.
Write-Host "[1/9] Verifying VM credentials..."
$authCheck = & $vmrun -T ws -gu soc -gp $GuestPassword runProgramInGuest $vmx "C:\Windows\System32\cmd.exe" "/c" "exit" 2>&1
$authCheckText = ($authCheck | Out-String)

if ($authCheckText -match "Invalid user name or password") {
    Write-Host "AUTH_ERROR: Invalid VM credentials."
    exit 1
}

Write-Host "[2/9] Exporting Sysmon log inside the VM..."
Run-InGuest "C:\Windows\System32\wevtutil.exe" @("epl", "Microsoft-Windows-Sysmon/Operational", "C:\logs\sysmon_$timestamp.evtx")

Write-Host "[3/9] Exporting Security log inside the VM..."
Run-InGuest "C:\Windows\System32\wevtutil.exe" @("epl", "Security", "C:\logs\security_$timestamp.evtx")

Write-Host "[4/9] Running Chainsaw (custom rules) INSIDE the VM..."
Run-InGuest "C:\Tools\Chainsaw\chainsaw.exe" @("hunt", "C:\logs\sysmon_$timestamp.evtx", "--sigma", "C:\Tools\SigmaRules\custom", "--mapping", "C:\Tools\Chainsaw\mappings\sigma-event-logs-all.yml", "--csv", "--output", "C:\logs\sysmon-custom-$timestamp")

Write-Host "[5/9] Running Chainsaw (community rules) INSIDE the VM..."
Run-InGuest "C:\Tools\Chainsaw\chainsaw.exe" @("hunt", "C:\logs\sysmon_$timestamp.evtx", "--sigma", "C:\Tools\SigmaRules\community", "--mapping", "C:\Tools\Chainsaw\mappings\sigma-event-logs-all.yml", "--csv", "--output", "C:\logs\sysmon-community-$timestamp")

Write-Host "[6/9] Running Chainsaw (custom rules on Security log) INSIDE the VM..."
Run-InGuest "C:\Tools\Chainsaw\chainsaw.exe" @("hunt", "C:\logs\security_$timestamp.evtx", "--sigma", "C:\Tools\SigmaRules\custom", "--mapping", "C:\Tools\Chainsaw\mappings\sigma-event-logs-all.yml", "--csv", "--output", "C:\logs\security-custom-$timestamp")

Write-Host "[7/9] Running Chainsaw (adopted rules on Security log) INSIDE the VM..."
Run-InGuest "C:\Tools\Chainsaw\chainsaw.exe" @("hunt", "C:\logs\security_$timestamp.evtx", "--sigma", "C:\Tools\SigmaRules\adopted", "--mapping", "C:\Tools\Chainsaw\mappings\sigma-event-logs-all.yml", "--csv", "--output", "C:\logs\security-adopted-$timestamp")

Write-Host "[8/9] Copying results back to host..."
$outputs = @("sysmon-custom-$timestamp", "sysmon-community-$timestamp", "security-custom-$timestamp", "security-adopted-$timestamp")
foreach ($folder in $outputs) {
    $destFolder = "$repo\detections\chainsaw-output\$folder"
    New-Item -ItemType Directory -Path $destFolder -Force | Out-Null
    & $vmrun -T ws -gu soc -gp $GuestPassword copyFileFromGuestToHost $vmx "C:\logs\$folder\sigma.csv" "$destFolder\sigma.csv" 2>&1 | Out-Null
}

Write-Host "[9/9] Running correlation engine..."
python "$repo\correlation\correlate.py"

Write-Host ""
Write-Host "Full pipeline complete. Results in:"
Write-Host "  $repo\detections\chainsaw-output\"
Write-Host "  $repo\correlation\incidents\"
