param(
    [Parameter(Mandatory=$true)]
    [string]$GuestPassword
)

$vmx = "C:\Users\Zirar\Documents\Virtual Machines\Windows 10 (Log Source)\Windows 10 (Log Source).vmx"
$vmrun = "C:\Program Files\VMware\VMware Workstation\vmrun.exe"
$repo = "C:\Users\Zirar\Documents\endpoint-threat-detection-framework"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

function Run-InGuest($exe, $cmdArgs) {
    & $vmrun -T ws -gu soc -gp $GuestPassword runProgramInGuest $vmx $exe @cmdArgs
}

Write-Host "[1/8] Exporting Sysmon log inside the VM..."
Run-InGuest "C:\Windows\System32\wevtutil.exe" @("epl", "Microsoft-Windows-Sysmon/Operational", "C:\logs\sysmon_$timestamp.evtx")

Write-Host "[2/8] Exporting Security log inside the VM..."
Run-InGuest "C:\Windows\System32\wevtutil.exe" @("epl", "Security", "C:\logs\security_$timestamp.evtx")

Write-Host "[3/8] Running Chainsaw (custom rules) INSIDE the VM..."
Run-InGuest "C:\Tools\Chainsaw\chainsaw.exe" @("hunt", "C:\logs\sysmon_$timestamp.evtx", "--sigma", "C:\Tools\SigmaRules\custom", "--mapping", "C:\Tools\Chainsaw\mappings\sigma-event-logs-all.yml", "--csv", "--output", "C:\logs\sysmon-custom-$timestamp")

Write-Host "[4/8] Running Chainsaw (community rules) INSIDE the VM..."
Run-InGuest "C:\Tools\Chainsaw\chainsaw.exe" @("hunt", "C:\logs\sysmon_$timestamp.evtx", "--sigma", "C:\Tools\SigmaRules\community", "--mapping", "C:\Tools\Chainsaw\mappings\sigma-event-logs-all.yml", "--csv", "--output", "C:\logs\sysmon-community-$timestamp")

Write-Host "[5/8] Running Chainsaw (custom rules on Security log) INSIDE the VM..."
Run-InGuest "C:\Tools\Chainsaw\chainsaw.exe" @("hunt", "C:\logs\security_$timestamp.evtx", "--sigma", "C:\Tools\SigmaRules\custom", "--mapping", "C:\Tools\Chainsaw\mappings\sigma-event-logs-all.yml", "--csv", "--output", "C:\logs\security-custom-$timestamp")

Write-Host "[6/8] Running Chainsaw (adopted rules on Security log) INSIDE the VM..."
Run-InGuest "C:\Tools\Chainsaw\chainsaw.exe" @("hunt", "C:\logs\security_$timestamp.evtx", "--sigma", "C:\Tools\SigmaRules\adopted", "--mapping", "C:\Tools\Chainsaw\mappings\sigma-event-logs-all.yml", "--csv", "--output", "C:\logs\security-adopted-$timestamp")

Write-Host "[7/8] Copying only the small CSV results back to host..."
$outputs = @("sysmon-custom-$timestamp", "sysmon-community-$timestamp", "security-custom-$timestamp", "security-adopted-$timestamp")
foreach ($folder in $outputs) {
    $destFolder = "$repo\detections\chainsaw-output\$folder"
    New-Item -ItemType Directory -Path $destFolder -Force | Out-Null
    & $vmrun -T ws -gu soc -gp $GuestPassword copyFileFromGuestToHost $vmx "C:\logs\$folder\sigma.csv" "$destFolder\sigma.csv"
}

Write-Host "[8/8] Running correlation engine..."
python "$repo\correlation\correlate.py"

Write-Host ""
Write-Host "Full pipeline complete (Chainsaw ran inside VM). Results in:"
Write-Host "  $repo\detections\chainsaw-output\"
Write-Host "  $repo\correlation\incidents\"