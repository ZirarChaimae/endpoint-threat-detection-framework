param(
    [Parameter(Mandatory=$true)]
    [string]$GuestPassword
)

$vmx = "C:\Users\Zirar\Documents\Virtual Machines\Windows 10 (Log Source)\Windows 10 (Log Source).vmx"
$vmrun = "C:\Program Files\VMware\VMware Workstation\vmrun.exe"
$repo = "C:\Users\Zirar\Documents\endpoint-threat-detection-framework"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

Write-Host "[1/6] Exporting Sysmon log inside the VM..."
& $vmrun -T ws -gu soc -gp $GuestPassword runProgramInGuest $vmx "C:\Windows\System32\wevtutil.exe" epl "Microsoft-Windows-Sysmon/Operational" "C:\logs\sysmon_$timestamp.evtx"

Write-Host "[2/6] Exporting Security log inside the VM..."
& $vmrun -T ws -gu soc -gp $GuestPassword runProgramInGuest $vmx "C:\Windows\System32\wevtutil.exe" epl "Security" "C:\logs\security_$timestamp.evtx"

Write-Host "[3/6] Copying Sysmon export to host..."
& $vmrun -T ws -gu soc -gp $GuestPassword copyFileFromGuestToHost $vmx "C:\logs\sysmon_$timestamp.evtx" "$repo\logs-samples\sysmon_$timestamp.evtx"

Write-Host "[4/6] Copying Security export to host..."
& $vmrun -T ws -gu soc -gp $GuestPassword copyFileFromGuestToHost $vmx "C:\logs\security_$timestamp.evtx" "$repo\logs-samples\security_$timestamp.evtx"

Write-Host ""
Write-Host "Done. Files created:"
Write-Host "  $repo\logs-samples\sysmon_$timestamp.evtx"
Write-Host "  $repo\logs-samples\security_$timestamp.evtx"

$chainsaw = "C:\Tools\Chainsaw\chainsaw.exe"
$mapping = "C:\Tools\Chainsaw\mappings\sigma-event-logs-all.yml"

Write-Host ""
Write-Host "[5/6] Running Chainsaw against custom rules (Sysmon log)..."
& $chainsaw hunt "$repo\logs-samples\sysmon_$timestamp.evtx" --sigma "$repo\sigma-rules\custom" --mapping $mapping --csv --output "$repo\detections\chainsaw-output\sysmon-$timestamp"

Write-Host "[6/6] Running Chainsaw against custom + adopted rules (Security log)..."
& $chainsaw hunt "$repo\logs-samples\security_$timestamp.evtx" --sigma "$repo\sigma-rules\custom" --mapping $mapping --csv --output "$repo\detections\chainsaw-output\security-custom-$timestamp"
Write-Host "[+] Running Chainsaw against community rule set (this may take longer)..."
& $chainsaw hunt "$repo\logs-samples\sysmon_$timestamp.evtx" --sigma "$repo\sigma-rules\community" --mapping $mapping --csv --output "$repo\detections\chainsaw-output\sysmon-community-$timestamp"
& $chainsaw hunt "$repo\logs-samples\security_$timestamp.evtx" --sigma "$repo\sigma-rules\adopted" --mapping $mapping --csv --output "$repo\detections\chainsaw-output\security-adopted-$timestamp"

Write-Host ""
Write-Host "Full pipeline complete. Detections saved under:"
Write-Host "  $repo\detections\chainsaw-output\sysmon-$timestamp\"
Write-Host "  $repo\detections\chainsaw-output\security-custom-$timestamp\"
Write-Host "  $repo\detections\chainsaw-output\security-adopted-$timestamp\"