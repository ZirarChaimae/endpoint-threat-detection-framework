# Keeps only the most recent output folder for each real hunt category
# under detections\chainsaw-output, and the most recent incidents_*.json
# under correlation\incidents. Safe to run any time -- later hunts/correlation
# runs are supersets of earlier ones, so nothing unique is lost.
#
# Usage (from repo root):
#   .\scripts\cleanup-old-hunts.ps1

$repoRoot = Split-Path -Parent $PSScriptRoot
$chainsawDir = Join-Path $repoRoot "detections\chainsaw-output"
$incidentsDir = Join-Path $repoRoot "correlation\incidents"

$prefixes = @("sysmon-custom-", "sysmon-community-", "security-custom-", "security-adopted-")

Write-Host "=== Pruning detections\chainsaw-output ==="
foreach ($prefix in $prefixes) {
    $matches = Get-ChildItem $chainsawDir -Directory | Where-Object { $_.Name -like "$prefix*" } | Sort-Object LastWriteTime -Descending
    if ($matches.Count -le 1) {
        Write-Host "  $prefix -> nothing to prune ($($matches.Count) folder(s))"
        continue
    }
    $keep = $matches[0]
    $remove = $matches[1..($matches.Count - 1)]
    Write-Host "  $prefix -> keeping $($keep.Name), removing $($remove.Count) older folder(s)"
    foreach ($f in $remove) {
        Remove-Item $f.FullName -Recurse -Force
    }
}

# Also remove anything that doesn't match any known prefix (old pre-fix format, stray files)
Write-Host ""
Write-Host "=== Checking for unrecognized entries in chainsaw-output ==="
Get-ChildItem $chainsawDir | ForEach-Object {
    $matchesKnownPrefix = $false
    foreach ($prefix in $prefixes) {
        if ($_.Name -like "$prefix*") { $matchesKnownPrefix = $true }
    }
    if (-not $matchesKnownPrefix) {
        Write-Host "  Unrecognized: $($_.Name) -- not touched automatically, review manually"
    }
}

Write-Host ""
Write-Host "=== Pruning correlation\incidents ==="
$incidentFiles = Get-ChildItem $incidentsDir -Filter "incidents_*.json" | Sort-Object LastWriteTime -Descending
if ($incidentFiles.Count -le 1) {
    Write-Host "  Nothing to prune ($($incidentFiles.Count) file(s))"
} else {
    $keep = $incidentFiles[0]
    $remove = $incidentFiles[1..($incidentFiles.Count - 1)]
    Write-Host "  Keeping $($keep.Name), removing $($remove.Count) older file(s)"
    foreach ($f in $remove) {
        Remove-Item $f.FullName -Force
    }
}

Write-Host ""
Write-Host "Done. Review with 'git status', then 'git add -A' and commit."
