# install-images.ps1
# Downloads and caches all detection tool Docker images

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SafeFixK8s - Installing Detection Images" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Load the detectors script
$detectorsScript = Join-Path $PSScriptRoot "detection\detectors.ps1"
if (!(Test-Path $detectorsScript)) {
    Write-Host "Error: detectors.ps1 not found!" -ForegroundColor Red
    exit 1
}

Write-Host "Loading detectors script..." -ForegroundColor Yellow
. $detectorsScript

Write-Host "`nPulling and caching Docker images (this may take several minutes)...`n" -ForegroundColor Yellow

# Force pull and save all images
Save-DetectorImages

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "All Images Installed!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

# Show what was cached
$imgCount = (Get-ChildItem -Path (Join-Path $PSScriptRoot "detection\images") -Filter *.tar -ErrorAction SilentlyContinue).Count
Write-Host "Cached $imgCount images in: detection\images\" -ForegroundColor Cyan

Write-Host "`nYou can now run detections offline!" -ForegroundColor Green
Write-Host "See COMMANDS.md for usage instructions.`n" -ForegroundColor White
