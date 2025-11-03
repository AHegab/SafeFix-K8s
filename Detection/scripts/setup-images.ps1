# setup-images.ps1
# Quick script to download and cache all detection tool images

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SafeFixK8s - Image Setup Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Load the detectors script
$detectorsScript = Join-Path $PSScriptRoot "detection\detectors.ps1"
if (!(Test-Path $detectorsScript)) {
    Write-Host "Error: detectors.ps1 not found at: $detectorsScript" -ForegroundColor Red
    exit 1
}

Write-Host "Loading detectors script..." -ForegroundColor Yellow
. $detectorsScript

Write-Host "Ensuring all detector images are available..." -ForegroundColor Yellow
Ensure-DetectorImages

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Images cached in: detection\images\" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Run detections: cd detection; . .\detectors.ps1; Det-RunAll -Path '..\tests'" -ForegroundColor White
Write-Host "  2. Or see COMMANDS.md for more options" -ForegroundColor White
Write-Host ""
