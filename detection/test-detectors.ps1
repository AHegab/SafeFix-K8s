# test-detectors.ps1
# Quick test script to verify detectors are working

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SafeFixK8s - Testing Detectors" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if we're in detection folder
if (!(Test-Path ".\detectors.ps1")) {
    Write-Host "Error: Please run this from the detection folder!" -ForegroundColor Red
    Write-Host "  cd detection" -ForegroundColor Yellow
    Write-Host "  .\test-detectors.ps1`n" -ForegroundColor Yellow
    exit 1
}

# Load detectors
Write-Host "Loading detectors..." -ForegroundColor Yellow
. .\detectors.ps1

# Check if tests folder exists
$testsPath = "..\tests"
if (!(Test-Path $testsPath)) {
    Write-Host "Error: Tests folder not found at: $testsPath" -ForegroundColor Red
    exit 1
}

Write-Host "Tests folder found: " -NoNewline
Write-Host (Resolve-Path $testsPath).Path -ForegroundColor Green

# Count YAML files
$yamlFiles = Get-ChildItem -Path $testsPath -Recurse -Include *.yaml,*.yml
Write-Host "YAML files to scan: $($yamlFiles.Count)`n" -ForegroundColor Cyan

# Ensure images
Write-Host "Checking Docker images..." -ForegroundColor Yellow
Ensure-DetectorImages
Write-Host ""

# Run a quick test with just one detector
Write-Host "Running quick test with KubeLinter..." -ForegroundColor Yellow
try {
    Det-KubeLinter -Path $testsPath
    Write-Host "✅ KubeLinter test passed!`n" -ForegroundColor Green
} catch {
    Write-Host "❌ KubeLinter test failed: $($_.Exception.Message)`n" -ForegroundColor Red
}

# Ask if user wants to run all
$response = Read-Host "Run all detectors? (y/N)"
if ($response -eq 'y' -or $response -eq 'Y') {
    Write-Host "`nRunning all detectors...`n" -ForegroundColor Cyan
    Det-RunAll -Path $testsPath
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Test Complete!" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green
    
    Write-Host "Check results in:" -ForegroundColor Cyan
    Write-Host "  detection\output\raw\*.json`n" -ForegroundColor White
} else {
    Write-Host "`nTest complete. To run all detectors:" -ForegroundColor Yellow
    Write-Host "  Det-RunAll -Path '..\tests'`n" -ForegroundColor White
}
