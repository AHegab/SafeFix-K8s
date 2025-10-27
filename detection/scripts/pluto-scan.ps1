# PowerShell script to run Pluto for detecting deprecated Kubernetes API versions
# Usage: .\detectors\scripts\pluto-scan.ps1 -Path "manifests" [-Out "output/raw/pluto_raw.txt"]
param(
    [string]$Path = ".",
    [string]$Out  = "output/raw/pluto_raw.txt"
)
$ErrorActionPreference = "Stop"
# Ensure output directory exists
New-Item -ItemType Directory -Force -Path (Split-Path $Out -Parent) | Out-Null

Write-Host "Scanning $Path for deprecated API versions with Pluto..."
docker run --rm -v "${PWD}:/data" renaultdigital/pluto:latest `
    detect-files --directory "/data/$Path" | Tee-Object -FilePath $Out
Write-Host "Pluto results saved to $Out"
