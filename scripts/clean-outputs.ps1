[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Rm([string]$p) { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue } }

# Root outputs
Rm "output"

# Detection outputs and temps
Rm "Detection\output"
Rm "Detection\results.json"
Rm "Detection\.tmp-extracted"

# Validations artifacts
Rm "Validations\evidence"
Rm "Validations\reports"
if (Test-Path -LiteralPath "Validations\safe_fix_proof.json") { Remove-Item -LiteralPath "Validations\safe_fix_proof.json" -Force -ErrorAction SilentlyContinue }

# Python caches
Get-ChildItem -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue | ForEach-Object { Rm $_.FullName }

Write-Host "Cleaned pipeline outputs and caches."