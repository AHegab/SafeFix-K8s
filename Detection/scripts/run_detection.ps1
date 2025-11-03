# run_detection.ps1
# Simple runner script for SafeFix-K8s detection layer

param(
    [string]$Path = "..\tests",
    [switch]$Extended
)

# Import the detectors module
. "$PSScriptRoot\detectors.ps1"

# Run all detectors
Run-AllDetectors -Path $Path -Extended:$Extended
