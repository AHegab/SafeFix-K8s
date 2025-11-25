# ============================================================================
# Rerun LLM Fixes and Validation for All Files
# ============================================================================
# This script:
# 1. Reruns the LLM orchestrator on all files to apply improved fixes
# 2. Validates all SECURED yamls with the enhanced validation system
# 3. Generates a comprehensive report
# ============================================================================

param(
    [string]$OutputDir = "Detection\output",
    [string]$TestsDir = "tests",
    [switch]$SkipLLMFixes,
    [switch]$SkipValidation,
    [switch]$DebugMode
)

$ErrorActionPreference = "Continue"

Write-Host "====================================================================================" -ForegroundColor Cyan
Write-Host " SafeFix-K8s: Rerun Fixes and Validation" -ForegroundColor Cyan
Write-Host "====================================================================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$logLevel = if ($DebugMode) { "DEBUG" } else { "INFO" }
$startTime = Get-Date

# Statistics
$stats = @{
    TotalFiles = 0
    LLMFixesApplied = 0
    LLMFixesFailed = 0
    ValidationPassed = 0
    ValidationFailed = 0
    ValidationNeedsReview = 0
}

# ============================================================================
# Step 1: Rerun LLM Fixes (if not skipped)
# ============================================================================

if (-not $SkipLLMFixes) {
    Write-Host "`n[STEP 1] Rerunning LLM Fixes..." -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Yellow

    $subdirs = Get-ChildItem -Path $OutputDir -Directory
    $totalDirs = ($subdirs | Measure-Object).Count
    $currentDir = 0

    foreach ($dir in $subdirs) {
        $currentDir++
        $stats.TotalFiles++

        $payload = Join-Path $dir.FullName "llm_payload.json"
        $originalYaml = Join-Path $dir.FullName ($dir.Name + ".yaml")

        # Handle different naming patterns
        if (-not (Test-Path $originalYaml)) {
            $yamlFiles = Get-ChildItem -Path $dir.FullName -Filter "*.yaml" |
                         Where-Object { $_.Name -notlike "SECURED_*" }
            if ($yamlFiles) {
                $originalYaml = $yamlFiles[0].FullName
            }
        }

        if (-not (Test-Path $payload) -or -not (Test-Path $originalYaml)) {
            Write-Host "[$currentDir/$totalDirs] Skipping $($dir.Name) - missing payload or yaml" -ForegroundColor Gray
            continue
        }

        Write-Host "[$currentDir/$totalDirs] Fixing $($dir.Name)..." -ForegroundColor Cyan

        try {
            # Run LLM orchestrator
            # Note: The orchestrator uses --payload (llm_payload.json), --tests-dir (where YAML files are), --out-dir
            # The YAML files are in the same directory as the payload, so use $dir.FullName as tests-dir
            $result = python LLMs\multi_llm_orchestrator.py `
                --payload $payload `
                --tests-dir $dir.FullName `
                --out-dir $dir.FullName `
                2>&1

            if ($DebugMode) {
                Write-Host $result -ForegroundColor DarkGray
            }

            if ($LASTEXITCODE -eq 0) {
                Write-Host "  [OK] Fixed successfully" -ForegroundColor Green
                $stats.LLMFixesApplied++
            } else {
                Write-Host "  [FAIL] Fix failed" -ForegroundColor Red
                if ($DebugMode) {
                    Write-Host "  Error: $result" -ForegroundColor DarkRed
                }
                $stats.LLMFixesFailed++
            }
        }
        catch {
            Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            $stats.LLMFixesFailed++
        }
    }

    Write-Host "`n LLM Fixes Summary:" -ForegroundColor Yellow
    Write-Host "  Total Files:       $($stats.TotalFiles)" -ForegroundColor White
    Write-Host "  Fixes Applied:     $($stats.LLMFixesApplied)" -ForegroundColor Green
    Write-Host "  Fixes Failed:      $($stats.LLMFixesFailed)" -ForegroundColor Red
    Write-Host ""
}

# ============================================================================
# Step 2: Run Validation (if not skipped)
# ============================================================================

if (-not $SkipValidation) {
    Write-Host "`n[STEP 2] Running Validation..." -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Yellow

    Get-ChildItem -Path $OutputDir -Directory | ForEach-Object {
        $d = $_.FullName
        $payload = Join-Path $d "llm_payload.json"

        if (Test-Path $payload) {
            Write-Host "Validating $($_.Name)..." -ForegroundColor Cyan

            python Validations\validation_gates_improved.py `
                --tests-dir $d `
                --fixed-dir $d `
                --payload $payload `
                --out-dir "$d\validation" `
                --config Validations\validation_config.yaml `
                --log-level $logLevel `
                --strict-mode `
                2>&1 | Out-Null

            # Read validation result
            $summary = Join-Path $d "validation\SUMMARY_VALIDATION.csv"
            if (Test-Path $summary) {
                $result = Import-Csv $summary
                switch ($result.status) {
                    "PASS" {
                        Write-Host "  [PASS]" -ForegroundColor Green
                        $stats.ValidationPassed++
                    }
                    "NEEDS_REVIEW" {
                        Write-Host "  [NEEDS_REVIEW]" -ForegroundColor Yellow
                        $stats.ValidationNeedsReview++
                    }
                    "FAIL" {
                        Write-Host "  [FAIL]" -ForegroundColor Red
                        $stats.ValidationFailed++
                    }
                }
            }
        }
    }

    Write-Host "`n Validation Summary:" -ForegroundColor Yellow
    Write-Host "  Passed:        $($stats.ValidationPassed)" -ForegroundColor Green
    Write-Host "  Needs Review:  $($stats.ValidationNeedsReview)" -ForegroundColor Yellow
    Write-Host "  Failed:        $($stats.ValidationFailed)" -ForegroundColor Red
    Write-Host ""
}

# ============================================================================
# Step 3: Generate Comprehensive Analysis
# ============================================================================

Write-Host "`n[STEP 3] Generating Analysis Report..." -ForegroundColor Yellow
Write-Host "============================================================================" -ForegroundColor Yellow

python Validations\analyze_all_results.py

# ============================================================================
# Final Summary
# ============================================================================

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host "`n====================================================================================" -ForegroundColor Cyan
Write-Host " COMPLETE" -ForegroundColor Cyan
Write-Host "====================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
Write-Host ""

if ($stats.TotalFiles -gt 0) {
    $passRate = [math]::Round(($stats.ValidationPassed / $stats.TotalFiles) * 100, 1)
    Write-Host "Pass Rate: $passRate%" -ForegroundColor $(if ($passRate -ge 70) { "Green" } elseif ($passRate -ge 50) { "Yellow" } else { "Red" })
}

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Review failed files in Detection\output\*\validation\" -ForegroundColor White
Write-Host "  2. Check FIX_GUIDE.md for detailed fix instructions" -ForegroundColor White
Write-Host "  3. Run again with -SkipLLMFixes to only revalidate" -ForegroundColor White
Write-Host ""

# Exit with appropriate code
if ($stats.ValidationFailed -eq 0) {
    exit 0
} else {
    exit 1
}
