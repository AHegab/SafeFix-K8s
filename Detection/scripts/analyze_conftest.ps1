# Analyze Conftest Detection Results
$json = Get-Content 'Detection\output\raw\conftest_expanded.json' -Raw | ConvertFrom-Json
$mainNamespace = $json | Where-Object { $_.namespace -eq 'main' }

Write-Host '=================================================' -ForegroundColor Cyan
Write-Host '     OPA POLICY DETECTION RESULTS ANALYSIS      ' -ForegroundColor Cyan
Write-Host '=================================================' -ForegroundColor Cyan
Write-Host ''

# Overall stats
Write-Host '=== OVERALL STATISTICS ===' -ForegroundColor Yellow
Write-Host "Total files scanned: $($mainNamespace.Count)"
$filesWithViolations = $mainNamespace | Where-Object { $_.failures }
Write-Host "Files with violations: $($filesWithViolations.Count)"
Write-Host "Files passing all policies: $($mainNamespace.Count - $filesWithViolations.Count)"
Write-Host ''

# Collect all failures
$allFailures = @()
foreach ($file in $mainNamespace) {
    if ($file.failures) {
        foreach ($failure in $file.failures) {
            $allFailures += $failure
        }
    }
}

Write-Host '=== VIOLATION BREAKDOWN BY TYPE ===' -ForegroundColor Yellow
$grouped = $allFailures | Group-Object -Property msg | Sort-Object Count -Descending
foreach ($group in $grouped) {
    Write-Host "[$($group.Count)x] $($group.Name)"
}
Write-Host ''

Write-Host '=== SUMMARY ===' -ForegroundColor Green
Write-Host "Unique violation types: $($grouped.Count)"
Write-Host "Total violations found: $($allFailures.Count)"
Write-Host ''

# Show detailed findings for each file
Write-Host '=== DETAILED FINDINGS BY FILE ===' -ForegroundColor Yellow
foreach ($file in $filesWithViolations) {
    $filename = ($file.filename -split '/')[-1]
    Write-Host "`n$filename" -ForegroundColor Cyan
    Write-Host "  Policies passed: $($file.successes)"
    Write-Host "  Violations found: $($file.failures.Count)"
    foreach ($failure in $file.failures) {
        Write-Host "    ❌ $($failure.msg)" -ForegroundColor Red
    }
}

Write-Host ''
Write-Host '=================================================' -ForegroundColor Cyan
Write-Host 'Analysis complete!' -ForegroundColor Green
