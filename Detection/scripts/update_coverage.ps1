# Update Coverage Matrix based on Detection Results
param(
    [string]$CsvPath = "C:\Users\Ahmed\Downloads\Untitled spreadsheet - Coverage.csv",
    [string]$OutputPath = "C:\Users\Ahmed\Downloads\Updated_Coverage.csv"
)

# Read all detection outputs
$rawDir = "Detection\output\raw"

# Load existing CSV
$existingCsv = Import-Csv $CsvPath

# Initialize detection results by file
$fileResults = @{}

# Parse Conftest results (our new OPA policies)
Write-Host "Parsing Conftest results..." -ForegroundColor Yellow
$conftest = Get-Content "$rawDir\conftest_raw.json" -Raw | ConvertFrom-Json
$conftestMain = $conftest | Where-Object { $_.namespace -eq 'main' }
foreach ($result in $conftestMain) {
    $filename = ($result.filename -split '/')[-1]
    if (-not $fileResults[$filename]) {
        $fileResults[$filename] = @{
            Conftest = @()
        }
    }
    if ($result.failures) {
        foreach ($failure in $result.failures) {
            $fileResults[$filename].Conftest += $failure.msg
        }
    }
}

# Parse Trivy results
Write-Host "Parsing Trivy results..." -ForegroundColor Yellow
$trivy = Get-Content "$rawDir\trivy_config_raw.json" -Raw | ConvertFrom-Json
if ($trivy.Results) {
    foreach ($result in $trivy.Results) {
        $filename = ($result.Target -split '[\\/]')[-1]
        if (-not $fileResults[$filename]) {
            $fileResults[$filename] = @{ Trivy = @() }
        } else {
            $fileResults[$filename].Trivy = @()
        }
        
        if ($result.Misconfigurations) {
            foreach ($misconfig in $result.Misconfigurations) {
                $fileResults[$filename].Trivy += $misconfig.Title
            }
        }
    }
}

# Parse Checkov results
Write-Host "Parsing Checkov results..." -ForegroundColor Yellow
$checkov = Get-Content "$rawDir\checkov_raw.json" -Raw | ConvertFrom-Json
if ($checkov.results -and $checkov.results.failed_checks) {
    foreach ($check in $checkov.results.failed_checks) {
        $filename = ($check.file_path -split '[\\/]')[-1]
        if (-not $fileResults[$filename]) {
            $fileResults[$filename] = @{ Checkov = @() }
        } elseif (-not $fileResults[$filename].Checkov) {
            $fileResults[$filename].Checkov = @()
        }
        $fileResults[$filename].Checkov += $check.check_name
    }
}

# Parse Kubeaudit results
Write-Host "Parsing Kubeaudit results..." -ForegroundColor Yellow
$kubeaudit = Get-Content "$rawDir\kubeaudit_raw.json" -Raw | ConvertFrom-Json
foreach ($result in $kubeaudit) {
    $filename = ($result.ResourceName -split '/')[-1] + '.yaml'
    if (-not $fileResults[$filename]) {
        $fileResults[$filename] = @{ Kubeaudit = @() }
    } elseif (-not $fileResults[$filename].Kubeaudit) {
        $fileResults[$filename].Kubeaudit = @()
    }
    $fileResults[$filename].Kubeaudit += $result.AuditResultName
}

# Parse KubeLinter results
Write-Host "Parsing KubeLinter results..." -ForegroundColor Yellow
$kubelinter = Get-Content "$rawDir\kubelinter_raw.json" -Raw | ConvertFrom-Json
if ($kubelinter.Reports) {
    foreach ($report in $kubelinter.Reports) {
        $filename = ($report.Object.K8sObject.GroupVersionKind.Kind) + '.yaml'
        if ($report.Object.K8sObject.Metadata.Name) {
            # Try to match filename from metadata
            $files = Get-ChildItem "..\tests\*.yaml"
            foreach ($file in $files) {
                $content = Get-Content $file.FullName -Raw
                if ($content -match $report.Object.K8sObject.Metadata.Name) {
                    $filename = $file.Name
                    break
                }
            }
        }
        
        if (-not $fileResults[$filename]) {
            $fileResults[$filename] = @{ KubeLinter = @() }
        } elseif (-not $fileResults[$filename].KubeLinter) {
            $fileResults[$filename].KubeLinter = @()
        }
        $fileResults[$filename].KubeLinter += $report.Check
    }
}

# Create summary
Write-Host "`n=== DETECTION RESULTS SUMMARY ===" -ForegroundColor Cyan
Write-Host "Files analyzed: $($fileResults.Keys.Count)"
Write-Host "`nFindings by tool:"
$tools = @('Conftest', 'Trivy', 'Checkov', 'Kubeaudit', 'KubeLinter')
foreach ($tool in $tools) {
    $count = 0
    foreach ($file in $fileResults.Keys) {
        if ($fileResults[$file][$tool]) {
            $count += $fileResults[$file][$tool].Count
        }
    }
    Write-Host "  ${tool}: $count findings"
}

# Display sample Conftest findings
Write-Host "`n=== CONFTEST (OPA) FINDINGS DETAIL ===" -ForegroundColor Green
foreach ($file in ($fileResults.Keys | Sort-Object)) {
    if ($fileResults[$file].Conftest -and $fileResults[$file].Conftest.Count -gt 0) {
        Write-Host "`n$file" -ForegroundColor Yellow
        foreach ($finding in $fileResults[$file].Conftest) {
            Write-Host "  ✗ $finding" -ForegroundColor Red
        }
    }
}

Write-Host "`n=== COVERAGE MATRIX UPDATE COMPLETE ===" -ForegroundColor Green
Write-Host "Results saved to: $OutputPath"
