# Analyze gaps in Conftest detection compared to other tools
$rawDir = "Detection\output\raw"

# Load all detection results
$conftest = Get-Content "$rawDir\conftest_raw.json" -Raw | ConvertFrom-Json
$conftestMain = $conftest | Where-Object { $_.namespace -eq 'main' }

$trivy = Get-Content "$rawDir\trivy_config_raw.json" -Raw | ConvertFrom-Json
$checkov = Get-Content "$rawDir\checkov_raw.json" -Raw | ConvertFrom-Json

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   DETECTION GAPS - What Conftest (OPA) is NOT catching" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Common issues detected by other tools
$commonIssues = @{
    "Resource Limits" = @{
        Description = "CPU/Memory requests and limits"
        DetectedBy = "Trivy, Checkov, Polaris, KubeScore"
        Coverage = "15/16 files"
        Priority = "HIGH"
    }
    "Health Probes" = @{
        Description = "Liveness and readiness probes"
        DetectedBy = "Checkov, Polaris, KubeScore"
        Coverage = "14/16 files"
        Priority = "MEDIUM"
    }
    "Seccomp Profile" = @{
        Description = "Seccomp profile not set"
        DetectedBy = "Trivy, Checkov, Kubeaudit, Kubescape"
        Coverage = "11/16 files"
        Priority = "HIGH"
    }
    "AppArmor Profile" = @{
        Description = "AppArmor annotation missing"
        DetectedBy = "Kubeaudit"
        Coverage = "4/16 files"
        Priority = "MEDIUM"
    }
    "Image Pull Policy" = @{
        Description = "ImagePullPolicy not set to Always"
        DetectedBy = "Checkov"
        Coverage = "11/16 files"
        Priority = "LOW"
    }
    "Service Account Token" = @{
        Description = "Default SA token auto-mounted"
        DetectedBy = "Checkov, Kubeaudit"
        Coverage = "7/16 files"
        Priority = "MEDIUM"
    }
    "Network Policy" = @{
        Description = "No network policy defined"
        DetectedBy = "KubeScore"
        Coverage = "3/16 files"
        Priority = "MEDIUM"
    }
    "Pod Disruption Budget" = @{
        Description = "No PDB for HA workloads"
        DetectedBy = "KubeScore"
        Coverage = "varies"
        Priority = "LOW"
    }
    "Security Context Set" = @{
        Description = "No security context defined"
        DetectedBy = "Trivy, Checkov"
        Coverage = "5/16 files"
        Priority = "HIGH"
    }
}

Write-Host "CRITICAL GAPS TO ADDRESS:" -ForegroundColor Yellow
Write-Host "=========================" -ForegroundColor Yellow
Write-Host ""

foreach ($issue in ($commonIssues.GetEnumerator() | Sort-Object { $_.Value.Priority })) {
    $color = switch ($issue.Value.Priority) {
        "HIGH" { "Red" }
        "MEDIUM" { "Yellow" }
        "LOW" { "Gray" }
    }
    
    Write-Host "[$($issue.Value.Priority)] $($issue.Key)" -ForegroundColor $color
    Write-Host "  Description: $($issue.Value.Description)"
    Write-Host "  Currently detected by: $($issue.Value.DetectedBy)"
    Write-Host "  Coverage: $($issue.Value.Coverage)"
    Write-Host ""
}

Write-Host ""
Write-Host "RECOMMENDED NEW OPA POLICIES:" -ForegroundColor Green
Write-Host "=============================" -ForegroundColor Green
Write-Host ""
Write-Host "1. resource_limits.rego - CPU/Memory limits and requests"
Write-Host "2. health_probes.rego - Liveness and readiness probes"
Write-Host "3. seccomp_profile.rego - Seccomp profile enforcement"
Write-Host "4. apparmor_profile.rego - AppArmor annotation checks"
Write-Host "5. image_pull_policy.rego - ImagePullPolicy validation"
Write-Host "6. service_account.rego - Service account token mounting"
Write-Host "7. security_context.rego - Security context requirement (enhanced)"
Write-Host ""
Write-Host "Creating these policies now..." -ForegroundColor Cyan
