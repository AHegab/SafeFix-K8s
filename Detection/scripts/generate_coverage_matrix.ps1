# Generate Coverage Matrix Excel Sheet
# Parses all detection tool outputs and creates coverage matrix matching the format

$ErrorActionPreference = "SilentlyContinue"

# Define test files
$testFiles = @(
    "3.efs_plugin_misconfig.yaml",
    "3.multus_cni_misconfig.yaml",
    "3.nginx_pod_example.yaml",
    "13.jenkins_agent_pod.yaml",
    "13.nginx_privileged_deployment.yaml",
    "14.deployment_single_replica.yaml",
    "14.genkubesec_privileged_pod.yaml",
    "14.ingress_deprecated_api.yaml",
    "15.pod_privilege_escalation.yaml",
    "16.busybox_pod_missing_memory.yaml",
    "20.wordpress_mariadb_compose.yaml",
    "26.flink_port_mismatch.yaml",
    "27.kubeteus_misconfigured_policy.yaml",
    "28.role_overly_permissive.yaml",
    "29.helm_rabbitmq_hardcoded_credentials.yaml",
    "34.unencrypted_secret.yaml"
)

# Define vulnerability categories and their detection mappings
$vulnCategories = @{
    "Default capabilities not dropped" = @{
        "trivy" = @("KSV003", "capabilities", "drop ALL")
        "checkov" = @("CKV_K8S_20", "CKV_K8S_37", "capabilities")
        "kubeaudit" = @("CapabilityShouldDropAll", "capabilities")
        "conftest" = @("capabilities_not_dropped", "capabilities_hardening")
    }
    "Default namespace" = @{
        "trivy" = @("KSV110", "default namespace")
        "checkov" = @("CKV_K8S_21", "default namespace")
        "polaris" = @("default namespace", "namespace")
        "kubescore" = @("default namespace")
        "conftest" = @("default_namespace", "namespace_default")
    }
    "Default service account token mounted" = @{
        "checkov" = @("CKV_K8S_41", "serviceAccountToken", "automountServiceAccountToken")
        "kubeaudit" = @("AutomountServiceAccountToken", "serviceaccount")
        "conftest" = @("service_account_token", "automount")
    }
    "Filesystem not read-only" = @{
        "checkov" = @("CKV_K8S_22", "readOnlyRootFilesystem")
        "kubeaudit" = @("ReadOnlyRootFilesystem", "readOnly")
        "kubelinter" = @("read-only-root-fs", "readOnlyRootFilesystem")
        "polaris" = @("readOnlyRootFilesystem")
        "conftest" = @("read_only_root_filesystem", "readOnlyRootFilesystem")
    }
    "Image not pinned by digest" = @{
        "checkov" = @("CKV_K8S_43", "digest", "image tag")
    }
    "ImagePullPolicy not Always" = @{
        "checkov" = @("CKV_K8S_15", "imagePullPolicy")
        "conftest" = @("image_pull_policy", "imagePullPolicy")
    }
    "No AppArmor profile" = @{
        "kubeaudit" = @("AppArmor", "apparmor")
        "conftest" = @("apparmor", "apparmor_profile")
    }
    "No CPU limit" = @{
        "trivy" = @("KSV011", "cpu limit")
        "checkov" = @("CKV_K8S_11", "CKV_K8S_13", "cpu limit")
        "polaris" = @("cpuLimitsMissing", "cpu")
        "kubescore" = @("cpu-limit")
        "conftest" = @("cpu_limit", "resource_limits")
    }
    "No CPU request" = @{
        "trivy" = @("KSV015", "cpu request")
        "checkov" = @("CKV_K8S_11", "CKV_K8S_13", "cpu request")
        "polaris" = @("cpuRequestsMissing", "cpu")
        "kubescore" = @("cpu-request")
        "conftest" = @("cpu_request", "resource_limits")
    }
    "No livenessProbe" = @{
        "checkov" = @("CKV_K8S_8", "livenessProbe")
        "polaris" = @("livenessProbe")
        "kubescore" = @("pod-probes", "liveness")
        "conftest" = @("liveness", "health_probes")
    }
    "No memory limit" = @{
        "trivy" = @("KSV018", "memory limit")
        "checkov" = @("CKV_K8S_12", "CKV_K8S_13", "memory limit")
        "polaris" = @("memoryLimitsMissing", "memory")
        "kubescore" = @("memory-limit")
        "conftest" = @("memory_limit", "resource_limits")
    }
    "No memory request" = @{
        "trivy" = @("KSV016", "memory request")
        "checkov" = @("CKV_K8S_12", "CKV_K8S_13", "memory request")
        "polaris" = @("memoryRequestsMissing", "memory")
        "kubescore" = @("memory-request")
        "conftest" = @("memory_request", "resource_limits")
    }
    "No network policy" = @{
        "kubescape" = @("NetworkPolicy", "network-policy")
    }
    "No readinessProbe" = @{
        "checkov" = @("CKV_K8S_9", "readinessProbe")
        "polaris" = @("readinessProbe")
        "kubescore" = @("pod-probes", "readiness")
        "conftest" = @("readiness", "health_probes")
    }
    "No seccomp profile" = @{
        "trivy" = @("KSV104", "seccomp")
        "checkov" = @("CKV_K8S_31", "seccomp")
        "kubeaudit" = @("SeccompProfile", "seccomp")
        "kubescape" = @("seccomp")
        "conftest" = @("seccomp", "seccomp_profile")
    }
    "No security context" = @{
        "trivy" = @("KSV012", "security context")
        "checkov" = @("CKV_K8S_30", "security context")
        "conftest" = @("security_context")
    }
    "Privilege escalation allowed" = @{
        "kubeaudit" = @("AllowPrivilegeEscalation", "privilege escalation")
        "polaris" = @("allowPrivilegeEscalation")
        "kubescore" = @("privilege-escalation")
        "conftest" = @("privilege_escalation", "allowPrivilegeEscalation")
    }
    "Privileged container" = @{
        "trivy" = @("KSV017", "privileged")
        "checkov" = @("CKV_K8S_16", "privileged")
        "kubeaudit" = @("privileged")
        "kubelinter" = @("privileged", "run-as-non-root")
        "polaris" = @("privileged")
        "kubescore" = @("privileged")
        "kubescape" = @("privileged")
        "conftest" = @("privileged", "privileged_container")
    }
    "Runs as root user" = @{
        "trivy" = @("KSV012", "runAsNonRoot")
        "checkov" = @("CKV_K8S_23", "runAsNonRoot")
        "kubeaudit" = @("RunAsNonRoot", "root")
        "kubelinter" = @("run-as-non-root")
        "polaris" = @("runAsRootAllowed")
        "kubescore" = @("root")
        "conftest" = @("run_as_non_root", "runAsNonRoot")
    }
    "Standalone Pod" = @{
        "kubescore" = @("standalone pod", "pod-networkpolicies")
    }
    "Using latest tag" = @{
        "trivy" = @("KSV013", "latest tag")
        "checkov" = @("CKV_K8S_14", "latest")
        "kubelinter" = @("latest-tag", "no-latest-image")
        "polaris" = @("tagNotSpecified")
        "conftest" = @("latest", "image_tag")
    }
    "Privileged CNI plugin config" = @{
        "conftest" = @("cni_privileged", "cni_embedded")
    }
    "Docker socket mounted" = @{
        "kubeaudit" = @("docker.sock", "hostPath")
        "kubelinter" = @("docker-sock")
        "conftest" = @("docker_socket", "docker.sock", "hostPath")
    }
    "Single replica (non-HA)" = @{
        "kubelinter" = @("minimum-three-replicas", "no-replicas-1")
    }
    "Ingress backend not found" = @{
        "kubescore" = @("ingress-targets-service")
    }
    "No TLS configured (Ingress)" = @{
        "polaris" = @("tlsSettingsMissing")
    }
    "Deployment selector missing" = @{
        "kubelinter" = @("mismatching-selector")
        "rbacpolice" = @("selector")
    }
    "NetworkPolicy missing selectors" = @{
        "trivy" = @("NetworkPolicy", "selector")
    }
    "Overly permissive Role" = @{
        "rbacpolice" = @("overly-permissive", "wildcard", "escalate")
    }
    "Unencrypted Secret" = @{
        "kubescore" = @("secret-unencrypted")
        "conftest" = @("plain_secret", "secret")
    }
}

# Helper function to check if finding matches vulnerability
function Test-FindingMatch {
    param($finding, $patterns)
    
    $findingText = ($finding | ConvertTo-Json -Depth 10 -Compress).ToLower()
    
    foreach ($pattern in $patterns) {
        if ($findingText -like "*$($pattern.ToLower())*") {
            return $true
        }
    }
    return $false
}

# Parse detection results
Write-Host "`n🔍 Parsing Detection Results..." -ForegroundColor Cyan

$rawPath = ".\output\raw"
$coverage = @{}

# Initialize coverage structure
foreach ($file in $testFiles) {
    $coverage[$file] = @{}
    foreach ($vuln in $vulnCategories.Keys) {
        $coverage[$file][$vuln] = @{
            "Trivy" = $false
            "Checkov" = $false
            "Kubeaudit" = $false
            "KubeLinter" = $false
            "Polaris" = $false
            "KubeScore" = $false
            "Kubescape" = $false
            "Conftest" = $false
            "KubeConform" = $false
            "RBAC-Police" = $false
        }
    }
}

# Parse Trivy results
Write-Host "  Parsing Trivy..." -NoNewline
$trivyPath = Join-Path $rawPath "trivy_config_raw.json"
if (Test-Path $trivyPath) {
    $trivyData = Get-Content $trivyPath | ConvertFrom-Json
    if ($trivyData.Results) {
        foreach ($result in $trivyData.Results) {
            $filename = Split-Path $result.Target -Leaf
            if ($result.Misconfigurations) {
                foreach ($misconfig in $result.Misconfigurations) {
                    foreach ($vuln in $vulnCategories.Keys) {
                        if ($vulnCategories[$vuln].ContainsKey("trivy")) {
                            if (Test-FindingMatch $misconfig $vulnCategories[$vuln]["trivy"]) {
                                if ($coverage.ContainsKey($filename)) {
                                    $coverage[$filename][$vuln]["Trivy"] = $true
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
Write-Host " ✓" -ForegroundColor Green

# Parse Checkov results
Write-Host "  Parsing Checkov..." -NoNewline
$checkovPath = Join-Path $rawPath "checkov_raw.json"
if (Test-Path $checkovPath) {
    $checkovData = Get-Content $checkovPath | ConvertFrom-Json
    if ($checkovData.results -and $checkovData.results.failed_checks) {
        foreach ($check in $checkovData.results.failed_checks) {
            $filename = Split-Path $check.file_path -Leaf
            foreach ($vuln in $vulnCategories.Keys) {
                if ($vulnCategories[$vuln].ContainsKey("checkov")) {
                    if (Test-FindingMatch $check $vulnCategories[$vuln]["checkov"]) {
                        if ($coverage.ContainsKey($filename)) {
                            $coverage[$filename][$vuln]["Checkov"] = $true
                        }
                    }
                }
            }
        }
    }
}
Write-Host " ✓" -ForegroundColor Green

# Parse Kubeaudit results
Write-Host "  Parsing Kubeaudit..." -NoNewline
$kubeauditPath = Join-Path $rawPath "kubeaudit_raw.json"
if (Test-Path $kubeauditPath) {
    $kubeauditData = Get-Content $kubeauditPath -Raw
    if ($kubeauditData.Trim() -ne "") {
        $lines = $kubeauditData -split "`n"
        foreach ($line in $lines) {
            if ($line.Trim() -ne "") {
                try {
                    $finding = $line | ConvertFrom-Json
                    $filename = Split-Path $finding.ResourceName -Leaf
                    if (-not $filename -and $finding.Metadata) {
                        $filename = Split-Path $finding.Metadata.Name -Leaf
                    }
                    
                    foreach ($vuln in $vulnCategories.Keys) {
                        if ($vulnCategories[$vuln].ContainsKey("kubeaudit")) {
                            if (Test-FindingMatch $finding $vulnCategories[$vuln]["kubeaudit"]) {
                                foreach ($file in $testFiles) {
                                    if ($coverage.ContainsKey($file)) {
                                        $coverage[$file][$vuln]["Kubeaudit"] = $true
                                    }
                                }
                            }
                        }
                    }
                } catch {}
            }
        }
    }
}
Write-Host " ✓" -ForegroundColor Green

# Parse KubeLinter results
Write-Host "  Parsing KubeLinter..." -NoNewline
$kubelinterPath = Join-Path $rawPath "kubelinter_raw.json"
if (Test-Path $kubelinterPath) {
    $kubelinterData = Get-Content $kubelinterPath | ConvertFrom-Json
    if ($kubelinterData.Reports) {
        foreach ($report in $kubelinterData.Reports) {
            $filename = Split-Path $report.Object.K8sObject.Source.Path -Leaf
            foreach ($vuln in $vulnCategories.Keys) {
                if ($vulnCategories[$vuln].ContainsKey("kubelinter")) {
                    if (Test-FindingMatch $report $vulnCategories[$vuln]["kubelinter"]) {
                        if ($coverage.ContainsKey($filename)) {
                            $coverage[$filename][$vuln]["KubeLinter"] = $true
                        }
                    }
                }
            }
        }
    }
}
Write-Host " ✓" -ForegroundColor Green

# Parse Polaris results
Write-Host "  Parsing Polaris..." -NoNewline
$polarisPath = Join-Path $rawPath "polaris_raw.json"
if (Test-Path $polarisPath) {
    $polarisData = Get-Content $polarisPath | ConvertFrom-Json
    if ($polarisData.Results) {
        foreach ($result in $polarisData.Results) {
            $filename = Split-Path $result.Name -Leaf
            if ($result.PodResult -and $result.PodResult.Results) {
                foreach ($checkResult in $result.PodResult.Results.Values) {
                    foreach ($vuln in $vulnCategories.Keys) {
                        if ($vulnCategories[$vuln].ContainsKey("polaris")) {
                            if (Test-FindingMatch $checkResult $vulnCategories[$vuln]["polaris"]) {
                                foreach ($file in $testFiles) {
                                    if ($coverage.ContainsKey($file)) {
                                        $coverage[$file][$vuln]["Polaris"] = $true
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
Write-Host " ✓" -ForegroundColor Green

# Parse KubeScore results
Write-Host "  Parsing KubeScore..." -NoNewline
$kubescorePath = Join-Path $rawPath "kubescore_raw.json"
if (Test-Path $kubescorePath) {
    $kubescoreData = Get-Content $kubescorePath | ConvertFrom-Json
    foreach ($item in $kubescoreData) {
        $filename = Split-Path $item.FileName -Leaf
        if ($item.Checks) {
            foreach ($check in $item.Checks) {
                foreach ($vuln in $vulnCategories.Keys) {
                    if ($vulnCategories[$vuln].ContainsKey("kubescore")) {
                        if (Test-FindingMatch $check $vulnCategories[$vuln]["kubescore"]) {
                            if ($coverage.ContainsKey($filename)) {
                                $coverage[$filename][$vuln]["KubeScore"] = $true
                            }
                        }
                    }
                }
            }
        }
    }
}
Write-Host " ✓" -ForegroundColor Green

# Parse Kubescape results
Write-Host "  Parsing Kubescape..." -NoNewline
$kubescapePath = Join-Path $rawPath "kubescape_raw.json"
if (Test-Path $kubescapePath) {
    $kubescapeData = Get-Content $kubescapePath | ConvertFrom-Json
    if ($kubescapeData.results) {
        foreach ($result in $kubescapeData.results) {
            foreach ($vuln in $vulnCategories.Keys) {
                if ($vulnCategories[$vuln].ContainsKey("kubescape")) {
                    if (Test-FindingMatch $result $vulnCategories[$vuln]["kubescape"]) {
                        foreach ($file in $testFiles) {
                            if ($coverage.ContainsKey($file)) {
                                $coverage[$file][$vuln]["Kubescape"] = $true
                            }
                        }
                    }
                }
            }
        }
    }
}
Write-Host " ✓" -ForegroundColor Green

# Parse Conftest results (use the latest expanded results)
Write-Host "  Parsing Conftest..." -NoNewline
$conftestPath = Join-Path $rawPath "conftest_raw.json"
if (Test-Path $conftestPath) {
    $conftestData = Get-Content $conftestPath -Raw | ConvertFrom-Json
    foreach ($result in $conftestData) {
        $filename = Split-Path $result.filename -Leaf
        if ($result.warnings -or $result.failures) {
            $allIssues = @()
            if ($result.warnings) { $allIssues += $result.warnings }
            if ($result.failures) { $allIssues += $result.failures }
            
            foreach ($issue in $allIssues) {
                foreach ($vuln in $vulnCategories.Keys) {
                    if ($vulnCategories[$vuln].ContainsKey("conftest")) {
                        if (Test-FindingMatch $issue $vulnCategories[$vuln]["conftest"]) {
                            if ($coverage.ContainsKey($filename)) {
                                $coverage[$filename][$vuln]["Conftest"] = $true
                            }
                        }
                    }
                }
            }
        }
    }
}
Write-Host " ✓" -ForegroundColor Green

# Parse RBAC-Police results
Write-Host "  Parsing RBAC-Police..." -NoNewline
$rbacPath = Join-Path $rawPath "rbacpolice_raw.json"
if (Test-Path $rbacPath) {
    $rbacData = Get-Content $rbacPath | ConvertFrom-Json
    foreach ($vuln in $vulnCategories.Keys) {
        if ($vulnCategories[$vuln].ContainsKey("rbacpolice")) {
            if (Test-FindingMatch $rbacData $vulnCategories[$vuln]["rbacpolice"]) {
                foreach ($file in $testFiles) {
                    if ($coverage.ContainsKey($file)) {
                        $coverage[$file][$vuln]["RBAC-Police"] = $true
                    }
                }
            }
        }
    }
}
Write-Host " ✓" -ForegroundColor Green

# Generate CSV output
Write-Host "`n📊 Generating Coverage Matrix CSV..." -ForegroundColor Cyan

$csvContent = @()
$csvContent += "File,Vulns,Trivy,Checkov,Kubeaudit,KubeLinter,Polaris,KubeScore,Kubescape,Conftest (OPA),KubeConform,RBAC-Police"

foreach ($file in $testFiles) {
    $fileVulns = $coverage[$file]
    $sortedVulns = $fileVulns.Keys | Sort-Object
    
    $hasVulns = $false
    foreach ($vuln in $sortedVulns) {
        $tools = $fileVulns[$vuln]
        if ($tools.Values -contains $true) {
            $hasVulns = $true
            $row = "$file,$vuln"
            foreach ($tool in @("Trivy", "Checkov", "Kubeaudit", "KubeLinter", "Polaris", "KubeScore", "Kubescape", "Conftest", "KubeConform", "RBAC-Police")) {
                $checkmark = if ($tools[$tool]) { [char]0x2714 } else { "" }
                $row += ",$checkmark"
            }
            $csvContent += $row
        }
    }
    
    if (-not $hasVulns) {
        $csvContent += "$file,No issues detected by the configured tools."
    }
    
    $csvContent += ""
}

$outputPath = "..\output\Coverage_Matrix_Updated.csv"
$csvContent | Out-File -FilePath $outputPath -Encoding UTF8

Write-Host "✅ Coverage matrix generated: $outputPath" -ForegroundColor Green

# Generate summary statistics
Write-Host "`n📈 Coverage Summary:" -ForegroundColor Cyan
$stats = @{}
foreach ($tool in @("Trivy", "Checkov", "Kubeaudit", "KubeLinter", "Polaris", "KubeScore", "Kubescape", "Conftest", "KubeConform", "RBAC-Police")) {
    $stats[$tool] = 0
}

foreach ($file in $testFiles) {
    foreach ($vuln in $coverage[$file].Keys) {
        foreach ($tool in $stats.Keys) {
            if ($coverage[$file][$vuln][$tool]) {
                $stats[$tool]++
            }
        }
    }
}

$sorted = $stats.GetEnumerator() | Sort-Object Value -Descending
foreach ($entry in $sorted) {
    $bar = "█" * [Math]::Min([Math]::Floor($entry.Value / 5), 40)
    Write-Host ("  {0,-15} {1,3} detections {2}" -f $entry.Key, $entry.Value, $bar) -ForegroundColor $(if ($entry.Value -gt 50) { "Green" } elseif ($entry.Value -gt 20) { "Yellow" } else { "Red" })
}

Write-Host "`n✅ Done! Coverage matrix saved to: $outputPath" -ForegroundColor Green
