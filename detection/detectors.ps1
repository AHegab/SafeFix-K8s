# detection/detectors.ps1
# SafeFix-K8s (LEAN): Kubernetes YAML detectors only

$ErrorActionPreference = "Stop"

# --- paths --------------------------------------------------------------------
$RepoRoot = Split-Path -Parent $PSScriptRoot
$DetectionDir = $PSScriptRoot

$OutputRoot = $env:SAFEFIX_OUTPUT_ROOT
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
  $OutputRoot = Join-Path $DetectionDir "output"
}
else {
  try {
    $OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
  }
  catch {
    $OutputRoot = Join-Path $DetectionDir "output"
  }
}

$DetectionLayer = Join-Path $OutputRoot "detection"
$OutDir = Join-Path $DetectionLayer "raw"
$LogsDir = Join-Path $DetectionLayer "logs"
New-Item -ItemType Directory -Force -Path $OutDir, $LogsDir | Out-Null
$env:SAFEFIX_DETECTION_RAW_DIR = $OutDir
$env:SAFEFIX_DETECTION_LOG_DIR = $LogsDir

# --- helpers ------------------------------------------------------------------
function Write-NonEmpty($Path) {
  if (!(Test-Path $Path) -or ((Get-Item $Path).Length -lt 3)) {
    throw "Output '$Path' missing/empty."
  }
}

function _WrapPlaceholder($Out, $tool, $msg) {
  '[{"tool":"' + $tool + '","note":"' + ($msg -replace '"', '''') + '"}]' |
  Set-Content -Encoding UTF8 -Path $Out
  Write-Host "[$tool] -> $Out (placeholder)"
}

# Resolve a user-supplied scan path from CWD or repo root (parent of detection/)
function Resolve-ScanPath {
  param([string]$Path)
  if ([IO.Path]::IsPathRooted($Path)) {
    if (!(Test-Path -LiteralPath $Path)) { throw "Path does not exist: $Path" }
    return (Resolve-Path -LiteralPath $Path).Path
  }
  # Try current working directory first
  $cwdTarget = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path))
  if (Test-Path -LiteralPath $cwdTarget) { return (Resolve-Path -LiteralPath $cwdTarget).Path }
  # Then try repo root (parent of detection/)
  $repoTarget = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
  if (Test-Path -LiteralPath $repoTarget) { return (Resolve-Path -LiteralPath $repoTarget).Path }
  throw "Cannot find path '$Path' from CWD or repo root ($RepoRoot)."
}

# Normalize a path to a /scan/<relpath> (so tools keep relative paths in JSON)
function To-ScanRel {
  param([string]$AbsRoot, [string]$AbsFile)
  $rel = $AbsFile.Substring($AbsRoot.Length).TrimStart('\', '/')
  return "/scan/" + ($rel -replace '\\', '/')
}

# --- image set (LEAN) ---------------------------------------------------------
function Get-DetectorImages {
  @(
    "stackrox/kube-linter:latest",
    "quay.io/fairwinds/polaris:latest",
    "bridgecrew/checkov:latest",
    "aquasec/trivy:latest",
    "quay.io/kubescape/kubescape:latest",
    "zegl/kube-score:latest",
    "cytopia/yamllint:latest",
    "ghcr.io/shopify/kubeaudit:latest",
    "ghcr.io/yannh/kubeconform:latest",
    "openpolicyagent/conftest:latest"   # ensure OPA is always available
  )
}

# --- image set (EXTENDED) -----------------------------------------------------
function Get-ExtendedDetectorImages {
  $base = Get-DetectorImages
  $extended = @(
    "us-docker.pkg.dev/fairwinds-ops/oss/pluto:v5"
  )
  return $base + $extended
}

function Ensure-DetectorImages {
  $missing = @()
  $want = Get-DetectorImages
  foreach ($img in $want) {
    $present = docker images --format "{{.Repository}}:{{.Tag}}" | Where-Object { $_ -eq $img }
    if (-not $present) { $missing += $img }
  }
  if ($missing.Count -gt 0) {
    Write-Host "Pulling: $($missing -join ', ')"
    foreach ($m in $missing) { docker pull $m | Out-Null }
  }
}

function Ensure-ExtendedDetectorImages {
  $missing = @()
  $want = Get-ExtendedDetectorImages
  foreach ($img in $want) {
    $present = docker images --format "{{.Repository}}:{{.Tag}}" | Where-Object { $_ -eq $img }
    if (-not $present) { $missing += $img }
  }
  if ($missing.Count -gt 0) {
    Write-Host "Pulling: $($missing -join ', ')"
    foreach ($m in $missing) {
      try { docker pull $m | Out-Null } catch { Write-Host "Warning: Could not pull $m" -ForegroundColor Yellow }
    }
  }
}

# --- timing / progress --------------------------------------------------------
$global:ToolTimings = New-Object System.Collections.ArrayList
function Invoke-WithTiming {
  param([string]$Name, [scriptblock]$Action)
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $status = "ok"
  try { & $Action } catch { $status = "error"; throw } finally {
    $sw.Stop()
    [void]$global:ToolTimings.Add([pscustomobject]@{Tool = $Name; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2); Status = $status })
  }
}


function Expand-EmbeddedConfigs {
  param([string]$Path)
  $abs = Resolve-ScanPath -Path $Path
  $out = Join-Path $DetectionDir ".tmp-extracted"
  New-Item -ItemType Directory -Force -Path $out | Out-Null

  Get-ChildItem -Path $abs -Recurse -File -Include *.yaml, *.yml | ForEach-Object {
    $doc = Get-Content $_.FullName -Raw
    $objs = [System.Management.Automation.Language.Parser]::ParseInput($doc, [ref]$null, [ref]$null) > $null; # noop, just to be safe
    # naive split by '---'
    $parts = $doc -split '^\s*---\s*$' -ne ''
    foreach ($p in $parts) {
      if ($p -match 'kind:\s*ConfigMap') {
        # extract possible embedded yaml under data:
        if ($p -match 'data:\s*(.+)$') {
          $matches = [regex]::Matches($p, '^\s{2,}([A-Za-z0-9._-]+):\s*\|\s*\n((?:\s{4,}.+\n?)+)', 'Multiline')
          foreach ($m in $matches) {
            $key = $m.Groups[1].Value
            $val = ($m.Groups[2].Value -replace '^\s{4}', '', 'Multiline')
            try {
              $parsed = ConvertFrom-Yaml $val
              $file = Join-Path $out ("embedded__{0}__{1}.yaml" -f ($_.BaseName), $key.Replace(':', '_'))
              $val | Set-Content -Encoding UTF8 -Path $file
            }
            catch { }
          }
        }
      }
    }
  }
  return $out
}


# --- detectors ----------------------------------------------------------------
function Det-KubeConform {
  param([string]$Path = ".", [string]$Out = "$OutDir\kubeconform_raw.json")
  try {
    $abs = Resolve-ScanPath -Path $Path
    docker run --rm -v "${abs}:/scan:ro" ghcr.io/yannh/kubeconform:latest `
      -summary -output json -strict -ignore-missing-schemas -verbose /scan `
    | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[kubeconform] -> $Out"
  }
  catch { _WrapPlaceholder $Out "kubeconform" $_.Exception.Message }
}

function Det-KubeLinter {
  param(
    [string]$Path = ".",
    [string]$Out = "$OutDir\kubelinter_raw.json",
    [string]$Cfg = (Join-Path $RepoRoot "policies\kubelinter-config.yaml")
  )
  try {
    $abs = Resolve-ScanPath -Path $Path
    if (Test-Path $Cfg) {
      docker run --rm -v "${abs}:/scan:ro" -v "${Cfg}:/cfg/kubelinter-config.yaml:ro" stackrox/kube-linter:latest `
        lint /scan --config /cfg/kubelinter-config.yaml --format json | Set-Content -Encoding UTF8 -Path $Out
    }
    else {
      docker run --rm -v "${abs}:/scan:ro" stackrox/kube-linter:latest `
        lint /scan --format json | Set-Content -Encoding UTF8 -Path $Out
    }
    Write-NonEmpty $Out; Write-Host "[kube-linter] -> $Out"
  }
  catch { _WrapPlaceholder $Out "kubelinter" $_.Exception.Message }
}

function Det-Polaris {
  param([string]$Path = ".", [string]$Out = "$OutDir\polaris_raw.json")
  try {
    $abs = Resolve-ScanPath -Path $Path
    docker run --rm -v "${abs}:/scan:ro" quay.io/fairwinds/polaris:latest `
      polaris audit --audit-path /scan --format json `
    | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[polaris] -> $Out"
  }
  catch { _WrapPlaceholder $Out "polaris" $_.Exception.Message }
}

function Det-Checkov {
  param([string]$Path = ".", [string]$Out = "$OutDir\checkov_raw.json")
  try {
    $abs = Resolve-ScanPath -Path $Path
    $checksDir = Join-Path $RepoRoot "Detection\policies\checkov"
    $local = $null
    try { $local = (Get-Command checkov -ErrorAction Stop).Source } catch { }
    $args = @("-d", $abs, "--framework", "kubernetes", "--quiet", "--compact", "-o", "json")
    if (Test-Path $checksDir) { $args += @("--external-checks-dir", $checksDir) }

    if ($local) {
      $prevEA = $ErrorActionPreference; $ErrorActionPreference = "Continue"
      & checkov @args 2>$null | Set-Content -Encoding UTF8 -Path $Out
      $ErrorActionPreference = $prevEA
    }
    else {
      # Build Docker command with proper arguments
      $dockerArgs = @("run", "--rm", "-v", "${abs}:/scan:ro")
      if (Test-Path $checksDir) { 
        $dockerArgs += @("-v", "${checksDir}:/ext:ro")
      }
      $dockerArgs += @("bridgecrew/checkov:latest", "-d", "/scan", "--framework", "kubernetes", "--quiet", "--compact")
      if (Test-Path $checksDir) {
        $dockerArgs += @("--external-checks-dir", "/ext")
      }
      $dockerArgs += @("-o", "json")
      
      docker @dockerArgs | Set-Content -Encoding UTF8 -Path $Out
    }
    Write-NonEmpty $Out; Write-Host "[checkov] -> $Out"
  }
  catch { _WrapPlaceholder $Out "checkov" $_.Exception.Message }
}

function Det-TrivyConfig {
  param([string]$Path = ".", [string]$Out = "$OutDir\trivy_config_raw.json")
  try {
    $abs = Resolve-ScanPath -Path $Path
    docker run --rm -v "${abs}:/scan:ro" aquasec/trivy:latest `
      config --quiet --format json /scan | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[trivy config] -> $Out"
  }
  catch { _WrapPlaceholder $Out "trivy-config" $_.Exception.Message }
}

function Det-Kubescape {
  param([string]$Path = ".", [string]$Out = "$OutDir\kubescape_raw.json")
  $abs = Resolve-ScanPath -Path $Path
  $env:KUBESCAPE_DISABLE_GIT_INFO = "true"
  $ks = $null; try { $ks = (Get-Command kubescape -ErrorAction Stop).Source } catch { }
  if ($ks) {
    try {
      $prevEA = $ErrorActionPreference
      $ErrorActionPreference = "Continue"
      & kubescape scan $abs --format json --format-version v2 --output $Out 2>$null | Out-Null
      $ErrorActionPreference = $prevEA
      if ((Test-Path $Out) -and ((Get-Item $Out).Length -gt 100)) {
        Write-Host "[kubescape] -> $Out"
      }
      else {
        _WrapPlaceholder $Out "kubescape" "failed: output file not created or too small"
      }
    }
    catch { _WrapPlaceholder $Out "kubescape" $_.Exception.Message }
  }
  else {
    try {
      $prevEA = $ErrorActionPreference
      $ErrorActionPreference = "Continue"
      docker run --rm -e "KUBESCAPE_DISABLE_GIT_INFO=true" -v "${abs}:/scan:ro" `
        quay.io/kubescape/kubescape:latest scan /scan --format json --format-version v2 --output /scan/kubescape_raw.json
      $ErrorActionPreference = $prevEA
      $tempOut = Join-Path $abs "kubescape_raw.json"
      if ((Test-Path $tempOut) -and ($tempOut -ne $Out)) { Move-Item -Force $tempOut $Out }
      Write-NonEmpty $Out; Write-Host "[kubescape] -> $Out"
    }
    catch { _WrapPlaceholder $Out "kubescape" $_.Exception.Message }
  }
}

function Det-KubeScore {
  param([string]$Path = ".", [string]$Out = "$OutDir\kubescore_raw.json")
  try {
    $abs = Resolve-ScanPath -Path $Path
    $files = Get-ChildItem -Path $abs -Recurse -File -Include *.yaml, *.yml |
    ForEach-Object { To-ScanRel -AbsRoot $abs -AbsFile $_.FullName }
    if ($files.Count -eq 0) { '[]' | Set-Content -Encoding UTF8 -Path $Out; Write-Host "[kube-score] -> $Out (no YAML)"; return }
    $cmd = @("run", "--rm", "-v", "${abs}:/scan:ro", "zegl/kube-score:latest", "score", "--output-format", "json") + $files
    docker @cmd | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[kube-score] -> $Out"
  }
  catch { _WrapPlaceholder $Out "kube-score" $_.Exception.Message }
}

function Det-Yamllint {
  param([string]$Path = ".", [string]$Out = "$OutDir\yamllint_raw.txt")
  try {
    $abs = Resolve-ScanPath -Path $Path
    docker run --rm -v "${abs}:/scan:ro" cytopia/yamllint:latest `
      -f parsable -s /scan | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[yamllint] -> $Out"
  }
  catch { _WrapPlaceholder $Out "yamllint" $_.Exception.Message }
}

function Det-KubeAudit {
  param([string]$Path = ".", [string]$Out = "$OutDir\kubeaudit_raw.json")
  $abs = Resolve-ScanPath -Path $Path
  $files = Get-ChildItem -Path $abs -Recurse -File -Include *.yaml, *.yml
  $accum = @()
  if ($files.Count -eq 0) {
    '[]' | Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[kubeaudit] -> $Out (no YAML)"
    return
  }
  $local = $null
  try { $local = (Get-Command kubeaudit -ErrorAction Stop).Source } catch { }
  $prevEA = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  Write-Host "[kubeaudit] Scanning $($files.Count) files..." -ForegroundColor Cyan
  foreach ($f in $files) {
    try {
      $raw = $null
      if ($local) {
        $raw = & kubeaudit all -f "$($f.FullName)" -p json 2>$null
      }
      else {
        $dir = $f.Directory.FullName
        $raw = docker run --rm -v "${dir}:/scan:ro" ghcr.io/shopify/kubeaudit:latest `
          all -f "/scan/$($f.Name)" -p json 2>$null
      }
      if ($raw) {
        $jsonLines = $raw | Where-Object { $_ -match '^\s*\{' -and $_ -notmatch 'Deprecation' -and $_ -notmatch 'WARNING' }
        foreach ($jsonLine in $jsonLines) {
          try {
            $obj = $jsonLine | ConvertFrom-Json
            # Preserve full relative path under /scan for better normalization
            $obj | Add-Member -NotePropertyName "file" -NotePropertyValue (To-ScanRel -AbsRoot $abs -AbsFile $f.FullName) -Force
            $accum += $obj
          }
          catch { continue }
        }
      }
    }
    catch { continue }
  }
  $ErrorActionPreference = $prevEA
  if ($accum.Count -eq 0) { '[]' | Set-Content -Encoding UTF8 -Path $Out; Write-Host "[kubeaudit] -> $Out (no findings)" }
  else { $accum | ConvertTo-Json -Depth 64 | Set-Content -Encoding UTF8 -Path $Out; Write-Host "[kubeaudit] -> $Out ($($accum.Count) findings)" }
}

# --- Conftest (OPA) -----------------------------------------------------------
function Det-Conftest {
  param([string]$Path = ".", [string]$Out = "$OutDir\conftest_raw.json", [string]$PolicyDir = "$RepoRoot\Detection\policies\conftest")
  try {
    $abs = Resolve-ScanPath -Path $Path
    if (-not (Test-Path $PolicyDir)) { _WrapPlaceholder $Out "conftest" "Policy directory not found"; return }
    
    # Try local conftest first
    $local = $null
    try { $local = (Get-Command conftest -ErrorAction Stop).Source } catch { }
    
    if ($local) {
      Write-Host "[conftest] Using local conftest at $local" -ForegroundColor Cyan
      & conftest test $abs --policy $PolicyDir --all-namespaces --output json | Set-Content -Encoding UTF8 -Path $Out
    }
    else {
      # Fallback to Docker
      Write-Host "[conftest] Using Docker container" -ForegroundColor Cyan
      docker run --rm -v "${abs}:/scan:ro" -v "${PolicyDir}:/policy:ro" openpolicyagent/conftest:latest `
        test /scan --policy /policy --all-namespaces --output json | Set-Content -Encoding UTF8 -Path $Out
    }
    Write-NonEmpty $Out; Write-Host "[conftest] -> $Out"
  }
  catch { _WrapPlaceholder $Out "conftest" $_.Exception.Message }
}

# --- Pluto (API deprecations) -------------------------------------------------
function Det-Pluto {
  param([string]$Path = ".", [string]$Out = "$OutDir\pluto_raw.json")
  $abs = Resolve-ScanPath -Path $Path
  $local = $null
  try { $local = (Get-Command pluto -ErrorAction Stop).Source } catch { }
  $prevEA = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    if ($local) {
      Write-Host "[pluto] Scanning for deprecated APIs..." -ForegroundColor Cyan
      $output = & pluto detect-files -d $abs --output json 2>&1
      $jsonLines = $output | Where-Object { $_ -match '^\s*\{' -or $_ -match '^\s*\[' }
      if ($jsonLines) {
        $jsonContent = $jsonLines -join "`n"
        try {
          $parsed = $jsonContent | ConvertFrom-Json
          $parsed | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 -Path $Out
          Write-Host "[pluto] -> $Out"
        }
        catch {
          $jsonContent | Set-Content -Encoding UTF8 -Path $Out
          Write-Host "[pluto] -> $Out"
        }
      }
      else {
        '{"items":[],"target-versions":{}}' | Set-Content -Encoding UTF8 -Path $Out
        Write-Host "[pluto] -> $Out (no deprecated APIs found)"
      }
    }
    else {
      '{"items":[],"target-versions":{},"note":"Pluto CLI not installed. Please install pluto locally for API deprecation scanning."}' |
      Set-Content -Encoding UTF8 -Path $Out
      Write-Host "[pluto] -> $Out (placeholder - tool not installed)"
    }
  }
  catch {
    '{"items":[],"target-versions":{},"note":"' + ($_.Exception.Message -replace '"', '\"') + '"}' |
    Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[pluto] -> $Out (placeholder - error)"
  }
  finally { $ErrorActionPreference = $prevEA }
}

# --- RBAC "police" (lightweight heuristic if real tool absent) ----------------
function Det-RBACPolice {
  param([string]$Path = ".", [string]$Out = "$OutDir\rbacpolice_raw.json")
  try {
    $abs = Resolve-ScanPath -Path $Path
    $rbacFiles = Get-ChildItem -Path $abs -Recurse -File -Include *.yaml, *.yml |
    Where-Object {
      $content = Get-Content $_.FullName -Raw
      $content -match 'kind:\s*(Role|ClusterRole|RoleBinding|ClusterRoleBinding)'
    }
    if ($rbacFiles.Count -eq 0) {
      '[{"tool":"rbac-police","note":"No RBAC manifests found"}]' | Set-Content -Encoding UTF8 -Path $Out
      Write-Host "[rbac-police] -> $Out (placeholder - no RBAC files)"; return
    }

    $findings = @()
    $dangerousVerbs = @('delete', 'deletecollection', 'create', 'update', 'patch', 'escalate', 'bind', 'impersonate')
    $sensitiveResources = @('secrets', 'configmaps', 'serviceaccounts', 'roles', 'clusterroles', 'rolebindings', 'clusterrolebindings')
    
    foreach ($f in $rbacFiles) {
      $text = Get-Content $f.FullName -Raw
      $fileName = (To-ScanRel -AbsRoot $abs -AbsFile $f.FullName)

      if ($text -match 'kind:\s*(Role|ClusterRole)') {
        $isClusterRole = $text -match 'kind:\s*ClusterRole'
        $kind = if ($isClusterRole) { "ClusterRole" } else { "Role" }
        
        if (($text -match 'verbs:\s*\[\s*[''"]?\*[''"]?\s*\]') -or 
          ($text -match 'verbs:\s*\n\s*-\s*[''"]?\*[''"]?')) {
          $findings += [pscustomobject]@{
            rule     = "WildcardVerbs"
            severity = "HIGH"
            message  = "Wildcard verbs (*) grants all permissions - violates least privilege principle"
            file     = $fileName
            kind     = $kind
            category = "excessive_permissions"
          }
        }
        if (($text -match 'resources:\s*\[\s*[''"]?\*[''"]?\s*\]') -or 
          ($text -match 'resources:\s*\n\s*-\s*[''"]?\*[''"]?')) {
          $findings += [pscustomobject]@{
            rule     = "WildcardResources"
            severity = "HIGH"
            message  = "Wildcard resources (*) grants access to all resource types"
            file     = $fileName
            kind     = $kind
            category = "excessive_permissions"
          }
        }
        if (($text -match 'apiGroups:\s*\[\s*[''"]?\*[''"]?\s*\]') -or 
          ($text -match 'apiGroups:\s*\n\s*-\s*[''"]?\*[''"]?')) {
          $findings += [pscustomobject]@{
            rule     = "WildcardAPIGroups"
            severity = "MEDIUM"
            message  = "Wildcard apiGroups (*) grants access to all API groups"
            file     = $fileName
            kind     = $kind
            category = "excessive_permissions"
          }
        }

        foreach ($verb in $dangerousVerbs) {
          if (($text -match "verbs:\s*\[.*[''`"]?$verb[''`"]?.*\]") -or 
            ($text -match "verbs:[\s\S]*?-\s*[''`"]?$verb[''`"]?")) {
            $findings += [pscustomobject]@{
              rule     = "DangerousVerb_$verb"
              severity = "MEDIUM"
              message  = "Dangerous verb '$verb' detected - ensure this is necessary"
              file     = $fileName
              kind     = $kind
              category = "dangerous_permissions"
            }
          }
        }

        foreach ($res in $sensitiveResources) {
          if (($text -match "resources:\s*\[.*[''`"]?$res[''`"]?.*\]") -or 
            ($text -match "resources:[\s\S]*?-\s*[''`"]?$res[''`"]?")) {
            $findings += [pscustomobject]@{
              rule     = "SensitiveResource_$res"
              severity = "MEDIUM"
              message  = "Access to sensitive resource '$res' - verify this is required"
              file     = $fileName
              kind     = $kind
              category = "sensitive_access"
            }
          }
        }

        if ($text -match 'name:\s*cluster-admin') {
          $findings += [pscustomobject]@{
            rule     = "ClusterAdminReference"
            severity = "CRITICAL"
            message  = "References cluster-admin role - grants full cluster access"
            file     = $fileName
            kind     = $kind
            category = "excessive_permissions"
          }
        }

        $verbMatches = [regex]::Matches($text, '-\s*([a-z]+)\s*(?=#|$|\n)')
        $detectedVerbs = $verbMatches | ForEach-Object { $_.Groups[1].Value }
        $dangerousCount = ($detectedVerbs | Where-Object { $_ -in $dangerousVerbs }).Count
        if ($dangerousCount -gt 2) {
          $findings += [pscustomobject]@{
            rule     = "MultipleDestructiveVerbs"
            severity = "HIGH"
            message  = "Multiple dangerous verbs detected ($dangerousCount) - likely overly permissive"
            file     = $fileName
            kind     = $kind
            category = "excessive_permissions"
          }
        }

        if ((($text -match "verbs:[\s\S]*?-\s*delete") -or ($text -match "verbs:\s*\[.*delete.*\]")) -and
          (($text -match "verbs:[\s\S]*?-\s*(create|update)") -or ($text -match "verbs:\s*\[.*(create|update).*\]"))) {
          $findings += [pscustomobject]@{
            rule     = "DeleteWithModifyPerms"
            severity = "MEDIUM"
            message  = "Both delete and create/update permissions - verify least privilege"
            file     = $fileName
            kind     = $kind
            category = "excessive_permissions"
          }
        }
      }

      if ($text -match 'kind:\s*(RoleBinding|ClusterRoleBinding)') {
        $isClusterBinding = $text -match 'kind:\s*ClusterRoleBinding'
        $kind = if ($isClusterBinding) { "ClusterRoleBinding" } else { "RoleBinding" }

        if ($text -match 'name:\s*system:masters') {
          $findings += [pscustomobject]@{
            rule     = "SystemMastersBinding"
            severity = "CRITICAL"
            message  = "Binding to system:masters group - grants full cluster access"
            file     = $fileName
            kind     = $kind
            category = "excessive_permissions"
          }
        }
        if ($text -match 'roleRef:[\s\S]*?name:\s*cluster-admin') {
          $findings += [pscustomobject]@{
            rule     = "ClusterAdminBinding"
            severity = "CRITICAL"
            message  = "Binds to cluster-admin role - grants full cluster access"
            file     = $fileName
            kind     = $kind
            category = "excessive_permissions"
          }
        }
      }
    }

    if ($findings.Count -eq 0) {
      '[]' | Set-Content -Encoding UTF8 -Path $Out
      Write-Host "[rbac-police] -> $Out (no findings)"
    }
    else {
      # Force array output even for single finding
      if ($findings.Count -eq 1) {
        # Wrap single object in array brackets, pretty-printed
        $json = $findings[0] | ConvertTo-Json -Depth 10
        "[$json]" | Set-Content -Encoding UTF8 -Path $Out
      }
      else {
        $findings | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 -Path $Out
      }
      Write-Host "[rbac-police] -> $Out ($($findings.Count) findings)"
    }
  }
  catch { _WrapPlaceholder $Out "rbac-police" $_.Exception.Message }
}

# --- Gitleaks (secrets) -------------------------------------------------------
function Det-Gitleaks {
  param(
    [string]$Path = ".",
    [string]$Out = "$OutDir\gitleaks_raw.json"
  )
  $prevEA = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    Write-Host "[gitleaks] Scanning for secrets..." -ForegroundColor Cyan
    $abs = Resolve-ScanPath -Path $Path
    $rulesPath = Join-Path $RepoRoot "Detection\policies\gitleaks-rules.toml"

    function Test-GitleaksNonEmpty {
      param([string]$Path)
      if (!(Test-Path -LiteralPath $Path)) { return $false }
      try {
        $content = Get-Content -LiteralPath $Path -Raw
        if ([string]::IsNullOrWhiteSpace($content)) { return $false }
        $trim = $content.Trim()
        if ($trim -eq "[]") { return $false }
        # Try parse as array; if not array, try object with common properties
        try {
          $json = $trim | ConvertFrom-Json
          if ($json -is [System.Array]) { return ($json.Count -gt 0) }
          if ($json -is [PSCustomObject]) {
            if ($json.findings) { return ($json.findings.Count -gt 0) }
            if ($json.Leaks) { return ($json.Leaks.Count -gt 0) }
          }
          return $true
        }
        catch { return ((Get-Item $Path).Length -gt 3) }
      }
      catch { return $false }
    }

    $gitleaksCmd = $null
    try { $gitleaksCmd = (Get-Command gitleaks -ErrorAction Stop).Source } catch { }

    if ($gitleaksCmd) {
      # First attempt: with repo rules
      & gitleaks detect --source $abs --no-git --report-path $Out --report-format json --config $rulesPath 2>$null
      if (-not (Test-GitleaksNonEmpty -Path $Out)) {
        Write-Host "[gitleaks] No findings with repo rules; retrying with default rules" -ForegroundColor Yellow
        & gitleaks detect --source $abs --no-git --report-path $Out --report-format json 2>$null
      }
      if (!(Test-Path $Out)) { '[]' | Set-Content -Encoding UTF8 -Path $Out }
      Write-Host "[gitleaks] -> $Out" -ForegroundColor Green
    }
    else {
      # Docker fallback
      $tmpOut = Join-Path $abs "gitleaks_raw.json"
      try {
        if (Test-Path $rulesPath) {
          docker run --rm -v "${abs}:/scan" -v "${rulesPath}:/rules.toml:ro" zricethezav/gitleaks:latest `
            detect --source /scan --no-git --report-path /scan/gitleaks_raw.json --report-format json --config /rules.toml 2>$null | Out-Null
        }
        else {
          docker run --rm -v "${abs}:/scan" zricethezav/gitleaks:latest `
            detect --source /scan --no-git --report-path /scan/gitleaks_raw.json --report-format json 2>$null | Out-Null
        }
        if ((Test-Path $tmpOut) -and ($tmpOut -ne $Out)) { Move-Item -Force $tmpOut $Out }
        if (-not (Test-GitleaksNonEmpty -Path $Out)) {
          Write-Host "[gitleaks] Docker run yielded no findings; retrying without custom rules" -ForegroundColor Yellow
          docker run --rm -v "${abs}:/scan" zricethezav/gitleaks:latest `
            detect --source /scan --no-git --report-path /scan/gitleaks_raw.json --report-format json 2>$null | Out-Null
          if ((Test-Path $tmpOut) -and ($tmpOut -ne $Out)) { Move-Item -Force $tmpOut $Out }
        }
        if (!(Test-Path $Out)) { '[]' | Set-Content -Encoding UTF8 -Path $Out }
        Write-Host "[gitleaks] -> $Out (docker)" -ForegroundColor Green
      }
      catch {
        '[{"note":"Gitleaks not installed and docker fallback failed: ' + ($_.Exception.Message -replace '"', '\"') + '"}]' | Set-Content -Encoding UTF8 -Path $Out
        Write-Host "[gitleaks] -> $Out (placeholder - not installed)"
      }
    }
  }
  catch {
    '[{"note":"' + ($_.Exception.Message -replace '"', '\"') + '"}]' | Set-Content -Encoding UTF8 -Path $Out
  }
  finally { $ErrorActionPreference = $prevEA }
}

# --- orchestration ------------------------------------------------------------
function Det-RunSingle {
  param(
    [string]$Path = ".",
    [string]$Tool = ""
  )
  
  $validTools = @(
    "KubeConform", "KubeLinter", "Polaris", "Checkov", "TrivyConfig",
    "Kubescape", "KubeScore", "Yamllint", "KubeAudit", "Conftest",
    "RBACPolice", "Pluto", "Gitleaks"
  )
  
  if (-not ($Tool -in $validTools)) {
    Write-Host "[ERROR] Invalid tool name: $Tool" -ForegroundColor Red
    Write-Host "Valid tools: $($validTools -join ', ')" -ForegroundColor Yellow
    return
  }
  
  $abs = Resolve-ScanPath -Path $Path
  Write-Host "Scanning with: $Tool" -ForegroundColor Cyan
  Write-Host "Path: $abs" -ForegroundColor Cyan
  
  Invoke-WithTiming -Name $Tool {
    switch ($Tool) {
      "KubeConform" { Det-KubeConform -Path $abs }
      "KubeLinter" { Det-KubeLinter  -Path $abs }
      "Polaris" { Det-Polaris     -Path $abs }
      "Checkov" { Det-Checkov     -Path $abs }
      "TrivyConfig" { Det-TrivyConfig -Path $abs }
      "Kubescape" { Det-Kubescape   -Path $abs }
      "KubeScore" { Det-KubeScore   -Path $abs }
      "Yamllint" { Det-Yamllint    -Path $abs }
      "KubeAudit" { Det-KubeAudit   -Path $abs }
      "Conftest" { Det-Conftest    -Path $abs }
      "RBACPolice" { Det-RBACPolice  -Path $abs }
      "Pluto" { Det-Pluto       -Path $abs }
      "Gitleaks" { Det-Gitleaks    -Path $abs }
    }
  }
  
  Write-Host "`n────────── Runtime summary ──────────"
  $global:ToolTimings | Sort-Object Seconds -Descending |
  Format-Table Tool, Seconds, Status -Auto
}

function Det-RunLean {
  param([string]$Path = ".")
  Ensure-DetectorImages
  $abs = Resolve-ScanPath -Path $Path
  Write-Host "Scanning: $abs" -ForegroundColor Cyan

  $steps = @(
    "KubeConform", "KubeLinter", "Polaris",
    "Checkov", "TrivyConfig", "Kubescape", "KubeScore",
    "Yamllint", "KubeAudit", "Conftest"
  )

  foreach ($s in $steps) {
    Invoke-WithTiming -Name $s {
      switch ($s) {
        "KubeConform" { Det-KubeConform -Path $abs }
        "KubeLinter" { Det-KubeLinter  -Path $abs }
        "Polaris" { Det-Polaris     -Path $abs }
        "Checkov" { Det-Checkov     -Path $abs }
        "TrivyConfig" { Det-TrivyConfig -Path $abs }
        "Kubescape" { Det-Kubescape   -Path $abs }
        "KubeScore" { Det-KubeScore   -Path $abs }
        "Yamllint" { Det-Yamllint    -Path $abs }
        "KubeAudit" { Det-KubeAudit   -Path $abs }
        "Conftest" { Det-Conftest    -Path $abs }
      }
    }
  }

  Write-Host "`n────────── Runtime summary ──────────"
  $global:ToolTimings | Sort-Object Seconds -Descending |
  Format-Table Tool, Seconds, Status -Auto
}

function Det-RunExtended {
  param([string]$Path = ".")

  Ensure-ExtendedDetectorImages
  $abs = Resolve-ScanPath -Path $Path

  # Expand embedded YAML/JSON (e.g., ConfigMap data: cni.conf) to temp dir
  $extracted = Expand-EmbeddedConfigs -Path $Path
  $hasExtracted = $false
  if (Test-Path $extracted) {
    $hasExtracted = ((Get-ChildItem -Path $extracted -Recurse -File -Include *.yaml, *.yml | Measure-Object).Count -gt 0)
  }

  Write-Host "Scanning: $abs (EXTENDED MODE)" -ForegroundColor Cyan
  if ($hasExtracted) {
    Write-Host "Detected embedded configs -> scanning extracted dir: $extracted" -ForegroundColor Cyan
  }

  # Helper to build alternate output path with _embedded suffix
  function New-EmbeddedOut([string]$defaultPath) {
    $dir = Split-Path $defaultPath -Parent
    $base = [IO.Path]::GetFileNameWithoutExtension($defaultPath)
    $ext = [IO.Path]::GetExtension($defaultPath)
    return (Join-Path $dir ("{0}_embedded{1}" -f $base, $ext))
  }

  # ---------- First pass: scan ORIGINAL path ----------
  $steps = @(
    "KubeConform", "KubeLinter", "Polaris",
    "Checkov", "TrivyConfig", "Kubescape", "KubeScore",
    "Yamllint", "KubeAudit", "RBACPolice", "Pluto", "Gitleaks", "Conftest"
  )

  foreach ($s in $steps) {
    Invoke-WithTiming -Name $s {
      switch ($s) {
        "KubeConform" { Det-KubeConform -Path $abs }
        "KubeLinter" { Det-KubeLinter  -Path $abs }
        "Polaris" { Det-Polaris     -Path $abs }
        "Checkov" { Det-Checkov     -Path $abs }
        "TrivyConfig" { Det-TrivyConfig -Path $abs }
        "Kubescape" { Det-Kubescape   -Path $abs }
        "KubeScore" { Det-KubeScore   -Path $abs }
        "Yamllint" { Det-Yamllint    -Path $abs }
        "KubeAudit" { Det-KubeAudit   -Path $abs }
        "RBACPolice" { Det-RBACPolice  -Path $abs }
        "Pluto" { Det-Pluto       -Path $abs }
        "Gitleaks" { Det-Gitleaks    -Path $abs }
        "Conftest" { Det-Conftest    -Path $abs }
      }
    }
  }

  # ---------- Second pass: scan EXTRACTED embedded configs ----------
  if ($hasExtracted) {
    Write-Host "`nScanning embedded-configs materialized at: $extracted" -ForegroundColor Cyan

    # Map of default output filenames (must match defaults in each detector)
    $defaultOuts = @{
      KubeConform = "$OutDir\kubeconform_raw.json";
      KubeLinter  = "$OutDir\kubelinter_raw.json";
      Polaris     = "$OutDir\polaris_raw.json";
      Checkov     = "$OutDir\checkov_raw.json";
      TrivyConfig = "$OutDir\trivy_config_raw.json";
      Kubescape   = "$OutDir\kubescape_raw.json";
      KubeScore   = "$OutDir\kubescore_raw.json";
      Yamllint    = "$OutDir\yamllint_raw.txt";
      KubeAudit   = "$OutDir\kubeaudit_raw.json";
      RBACPolice  = "$OutDir\rbacpolice_raw.json";
      Pluto       = "$OutDir\pluto_raw.json";
      Conftest    = "$OutDir\conftest_raw.json";
    }

    # Tools that make sense to rescan on the extracted YAML (skip Gitleaks)
    $embeddedSteps = @(
      "KubeConform", "KubeLinter", "Polaris",
      "Checkov", "TrivyConfig", "Kubescape", "KubeScore",
      "Yamllint", "KubeAudit", "RBACPolice", "Pluto", "Conftest"
    )

    foreach ($s in $embeddedSteps) {
      $embeddedOut = New-EmbeddedOut $defaultOuts[$s]
      Invoke-WithTiming -Name ("{0} (embedded)" -f $s) {
        switch ($s) {
          "KubeConform" { Det-KubeConform -Path $extracted -Out $embeddedOut }
          "KubeLinter" { Det-KubeLinter  -Path $extracted -Out $embeddedOut }
          "Polaris" { Det-Polaris     -Path $extracted -Out $embeddedOut }
          "Checkov" { Det-Checkov     -Path $extracted -Out $embeddedOut }
          "TrivyConfig" { Det-TrivyConfig -Path $extracted -Out $embeddedOut }
          "Kubescape" { Det-Kubescape   -Path $extracted -Out $embeddedOut }
          "KubeScore" { Det-KubeScore   -Path $extracted -Out $embeddedOut }
          "Yamllint" { Det-Yamllint    -Path $extracted -Out $embeddedOut }
          "KubeAudit" { Det-KubeAudit   -Path $extracted -Out $embeddedOut }
          "RBACPolice" { Det-RBACPolice  -Path $extracted -Out $embeddedOut }
          "Pluto" { Det-Pluto       -Path $extracted -Out $embeddedOut }
          "Conftest" { Det-Conftest    -Path $extracted -Out $embeddedOut }
          "gitleaks" { Det-Gitleaks    -Path $extracted -Out $embeddedOut }
        }
      }
    }
  }

  Write-Host "`n────────── Runtime summary (EXTENDED) ──────────"
  $global:ToolTimings | Sort-Object Seconds -Descending | Format-Table Tool, Seconds, Status -Auto
}

# --- Unified Detection Runner -------------------------------------------------
function Run-AllDetectors {
  param(
    [string]$Path = ".",
    [switch]$Extended
  )
  
  Write-Host "`n========================================" -ForegroundColor Green
  Write-Host "  SafeFix-K8s Detection Layer" -ForegroundColor Green
  Write-Host "========================================`n" -ForegroundColor Green
  

  Write-Host "Mode: EXTENDED (all tools + embedded configs)" -ForegroundColor Cyan
  Det-RunExtended -Path $Path

  Write-Host "`n========================================" -ForegroundColor Green
  Write-Host "  Detection Complete!" -ForegroundColor Green
  Write-Host "  Output location: $OutDir" -ForegroundColor Green
  Write-Host "========================================`n" -ForegroundColor Green
}
