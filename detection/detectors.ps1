# detection/detectors.ps1
# SafeFix-K8s (LEAN/EXTENDED): Kubernetes YAML detectors

$ErrorActionPreference = "Stop"

# --- paths --------------------------------------------------------------------
$RepoRoot     = Split-Path -Parent $PSScriptRoot
$DetectionDir = $PSScriptRoot

$OutputRoot = $env:SAFEFIX_OUTPUT_ROOT
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
  $OutputRoot = Join-Path $DetectionDir "output"
} else {
  try { $OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot) }
  catch { $OutputRoot = Join-Path $DetectionDir "output" }
}

$DetectionLayer = Join-Path $OutputRoot "detection"
$OutDir  = Join-Path $DetectionLayer "raw"
$LogsDir = Join-Path $DetectionLayer "logs"

function Ensure-OutDirs {
  New-Item -ItemType Directory -Force -Path $OutDir,$LogsDir | Out-Null
  $env:SAFEFIX_DETECTION_RAW_DIR = $OutDir
  $env:SAFEFIX_DETECTION_LOG_DIR = $LogsDir
}
Ensure-OutDirs

# --- helpers ------------------------------------------------------------------
function Write-NonEmpty($Path) {
  if (!(Test-Path $Path) -or ((Get-Item $Path).Length -lt 3)) {
    throw "Output '$Path' missing/empty."
  }
}
function _WrapPlaceholder($Out, $tool, $msg) {
  Ensure-OutDirs
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
  $cwdTarget  = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path))
  if (Test-Path -LiteralPath $cwdTarget) { return (Resolve-Path -LiteralPath $cwdTarget).Path }
  $repoTarget = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
  if (Test-Path -LiteralPath $repoTarget) { return (Resolve-Path -LiteralPath $repoTarget).Path }
  throw "Cannot find path '$Path' from CWD or repo root ($RepoRoot)."
}

# Normalize to /scan/<relpath> (so tools keep relative paths in JSON)
function To-ScanRel {
  param([string]$AbsRoot, [string]$AbsFile)
  $rel = $AbsFile.Substring($AbsRoot.Length).TrimStart('\', '/')
  return "/scan/" + ($rel -replace '\\', '/')
}

# --- image set ---------------------------------------------------------------
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
    "openpolicyagent/conftest:latest"
  )
}
function Get-ExtendedDetectorImages {
  (Get-DetectorImages) + @(
    "us-docker.pkg.dev/fairwinds-ops/oss/pluto:v5"
  )
}
function Ensure-DetectorImages {
  $missing = @()
  foreach ($img in (Get-DetectorImages)) {
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
  foreach ($img in (Get-ExtendedDetectorImages)) {
    $present = docker images --format "{{.Repository}}:{{.Tag}}" | Where-Object { $_ -eq $img }
    if (-not $present) { $missing += $img }
  }
  if ($missing.Count -gt 0) {
    Write-Host "Pulling: $($missing -join ', ')"
    foreach ($m in $missing) {
      try { docker pull $m | Out-Null } catch { Write-Host "Warn: could not pull $m" -ForegroundColor Yellow }
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
    [void]$global:ToolTimings.Add([pscustomobject]@{
      Tool = $Name; Seconds = [math]::Round($sw.Elapsed.TotalSeconds,2); Status = $status
    })
  }
}

# --- embedded configs extraction ---------------------------------------------
function Expand-EmbeddedConfigs {
  param([string]$Path)
  $abs = Resolve-ScanPath -Path $Path
  $out = Join-Path $DetectionDir ".tmp-extracted"
  New-Item -ItemType Directory -Force -Path $out | Out-Null

  Get-ChildItem -Path $abs -Recurse -File -Include *.yaml, *.yml | ForEach-Object {
    $doc = Get-Content $_.FullName -Raw
    $parts = $doc -split '^\s*---\s*$' -ne ''
    foreach ($p in $parts) {
      if ($p -match 'kind:\s*ConfigMap') {
        $matches = [regex]::Matches($p, '^\s{2,}([A-Za-z0-9._-]+):\s*\|\s*\n((?:\s{4,}.+\n?)+)', 'Multiline')
        foreach ($m in $matches) {
          $key = $m.Groups[1].Value
          $val = ($m.Groups[2].Value -replace '^\s{4}', '', 'Multiline')
          try {
            # if powershell-yaml is available this validates; otherwise it just writes the block out
            $null = $val | Out-String
            $file = Join-Path $out ("embedded__{0}__{1}.yaml" -f ($_.BaseName), $key.Replace(':','_'))
            $val | Set-Content -Encoding UTF8 -Path $file
          } catch { }
        }
      }
    }
  }
  return $out
}

# --- detectors ---------------------------------------------------------------
function Det-KubeConform {
  param([string]$Path=".", [string]$Out = "$OutDir\kubeconform_raw.json")
  Ensure-OutDirs
  try {
    $abs = Resolve-ScanPath -Path $Path
    docker run --rm -v "$($abs):/scan:ro" ghcr.io/yannh/kubeconform:latest `
      -summary -output json -strict -ignore-missing-schemas -verbose /scan `
      | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[kubeconform] -> $Out"
  } catch { _WrapPlaceholder $Out "kubeconform" $_.Exception.Message }
}
function Det-KubeLinter {
  param([string]$Path=".", [string]$Out="$OutDir\kubelinter_raw.json",
        [string]$Cfg=(Join-Path $RepoRoot "policies\kubelinter-config.yaml"))
  Ensure-OutDirs
  try {
    $abs = Resolve-ScanPath -Path $Path
    if (Test-Path $Cfg) {
      docker run --rm -v "$($abs):/scan:ro" -v "$($Cfg):/cfg/kubelinter-config.yaml:ro" stackrox/kube-linter:latest `
        lint /scan --config /cfg/kubelinter-config.yaml --format json | Set-Content -Encoding UTF8 -Path $Out
    } else {
      docker run --rm -v "$($abs):/scan:ro" stackrox/kube-linter:latest `
        lint /scan --format json | Set-Content -Encoding UTF8 -Path $Out
    }
    Write-NonEmpty $Out; Write-Host "[kube-linter] -> $Out"
  } catch { _WrapPlaceholder $Out "kubelinter" $_.Exception.Message }
}
function Det-Polaris {
  param([string]$Path=".", [string]$Out="$OutDir\polaris_raw.json")
  Ensure-OutDirs
  try {
    $abs = Resolve-ScanPath -Path $Path
    docker run --rm -v "$($abs):/scan:ro" quay.io/fairwinds/polaris:latest `
      polaris audit --audit-path /scan --format json `
      | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[polaris] -> $Out"
  } catch { _WrapPlaceholder $Out "polaris" $_.Exception.Message }
}
function Det-Checkov {
  param([string]$Path=".", [string]$Out="$OutDir\checkov_raw.json")
  Ensure-OutDirs
  try {
    $abs = Resolve-ScanPath -Path $Path
    $checksDir = Join-Path $RepoRoot "Detection\policies\checkov"
    $local = $null
    try { $local = (Get-Command checkov -ErrorAction Stop).Source } catch { }
    $args = @("-d",$abs,"--framework","kubernetes","--quiet","--compact","-o","json")
    if (Test-Path $checksDir) { $args += @("--external-checks-dir",$checksDir) }

    if ($local) {
      $prevEA=$ErrorActionPreference; $ErrorActionPreference="Continue"
      & checkov @args 2>$null | Set-Content -Encoding UTF8 -Path $Out
      $ErrorActionPreference=$prevEA
    } else {
      $dockerArgs = @("run","--rm","-v","$($abs):/scan:ro","bridgecrew/checkov:latest","-d","/scan","--framework","kubernetes","--quiet","--compact","-o","json")
      if (Test-Path $checksDir) {
        $dockerArgs = @("run","--rm","-v","$($abs):/scan:ro","-v","$($checksDir):/ext:ro","bridgecrew/checkov:latest","-d","/scan","--framework","kubernetes","--quiet","--compact","--external-checks-dir","/ext","-o","json")
      }
      docker @dockerArgs | Set-Content -Encoding UTF8 -Path $Out
    }
    Write-NonEmpty $Out; Write-Host "[checkov] -> $Out"
  } catch { _WrapPlaceholder $Out "checkov" $_.Exception.Message }
}
function Det-TrivyConfig {
  param([string]$Path=".", [string]$Out="$OutDir\trivy_config_raw.json")
  Ensure-OutDirs
  try {
    $abs = Resolve-ScanPath -Path $Path
    docker run --rm -v "$($abs):/scan:ro" aquasec/trivy:latest `
      config --quiet --format json /scan | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[trivy config] -> $Out"
  } catch { _WrapPlaceholder $Out "trivy-config" $_.Exception.Message }
}
function Det-Kubescape {
  param([string]$Path=".", [string]$Out="$OutDir\kubescape_raw.json")
  Ensure-OutDirs
  $abs = Resolve-ScanPath -Path $Path
  $env:KUBESCAPE_DISABLE_GIT_INFO = "true"
  $ks = $null; try { $ks = (Get-Command kubescape -ErrorAction Stop).Source } catch { }
  if ($ks) {
    try {
      $prevEA=$ErrorActionPreference; $ErrorActionPreference="Continue"
      & kubescape scan $abs --format json --format-version v2 --output $Out 2>$null | Out-Null
      $ErrorActionPreference=$prevEA
      if ((Test-Path $Out) -and ((Get-Item $Out).Length -gt 100)) { Write-Host "[kubescape] -> $Out" }
      else { _WrapPlaceholder $Out "kubescape" "failed: output file not created or too small" }
    } catch { _WrapPlaceholder $Out "kubescape" $_.Exception.Message }
  } else {
    try {
      $prevEA=$ErrorActionPreference; $ErrorActionPreference="Continue"
      docker run --rm -e "KUBESCAPE_DISABLE_GIT_INFO=true" -v "$($abs):/scan" `
        quay.io/kubescape/kubescape:latest scan /scan --format json --format-version v2 --output /scan/kubescape_raw.json
      $ErrorActionPreference=$prevEA
      $tempOut = Join-Path $abs "kubescape_raw.json"
      if ((Test-Path $tempOut) -and ($tempOut -ne $Out)) { Move-Item -Force $tempOut $Out }
      Write-NonEmpty $Out; Write-Host "[kubescape] -> $Out"
    } catch { _WrapPlaceholder $Out "kubescape" $_.Exception.Message }
  }
}
function Det-KubeScore {
  param([string]$Path=".", [string]$Out="$OutDir\kubescore_raw.json")
  Ensure-OutDirs
  try {
    $abs = Resolve-ScanPath -Path $Path
    $files = Get-ChildItem -Path $abs -Recurse -File -Include *.yaml, *.yml |
      ForEach-Object { To-ScanRel -AbsRoot $abs -AbsFile $_.FullName }
    if ($files.Count -eq 0) { '[]' | Set-Content -Encoding UTF8 -Path $Out; Write-Host "[kube-score] -> $Out (no YAML)"; return }
    $cmd = @("run","--rm","-v","$($abs):/scan:ro","zegl/kube-score:latest","score","--output-format","json") + $files
    docker @cmd | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[kube-score] -> $Out"
  } catch { _WrapPlaceholder $Out "kube-score" $_.Exception.Message }
}
function Det-Yamllint {
  param([string]$Path=".", [string]$Out="$OutDir\yamllint_raw.txt")
  Ensure-OutDirs
  try {
    $abs = Resolve-ScanPath -Path $Path
    docker run --rm -v "$($abs):/scan:ro" cytopia/yamllint:latest `
      -f parsable -s /scan | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[yamllint] -> $Out"
  } catch { _WrapPlaceholder $Out "yamllint" $_.Exception.Message }
}
function Det-KubeAudit {
  param([string]$Path=".", [string]$Out="$OutDir\kubeaudit_raw.json")
  Ensure-OutDirs
  $abs = Resolve-ScanPath -Path $Path
  $files = Get-ChildItem -Path $abs -Recurse -File -Include *.yaml, *.yml
  $accum = @()
  if ($files.Count -eq 0) { '[]' | Set-Content -Encoding UTF8 -Path $Out; Write-Host "[kubeaudit] -> $Out (no YAML)"; return }
  $local = $null
  try { $local = (Get-Command kubeaudit -ErrorAction Stop).Source } catch { }
  $prevEA=$ErrorActionPreference; $ErrorActionPreference="Continue"
  Write-Host "[kubeaudit] Scanning $($files.Count) files..." -ForegroundColor Cyan
  foreach ($f in $files) {
    try {
      $raw = $null
      if ($local) {
        $raw = & kubeaudit all -f "$($f.FullName)" -p json 2>$null
      } else {
        $dir = $f.Directory.FullName
        $raw = docker run --rm -v "$($dir):/scan:ro" ghcr.io/shopify/kubeaudit:latest `
          all -f "/scan/$($f.Name)" -p json 2>$null
      }
      if ($raw) {
        $jsonLines = $raw | Where-Object { $_ -match '^\s*\{' -and $_ -notmatch 'Deprecation' -and $_ -notmatch 'WARNING' }
        foreach ($jsonLine in $jsonLines) {
          try {
            $obj = $jsonLine | ConvertFrom-Json
            $obj | Add-Member -NotePropertyName "file" -NotePropertyValue (To-ScanRel -AbsRoot $abs -AbsFile $f.FullName) -Force
            $accum += $obj
          } catch { continue }
        }
      }
    } catch { continue }
  }
  $ErrorActionPreference=$prevEA
  if ($accum.Count -eq 0) { '[]' | Set-Content -Encoding UTF8 -Path $Out; Write-Host "[kubeaudit] -> $Out (no findings)" }
  else { $accum | ConvertTo-Json -Depth 64 | Set-Content -Encoding UTF8 -Path $Out; Write-Host "[kubeaudit] -> $Out ($($accum.Count) findings)" }
}
function Det-Conftest {
  param([string]$Path=".", [string]$Out="$OutDir\conftest_raw.json")
  Ensure-OutDirs
  try {
    $abs = Resolve-ScanPath -Path $Path
    $PolicyDirs = @(
      "$RepoRoot\Detection\policies\conftest",
      "$RepoRoot\policies\opa",
      "$RepoRoot\policies\opa_minimal"
    ) | Where-Object { Test-Path $_ }
    if ($PolicyDirs.Count -eq 0) { _WrapPlaceholder $Out "conftest" "No OPA/conftest policy directories found"; return }

    # Merge policies into a temp folder
    $tempPolicyDir = Join-Path $env:TEMP ("conftest_policies_" + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Force -Path $tempPolicyDir | Out-Null
    foreach ($srcDir in $PolicyDirs) {
      Get-ChildItem -Path $srcDir -Recurse -File -Include *.rego | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination (Join-Path $tempPolicyDir $_.Name) -Force
      }
    }

    $local = $null; try { $local = (Get-Command conftest -ErrorAction Stop).Source } catch { }
    if ($local) {
      & conftest test $abs --policy $tempPolicyDir --all-namespaces --output json | Set-Content -Encoding UTF8 -Path $Out
    } else {
      $cmd = "docker run --rm -v `"$($abs):/scan:ro`" -v `"$($tempPolicyDir):/policy:ro`" openpolicyagent/conftest:latest test /scan --policy /policy --all-namespaces --output json"
      Invoke-Expression $cmd | Set-Content -Encoding UTF8 -Path $Out
    }
    Write-NonEmpty $Out; Write-Host "[conftest] -> $Out (OPA policies merged)"
    Remove-Item -Recurse -Force -Path $tempPolicyDir
  } catch { _WrapPlaceholder $Out "conftest" $_.Exception.Message }
}
function Det-Pluto {
  param([string]$Path=".", [string]$Out="$OutDir\pluto_raw.json")
  Ensure-OutDirs
  $abs = Resolve-ScanPath -Path $Path
  $prevEA=$ErrorActionPreference; $ErrorActionPreference="Continue"
  try {
    $local = $null; try { $local = (Get-Command pluto -ErrorAction Stop).Source } catch { }
    if ($local) {
      $output = & pluto detect-files -d $abs --output json 2>&1
      $content = ($output | Where-Object { $_ -match '^\s*[\{\[]' }) -join "`n"
      if ([string]::IsNullOrWhiteSpace($content)) { '{"items":[],"target-versions":{}}' | Set-Content -Encoding UTF8 -Path $Out }
      else { $content | Set-Content -Encoding UTF8 -Path $Out }
    } else {
      # Docker fallback
      docker run --rm -v "$($abs):/scan:ro" us-docker.pkg.dev/fairwinds-ops/oss/pluto:v5 `
        detect-files -d /scan --output json | Set-Content -Encoding UTF8 -Path $Out
    }
    Write-Host "[pluto] -> $Out"
  } catch {
    '{"items":[],"target-versions":{},"note":"' + ($_.Exception.Message -replace '"','\"') + '"}' |
      Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[pluto] -> $Out (placeholder - error)"
  } finally { $ErrorActionPreference = $prevEA }
}
function Det-RBACPolice {
  param([string]$Path=".", [string]$Out="$OutDir\rbacpolice_raw.json")
  Ensure-OutDirs
  try {
    $abs = Resolve-ScanPath -Path $Path
    # If official image exists, use it. Else, fall back to heuristic scanner below.
    $ok = $false
    try {
      docker run --rm -v "$($abs):/scan:ro" ghcr.io/falcohq/rbac-police:latest `
        verify -f /scan -o json | Set-Content -Encoding UTF8 -Path $Out
      $ok = $true
    } catch { $ok = $false }
    if ($ok) { Write-Host "[rbac-police] -> $Out"; return }

    # Heuristic fallback (keeps pipeline green)
    $rbacFiles = Get-ChildItem -Path $abs -Recurse -File -Include *.yaml, *.yml |
      Where-Object { (Get-Content $_.FullName -Raw) -match 'kind:\s*(Role|ClusterRole|RoleBinding|ClusterRoleBinding)' }
    if ($rbacFiles.Count -eq 0) {
      '[{"tool":"rbac-police","note":"No RBAC manifests found"}]' | Set-Content -Encoding UTF8 -Path $Out
      Write-Host "[rbac-police] -> $Out (placeholder - no RBAC files)"; return
    }

    $findings = @()
    $dangerousVerbs = @('delete','deletecollection','create','update','patch','escalate','bind','impersonate')
    $sensitiveResources = @('secrets','configmaps','serviceaccounts','roles','clusterroles','rolebindings','clusterrolebindings')
    foreach ($f in $rbacFiles) {
      $text = Get-Content $f.FullName -Raw
      $fileName = (To-ScanRel -AbsRoot $abs -AbsFile $f.FullName)
      if ($text -match 'kind:\s*(Role|ClusterRole)') {
        $kind = if ($text -match 'kind:\s*ClusterRole') { "ClusterRole" } else { "Role" }
        if (($text -match 'verbs:\s*\[\s*\*\s*\]') -or ($text -match 'verbs:\s*\n\s*-\s*\*')) {
          $findings += [pscustomobject]@{ rule="WildcardVerbs"; severity="HIGH"; message="Wildcard verbs (*)"; file=$fileName; kind=$kind; category="excessive_permissions" }
        }
        if (($text -match 'resources:\s*\[\s*\*\s*\]') -or ($text -match 'resources:\s*\n\s*-\s*\*')) {
          $findings += [pscustomobject]@{ rule="WildcardResources"; severity="HIGH"; message="Wildcard resources (*)"; file=$fileName; kind=$kind; category="excessive_permissions" }
        }
        if (($text -match 'apiGroups:\s*\[\s*\*\s*\]') -or ($text -match 'apiGroups:\s*\n\s*-\s*\*')) {
          $findings += [pscustomobject]@{ rule="WildcardAPIGroups"; severity="MEDIUM"; message="Wildcard apiGroups (*)"; file=$fileName; kind=$kind; category="excessive_permissions" }
        }
        foreach ($verb in $dangerousVerbs) {
          if (($text -match "verbs:\s*\[.*\b$verb\b.*\]") -or ($text -match "verbs:[\s\S]*?-\s*$verb(\s|$)")) {
            $findings += [pscustomobject]@{ rule="DangerousVerb_$verb"; severity="MEDIUM"; message="Verb '$verb'"; file=$fileName; kind=$kind; category="dangerous_permissions" }
          }
        }
        foreach ($res in $sensitiveResources) {
          if (($text -match "resources:\s*\[.*\b$res\b.*\]") -or ($text -match "resources:[\s\S]*?-\s*$res(\s|$)")) {
            $findings += [pscustomobject]@{ rule="SensitiveResource_$res"; severity="MEDIUM"; message="Resource '$res'"; file=$fileName; kind=$kind; category="sensitive_access" }
          }
        }
        if ($text -match 'name:\s*cluster-admin') {
          $findings += [pscustomobject]@{ rule="ClusterAdminReference"; severity="CRITICAL"; message="Ref cluster-admin"; file=$fileName; kind=$kind; category="excessive_permissions" }
        }
      }
      if ($text -match 'kind:\s*(RoleBinding|ClusterRoleBinding)') {
        $kind = if ($text -match 'kind:\s*ClusterRoleBinding') { "ClusterRoleBinding" } else { "RoleBinding" }
        if ($text -match 'name:\s*system:masters') {
          $findings += [pscustomobject]@{ rule="SystemMastersBinding"; severity="CRITICAL"; message="system:masters"; file=$fileName; kind=$kind; category="excessive_permissions" }
        }
        if ($text -match 'roleRef:[\s\S]*?name:\s*cluster-admin') {
          $findings += [pscustomobject]@{ rule="ClusterAdminBinding"; severity="CRITICAL"; message="Binds cluster-admin"; file=$fileName; kind=$kind; category="excessive_permissions" }
        }
      }
    }
    if ($findings.Count -eq 0) { '[]' | Set-Content -Encoding UTF8 -Path $Out; Write-Host "[rbac-police] -> $Out (no findings)" }
    else {
      if ($findings.Count -eq 1) {
        $json = $findings[0] | ConvertTo-Json -Depth 10
        "[$json]" | Set-Content -Encoding UTF8 -Path $Out
      } else {
        $findings | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 -Path $Out
      }
      Write-Host "[rbac-police] -> $Out ($($findings.Count) findings)"
    }
  } catch { _WrapPlaceholder $Out "rbac-police" $_.Exception.Message }
}
function Det-Gitleaks {
  param([string]$Path=".", [string]$Out="$OutDir\gitleaks_raw.json")
  Ensure-OutDirs
  $prevEA=$ErrorActionPreference; $ErrorActionPreference="Continue"
  try {
    $abs = Resolve-ScanPath -Path $Path
    $rulesPath = Join-Path $RepoRoot "Detection\policies\gitleaks-rules.toml"
    function Test-GitleaksNonEmpty([string]$Path) {
      if (!(Test-Path -LiteralPath $Path)) { return $false }
      try {
        $content = Get-Content -LiteralPath $Path -Raw
        if ([string]::IsNullOrWhiteSpace($content)) { return $false }
        $trim = $content.Trim()
        if ($trim -eq "[]") { return $false }
        try {
          $json = $trim | ConvertFrom-Json
          if ($json -is [System.Array]) { return ($json.Count -gt 0) }
          if ($json -is [PSCustomObject]) {
            if ($json.findings) { return ($json.findings.Count -gt 0) }
            if ($json.Leaks)    { return ($json.Leaks.Count -gt 0) }
          }
          return $true
        } catch { return ((Get-Item $Path).Length -gt 3) }
      } catch { return $false }
    }
    $gitleaksCmd = $null; try { $gitleaksCmd = (Get-Command gitleaks -ErrorAction Stop).Source } catch { }
    if ($gitleaksCmd) {
      & gitleaks detect --source $abs --no-git --report-path $Out --report-format json --config $rulesPath 2>$null
      if (-not (Test-GitleaksNonEmpty -Path $Out)) {
        Write-Host "[gitleaks] No findings with repo rules; retry with defaults" -ForegroundColor Yellow
        & gitleaks detect --source $abs --no-git --report-path $Out --report-format json 2>$null
      }
      if (!(Test-Path $Out)) { '[]' | Set-Content -Encoding UTF8 -Path $Out }
      Write-Host "[gitleaks] -> $Out"
    } else {
      $tmpOut = Join-Path $abs "gitleaks_raw.json"
      try {
        if (Test-Path $rulesPath) {
          docker run --rm -v "$($abs):/scan" -v "$($rulesPath):/rules.toml:ro" zricethezav/gitleaks:latest `
            detect --source /scan --no-git --report-path /scan/gitleaks_raw.json --report-format json --config /rules.toml 2>$null | Out-Null
        } else {
          docker run --rm -v "$($abs):/scan" zricethezav/gitleaks:latest `
            detect --source /scan --no-git --report-path /scan/gitleaks_raw.json --report-format json 2>$null | Out-Null
        }
        if ((Test-Path $tmpOut) -and ($tmpOut -ne $Out)) { Move-Item -Force $tmpOut $Out }
        if (-not (Test-GitleaksNonEmpty -Path $Out)) {
          Write-Host "[gitleaks] Docker run yielded no findings; retry without custom rules" -ForegroundColor Yellow
          docker run --rm -v "$($abs):/scan" zricethezav/gitleaks:latest `
            detect --source /scan --no-git --report-path /scan/gitleaks_raw.json --report-format json 2>$null | Out-Null
          if ((Test-Path $tmpOut) -and ($tmpOut -ne $Out)) { Move-Item -Force $tmpOut $Out }
        }
        if (!(Test-Path $Out)) { '[]' | Set-Content -Encoding UTF8 -Path $Out }
        Write-Host "[gitleaks] -> $Out (docker)"
      } catch {
        '[{"note":"Gitleaks not installed and docker fallback failed: ' + ($_.Exception.Message -replace '"','\"') + '"}]' |
          Set-Content -Encoding UTF8 -Path $Out
        Write-Host "[gitleaks] -> $Out (placeholder)"
      }
    }
  } catch {
    '[{"note":"' + ($_.Exception.Message -replace '"','\"') + '"}]' | Set-Content -Encoding UTF8 -Path $Out
  } finally { $ErrorActionPreference = $prevEA }
}

# --- Run blocks ---------------------------------------------------------------
function Det-RunSingle {
  param([string]$Path=".", [string]$Tool="")
  $validTools = @(
    "KubeConform","KubeLinter","Polaris","Checkov","TrivyConfig","Kubescape",
    "KubeScore","Yamllint","KubeAudit","Conftest","RBACPolice","Pluto","Gitleaks"
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
      "KubeLinter"  { Det-KubeLinter  -Path $abs }
      "Polaris"     { Det-Polaris     -Path $abs }
      "Checkov"     { Det-Checkov     -Path $abs }
      "TrivyConfig" { Det-TrivyConfig -Path $abs }
      "Kubescape"   { Det-Kubescape   -Path $abs }
      "KubeScore"   { Det-KubeScore   -Path $abs }
      "Yamllint"    { Det-Yamllint    -Path $abs }
      "KubeAudit"   { Det-KubeAudit   -Path $abs }
      "Conftest"    { Det-Conftest    -Path $abs }
      "RBACPolice"  { Det-RBACPolice  -Path $abs }
      "Pluto"       { Det-Pluto       -Path $abs }
      "Gitleaks"    { Det-Gitleaks    -Path $abs }
    }
  }
  Write-Host "`n────────── Runtime summary ──────────"
  $global:ToolTimings | Sort-Object Seconds -Descending | Format-Table Tool, Seconds, Status -Auto
}

function Det-RunLean {
  param([string]$Path=".")
  Ensure-DetectorImages
  $abs = Resolve-ScanPath -Path $Path
  Write-Host "Scanning: $abs" -ForegroundColor Cyan
  $steps = @("KubeConform","KubeLinter","Polaris","Checkov","TrivyConfig","Kubescape","KubeScore","Yamllint","KubeAudit","Conftest")
  foreach ($s in $steps) {
    Invoke-WithTiming -Name $s {
      switch ($s) {
        "KubeConform" { Det-KubeConform -Path $abs }
        "KubeLinter"  { Det-KubeLinter  -Path $abs }
        "Polaris"     { Det-Polaris     -Path $abs }
        "Checkov"     { Det-Checkov     -Path $abs }
        "TrivyConfig" { Det-TrivyConfig -Path $abs }
        "Kubescape"   { Det-Kubescape   -Path $abs }
        "KubeScore"   { Det-KubeScore   -Path $abs }
        "Yamllint"    { Det-Yamllint    -Path $abs }
        "KubeAudit"   { Det-KubeAudit   -Path $abs }
        "Conftest"    { Det-Conftest    -Path $abs }
      }
    }
  }
  Write-Host "`n────────── Runtime summary ──────────"
  $global:ToolTimings | Sort-Object Seconds -Descending | Format-Table Tool, Seconds, Status -Auto
}

function Det-RunExtended {
  param([string]$Path=".")
  Ensure-ExtendedDetectorImages
  $abs = Resolve-ScanPath -Path $Path

  $extracted = Expand-EmbeddedConfigs -Path $Path
  $hasExtracted = $false
  if (Test-Path $extracted) {
    $hasExtracted = ((Get-ChildItem -Path $extracted -Recurse -File -Include *.yaml, *.yml | Measure-Object).Count -gt 0)
  }

  Write-Host "Scanning: $abs (EXTENDED MODE)" -ForegroundColor Cyan
  if ($hasExtracted) { Write-Host "Detected embedded configs -> scanning extracted dir: $extracted" -ForegroundColor Cyan }

  $steps = @("KubeConform","KubeLinter","Polaris","Checkov","TrivyConfig","Kubescape","KubeScore","Yamllint","KubeAudit","RBACPolice","Pluto","Gitleaks","Conftest")
  foreach ($s in $steps) {
    Invoke-WithTiming -Name $s {
      switch ($s) {
        "KubeConform" { Det-KubeConform -Path $abs }
        "KubeLinter"  { Det-KubeLinter  -Path $abs }
        "Polaris"     { Det-Polaris     -Path $abs }
        "Checkov"     { Det-Checkov     -Path $abs }
        "TrivyConfig" { Det-TrivyConfig -Path $abs }
        "Kubescape"   { Det-Kubescape   -Path $abs }
        "KubeScore"   { Det-KubeScore   -Path $abs }
        "Yamllint"    { Det-Yamllint    -Path $abs }
        "KubeAudit"   { Det-KubeAudit   -Path $abs }
        "RBACPolice"  { Det-RBACPolice  -Path $abs }
        "Pluto"       { Det-Pluto       -Path $abs }
        "Gitleaks"    { Det-Gitleaks    -Path $abs }
        "Conftest"    { Det-Conftest    -Path $abs }
      }
    }
  }

  if ($hasExtracted) {
    Write-Host "`nScanning embedded-configs materialized at: $extracted" -ForegroundColor Cyan
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
    $embeddedSteps = @("KubeConform","KubeLinter","Polaris","Checkov","TrivyConfig","Kubescape","KubeScore","Yamllint","KubeAudit","RBACPolice","Pluto","Conftest")

    function New-EmbeddedOut([string]$defaultPath) {
      $dir = Split-Path $defaultPath -Parent
      $base = [IO.Path]::GetFileNameWithoutExtension($defaultPath)
      $ext = [IO.Path]::GetExtension($defaultPath)
      return (Join-Path $dir ("{0}_embedded{1}" -f $base, $ext))
    }

    foreach ($s in $embeddedSteps) {
      $embeddedOut = New-EmbeddedOut $defaultOuts[$s]
      Invoke-WithTiming -Name ("{0} (embedded)" -f $s) {
        switch ($s) {
          "KubeConform" { Det-KubeConform -Path $extracted -Out $embeddedOut }
          "KubeLinter"  { Det-KubeLinter  -Path $extracted -Out $embeddedOut }
          "Polaris"     { Det-Polaris     -Path $extracted -Out $embeddedOut }
          "Checkov"     { Det-Checkov     -Path $extracted -Out $embeddedOut }
          "TrivyConfig" { Det-TrivyConfig -Path $extracted -Out $embeddedOut }
          "Kubescape"   { Det-Kubescape   -Path $extracted -Out $embeddedOut }
          "KubeScore"   { Det-KubeScore   -Path $extracted -Out $embeddedOut }
          "Yamllint"    { Det-Yamllint    -Path $extracted -Out $embeddedOut }
          "KubeAudit"   { Det-KubeAudit   -Path $extracted -Out $embeddedOut }
          "RBACPolice"  { Det-RBACPolice  -Path $extracted -Out $embeddedOut }
          "Pluto"       { Det-Pluto       -Path $extracted -Out $embeddedOut }
          "Conftest"    { Det-Conftest    -Path $extracted -Out $embeddedOut }
        }
      }
    }
  }

  Write-Host "`n────────── Runtime summary (EXTENDED) ──────────"
  $global:ToolTimings | Sort-Object Seconds -Descending | Format-Table Tool, Seconds, Status -Auto
}

# --- Unified Detection Runner -------------------------------------------------
function Run-AllDetectors {
  param([string]$Path=".", [switch]$Extended)
  Write-Host "`n========================================" -ForegroundColor Green
  Write-Host "  SafeFix-K8s Detection Layer" -ForegroundColor Green
  Write-Host "========================================`n" -ForegroundColor Green

  if ($Extended) {
    Write-Host "Mode: EXTENDED (all tools + embedded configs)" -ForegroundColor Cyan
    Det-RunExtended -Path $Path
  } else {
    Write-Host "Mode: LEAN (core tools)" -ForegroundColor Cyan
    Det-RunLean -Path $Path
  }

  Write-Host "`n========================================" -ForegroundColor Green
  Write-Host "  Detection Complete!" -ForegroundColor Green
  Write-Host "  Output location: $OutDir" -ForegroundColor Green
  Write-Host "========================================`n" -ForegroundColor Green
}
