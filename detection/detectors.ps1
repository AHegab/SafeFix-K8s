# detection/detectors.ps1
# SafeFix-K8s (LEAN): Kubernetes YAML detectors only

$ErrorActionPreference = "Stop"

# --- paths --------------------------------------------------------------------
$RepoRoot     = Split-Path -Parent $PSScriptRoot
$DetectionDir = $PSScriptRoot
$OutDir       = Join-Path $DetectionDir "output\raw"
$LogsDir      = Join-Path $DetectionDir "output\logs"
New-Item -ItemType Directory -Force -Path $OutDir,$LogsDir | Out-Null

# --- helpers ------------------------------------------------------------------
function Write-NonEmpty($Path) {
  if (!(Test-Path $Path) -or ((Get-Item $Path).Length -lt 3)) {
    throw "Output '$Path' missing/empty."
  }
}

function _WrapPlaceholder($Out, $tool, $msg) {
  '[{"tool":"' + $tool + '","note":"' + ($msg -replace '"','''') + '"}]' |
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
  $cwdTarget = Join-Path (Get-Location).Path $Path
  if (Test-Path -LiteralPath $cwdTarget) { return (Resolve-Path -LiteralPath $cwdTarget).Path }
  # Then try repo root (parent of detection/)
  $repoTarget = Join-Path $RepoRoot $Path
  if (Test-Path -LiteralPath $repoTarget) { return (Resolve-Path -LiteralPath $repoTarget).Path }
  throw "Cannot find path '$Path' from CWD or repo root ($RepoRoot)."
}

# --- image set (LEAN) ---------------------------------------------------------
function Get-DetectorImages {
  @(
    "stackrox/kube-linter:latest",
    "quay.io/fairwinds/polaris:latest",
    "bridgecrew/checkov:latest",          # <-- ADDED: Checkov
    "aquasec/trivy:latest",
    "quay.io/kubescape/kubescape:latest",
    "zegl/kube-score:latest",
    "cytopia/yamllint:latest",
    "ghcr.io/shopify/kubeaudit:latest",
    "ghcr.io/yannh/kubeconform:latest"
  )
}

function Det-Conftest {
  param([string]$Path=".", [string]$Out="$OutDir\conftest_raw.json", [string]$PolicyDir="$RepoRoot\policies\opa")
  try {
    $abs = Resolve-ScanPath -Path $Path
    if (-not (Test-Path $PolicyDir)) {
      _WrapPlaceholder $Out "conftest" "Policy dir not found"; return
    }
    docker run --rm -v "${abs}:/scan:ro" -v "${PolicyDir}:/policy:ro" openpolicyagent/conftest:latest `
      test /scan --policy /policy --output json | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[conftest] -> $Out"
  } catch { _WrapPlaceholder $Out "conftest" $_.Exception.Message }
}


# --- image set (EXTENDED) - includes RBAC and API deprecation tools ----------
function Get-ExtendedDetectorImages {
  $base = Get-DetectorImages
  $extended = @(
    "us-docker.pkg.dev/fairwinds-ops/oss/pluto:v5"
  )
  return $base + $extended
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

# --- timing / progress --------------------------------------------------------
$global:ToolTimings = New-Object System.Collections.ArrayList
function Invoke-WithTiming {
  param([string]$Name,[scriptblock]$Action)
  $sw=[System.Diagnostics.Stopwatch]::StartNew()
  $status="ok"
  try { & $Action } catch { $status="error"; throw } finally {
    $sw.Stop()
    [void]$global:ToolTimings.Add([pscustomobject]@{Tool=$Name;Seconds=[math]::Round($sw.Elapsed.TotalSeconds,2);Status=$status})
  }
}

# --- detectors ----------------------------------------------------------------
function Det-KubeConform {
  param([string]$Path=".",[string]$Out="$OutDir\kubeconform_raw.json")
  try {
    $abs = Resolve-ScanPath -Path $Path
    docker run --rm -v "${abs}:/scan:ro" ghcr.io/yannh/kubeconform:latest `
      -summary -output json -strict -ignore-missing-schemas -verbose /scan `
      | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[kubeconform] -> $Out"
  } catch { _WrapPlaceholder $Out "kubeconform" $_.Exception.Message }
}

function Det-KubeLinter {
  param([string]$Path=".",[string]$Out="$OutDir\kubelinter_raw.json")
  try {
    $abs = Resolve-ScanPath -Path $Path
    docker run --rm -v "${abs}:/scan:ro" stackrox/kube-linter:latest `
      lint /scan --format json | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[kube-linter] -> $Out"
  } catch { _WrapPlaceholder $Out "kubelinter" $_.Exception.Message }
}

function Det-Polaris {
  param([string]$Path=".",[string]$Out="$OutDir\polaris_raw.json")
  try {
    $abs = Resolve-ScanPath -Path $Path
    docker run --rm -v "${abs}:/scan:ro" quay.io/fairwinds/polaris:latest `
      polaris audit --audit-path /scan --format json `
      | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[polaris] -> $Out"
  } catch { _WrapPlaceholder $Out "polaris" $_.Exception.Message }
}

# --- NEW: Checkov (Kubernetes framework only) ---------------------------------
function Det-Checkov {
  param([string]$Path=".",[string]$Out="$OutDir\checkov_raw.json")
  try {
    $abs = Resolve-ScanPath -Path $Path
    $checks = Join-Path $RepoRoot "policies\checkov"   # <- custom checks

    $local = $null
    try { $local = (Get-Command checkov -ErrorAction Stop).Source } catch { }

    if ($local) {
      $prevEA = $ErrorActionPreference; $ErrorActionPreference = "Continue"
      & checkov -d $abs --framework kubernetes --external-checks-dir $checks -o json 2>$null |
        Set-Content -Encoding UTF8 -Path $Out
      $ErrorActionPreference = $prevEA
    } else {
      docker run --rm -v "${abs}:/scan:ro" -v "${checks}:/ext:ro" bridgecrew/checkov:latest `
        -d /scan --framework kubernetes --external-checks-dir /ext -o json |
        Set-Content -Encoding UTF8 -Path $Out
    }
    Write-NonEmpty $Out; Write-Host "[checkov] -> $Out"
  } catch {
    _WrapPlaceholder $Out "checkov" $_.Exception.Message
  }
}


function Det-TrivyConfig {
  param([string]$Path=".",[string]$Out="$OutDir\trivy_config_raw.json")
  try {
    $abs = Resolve-ScanPath -Path $Path
    docker run --rm -v "${abs}:/scan:ro" aquasec/trivy:latest `
      config --quiet --format json /scan | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[trivy config] -> $Out"
  } catch { _WrapPlaceholder $Out "trivy-config" $_.Exception.Message }
}

function Det-Kubescape {
  param(
    [string]$Path=".",
    [string]$Out="$OutDir\kubescape_raw.json"
  )
  $abs = Resolve-ScanPath -Path $Path
  $ks = $null; try { $ks = (Get-Command kubescape -ErrorAction Stop).Source } catch { }

  if ($ks) {
    try {
      $prevEA = $ErrorActionPreference
      $ErrorActionPreference = "Continue"
      $output = & kubescape scan $abs --format json --format-version v2 --output $Out 2>&1
      $ErrorActionPreference = $prevEA
      $output | Out-Host
      Start-Sleep -Milliseconds 500
      if ((Test-Path $Out) -and ((Get-Item $Out).Length -gt 100)) {
        Write-Host "[kubescape] -> $Out"
      } else {
        '[{"tool":"kubescape","note":"failed: output file not created or too small"}]' |
          Set-Content -Encoding UTF8 -Path $Out
        Write-Host "[kubescape] -> $Out (placeholder)"
      }
    } catch {
      '[{"tool":"kubescape","note":"failed: ' + ($_.Exception.Message -replace '"','''') + '"}]' |
        Set-Content -Encoding UTF8 -Path $Out
      Write-Host "[kubescape] -> $Out (placeholder)"
    }
  } else {
    try {
      $prevEA = $ErrorActionPreference
      $ErrorActionPreference = "Continue"
      docker run --rm -v "${abs}:/scan:ro" quay.io/kubescape/kubescape:latest `
        scan /scan --format json --format-version v2 --output /scan/kubescape_raw.json
      $ErrorActionPreference = $prevEA
      $tempOut = Join-Path $abs "kubescape_raw.json"
      if ((Test-Path $tempOut) -and ($tempOut -ne $Out)) { Move-Item -Force $tempOut $Out }
      Write-Host "[kubescape] -> $Out"
    } catch {
      '[{"tool":"kubescape","note":"failed: ' + ($_.Exception.Message -replace '"','''') + '"}]' |
        Set-Content -Encoding UTF8 -Path $Out
      Write-Host "[kubescape] -> $Out (placeholder)"
    }
  }
}

function Det-KubeScore {
  param([string]$Path=".",[string]$Out="$OutDir\kubescore_raw.json")
  try {
    $abs = Resolve-ScanPath -Path $Path
    $files = Get-ChildItem -Path $abs -Recurse -File -Include *.yaml,*.yml |
      ForEach-Object { "/scan/" + $_.Name }
    if ($files.Count -eq 0) { '[]' | Set-Content -Encoding UTF8 -Path $Out; Write-Host "[kube-score] -> $Out (no YAML)"; return }
    $cmd=@("run","--rm","-v","${abs}:/scan:ro","zegl/kube-score:latest","score","--output-format","json") + $files
    docker @cmd | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[kube-score] -> $Out"
  } catch { _WrapPlaceholder $Out "kube-score" $_.Exception.Message }
}

function Det-Yamllint {
  param([string]$Path=".",[string]$Out="$OutDir\yamllint_raw.txt")
  try {
    $abs = Resolve-ScanPath -Path $Path
    docker run --rm -v "${abs}:/scan:ro" cytopia/yamllint:latest `
      -f parsable -s /scan | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[yamllint] -> $Out"
  } catch { _WrapPlaceholder $Out "yamllint" $_.Exception.Message }
}

function Det-KubeAudit {
  param([string]$Path=".", [string]$Out="$OutDir\kubeaudit_raw.json")

  $abs   = Resolve-ScanPath -Path $Path
  $files = Get-ChildItem -Path $abs -Recurse -File -Include *.yaml,*.yml
  $accum = @()

  if ($files.Count -eq 0) {
    '[]' | Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[kubeaudit] -> $Out (no YAML)"
    return
  }

  $local = $null
  try {
    $local = (Get-Command kubeaudit -ErrorAction Stop).Source
    Write-Host "[kubeaudit] Using local kubeaudit: $local" -ForegroundColor Gray
  } catch {
    Write-Host "[kubeaudit] Local kubeaudit not found, will use Docker" -ForegroundColor Gray
  }

  $prevEA = $ErrorActionPreference
  $ErrorActionPreference = "Continue"

  Write-Host "[kubeaudit] Scanning $($files.Count) files..." -ForegroundColor Cyan

  foreach ($f in $files) {
    Write-Host "  Processing: $($f.Name)" -ForegroundColor Gray
    try {
      $raw = $null
      if ($local) {
        $raw = & kubeaudit all -f "$($f.FullName)" -p json 2>$null
      } else {
        $dir = $f.Directory.FullName
        $raw = docker run --rm -v "${dir}:/scan:ro" ghcr.io/shopify/kubeaudit:latest `
                 all -f "/scan/$($f.Name)" -p json 2>$null
      }

      if ($raw) {
        $jsonLines = $raw | Where-Object { $_ -match '^\s*\{' -and $_ -notmatch 'Deprecation' -and $_ -notmatch 'WARNING' }
        if ($jsonLines) {
          foreach ($jsonLine in $jsonLines) {
            try {
              $obj = $jsonLine | ConvertFrom-Json
              $obj | Add-Member -NotePropertyName "file" -NotePropertyValue $f.FullName -Force
              $accum += $obj
            } catch { continue }
          }
          Write-Host "    Found $($jsonLines.Count) findings" -ForegroundColor Green
        } else {
          Write-Host "    No findings" -ForegroundColor Gray
        }
      } else {
        Write-Host "    No output from kubeaudit" -ForegroundColor Gray
      }
    } catch {
      Write-Host "    Error processing file: $($_.Exception.Message)" -ForegroundColor Red
    }
  }

  $ErrorActionPreference = $prevEA

  if ($accum.Count -eq 0) {
    '[]' | Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[kubeaudit] -> $Out (no findings)"
  } else {
    $accum | ConvertTo-Json -Depth 64 | Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[kubeaudit] -> $Out ($($accum.Count) findings)"
  }
}

# --- extended detectors (CIS, RBAC, API deprecation) -------------------------
function Det-KubeBench {
  param([string]$Path=".",[string]$Out="$OutDir\kube-bench_raw.json")
  Write-Host "[kube-bench] Note: kube-bench requires running cluster node access" -ForegroundColor Yellow
  Write-Host "[kube-bench] This tool checks CIS benchmarks on actual cluster nodes, not YAML files" -ForegroundColor Yellow
  $local = $null
  try { $local = (Get-Command kube-bench -ErrorAction Stop).Source } catch { }
  $prevEA = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    if ($local) {
      Write-Host "[kube-bench] Running local kube-bench..." -ForegroundColor Cyan
      $output = & kube-bench run --json 2>&1
      $jsonOutput = $output | Where-Object { $_ -match '^\s*[\{\[]' }
      if ($jsonOutput) {
        $jsonOutput | Out-String | Set-Content -Encoding UTF8 -Path $Out
        Write-Host "[kube-bench] -> $Out"
      } else {
        '[{"tool":"kube-bench","note":"kube-bench requires access to a running Kubernetes cluster node. Cannot analyze YAML manifests.","context":"CIS Kubernetes Benchmark checks require runtime node inspection"}]' |
          Set-Content -Encoding UTF8 -Path $Out
        Write-Host "[kube-bench] -> $Out (placeholder)"
      }
    } else {
      '[{"tool":"kube-bench","note":"kube-bench not installed and requires cluster node access. This tool checks CIS Kubernetes Benchmark compliance on running nodes, not YAML files.","install":"https://github.com/aquasecurity/kube-bench/releases"}]' |
        Set-Content -Encoding UTF8 -Path $Out
      Write-Host "[kube-bench] -> $Out (placeholder)"
    }
  } catch {
    Write-Host "[kube-bench] Error: $($_.Exception.Message)" -ForegroundColor Red
    '[{"tool":"kube-bench","note":"' + ($_.Exception.Message -replace '"','\"') + '"}]' | Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[kube-bench] -> $Out (placeholder - error)"
  } finally { $ErrorActionPreference = $prevEA }
}

function Det-RBACPolice {
  param([string]$Path=".",[string]$Out="$OutDir\rbacpolice_raw.json")
  $abs = Resolve-ScanPath -Path $Path
  $rbacFiles = Get-ChildItem -Path $abs -Recurse -File -Include *.yaml,*.yml |
    Where-Object {
      $content = Get-Content $_.FullName -Raw
      $content -match 'kind:\s*(Role|RoleBinding|ClusterRole|ClusterRoleBinding|ServiceAccount)'
    }
  if ($rbacFiles.Count -eq 0) {
    '[{"tool":"rbac-police","note":"No RBAC manifests (Role, RoleBinding, ClusterRole, ClusterRoleBinding, ServiceAccount) found in scan directory"}]' |
      Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[rbac-police] -> $Out (placeholder - no RBAC files)"
    return
  }
  # (rest of RBACPolice function unchanged from your version)
  # ...
  # For brevity, keep your existing RBACPolice body here
}

function Det-Pluto {
  param([string]$Path=".",[string]$Out="$OutDir\pluto_raw.json")
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
          Write-Host "[pluto] -> $Out ($($parsed.items.Count) deprecated APIs found)"
        } catch {
          $jsonContent | Set-Content -Encoding UTF8 -Path $Out
          Write-Host "[pluto] -> $Out"
        }
      } else {
        '{"items":[],"target-versions":{}}' | Set-Content -Encoding UTF8 -Path $Out
        Write-Host "[pluto] -> $Out (no deprecated APIs found)"
      }
    } else {
      '{"items":[],"target-versions":{},"note":"Pluto CLI not installed. Please install pluto locally for API deprecation scanning."}' |
        Set-Content -Encoding UTF8 -Path $Out
      Write-Host "[pluto] -> $Out (placeholder - tool not installed)"
    }
  } catch {
    Write-Host "[pluto] Error: $($_.Exception.Message)" -ForegroundColor Red
    '{"items":[],"target-versions":{},"note":"' + ($_.Exception.Message -replace '"','\"') + '"}' | Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[pluto] -> $Out (placeholder - error)"
  } finally { $ErrorActionPreference = $prevEA }
}

# --- gitleaks (secret scanning) -----------------------------------------------
function Det-Gitleaks {
  param([string]$Path=".")
  $Out = Join-Path $OutDir "gitleaks_raw.json"
  $prevEA = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    Write-Host "[gitleaks] Scanning for secrets..." -ForegroundColor Cyan
    $gitleaksCmd = Get-Command gitleaks -ErrorAction SilentlyContinue
    if ($gitleaksCmd) {
      $abs = Resolve-ScanPath -Path $Path
      Write-Host "[gitleaks] Running: gitleaks detect --source `"$abs`" --no-git --report-path `"$Out`""
      $exitCode = 0
      try {
        & gitleaks detect --source $abs --no-git --report-path $Out --report-format json 2>$null
        $exitCode = $LASTEXITCODE
      } catch { $exitCode = 0 }
      if (Test-Path $Out) {
        $content = Get-Content -Path $Out -Raw -Encoding UTF8
        if ($content -and $content.Trim().Length -gt 2) {
          $findingsCount = (ConvertFrom-Json $content).Count
          if ($findingsCount -gt 0) { Write-Host "[gitleaks] -> $Out ($findingsCount secrets detected!)" -ForegroundColor Yellow }
          else { Write-Host "[gitleaks] -> $Out (no secrets found)" }
        } else {
          '[]' | Set-Content -Encoding UTF8 -Path $Out
          Write-Host "[gitleaks] -> $Out (no secrets found)"
        }
      } else {
        '[]' | Set-Content -Encoding UTF8 -Path $Out
        Write-Host "[gitleaks] -> $Out (no secrets found)"
      }
    } else {
      '[{"note":"Gitleaks not installed. Install locally for secret scanning."}]' | Set-Content -Encoding UTF8 -Path $Out
      Write-Host "[gitleaks] -> $Out (placeholder - tool not installed)"
    }
  } catch {
    Write-Host "[gitleaks] Error: $($_.Exception.Message)" -ForegroundColor Red
    '[{"note":"' + ($_.Exception.Message -replace '"','\"') + '"}]' | Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[gitleaks] -> $Out (placeholder - error)"
  } finally { $ErrorActionPreference = $prevEA }
}

# --- orchestration ------------------------------------------------------------
function Det-RunLean {
  param([string]$Path=".")
  Ensure-DetectorImages
  $abs = Resolve-ScanPath -Path $Path
  Write-Host "Scanning: $abs" -ForegroundColor Cyan

 $steps=@(
  "KubeConform","KubeLinter","Polaris",
  "Checkov","TrivyConfig","Kubescape","KubeScore",
  "Yamllint","KubeAudit",
  "Conftest"     # <-- add this
)

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
      }
    }
  }

  Write-Host "`n────────── Runtime summary ──────────"
  $global:ToolTimings | Sort-Object Seconds -Descending |
    Format-Table Tool,Seconds,Status -Auto
}

# --- extended orchestration (11 tools + Checkov = 12) -------------------------
function Det-RunExtended {
  param([string]$Path=".")
  Ensure-ExtendedDetectorImages
  $abs = Resolve-ScanPath -Path $Path
  Write-Host "Scanning: $abs (EXTENDED MODE - 12 tools)" -ForegroundColor Cyan

 $steps=@(
  "KubeConform","KubeLinter","Polaris",
  "Checkov","TrivyConfig","Kubescape","KubeScore",
  "Yamllint","KubeAudit","RBACPolice","Pluto","Gitleaks",
  "Conftest"     # <-- add this
)
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
      }
    }
  }

  Write-Host "`n────────── Runtime summary (EXTENDED) ──────────"
  $global:ToolTimings | Sort-Object Seconds -Descending |
    Format-Table Tool,Seconds,Status -Auto

  Write-Host "`nNote: Extended tools (rbac-police, pluto, gitleaks) may require" -ForegroundColor Yellow
  Write-Host "      specific manifests (RBAC, deprecated APIs, secrets) to produce results." -ForegroundColor Yellow
}
