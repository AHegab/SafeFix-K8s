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
    "aquasec/trivy:latest",
    "quay.io/kubescape/kubescape:latest",
    "zegl/kube-score:latest",
    "cytopia/yamllint:latest",
    "ghcr.io/shopify/kubeaudit:latest",
    "ghcr.io/yannh/kubeconform:latest"
  )
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
    # v3 CLI: directory scan with format json and format-version v2
    # Completely isolate from global error handling
    try {
      $prevEA = $ErrorActionPreference
      $ErrorActionPreference = "Continue"
      
      # Execute kubescape directly - let it display all output
      $output = & kubescape scan $abs --format json --format-version v2 --output $Out 2>&1
      
      $ErrorActionPreference = $prevEA
      
      # Display the output
      $output | Out-Host
      
      # Wait a moment for file to be fully written
      Start-Sleep -Milliseconds 500
      
      # Check if output file exists and has content
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
      Write-Host "[kubescape] -> $Out (placeholder - error: $($_.Exception.Message))"
    }
  } else {
    # Docker fallback
    try {
      $prevEA = $ErrorActionPreference
      $ErrorActionPreference = "Continue"
      
      docker run --rm -v "${abs}:/scan:ro" quay.io/kubescape/kubescape:latest `
        scan /scan --format json --format-version v2 --output /scan/kubescape_raw.json
      
      $ErrorActionPreference = $prevEA
      
      # Move output from abs path to desired output location if needed
      $tempOut = Join-Path $abs "kubescape_raw.json"
      if ((Test-Path $tempOut) -and ($tempOut -ne $Out)) {
        Move-Item -Force $tempOut $Out
      }
      
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
        # Run kubeaudit with JSON output (-p json)
        # Redirect stderr to null to suppress warnings, keep stdout for JSON
        $raw = & kubeaudit all -f "$($f.FullName)" -p json 2>$null
      } else {
        $dir = $f.Directory.FullName
        $raw = docker run --rm -v "${dir}:/scan:ro" ghcr.io/shopify/kubeaudit:latest `
                 all -f "/scan/$($f.Name)" -p json 2>$null
      }

      # Try to parse JSON output
      if ($raw) {
        # Filter to only lines that look like JSON
        # Skip deprecation warnings, error messages, etc.
        $jsonLines = $raw | Where-Object { 
          $_ -match '^\s*\{' -and $_ -notmatch 'Deprecation' -and $_ -notmatch 'WARNING'
        }
        
        if ($jsonLines) {
          # Each line should be a complete JSON object from kubeaudit
          foreach ($jsonLine in $jsonLines) {
            try {
              $obj = $jsonLine | ConvertFrom-Json
              
              # Add file path to the finding
              $obj | Add-Member -NotePropertyName "file" -NotePropertyValue $f.FullName -Force
              $accum += $obj
            } catch {
              # Skip lines that aren't valid JSON
              continue
            }
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

  # Save results
  if ($accum.Count -eq 0) { 
    '[]' | Set-Content -Encoding UTF8 -Path $Out 
    Write-Host "[kubeaudit] -> $Out (no findings)"
  } else { 
    $accum | ConvertTo-Json -Depth 64 | Set-Content -Encoding UTF8 -Path $Out 
    Write-Host "[kubeaudit] -> $Out ($($accum.Count) findings)"
  }
}

# --- orchestration ------------------------------------------------------------
function Det-RunLean {
  param([string]$Path=".")
  Ensure-DetectorImages

  $abs = Resolve-ScanPath -Path $Path
  Write-Host "Scanning: $abs" -ForegroundColor Cyan

  $steps=@(
    "KubeConform","KubeLinter","Polaris",
    "TrivyConfig","Kubescape","KubeScore","Yamllint","KubeAudit"
  )

  foreach ($s in $steps) {
    Invoke-WithTiming -Name $s {
      switch ($s) {
        "KubeConform" { Det-KubeConform -Path $abs }
        "KubeLinter"  { Det-KubeLinter  -Path $abs }
        "Polaris"     { Det-Polaris     -Path $abs }
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
