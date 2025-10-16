# scripts/detectors.ps1
# SafeFix-K8s detectors runner
# - Caches all Docker images in <repo>/images/*.tar so runs can be offline
# - Shows a progress bar and per-tool timings + total runtime summary
# - Logs all operations to output/logs/detectors_YYYYMMDD_HHMMSS.log

$ErrorActionPreference = "Stop"

# --- paths --------------------------------------------------------------------
$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutDir   = Join-Path $RepoRoot "output\raw"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$LogsDir = Join-Path $RepoRoot "output\logs"
New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null

# Create timestamped log file for this run
$global:DetectorLogFile = Join-Path $LogsDir ("detectors_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")

# --- logging ------------------------------------------------------------------
function Write-Log {
  param(
    [Parameter(Mandatory)][string]$Message,
    [string]$Level = "INFO"
  )
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $logMsg = "[$timestamp] [$Level] $Message"
  
  # Console output with colors
  switch ($Level) {
    "ERROR" { Write-Host $logMsg -ForegroundColor Red }
    "WARN"  { Write-Host $logMsg -ForegroundColor Yellow }
    "INFO"  { Write-Host $logMsg -ForegroundColor Cyan }
    default { Write-Host $logMsg }
  }
  
  # File output
  Add-Content -Path $global:DetectorLogFile -Value $logMsg -Encoding UTF8
}

# --- helpers ------------------------------------------------------------------
function Write-NonEmpty($Path) {
  if (!(Test-Path $Path) -or ((Get-Item $Path).Length -lt 3)) {
    throw "Output file '$Path' is missing or empty."
  }
}

$ToolsDir    = Join-Path $RepoRoot "tools"
$KsDir       = Join-Path $ToolsDir "kubescape"
$KsLocalExe  = Join-Path $KsDir "kubescape.exe"
$KsArtifacts = Join-Path $KsDir "artifacts"   # local policy bundle cache

function Get-KubescapeExe {
  try {
    $cmd = Get-Command kubescape -ErrorAction Stop
    return $cmd.Source
  } catch {
    if (!(Test-Path $KsLocalExe)) {
      New-Item -ItemType Directory -Force -Path $KsDir | Out-Null
      Write-Host "Downloading Kubescape CLI -> $KsLocalExe"
      $url = "https://github.com/kubescape/kubescape/releases/latest/download/kubescape-windows-amd64.exe"
      Invoke-WebRequest -Uri $url -OutFile $KsLocalExe -UseBasicParsing
      Unblock-File -Path $KsLocalExe -ErrorAction SilentlyContinue
    }
    return $KsLocalExe
  }
}

function Ensure-KubescapeArtifacts {
  if (Test-Path $KsArtifacts -and (Get-ChildItem $KsArtifacts -Recurse -ErrorAction SilentlyContinue)) { return }
  New-Item -ItemType Directory -Force -Path $KsArtifacts | Out-Null
  $exe = Get-KubescapeExe
  Write-Host "Fetching Kubescape artifacts (one-time) -> $KsArtifacts"
  & $exe download artifacts --output $KsArtifacts 2>&1 `
    | Tee-Object -FilePath (Join-Path $LogsDir "kubescape_download.log") | Out-Null
}

function _WrapPlaceholder($Out, $tool, $msg) {
  Write-Log "Creating placeholder for $tool : $msg" "WARN"
  '[{"tool":"' + $tool + '","note":"' + ($msg -replace '"','''') + '"}]' |
    Set-Content -Encoding UTF8 -Path $Out
  Write-Host "[$tool] -> $Out (placeholder)"
}

# --- images cache inside repo -------------------------------------------------
$ImagesDir = Join-Path $RepoRoot "images"
New-Item -ItemType Directory -Force -Path $ImagesDir | Out-Null

function Get-DetectorImages {
  @(
    "stackrox/kube-linter:latest",
    "quay.io/fairwinds/polaris:latest",
    "aquasec/trivy:latest",
    "anchore/syft:latest",
    "anchore/grype:latest",
    "hadolint/hadolint:latest",
    "goodwithtech/dockle:latest",
    "zricethezav/gitleaks:latest",
    "trufflesecurity/trufflehog:latest",
    "bridgecrew/checkov:latest",
    "tenable/terrascan:latest",
    "zegl/kube-score:latest",
    "cytopia/yamllint:latest",
    "quay.io/kubescape/kubescape:latest",
    "kubesec/kubesec:latest",
    "ghcr.io/shopify/kubeaudit:latest",
    "ghcr.io/kyverno/kyverno-cli:latest"
  )
}

function Save-DetectorImages {
  $imgs = Get-DetectorImages
  foreach ($img in $imgs) {
    $safe = $img.Replace("/","_").Replace(":","_") + ".tar"
    $tar  = Join-Path $ImagesDir $safe
    if (Test-Path $tar) { continue }
    Write-Host "Saving $img -> $tar"
    docker pull $img | Out-Null
    docker save -o $tar $img
  }
  Write-Host "All images saved to: $ImagesDir"
}

function Load-DetectorImages {
  $loaded = @()
  Get-ChildItem -Path $ImagesDir -Filter *.tar | ForEach-Object {
    Write-Host "Loading image $($_.Name) ..."
    docker load -i $_.FullName | Out-Null
    $loaded += $_.Name
  }
  if ($loaded.Count -gt 0) { Write-Host ("Loaded {0} images from repo cache." -f $loaded.Count) }
}

function Ensure-DetectorImages {
  Load-DetectorImages
  $missing = @()
  foreach ($img in Get-DetectorImages) {
    $present = docker images --format "{{.Repository}}:{{.Tag}}" | Where-Object { $_ -eq $img }
    if (-not $present) { $missing += $img }
  }
  if ($missing.Count -gt 0) {
    Write-Host "Missing images: $($missing -join ', ')"
    foreach ($m in $missing) { docker pull $m | Out-Null }
    Save-DetectorImages
  }
}

# Backwards-compatible alias
function Pull-Detectors { Ensure-DetectorImages }

# --- timing / progress --------------------------------------------------------
$global:ToolTimings = New-Object System.Collections.ArrayList
$script:StepIndex = 0
$script:TotalSteps = 0

function Start-ProgressSession([int]$count) {
  $script:StepIndex = 0
  $script:TotalSteps = [Math]::Max($count,1)
  Write-Progress -Activity "SafeFix-K8s detectors" -Status "Starting..." -PercentComplete 0
}

function Step-Progress([string]$name, [int]$inc = 1) {
  $script:StepIndex += $inc
  $pct = [int](100 * $script:StepIndex / $script:TotalSteps)
  Write-Progress -Activity "SafeFix-K8s detectors" -Status "Running: $name" -PercentComplete $pct
}

function End-Progress() {
  Write-Progress -Activity "SafeFix-K8s detectors" -Completed
}

function Invoke-WithTiming {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][scriptblock]$Action
  )
  Write-Log "Starting $Name" "INFO"
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $status = "ok"
  $errorMsg = $null
  try {
    & $Action
  }
  catch {
    $status = "error"
    $errorMsg = $_.Exception.Message
    Write-Log "$Name failed: $errorMsg" "ERROR"
    throw
  }
  finally {
    $sw.Stop()
    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds,2)
    Write-Log "$Name completed in $elapsed seconds (status: $status)" "INFO"
    [void]$global:ToolTimings.Add([pscustomobject]@{
      Tool   = $Name
      Seconds= $elapsed
      Status = $status
    })
  }
}

# --- manifest linters ---------------------------------------------------------
function Det-KubeLinter {
  param([string]$Path=".",[string]$Out="$OutDir\kubelinter_raw.json")
  try {
    docker run --rm -v "${PWD}:/work:ro" stackrox/kube-linter:latest `
      lint "/work/$Path" --format json | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[kube-linter] -> $Out"
  } catch { _WrapPlaceholder $Out "kubelinter" $_.Exception.Message }
}

function Det-Polaris {
  param([string]$Path=".",[string]$Out="$OutDir\polaris_raw.json")
  try {
    docker run --rm -v "${PWD}:/work:ro" quay.io/fairwinds/polaris:latest `
      polaris audit --audit-path "/work/$Path" --format json `
      | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[polaris] -> $Out"
  } catch { _WrapPlaceholder $Out "polaris" $_.Exception.Message }
}

function Det-KubeScore {
  param([string]$Path=".",[string]$Out="$OutDir\kubescore_raw.json")
  try {
    $root  = (Resolve-Path $Path).Path
    $files = Get-ChildItem -Path $root -Recurse -File -Include *.yaml,*.yml |
      ForEach-Object { "/work/" + ($_.FullName.Substring($PWD.Path.Length).TrimStart('\','/').Replace('\','/')) }
    if ($files.Count -eq 0) { throw "kube-score: no YAML in '$Path'." }
    $cmd = @("run","--rm","-v","${PWD}:/work:ro","zegl/kube-score:latest","score","--output-format","json") + $files
    docker @cmd | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[kube-score] -> $Out"
  } catch { _WrapPlaceholder $Out "kube-score" $_.Exception.Message }
}

# --- replacements / additions -------------------------------------------------
# KUBESCAPE (local CLI; JSON to file; cached artifacts)
function Det-Kubescape {
  param(
    [string]$Path = ".",
    [string]$Out  = "$OutDir\kubescape_raw.json"
  )
  try {
    # 1) Ensure CLI exists
    $ks = $null
    try { $ks = (Get-Command kubescape -ErrorAction Stop).Source }
    catch { throw "kubescape CLI not found in PATH. Install it or put kubescape.exe under tools\kubescape." }

    # 2) Find YAMLs (so we can fail gracefully if none)
    $root = (Resolve-Path -LiteralPath $Path).Path
    $ymls = Get-ChildItem -Path $root -Recurse -File -Include *.yaml,*.yml -ErrorAction SilentlyContinue
    if (-not $ymls -or $ymls.Count -eq 0) {
      '[]' | Set-Content -Encoding UTF8 -Path $Out
      Write-Host "[kubescape] -> $Out (no YAML files)"
      return
    }

    # 3) Run exactly like your screenshot, but emit JSON to $Out
    # Kubescape supports: --format json --output <file>
    & $ks scan $root --format json --output $Out | Out-Null

    # Some versions write to '<file>.json'; normalize if needed
    if (!(Test-Path $Out)) {
      if (Test-Path "${Out}.json") { Move-Item -Force "${Out}.json" $Out }
    }

    Write-NonEmpty $Out
    Write-Host "[kubescape] -> $Out"
  }
  catch {
    '[]' | Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[kubescape] -> $Out (error: $($_.Exception.Message))"
  }
}

# KUBESEC (Docker; scan each file, merge JSON)
function Det-Kubesec {
  param(
    [string]$Path = ".",
    [string]$Out  = "$OutDir\kubesec_raw.json"
  )
  try {
    $root = (Resolve-Path -LiteralPath $Path).Path
    $cand = Get-ChildItem -Path $root -Recurse -File -Include *.yml,*.yaml -ErrorAction SilentlyContinue
    if (-not $cand -or $cand.Count -eq 0) {
      '[]' | Set-Content -Encoding UTF8 -Path $Out
      Write-Host "[kubesec] -> $Out (no YAML files)"
      return
    }

    $manifests = foreach ($f in $cand) {
      $head = Get-Content -Path $f.FullName -TotalCount 200 -ErrorAction SilentlyContinue | Out-String
      if ($head -match '(?m)^\s*apiVersion\s*:' -and $head -match '(?m)^\s*kind\s*:') { $f }
    }
    if (-not $manifests -or $manifests.Count -eq 0) {
      '[]' | Set-Content -Encoding UTF8 -Path $Out
      Write-Host "[kubesec] -> $Out (no K8s manifests)"
      return
    }

    $stderrLog = Join-Path $LogsDir "kubesec_stderr.txt"
    '' | Set-Content -Encoding UTF8 -Path $stderrLog
    $all = New-Object System.Collections.ArrayList

    foreach ($f in $manifests) {
      $rel = $f.FullName.Substring($PWD.Path.Length).TrimStart('\','/')
      $workPath = "/work/$($rel -replace '\\','/')"

      $raw = docker run --rm -v "${PWD}:/work:ro" kubesec/kubesec:latest `
              scan --format=json $workPath 2>&1

      ($raw -split "`r?`n" | % { $_.Trim() } |
        ? { $_ -and -not ($_.StartsWith('[') -or $_.StartsWith('{')) }) |
        Add-Content -Path $stderrLog

      $parsed = $null
      try { $parsed = ($raw | ConvertFrom-Json) } catch {
        $m = [regex]::Match($raw, '(?s)(\[[\s\S]*\]|\{[\s\S]*\})')
        if ($m.Success) { try { $parsed = ($m.Value | ConvertFrom-Json) } catch { } }
      }

      if ($parsed -ne $null) {
        if ($parsed -is [System.Collections.IEnumerable] -and -not ($parsed -is [string])) {
          foreach ($item in $parsed) { [void]$all.Add($item) }
        } else {
          [void]$all.Add($parsed)
        }
      }
    }

    if ($all.Count -eq 0) { '[]' | Set-Content -Encoding UTF8 -Path $Out }
    else { ($all | ConvertTo-Json -Depth 64) | Set-Content -Encoding UTF8 -Path $Out }

    try { $null = (Get-Content -Raw -Encoding UTF8 $Out) | ConvertFrom-Json } catch { '[]' | Set-Content -Encoding UTF8 -Path $Out }
    Write-Host "[kubesec] -> $Out"
  }
  catch {
    '[]' | Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[kubesec] -> $Out (error: $($_.Exception.Message))"
  }
}

# KUBEAUDIT (Docker)
function Det-KubeAudit {
  param([string]$Path=".", [string]$Out="$OutDir\kubeaudit_raw.json")
  try {
    $cmd = @(
      "run","--rm","-v","${PWD}:/work:ro",
      "shopify/kubeaudit:latest",             # docker hub image (works out-of-box)
      "all","-f","/work/$Path","-o","json"
    )
    $raw = docker @cmd 2>&1
    if (-not $raw) { $raw = "[]" }
    $raw | Set-Content -Encoding UTF8 -Path $Out
    if ((Get-Item $Out).Length -lt 3) { '[]' | Set-Content -Encoding UTF8 -Path $Out }
    Write-Host "[kubeaudit] -> $Out"
  } catch {
    # fallback: try GHCR and invoke binary path
    try {
      $raw = docker run --rm -v "${PWD}:/work:ro" `
        ghcr.io/shopify/kubeaudit:latest /usr/local/bin/kubeaudit all -f "/work/$Path" -o json 2>&1
      if (-not $raw) { $raw = "[]" }
      $raw | Set-Content -Encoding UTF8 -Path $Out
      if ((Get-Item $Out).Length -lt 3) { '[]' | Set-Content -Encoding UTF8 -Path $Out }
      Write-Host "[kubeaudit] -> $Out"
    } catch {
      '[]' | Set-Content -Encoding UTF8 -Path $Out
      Write-Host "[kubeaudit] -> $Out (fallback failed: $($_.Exception.Message))"
    }
  }
}


# KYVERNO-CLI (Docker) — optional, if you have policies/
function Det-Kyverno {
  param(
    [string]$Path=".",
    [string]$Policies="policies",
    [string]$Out="$OutDir\kyverno_raw.json"
  )
  try {
    $raw = docker run --rm -v "${PWD}:/work:ro" ghcr.io/kyverno/kyverno-cli:latest `
      apply "/work/$Policies/*.yaml" --resource "/work/$Path" --policy-report -o json 2>&1
    if (-not $raw) { $raw = "[]" }
    $raw | Set-Content -Encoding UTF8 -Path $Out
    if ((Get-Item $Out).Length -lt 3) { '[]' | Set-Content -Encoding UTF8 -Path $Out }
    Write-Host "[kyverno] -> $Out"
  } catch {
    '[]' | Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[kyverno] -> $Out (error: $($_.Exception.Message))"
  }
}


# --- config scanners / IaC ----------------------------------------------------
function Det-TrivyConfig {
  param([string]$Path=".",[string]$Out="$OutDir\trivy_config_raw.json")
  try {
    docker run --rm -v "${PWD}:/work:ro" aquasec/trivy:latest `
      config --quiet --format json "/work/$Path" | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[trivy config] -> $Out"
  } catch { _WrapPlaceholder $Out "trivy-config" $_.Exception.Message }
}

function Det-Checkov {
  param([string]$Path=".",[string]$Out="$OutDir\checkov_raw.json")
  try {
    docker run --rm -v "${PWD}:/work:ro" bridgecrew/checkov:latest `
      -d "/work/$Path" -o json | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[checkov] -> $Out"
  } catch { _WrapPlaceholder $Out "checkov" $_.Exception.Message }
}

function Det-Terrascan {
  param([string]$Path=".",[string]$Out="$OutDir\terrascan_raw.json")
  try {
    docker run --rm -v "${PWD}:/work:ro" tenable/terrascan:latest `
      scan -d "/work/$Path" -o json | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[terrascan] -> $Out"
  } catch { _WrapPlaceholder $Out "terrascan" $_.Exception.Message }
}

function Det-Yamllint {
  param([string]$Path=".",[string]$Out="$OutDir\yamllint_raw.txt")
  try {
    docker run --rm -v "${PWD}:/work:ro" cytopia/yamllint:latest `
      -f parsable -s "/work/$Path" | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[yamllint] -> $Out"
  } catch { _WrapPlaceholder $Out "yamllint" $_.Exception.Message }
}

# --- image scanners -----------------------------------------------------------
function Det-Syft {
  param([string]$Image,[string]$Out="$OutDir\syft_raw.json")
  if (-not $Image) { throw "Det-Syft needs -Image (e.g., nginx:alpine)" }
  try {
    docker run --rm anchore/syft:latest "$Image" -o json | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[syft $Image] -> $Out"
  } catch { _WrapPlaceholder $Out "syft" $_.Exception.Message }
}

function Det-Grype {
  param([string]$Image,[string]$Out="$OutDir\grype_raw.json")
  if (-not $Image) { throw "Det-Grype needs -Image (e.g., nginx:alpine)" }
  try {
    docker run --rm anchore/grype:latest "$Image" -o json | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[grype $Image] -> $Out"
  } catch { _WrapPlaceholder $Out "grype" $_.Exception.Message }
}

function Det-Hadolint {
  param([string]$Dockerfile="Dockerfile",[string]$Out="$OutDir\hadolint_raw.json")
  try {
    if (-not (Test-Path $Dockerfile)) { throw "Dockerfile not found: $Dockerfile" }
    docker run --rm -v "${PWD}:/work:ro" hadolint/hadolint:latest `
      hadolint -f json "/work/$Dockerfile" | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[hadolint] -> $Out"
  } catch { _WrapPlaceholder $Out "hadolint" $_.Exception.Message }
}

function Det-Dockle {
  param([string]$Image,[string]$Out="$OutDir\dockle_raw.json")
  if (-not $Image) { throw "Det-Dockle needs -Image (built or pulled)" }
  try {
    docker run --rm goodwithtech/dockle:latest -f json "$Image" | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[dockle $Image] -> $Out"
  } catch { _WrapPlaceholder $Out "dockle" $_.Exception.Message }
}

# --- secrets scanners ---------------------------------------------------------
function Det-Gitleaks {
  param([string]$Path=".",[string]$Out="$OutDir\gitleaks_raw.json")
  try {
    docker run --rm -v "${PWD}:/work" zricethezav/gitleaks:latest `
      detect -s "/work/$Path" --no-git -f json -r - `
      | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[gitleaks] -> $Out"
  } catch { _WrapPlaceholder $Out "gitleaks" $_.Exception.Message }
}

function Det-TruffleHog {
  param([string]$Path=".",[string]$Out="$OutDir\trufflehog_raw.json")
  try {
    $exFile = Join-Path $env:TEMP "trufflehog_exclude.txt"
@(
  "^/work/\.venv($|/)",
  "^/\.venv($|/)",
  "^/work/output($|/)",
  "^/output($|/)",
  "^/work/images($|/)",
  "^/images($|/)",
  "^/work/\.git($|/)",
  "^/\.git($|/)"
) | Set-Content -Encoding UTF8 -Path $exFile

    $args = @(
      "run","--rm",
      "-v","${PWD}:/work",
      "-v","${exFile}:/exclude.txt:ro",
      "trufflesecurity/trufflehog:latest",
      "filesystem","/work/$Path",
      "--json",
      "--exclude-paths","/exclude.txt",
      "--only-verified"
    )
        $outText = docker @args 2>&1
    if (-not $outText) { $outText = "[]" }
    $outText | Set-Content -Encoding UTF8 -Path $Out
    # don't fail just because it's empty
    if ((Get-Item $Out).Length -lt 3) { '[]' | Set-Content -Encoding UTF8 -Path $Out }
    Write-Host "[trufflehog] -> $Out"

  } catch { _WrapPlaceholder $Out "trufflehog" $_.Exception.Message }
}

# --- convenience: run everything ---------------------------------------------
function Det-RunAll {
  param(
    [string]$Path=".",
    [string]$Image=""
  )

  Write-Log "============================================================" "INFO"
  Write-Log "SafeFixK8s Detectors Starting" "INFO"
  Write-Log "Log file: $global:DetectorLogFile" "INFO"
  Write-Log "Target path: $Path" "INFO"
  if ($Image) { Write-Log "Image scan: $Image" "INFO" }
  Write-Log "============================================================" "INFO"

  Ensure-DetectorImages

  $steps = @(
    "KubeLinter","Polaris","TrivyConfig","KubeScore",
    "Yamllint","Checkov","Terrascan",
    "Kubescape","Kubesec","KubeAudit","Kyverno",
    "Gitleaks","TruffleHog"
  )
  if ($Image) { $steps += @("Syft","Grype","Hadolint","Dockle") }

  Write-Log "Running $($steps.Count) detector tools" "INFO"

  Start-ProgressSession -count $steps.Count
  $totalSw = [System.Diagnostics.Stopwatch]::StartNew()

  foreach ($s in $steps) {
    Step-Progress $s
    switch ($s) {
      "KubeLinter"   { Invoke-WithTiming -Name $s { Det-KubeLinter -Path $Path } }
      "Polaris"      { Invoke-WithTiming -Name $s { Det-Polaris -Path $Path } }
      "TrivyConfig"  { Invoke-WithTiming -Name $s { Det-TrivyConfig -Path $Path } }
      "KubeScore"    { Invoke-WithTiming -Name $s { Det-KubeScore -Path $Path } }
      "Yamllint"     { Invoke-WithTiming -Name $s { Det-Yamllint -Path $Path } }
      "Checkov"      { Invoke-WithTiming -Name $s { Det-Checkov -Path $Path } }
      "Terrascan"    { Invoke-WithTiming -Name $s { Det-Terrascan -Path $Path } }

      "Kubescape"    { Invoke-WithTiming -Name $s { Det-Kubescape -Path $Path } }
      "Kubesec"      { Invoke-WithTiming -Name $s { Det-Kubesec   -Path $Path } }
      "KubeAudit"    { Invoke-WithTiming -Name $s { Det-KubeAudit -Path $Path } }
      "Kyverno"      { Invoke-WithTiming -Name $s { Det-Kyverno   -Path $Path } }

      "Gitleaks"     { Invoke-WithTiming -Name $s { Det-Gitleaks -Path . } }
      "TruffleHog"   { Invoke-WithTiming -Name $s { Det-TruffleHog -Path . } }

      "Syft"         { Invoke-WithTiming -Name $s { if ($Image) { Det-Syft -Image $Image } } }
      "Grype"        { Invoke-WithTiming -Name $s { if ($Image) { Det-Grype -Image $Image } } }
      "Hadolint"     { Invoke-WithTiming -Name $s { if ($Image) { Det-Hadolint -Dockerfile (Join-Path $PWD "Dockerfile") } } }
      "Dockle"       { Invoke-WithTiming -Name $s { if ($Image) { Det-Dockle -Image $Image } } }
    }
  }

  $totalSw.Stop()
  End-Progress

  Write-Log "" "INFO"
  Write-Log "============================================================" "INFO"
  Write-Log "Detectors Runtime Summary" "INFO"
  Write-Log "============================================================" "INFO"
  
  $global:ToolTimings | Sort-Object Seconds -Descending |
    Format-Table @{Label="Tool";Expression={$_.Tool}}, @{Label="Sec";Expression={$_.Seconds}}, Status -Auto
  
  $totalTime = [math]::Round($totalSw.Elapsed.TotalSeconds, 2)
  Write-Log "Total time: $totalTime sec" "INFO"
  Write-Log "All detectors finished." "INFO"
  Write-Log "Log saved to: $global:DetectorLogFile" "INFO"
  Write-Log "============================================================" "INFO"
}
