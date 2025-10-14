# scripts/detectors.ps1
# SafeFix-K8s detectors runner
# - Caches all Docker images in <repo>/images/*.tar so runs can be offline
# - Shows a progress bar and per-tool timings + total runtime summary

$ErrorActionPreference = "Stop"

# --- paths --------------------------------------------------------------------
$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutDir   = Join-Path $RepoRoot "output\raw"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# --- helpers ------------------------------------------------------------------
function Write-NonEmpty($Path) {
  if (!(Test-Path $Path) -or ((Get-Item $Path).Length -lt 3)) {
    throw "Output file '$Path' is missing or empty."
  }
}

# paths
$ToolsDir    = Join-Path $RepoRoot "tools"
$KsDir       = Join-Path $ToolsDir "kubescape"
$KsLocalExe  = Join-Path $KsDir "kubescape.exe"
$KsArtifacts = Join-Path $KsDir "artifacts"   # local policy bundle cache
$LogsDir     = Join-Path $RepoRoot "output\logs"
New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null

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
  '[{"tool":"' + $tool + '","note":"' + ($msg -replace '"','''') + '"}]' |
    Set-Content -Encoding UTF8 -Path $Out
  Write-Host "[$tool] -> $Out (placeholder)"
}

# --- images cache inside repo -------------------------------------------------
$ImagesDir = Join-Path $RepoRoot "images"         # <repo>/images
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
    # keep these two only; no “kubescape-ci”
    "quay.io/kubescape/kubescape:latest",
    "kubesec/kubesec:latest"
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
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $status = "ok"
  try   { & $Action }
  catch { $status = "error"; throw }
  finally {
    $sw.Stop()
    [void]$global:ToolTimings.Add([pscustomobject]@{
      Tool   = $Name
      Seconds= [math]::Round($sw.Elapsed.TotalSeconds,2)
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
# --- KUBESCAPE (local CLI; JSON straight to file) -----------------------------
function Det-Kubescape {
  param([string]$Path=".", [string]$Out="$OutDir\kubescape_raw.json")
  try {
    Ensure-KubescapeArtifacts
    $ks = (Get-Command kubescape -ErrorAction Stop).Source
    $root = (Resolve-Path -LiteralPath $Path).Path
    & $ks scan $root --format json --format-version v2 --use-artifacts-from $KsArtifacts --output $Out | Out-Null
    if (!(Test-Path $Out) -and (Test-Path "${Out}.json")) { Move-Item -Force "${Out}.json" $Out }
    Write-NonEmpty $Out; Write-Host "[kubescape] -> $Out"
  } catch {
    '[]' | Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[kubescape] -> $Out (error: $($_.Exception.Message))"
  }
}

# --- KUBESEC (Docker; robust relative paths + JSON merge) ---------------------
# --- KUBESEC (Docker; read files via STDIN, merge JSON) ----------------------
# --- KUBESEC (Docker; pass files as args, merge per-file JSON lines) ----------
# --- KUBESEC (scan each file, parse robustly, merge JSON) ---------------------
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

    # Keep likely K8s manifests
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
      # build /work/<relative> so docker can read it
      $rel = $f.FullName.Substring($PWD.Path.Length).TrimStart('\','/')
      $workPath = "/work/$($rel -replace '\\','/')"

      $raw = docker run --rm -v "${PWD}:/work:ro" kubesec/kubesec:latest `
               scan --format=json $workPath 2>&1

      # log noise
      ($raw -split "`r?`n" | % { $_.Trim() } |
        ? { $_ -and -not ($_.StartsWith('[') -or $_.StartsWith('{')) }) |
        Add-Content -Path $stderrLog

      # try parse as-is
      $parsed = $null
      try { $parsed = ($raw | ConvertFrom-Json) } catch {
        # fall back: extract the first JSON array/object in the output
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

    # sanity
    try { $null = (Get-Content -Raw -Encoding UTF8 $Out) | ConvertFrom-Json } catch { '[]' | Set-Content -Encoding UTF8 -Path $Out }
    Write-Host "[kubesec] -> $Out"
  }
  catch {
    '[]' | Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[kubesec] -> $Out (error: $($_.Exception.Message))"
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
  "^/work/\.venv/",
  "^/work/.*/__pycache__/",
  "^/work/.*\.pyc$",
  "^/work/output/",
  "^/work/images/",            # cache noise
  "^/work/\.git/",
  "^/work/docker-bench-security/"
) | Set-Content -Encoding UTF8 -Path $exFile

    $args = @(
      "run","--rm",
      "-v","${PWD}:/work",
      "-v","${exFile}:/exclude.txt:ro",
      "trufflesecurity/trufflehog:latest",
      "filesystem","/work/$Path",
      "--json",
      "--exclude-paths","/exclude.txt"
    )
    docker @args | Set-Content -Encoding UTF8 -Path $Out
    Remove-Item $exFile -ErrorAction SilentlyContinue
    Write-NonEmpty $Out; Write-Host "[trufflehog] -> $Out"
  } catch { _WrapPlaceholder $Out "trufflehog" $_.Exception.Message }
}

# --- convenience: run everything ---------------------------------------------
function Det-RunAll {
  param(
    [string]$Path=".",
    [string]$Image=""
  )

  Ensure-DetectorImages

  $steps = @(
    "KubeLinter","Polaris","TrivyConfig","KubeScore",
    "Yamllint","Checkov","Terrascan",
    "Kubescape","Kubesec",
    "Gitleaks","TruffleHog"
  )
  if ($Image) { $steps += @("Syft","Grype","Hadolint","Dockle") }

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
      "Kubesec"      { Invoke-WithTiming -Name $s { Det-Kubesec -Path $Path } }
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

  Write-Host ""
  Write-Host "────────── Detectors runtime summary ──────────"
  $global:ToolTimings | Sort-Object Seconds -Descending |
    Format-Table @{Label="Tool";Expression={$_.Tool}}, @{Label="Sec";Expression={$_.Seconds}}, Status -Auto
  Write-Host ("Total time: {0:N2} sec" -f $totalSw.Elapsed.TotalSeconds)
  Write-Host "All detectors finished."
}
