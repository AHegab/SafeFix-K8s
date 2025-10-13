# scripts/detectors.ps1
$ErrorActionPreference = "Stop"

# --- paths --------------------------------------------------------------------
$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutDir   = Join-Path $PSScriptRoot "..\output\raw"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# --- helpers ------------------------------------------------------------------
function Write-NonEmpty($Path) {
  if (!(Test-Path $Path) -or ((Get-Item $Path).Length -lt 3)) {
    throw "Output file '$Path' is missing or empty."
  }
}

function _ContainerPath($HostPath) {
  $rel = (Resolve-Path $HostPath).Path.Substring($PWD.Path.Length).TrimStart('\','/')
  return "/work/$($rel.Replace('\','/'))"
}

function _WrapPlaceholder($Out, $tool, $msg) {
  '[{"tool":"' + $tool + '","note":"' + ($msg -replace '"','''') + '"}]' |
    Set-Content -Encoding UTF8 -Path $Out
  Write-Host "[$tool] -> $Out (placeholder)"
}

# --- image pulls --------------------------------------------------------------
function Pull-Detectors {
  docker pull stackrox/kube-linter:latest
  docker pull quay.io/fairwinds/polaris:latest
  docker pull aquasec/trivy:latest
  docker pull anchore/syft:latest
  docker pull anchore/grype:latest
  docker pull hadolint/hadolint:latest
  docker pull goodwithtech/dockle:latest
  docker pull zricethezav/gitleaks:latest
  docker pull trufflesecurity/trufflehog:latest
  docker pull bridgecrew/checkov:latest
  docker pull tenable/terrascan:latest
  docker pull zegl/kube-score:latest
  docker pull cytopia/yamllint:latest
  # NEW:
  docker pull quay.io/kubescape/kubescape:latest
  docker pull kubesec/kubesec:latest
}


# --- manifest linters ---------------------------------------------------------
function Det-KubeLinter {
  param([string]$Path="tests",[string]$Out="$OutDir\kubelinter_raw.json")
  try {
    docker run --rm -v "${PWD}:/work:ro" stackrox/kube-linter:latest `
      lint "/work/$Path" --format json | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[kube-linter] -> $Out"
  } catch { _WrapPlaceholder $Out "kubelinter" $_.Exception.Message }
}

function Det-Polaris {
  param([string]$Path="tests",[string]$Out="$OutDir\polaris_raw.json")
  try {
    docker run --rm -v "${PWD}:/work:ro" quay.io/fairwinds/polaris:latest `
      polaris audit --audit-path "/work/$Path" --format json `
      | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[polaris] -> $Out"
  } catch { _WrapPlaceholder $Out "polaris" $_.Exception.Message }
}

function Det-KubeScore {
  param([string]$Path="tests",[string]$Out="$OutDir\kubescore_raw.json")
  try {
    $root  = (Resolve-Path $Path).Path
    $files = Get-ChildItem -Path $root -Recurse -Include *.yaml,*.yml |
      ForEach-Object { "/work/" + ($_.FullName.Substring($PWD.Path.Length).TrimStart('\','/').Replace('\','/')) }
    if ($files.Count -eq 0) { throw "kube-score: no YAML in '$Path'." }
    $cmd = @("run","--rm","-v","${PWD}:/work:ro","zegl/kube-score:latest","score","--output-format","json") + $files
    docker @cmd | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[kube-score] -> $Out"
  } catch { _WrapPlaceholder $Out "kube-score" $_.Exception.Message }
}

# --- replacements / additions -------------------------------------------------
function Det-Kubescape {
  param(
    [string]$Path = "tests",
    [string]$Out  = "$OutDir\kubescape_raw.json"
  )
  # Scans all YAML under $Path. Kubescape supports -f on directories.
  # json v2 is the most structured (useful for normalization).
  try {
    docker run --rm -v "${PWD}:/work:ro" `
      "quay.io/kubescape/kubescape:latest" `
      scan -f "/work/$Path" `
      --format json --format-version v2 -o - --eula-sign `
      | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out
    Write-Host "[kubescape] -> $Out"
  }
  catch {
    '[{"tool":"kubescape","error":"run_failed"}]' | Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[kubescape] -> $Out (placeholder)"
  }
}


function Det-Kubesec {
  param(
    [string]$Path = "tests",
    [string]$Out  = "$OutDir\kubesec_raw.json"
  )
  # Kubesec container: docker.io/kubesec/kubesec:latest
  # It prints one JSON object per file. We'll wrap results into an array.
  try {
    $root  = (Resolve-Path $Path).Path
    $files = Get-ChildItem -Path $root -Recurse -Include *.yml,*.yaml
    if ($files.Count -eq 0) {
      '[]' | Set-Content -Encoding UTF8 -Path $Out
      Write-Host "[kubesec] -> $Out (no files)"
      return
    }

    $tmp = New-TemporaryFile
    Remove-Item $tmp -Force
    $tmp = [System.IO.Path]::ChangeExtension($tmp, ".jsonl")

    foreach ($f in $files) {
      $rel = $f.FullName.Substring($PWD.Path.Length).TrimStart('\','/')
      $wpath = "/work/$rel".Replace('\','/')
      $res = docker run --rm -v "${PWD}:/work:ro" `
        "kubesec/kubesec:latest" `
        scan --format=json "$wpath"
      # Each run returns a single JSON object; append as line-delimited JSON
      $res | Add-Content -Encoding UTF8 -Path $tmp
    }

    # Convert JSONL -> JSON array
    $arr = @()
    Get-Content -Path $tmp -Encoding UTF8 | ForEach-Object {
      if ($_ -and $_.Trim().Length -gt 0) {
        try { $arr += ($_ | ConvertFrom-Json) } catch { }
      }
    }
    ($arr | ConvertTo-Json -Depth 50) | Set-Content -Encoding UTF8 -Path $Out
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Write-NonEmpty $Out
    Write-Host "[kubesec] -> $Out"
  }
  catch {
    '[]' | Set-Content -Encoding UTF8 -Path $Out
    Write-Host "[kubesec] -> $Out (placeholder)"
  }
}


# (Optional) If you still want kubeaudit, keep this offline-fetch runner.
# Disabled by default; Kubescape+KubeLinter+Polaris already cover kubeaudit’s space.
<# 
function Det-KubeAudit {
  param([string]$Path="tests",[string]$Out="$OutDir\kubeaudit_raw.json",[string]$Version="0.22.2")
  try {
    $target = if ($Path -eq "tests") { "/work/tests" } else { _ContainerPath $Path }
    $script = @"
set -e
apk add --no-cache curl tar ca-certificates >/dev/null
URL="https://github.com/Shopify/kubeaudit/releases/download/v${Version}/kubeaudit_${Version}_linux_amd64.tar.gz"
curl -sSL "\$URL" -o /tmp/k.tgz
tar -xzf /tmp/k.tgz -C /usr/local/bin kubeaudit
/usr/local/bin/kubeaudit all -f "$target" -o json
"@
    $hostScript = New-TemporaryFile
    Set-Content -Encoding ASCII -Path $hostScript -Value $script
    $args = @("run","--rm","-v","${PWD}:/work:ro","-v","$((Resolve-Path $hostScript).Path):/run.sh:ro","alpine:3.20","/bin/sh","/run.sh")
    docker @args | Set-Content -Encoding UTF8 -Path $Out
    Remove-Item $hostScript -ErrorAction SilentlyContinue
    Write-NonEmpty $Out; Write-Host "[kubeaudit] -> $Out"
  } catch { _WrapPlaceholder $Out "kubeaudit" $_.Exception.Message }
}
#>

# --- config scanners / IaC ----------------------------------------------------
function Det-TrivyConfig {
  param([string]$Path="tests",[string]$Out="$OutDir\trivy_config_raw.json")
  try {
    docker run --rm -v "${PWD}:/work:ro" aquasec/trivy:latest `
      config --quiet --format json "/work/$Path" | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[trivy config] -> $Out"
  } catch { _WrapPlaceholder $Out "trivy-config" $_.Exception.Message }
}

function Det-Checkov {
  param([string]$Path="tests",[string]$Out="$OutDir\checkov_raw.json")
  try {
    docker run --rm -v "${PWD}:/work:ro" bridgecrew/checkov:latest `
      -d "/work/$Path" -o json | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[checkov] -> $Out"
  } catch { _WrapPlaceholder $Out "checkov" $_.Exception.Message }
}

function Det-Terrascan {
  param([string]$Path="tests",[string]$Out="$OutDir\terrascan_raw.json")
  try {
    docker run --rm -v "${PWD}:/work:ro" tenable/terrascan:latest `
      scan -d "/work/$Path" -o json | Set-Content -Encoding UTF8 -Path $Out
    Write-NonEmpty $Out; Write-Host "[terrascan] -> $Out"
  } catch { _WrapPlaceholder $Out "terrascan" $_.Exception.Message }
}

function Det-Yamllint {
  param([string]$Path="tests",[string]$Out="$OutDir\yamllint_raw.txt")
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
    docker run --rm -v "${PWD}:/work:ro" hadolint/hadolint `
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
    @("^/work/\.venv/","^/work/output/") | Set-Content -Encoding UTF8 -Path $exFile
    docker run --rm -v "${PWD}:/work" -v "${exFile}:/exclude.txt:ro" trufflesecurity/trufflehog:latest `
      filesystem /work/$Path --json --exclude-paths /exclude.txt `
      | Set-Content -Encoding UTF8 -Path $Out
    Remove-Item $exFile -ErrorAction SilentlyContinue
    Write-NonEmpty $Out; Write-Host "[trufflehog] -> $Out"
  } catch { _WrapPlaceholder $Out "trufflehog" $_.Exception.Message }
}

# --- convenience: run everything ---------------------------------------------
function Det-RunAll {
  param(
    [string]$Path="tests",
    [string]$Image=""
  )
  Det-KubeLinter -Path $Path
  Det-Polaris    -Path $Path
  Det-TrivyConfig -Path $Path
  Det-KubeScore  -Path $Path
  Det-Yamllint   -Path $Path
  Det-Checkov    -Path $Path
  Det-Terrascan  -Path $Path

  # NEW
  Det-Kubescape  -Path $Path
  Det-Kubesec    -Path $Path

  Det-Gitleaks   -Path .
  Det-TruffleHog -Path .

  if ($Image) {
    Det-Syft  -Image $Image
    Det-Grype -Image $Image
    Det-Hadolint -Dockerfile (Join-Path $PWD "Dockerfile")
    Det-Dockle -Image $Image
  }
  Write-Host "All detectors finished."
}
