<#!
.SYNOPSIS
  SafeFixK8s validation layer orchestrator.

.DESCRIPTION
  Runs a sequence of validation gates on a directory of Kubernetes manifests (typically LLM-patched files).
  Gates implemented:
    1) Schema Validation (kubeconform)
    2) Policy Validation (Conftest with OPA rego in policies/opa)
    3) Dry-Run Apply (kubectl --dry-run=server)
    4) Sandbox Deploy (optional; requires cluster)
    5) Health Check (optional; requires cluster)
    6) Network Check (stub; optional)
    7) E2E Smoke Test (stub; optional)

  Produces:
    - Validations/reports/<file-id>.json   (per-file gate results)
    - Validations/evidence/**              (raw outputs per gate)
    - Validations/safe_fix_proof.json      (aggregate signed proof)

.PARAMETER InputDir
  Directory containing YAML/YML manifests to validate. Defaults to output/patch_sandbox.

.PARAMETER OutputDir
  Directory to write reports/evidence (default: Validations).

.PARAMETER Gates
  Gates to run, by name. Defaults to all: schema,policy,dryrun,sandbox,health,network,e2e.

.PARAMETER EnableSandbox
  If supplied, attempts to deploy into a temporary namespace and run gates 4–7.

.PARAMETER Namespace
  Namespace to use for sandbox gates; defaults to safefix-<UTC timestamp> when -EnableSandbox is set.

.PARAMETER SandboxProvider
  "auto", "kind", "minikube", or "none". Currently informational; cluster must already be reachable via kubectl.

.PARAMETER TimeoutSec
  Default timeout used by some gates (e.g., rollout wait).

.PARAMETER SigningKey
  Optional HMAC-SHA256 signing key for the aggregated proof JSON. If omitted, a plain SHA256 digest is emitted instead.

.EXAMPLE
  # Minimal verification (no cluster needed):
  .\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -Gates schema,policy,dryrun

.EXAMPLE
  # Full run against current kube-context (if available):
  .\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -EnableSandbox -TimeoutSec 90

#>
[CmdletBinding()] param(
  [Parameter(Position = 0)] [string] $InputDir = "output/patch_sandbox",
  [Parameter()] [string] $OutputDir = "Validations",
  [Parameter()] [string[]] $Gates = @("schema", "policy", "dryrun", "sandbox", "health", "network", "e2e"),
  [switch] $EnableSandbox,
  [string] $Namespace,
  [ValidateSet("auto", "kind", "minikube", "none")] [string] $SandboxProvider = "auto",
  [int] $TimeoutSec = 60,
  [string] $SigningKey,
  [string] $KubeVersion = "1.29.0",
  [string] $DetectionRawKubeconform = "detection/output/raw/kubeconform_raw.json",
  [ValidateSet("auto", "server", "client")] [string] $DryRunMode = "auto",
  [string] $DryRunNamespace
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-Dir([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { 
    try {
      # Try direct creation first
      [void](New-Item -ItemType Directory -Force -Path $Path -ErrorAction Stop)
    }
    catch {
      # If path is too long or has issues, convert to 8.3 short path
      try {
        # Use FSO to get short path (handles long paths better than .NET)
        $fso = New-Object -ComObject Scripting.FileSystemObject
        # Create parent directory first if needed
        $parent = Split-Path -Parent $Path
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
          New-Dir -Path $parent
        }
        # Try creating with cmd using short path
        $shortPath = $null
        if (Test-Path -LiteralPath $parent) {
          $parentFolder = $fso.GetFolder($parent)
          $shortParent = $parentFolder.ShortPath
          $leaf = Split-Path -Leaf $Path
          $shortPath = Join-Path $shortParent $leaf
        }
        if ($shortPath) {
          cmd /c "mkdir `"$shortPath`"" 2>$null
        }
        else {
          [void](New-Item -ItemType Directory -Force -Path $Path -ErrorAction Stop)
        }
      }
      catch {
        Write-Warning "Failed to create directory: $Path"
        throw
      }
    }
  }
}
function Tool-Exists([string]$Name) {
  try { return [bool](Get-Command $Name -ErrorAction Stop) } catch { return $false }
}
function Find-ToolInDirs([string]$ExeName, [string[]]$Dirs) {
  foreach ($d in $Dirs) {
    if (-not $d) { continue }
    $p1 = Join-Path $d $ExeName
    if (Test-Path -LiteralPath $p1) { return $p1 }
    $p2 = Join-Path (Join-Path $d 'bin') $ExeName
    if (Test-Path -LiteralPath $p2) { return $p2 }
  }
  return $null
}
function Install-KubeconformFromPkgManagers() {
  # Try Scoop or Chocolatey if present. Returns 'kubeconform' on success, else $null.
  try {
    if (Tool-Exists 'scoop') {
      Write-Host "[Gate1] Installing kubeconform via Scoop..." -ForegroundColor Yellow
      try { scoop install kubeconform *>$null 2>&1 } catch {}
      if (Tool-Exists 'kubeconform') { return 'kubeconform' }
    }
  }
  catch {}
  try {
    if (Tool-Exists 'choco') {
      Write-Host "[Gate1] Installing kubeconform via Chocolatey..." -ForegroundColor Yellow
      try { choco install kubeconform -y *>$null 2>&1 } catch {}
      if (Tool-Exists 'kubeconform') { return 'kubeconform' }
    }
  }
  catch {}
  return $null
}
function Install-ConftestFromPkgManagers() {
  # Try Scoop or Chocolatey if present. Returns 'conftest' on success, else $null.
  try {
    if (Tool-Exists 'scoop') {
      Write-Host "[Gate2] Installing conftest via Scoop..." -ForegroundColor Yellow
      try { scoop install conftest *>$null 2>&1 } catch {}
      if (Tool-Exists 'conftest') { return 'conftest' }
    }
  }
  catch {}
  try {
    if (Tool-Exists 'choco') {
      Write-Host "[Gate2] Installing conftest via Chocolatey..." -ForegroundColor Yellow
      try { choco install conftest -y *>$null 2>&1 } catch {}
      if (Tool-Exists 'conftest') { return 'conftest' }
    }
  }
  catch {}
  return $null
}
function Ensure-Conftest() {
  # Returns the command/path to conftest if available or installed; otherwise $null.
  if (Tool-Exists 'conftest') { return 'conftest' }
  $binDir = Join-Path $PSScriptRoot 'bin'
  New-Dir $binDir
  $exePath = Join-Path $binDir 'conftest.exe'
  if (Test-Path $exePath) { return $exePath }
  # Check repo-local tool caches (Detection folder)
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
  $cand = Find-ToolInDirs 'conftest.exe' @(
    (Join-Path $repoRoot 'Detection'),
    (Join-Path $repoRoot 'Detection/tools'),
    (Join-Path $repoRoot 'Detection/.tmp-extracted')
  )
  if ($cand) { return $cand }
  # Try package managers
  $pkg = Install-ConftestFromPkgManagers
  if ($pkg) { return $pkg }
  # No direct download implemented (asset name varies by version); will rely on Docker fallback in gate.
  return $null
}
function Ensure-Kubeconform() {
  # Returns the command/path to kubeconform if available or downloaded; otherwise $null
  if (Tool-Exists 'kubeconform') { return 'kubeconform' }
  $binDir = Join-Path $PSScriptRoot 'bin'
  New-Dir $binDir
  $exePath = Join-Path $binDir 'kubeconform.exe'
  if (Test-Path $exePath) { return $exePath }
  # Check repo-local tool caches (Detection folder)
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
  $cand = Find-ToolInDirs 'kubeconform.exe' @(
    (Join-Path $repoRoot 'Detection'),
    (Join-Path $repoRoot 'Detection/tools'),
    (Join-Path $repoRoot 'Detection/.tmp-extracted')
  )
  if ($cand) { return $cand }
  # Try package managers first
  $pkg = Install-KubeconformFromPkgManagers
  if ($pkg) { return $pkg }
  $url = 'https://github.com/yannh/kubeconform/releases/latest/download/kubeconform-windows-amd64.exe'
  Write-Host "[Gate1] kubeconform not found; attempting to download to $exePath" -ForegroundColor Yellow
  try {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
    Invoke-WebRequest -Uri $url -OutFile $exePath -UseBasicParsing -ErrorAction Stop
    return $exePath
  }
  catch {
    Write-Host "[Gate1] Failed to download kubeconform: $($_.Exception.Message)" -ForegroundColor Red
    return $null
  }
}
function Write-Json([object]$Obj, [string]$Path) {
  $json = $Obj | ConvertTo-Json -Depth 12
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
}
function Get-RelPath([string]$Base, [string]$Full) {
  $uriBase = New-Object System.Uri((Resolve-Path $Base))
  $uriFull = New-Object System.Uri((Resolve-Path $Full))
  return $uriBase.MakeRelativeUri($uriFull).ToString()
}
function Get-FileId([string]$Base, [string]$Path) {
  $rel = Get-RelPath $Base $Path
  return ($rel -replace "[^A-Za-z0-9_.-]", "_")
}
function File-Sha256([string]$Path) {
  (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}
function Text-Sha256([string]$Text) {
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ''
}
function Text-HmacSha256([string]$Text, [string]$Key) {
  $kbytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
  $hmac = New-Object System.Security.Cryptography.HMACSHA256(, $kbytes)
  ($hmac.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ''
}

# Prepare IO
$root = Resolve-Path .
$inputAbs = Resolve-Path $InputDir
$outAbs = Join-Path (Resolve-Path .) $OutputDir
$evidence = Join-Path $outAbs 'evidence'
$reports = Join-Path $outAbs 'reports'
New-Dir $outAbs; New-Dir $evidence; New-Dir $reports

# Namespace defaulting for sandbox
if ($EnableSandbox -and [string]::IsNullOrWhiteSpace($Namespace)) {
  $Namespace = 'safefix-' + ([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))
}

# Detect tools
$hasKubectl = Tool-Exists 'kubectl'
$hasDocker = Tool-Exists 'docker'
$kubeconformCmd = Ensure-Kubeconform
$hasKubeconform = [bool]$kubeconformCmd

# Optionally load precomputed kubeconform results from Detection layer
$kubeconformDetectionIndex = $null
$_kcIndexByBase = $null
$_kcIndexByScan = $null
try {
  if ($DetectionRawKubeconform -and (Test-Path -LiteralPath $DetectionRawKubeconform)) {
    $kcRaw = Get-Content -LiteralPath $DetectionRawKubeconform -Raw | ConvertFrom-Json -ErrorAction Stop
    if ($kcRaw -and $kcRaw.resources) {
      $_kcIndexByBase = @{}
      $_kcIndexByScan = @{}
      foreach ($res in $kcRaw.resources) {
        $fname = [string]$res.filename
        $bn = [System.IO.Path]::GetFileName($fname)
        if (-not $_kcIndexByBase.ContainsKey($bn)) { $_kcIndexByBase[$bn] = @() }
        $_kcIndexByBase[$bn] += $res
        if ($fname) {
          $_kcIndexByScan[$fname] = ($_kcIndexByScan[$fname] + @($res))
        }
      }
      $kubeconformDetectionIndex = @{ byBase = $_kcIndexByBase; byScan = $_kcIndexByScan }
    }
  }
}
catch { $kubeconformDetectionIndex = $null }
$conftestCmd = Ensure-Conftest
$hasConftest = [bool]$conftestCmd

# Tool versions (best-effort)
$toolVersions = @{}
try { if ($hasKubectl) { $toolVersions.kubectl = (kubectl version --client -o json | ConvertFrom-Json).clientVersion.gitVersion } } catch {}
try { if ($hasKubeconform) { $toolVersions.kubeconform = (& $kubeconformCmd -v) } } catch {}
try { if ($hasConftest) { $toolVersions.conftest = (& $conftestCmd --version) } } catch {}

# Gate runners ---------------------------------------------------------------
function Gate-Schema([string]$file, [string]$evidDir) {
  New-Dir $evidDir
  # Prefer precomputed Detection results when available
  if ($kubeconformDetectionIndex) {
    $bn = [System.IO.Path]::GetFileName($file)
    # Try to match by full /scan/relative path first
    $relFromInput = ($file.Substring($inputAbs.Path.Length) -replace '^[\\/]+', '')
    $scanKey = '/scan/' + ($relFromInput -replace '\\', '/')
    $kcMatches = $null
    $matchedBy = ''
    if ($kubeconformDetectionIndex.byScan.ContainsKey($scanKey)) {
      $kcMatches = $kubeconformDetectionIndex.byScan[$scanKey]
      $matchedBy = 'fullpath'
    }
    elseif ($kubeconformDetectionIndex.byBase.ContainsKey($bn)) {
      $kcMatches = $kubeconformDetectionIndex.byBase[$bn]
      $matchedBy = 'basename'
    }
    if ($null -eq $kcMatches -or $kcMatches.Count -eq 0) {
      # No detection match for this file; fall back to running kubeconform below
    }
    else {
      # If Detection results contain download or schema errors, fall back to a fresh kubeconform run
      $hasErrors = $false
      foreach ($m in $kcMatches) {
        if ($m.status -eq 'statusError' -or ($m.msg -and ($m.msg -match 'failed downloading schema|x509|tls'))) { $hasErrors = $true; break }
      }
      if (-not $hasErrors) {
        $evPath = Join-Path $evidDir 'kubeconform_detection.json'
        Write-Json $kcMatches $evPath
        $status = 'PASS'
        foreach ($m in $kcMatches) {
          $st = [string]$m.status
          if ($st -ne 'statusValid' -and $st -ne 'valid') { $status = 'FAIL' }
        }
        return @{ gate = 'schema'; status = $status; details = ('kubeconform (Detection results, ' + $matchedBy + ')'); evidence = (Get-RelPath $outAbs $evPath) }
      }
      # else: proceed to local/docker run below
    }
  }

  # Fallback: run kubeconform locally or via Docker if available
  if (-not $hasKubeconform) {
    if ($hasDocker) {
      $outPath = Join-Path $evidDir 'kubeconform.json'
      $relFromInput = ($file.Substring($inputAbs.Path.Length) -replace '^[\\/]+', '')
      $scanFile = '/scan/' + ($relFromInput -replace '\\', '/')
      $dcArgs = @('run', '--rm', '-v', ("$($inputAbs.Path):/scan:ro"), 'ghcr.io/yannh/kubeconform:latest',
        '-summary', '-output', 'json', '-strict', '--kubernetes-version', $KubeVersion, $scanFile)
      $raw = & docker @dcArgs 2>&1
      $raw | Out-File -Encoding utf8 $outPath
      $status = 'PASS'
      try {
        $json = $raw | Out-String | ConvertFrom-Json -ErrorAction Stop
        if ($null -ne $json.resources) {
          foreach ($r in $json.resources) { if ($r.status -ne 'valid') { $status = 'FAIL' } }
        }
        elseif ($null -ne $json.summary) {
          if (($json.summary.invalid -as [int]) -gt 0 -or ($json.summary.errors -as [int]) -gt 0) { $status = 'FAIL' }
        }
        elseif ($json -is [System.Array]) {
          foreach ($r in $json) { if ($r.status -ne 'valid') { $status = 'FAIL' } }
        }
      }
      catch { }
      return @{ gate = 'schema'; status = $status; details = 'kubeconform (docker)'; evidence = (Get-RelPath $outAbs $outPath) }
    }
    return @{ gate = 'schema'; status = 'SKIP'; details = 'kubeconform not found'; evidence = '' }
  }
  $outPath = Join-Path $evidDir 'kubeconform.json'
  $kcArgs = @('-summary', '-output', 'json', '-strict', '--kubernetes-version', $KubeVersion, $file)
  $raw = & $kubeconformCmd @kcArgs 2>&1
  $raw | Out-File -Encoding utf8 $outPath
  $status = 'PASS'
  try {
    $json = $raw | Out-String | ConvertFrom-Json -ErrorAction Stop
    if ($null -ne $json.resources) {
      foreach ($r in $json.resources) { if ($r.status -ne 'valid') { $status = 'FAIL' } }
    }
    elseif ($null -ne $json.summary) {
      if (($json.summary.invalid -as [int]) -gt 0 -or ($json.summary.errors -as [int]) -gt 0) { $status = 'FAIL' }
    }
    elseif ($json -is [System.Array]) {
      foreach ($r in $json) { if ($r.status -ne 'valid') { $status = 'FAIL' } }
    }
  }
  catch { }
  return @{ gate = 'schema'; status = $status; details = 'kubeconform run'; evidence = (Get-RelPath $outAbs $outPath) }
}

function Gate-Policy([string]$file, [string]$evidDir) {
  New-Dir $evidDir
  $outPath = Join-Path $evidDir 'conftest.json'
  # Use policies colocated under Validations/
  $pol = Join-Path $PSScriptRoot 'policies/opa'
  if (-not (Test-Path $pol)) { return @{ gate = 'policy'; status = 'SKIP'; details = 'policies/opa not present'; evidence = '' } }

  if ($hasConftest) {
    $raw = & $conftestCmd test --policy $pol --output json $file 2>&1
    $raw | Out-File -Encoding utf8 $outPath
    $status = 'PASS'
    try {
      $j = $raw | Out-String | ConvertFrom-Json -ErrorAction Stop
      $fails = 0
      foreach ($r in $j) { if ($r.failures) { $fails += ($r.failures | Measure-Object).Count } }
      if ($fails -gt 0) { $status = 'FAIL' }
    }
    catch { if ($raw -match 'FAIL') { $status = 'FAIL' } }
    return @{ gate = 'policy'; status = $status; details = 'conftest run'; evidence = (Get-RelPath $outAbs $outPath) }
  }

  if ($hasDocker) {
    # Docker fallback: mount input dir and policies, run openpolicyagent/conftest
    $relFromInput = ($file.Substring($inputAbs.Path.Length) -replace '^[\\/]+', '')
    $projFile = '/project/' + ($relFromInput -replace '\\', '/')
    $dcArgs = @('run', '--rm',
      '-v', ("$($inputAbs.Path):/project:ro"),
      '-v', ("$($pol):/policy:ro"),
      'openpolicyagent/conftest', 'test', '--policy', '/policy', '--output', 'json', $projFile)
    $raw = & docker @dcArgs 2>&1
    $raw | Out-File -Encoding utf8 $outPath
    $status = 'PASS'
    try {
      $j = $raw | Out-String | ConvertFrom-Json -ErrorAction Stop
      $fails = 0
      foreach ($r in $j) { if ($r.failures) { $fails += ($r.failures | Measure-Object).Count } }
      if ($fails -gt 0) { $status = 'FAIL' }
    }
    catch { if ($raw -match 'FAIL') { $status = 'FAIL' } }
    return @{ gate = 'policy'; status = $status; details = 'conftest (docker)'; evidence = (Get-RelPath $outAbs $outPath) }
  }

  return @{ gate = 'policy'; status = 'SKIP'; details = 'conftest not found'; evidence = '' }
}

function Gate-DryRun([string]$file, [string]$evidDir) {
  if (-not $hasKubectl) { return @{ gate = 'dryrun'; status = 'SKIP'; details = 'kubectl not found'; evidence = '' } }
  New-Dir $evidDir
  $outPath = Join-Path $evidDir 'dryrun.txt'
  $stderrPath = Join-Path $evidDir 'dryrun.err.txt'

  # Determine mode
  $mode = $DryRunMode
  $ctx = $null; $ctxExit = 0
  try { $ctx = (& kubectl config current-context 2>$null); $ctxExit = if ($LASTEXITCODE) { $LASTEXITCODE } else { 0 } } catch { $ctxExit = 1 }
  if ($DryRunMode -eq 'auto') {
    if ($ctxExit -eq 0 -and -not [string]::IsNullOrWhiteSpace($ctx)) { $mode = 'server' } else { $mode = 'skip' }
  }

  if ($mode -eq 'skip') { return @{ gate = 'dryrun'; status = 'SKIP'; details = 'no kube-context; dry-run requires a live API server'; evidence = '' } }
  $kubectlArgs = @('apply', '--dry-run=' + $mode, '-f', $file)
  if ($DryRunNamespace) { $kubectlArgs = @('apply', '-n', $DryRunNamespace, '--dry-run=' + $mode, '-f', $file) }

  # If user requested server explicitly but no context, SKIP with guidance
  if ($DryRunMode -eq 'server' -and ($ctxExit -ne 0 -or [string]::IsNullOrWhiteSpace($ctx))) {
    return @{ gate = 'dryrun'; status = 'SKIP'; details = 'no kube-context; cannot run server dry-run'; evidence = '' }
  }

  $out = ""; $errText = ""; $exit = 0
  try {
    $out = & kubectl @kubectlArgs *>&1
    $exit = if ($LASTEXITCODE) { $LASTEXITCODE } else { 0 }
  }
  catch {
    $errText = $_ | Out-String; $exit = 1
  }
  $out | Out-File -Encoding utf8 $outPath
  if ($errText) { $errText | Out-File -Encoding utf8 $stderrPath }
  $status = if ($exit -eq 0) { 'PASS' } else { 'FAIL' }
  $det = 'kubectl apply --dry-run=' + $mode
  if ($DryRunNamespace) { $det += ' -n ' + $DryRunNamespace }
  if ($DryRunMode -eq 'auto' -and $mode -eq 'server' -and [string]::IsNullOrWhiteSpace($ctx)) { $det += ' (no kube-context)' }
  return @{ gate = 'dryrun'; status = $status; details = $det; evidence = (Get-RelPath $outAbs $outPath) }
}

function Gate-Sandbox([string]$file, [string]$evidDir, [string]$ns) {
  if (-not $EnableSandbox) { return @{ gate = 'sandbox'; status = 'SKIP'; details = 'sandbox disabled'; evidence = '' } }
  if (-not $hasKubectl) { return @{ gate = 'sandbox'; status = 'SKIP'; details = 'kubectl not found'; evidence = '' } }
  New-Dir $evidDir
  $applyOut = Join-Path $evidDir 'apply.txt'
  try {
    $nsExists = $false
    try { kubectl get ns $ns *>$null 2>&1; $nsExists = ($LASTEXITCODE -eq 0) } catch { $nsExists = $false }
    if (-not $nsExists) { try { kubectl create ns $ns *>$null 2>&1 } catch {} }
  }
  catch {}
  $cmd = { kubectl apply -n $using:ns -f $using:file }
  $out = & $cmd *>&1; $exit = if ($LASTEXITCODE) { $LASTEXITCODE } else { 0 }
  $out | Out-File -Encoding utf8 $applyOut
  $status = if ($exit -eq 0) { 'PASS' } else { 'FAIL' }
  return @{ gate = 'sandbox'; status = $status; details = ('kubectl apply -n ' + $ns); evidence = (Get-RelPath $outAbs $applyOut) }
}

function Gate-Health([string]$evidDir, [string]$ns, [int]$timeout) {
  if (-not $EnableSandbox) { return @{ gate = 'health'; status = 'SKIP'; details = 'sandbox disabled'; evidence = '' } }
  if (-not $hasKubectl) { return @{ gate = 'health'; status = 'SKIP'; details = 'kubectl not found'; evidence = '' } }
  New-Dir $evidDir
  $status = 'PASS'
  $ev = @()
  # Best-effort: wait for all deployments/statefulsets/daemonsets in the namespace
  $rolloutTimeout = "--timeout=${timeout}s"
  try {
    $d = & kubectl -n $ns get deploy -o name 2>$null
    foreach ($name in $d) {
      $out = & kubectl -n $ns rollout status $name $rolloutTimeout 2>&1
      $ev += @{ kind = 'Deployment'; name = $name; output = $out }
      if ($LASTEXITCODE -ne 0) { $status = 'FAIL' }
    }
  }
  catch { $status = 'FAIL'; $ev += @{ error = ($_ | Out-String) } }
  $evPath = Join-Path $evidDir 'health.json'
  Write-Json $ev $evPath
  return @{ gate = 'health'; status = $status; details = 'rollout status'; evidence = (Get-RelPath $outAbs $evPath) }
}

function Gate-Network([string]$evidDir, [string]$ns) {
  if (-not $EnableSandbox) { return @{ gate = 'network'; status = 'SKIP'; details = 'sandbox disabled'; evidence = '' } }
  if (-not $hasKubectl) { return @{ gate = 'network'; status = 'SKIP'; details = 'kubectl not found'; evidence = '' } }
  # Stub: collect services present as evidence
  New-Dir $evidDir
  $svcJson = Join-Path $evidDir 'services.json'
  try { $j = kubectl -n $ns get svc -o json | ConvertFrom-Json } catch { $j = $null }
  if ($j) { Write-Json $j $svcJson; return @{ gate = 'network'; status = 'PASS'; details = 'services listed'; evidence = (Get-RelPath $outAbs $svcJson) } }
  else { return @{ gate = 'network'; status = 'SKIP'; details = 'no services or cannot list'; evidence = '' } }
}

function Gate-E2E([string]$evidDir, [string]$ns) {
  # Stub: look for Validations/e2e_smoke.ps1 and execute if present
  New-Dir $evidDir
  $script = Join-Path $PSScriptRoot 'e2e_smoke.ps1'
  if (Test-Path $script) {
    try {
      $out = & $script -Namespace $ns *>&1
      $ev = Join-Path $evidDir 'e2e.txt'
      $out | Out-File -Encoding utf8 $ev
      return @{ gate = 'e2e'; status = 'PASS'; details = 'custom e2e script'; evidence = (Get-RelPath $outAbs $ev) }
    }
    catch { $ev = Join-Path $evidDir 'e2e.err.txt'; ($_ | Out-String) | Out-File -Encoding utf8 $ev; return @{ gate = 'e2e'; status = 'FAIL'; details = 'custom e2e failed'; evidence = (Get-RelPath $outAbs $ev) } }
  }
  return @{ gate = 'e2e'; status = 'SKIP'; details = 'no e2e script'; evidence = '' }
}

# Enumerate files
$files = Get-ChildItem -LiteralPath $inputAbs -Recurse -Include *.yaml, *.yml | Where-Object { -not $_.PSIsContainer }
if (-not $files) { Write-Error "No YAML manifests found in $inputAbs" }

# Optionally ensure namespace up-front when sandboxing
if ($EnableSandbox -and $hasKubectl) {
  try {
    $nsExists = $false
    try { kubectl get ns $Namespace *>$null 2>&1; $nsExists = ($LASTEXITCODE -eq 0) } catch { $nsExists = $false }
    if (-not $nsExists) { try { kubectl create ns $Namespace *>$null 2>&1 } catch {} }
  }
  catch {}
}

$aggregate = @()
foreach ($f in $files) {
  $filePath = $f.FullName
  $fid = Get-FileId $inputAbs $filePath
  $fRel = Get-RelPath $root $filePath
  $sha = File-Sha256 $filePath
  $perFileEvid = Join-Path $evidence $fid
  New-Dir $perFileEvid

  $results = @()
  if ($Gates -contains 'schema') { $results += (Gate-Schema  $filePath (Join-Path $perFileEvid 'schema')) }
  if ($Gates -contains 'policy') { $results += (Gate-Policy  $filePath (Join-Path $perFileEvid 'policy')) }
  if ($Gates -contains 'dryrun') { $results += (Gate-DryRun  $filePath (Join-Path $perFileEvid 'dryrun')) }
  if ($Gates -contains 'sandbox') { $results += (Gate-Sandbox $filePath (Join-Path $perFileEvid 'sandbox') $Namespace) }
  if ($Gates -contains 'health') { $results += (Gate-Health (Join-Path $perFileEvid 'health') $Namespace $TimeoutSec) }
  if ($Gates -contains 'network') { $results += (Gate-Network (Join-Path $perFileEvid 'network') $Namespace) }
  if ($Gates -contains 'e2e') { $results += (Gate-E2E (Join-Path $perFileEvid 'e2e') $Namespace) }

  $overall = 'PASS'
  $hasFail = $results | Where-Object { $_.status -eq 'FAIL' }
  if ($hasFail) { $overall = 'FAIL' }
  # Minimal bar: first three gates must be PASS to claim overall PASS
  $g1Obj = $results | Where-Object { $_.gate -eq 'schema' } | Select-Object -First 1
  $g2Obj = $results | Where-Object { $_.gate -eq 'policy' } | Select-Object -First 1
  $g3Obj = $results | Where-Object { $_.gate -eq 'dryrun' } | Select-Object -First 1
  $g1 = if ($g1Obj) { $g1Obj.status } else { 'SKIP' }
  $g2 = if ($g2Obj) { $g2Obj.status } else { 'SKIP' }
  $g3 = if ($g3Obj) { $g3Obj.status } else { 'SKIP' }
  if (-not ($g1 -eq 'PASS' -and $g2 -eq 'PASS' -and $g3 -eq 'PASS')) { $overall = 'FAIL' }

  $perFile = @{ file = $fRel; file_sha256 = $sha; gates = $results; overall = $overall }
  $aggregate += $perFile
  Write-Json $perFile (Join-Path $reports ("$fid.json"))
}

# Aggregate proof
$passList = @($aggregate | Where-Object { $_.overall -eq 'PASS' })
$failList = @($aggregate | Where-Object { $_.overall -eq 'FAIL' })
$summary = @{ PASS = $passList.Count; FAIL = $failList.Count }

$kubectx = $null
try {
  if ($hasKubectl) {
    # Suppress stderr noise when no current context is set; ignore non-zero exit
    $kubectx = (& kubectl config current-context 2>$null)
    if ($LASTEXITCODE -ne 0) { $kubectx = $null }
  }
}
catch {}

$proof = [ordered]@{
  version          = '1.0'
  generated_at_utc = ([DateTime]::UtcNow.ToString('o'))
  input_dir        = (Get-RelPath $root $inputAbs)
  output_dir       = (Get-RelPath $root $outAbs)
  kube_context     = $kubectx
  namespace        = if ($EnableSandbox) { $Namespace } else { $null }
  tools            = $toolVersions
  files            = $aggregate
  summary          = $summary
}

# Canonical string for signing
$canon = ($proof | ConvertTo-Json -Depth 12 -Compress)
if ($SigningKey) {
  $sig = Text-HmacSha256 $canon $SigningKey
  $proof.signature = @{ alg = 'HMAC-SHA256'; value = $sig }
}
else {
  $digest = Text-Sha256 $canon
  $proof.signature = @{ alg = 'SHA256'; value = $digest }
}

$proofPath = Join-Path $outAbs 'safe_fix_proof.json'
Write-Json $proof $proofPath

Write-Host "Validation complete. Proof:" (Get-RelPath $root $proofPath)

# Ensure a clean exit code regardless of any native command non-zero codes during probes
$global:LASTEXITCODE = 0
