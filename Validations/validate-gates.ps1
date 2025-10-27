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
  [Parameter(Position=0)] [string] $InputDir = "output/patch_sandbox",
  [Parameter()] [string] $OutputDir = "Validations",
  [Parameter()] [string[]] $Gates = @("schema","policy","dryrun","sandbox","health","network","e2e"),
  [switch] $EnableSandbox,
  [string] $Namespace,
  [ValidateSet("auto","kind","minikube","none")] [string] $SandboxProvider = "auto",
  [int] $TimeoutSec = 60,
  [string] $SigningKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-Dir([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { [void](New-Item -ItemType Directory -Force -Path $Path) }
}
function Tool-Exists([string]$Name) {
  try { return [bool](Get-Command $Name -ErrorAction Stop) } catch { return $false }
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
  $sha   = [System.Security.Cryptography.SHA256]::Create()
  ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ''
}
function Text-HmacSha256([string]$Text, [string]$Key) {
  $kbytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
  $bytes  = [System.Text.Encoding]::UTF8.GetBytes($Text)
  $hmac   = New-Object System.Security.Cryptography.HMACSHA256(,$kbytes)
  ($hmac.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ''
}

# Prepare IO
$root = Resolve-Path .
$inputAbs  = Resolve-Path $InputDir
$outAbs    = Join-Path (Resolve-Path .) $OutputDir
$evidence  = Join-Path $outAbs 'evidence'
$reports   = Join-Path $outAbs 'reports'
New-Dir $outAbs; New-Dir $evidence; New-Dir $reports

# Namespace defaulting for sandbox
if ($EnableSandbox -and [string]::IsNullOrWhiteSpace($Namespace)) {
  $Namespace = 'safefix-' + ([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))
}

# Detect tools
$hasKubectl     = Tool-Exists 'kubectl'
$hasKubeconform = Tool-Exists 'kubeconform'
$hasConftest    = Tool-Exists 'conftest'

# Tool versions (best-effort)
$toolVersions = @{}
try { if ($hasKubectl) { $toolVersions.kubectl = (kubectl version --client -o json | ConvertFrom-Json).clientVersion.gitVersion } } catch {}
try { if ($hasKubeconform) { $toolVersions.kubeconform = (kubeconform -version) } } catch {}
try { if ($hasConftest) { $toolVersions.conftest = (conftest --version) } } catch {}

# Gate runners ---------------------------------------------------------------
function Gate-Schema([string]$file, [string]$evidDir) {
  if (-not $hasKubeconform) { return @{ gate='schema'; status='SKIP'; details='kubeconform not found'; evidence='' } }
  New-Dir $evidDir
  $outPath = Join-Path $evidDir 'kubeconform.json'
  $args = @('-summary','-output','json','-strict', '--kubernetes-version','1.29.0', $file)
  $raw = & kubeconform @args 2>&1
  $raw | Out-File -Encoding utf8 $outPath
  $status = 'PASS'
  try {
    $json = $raw | Out-String | ConvertFrom-Json -ErrorAction Stop
    # kubeconform json contains per-file results with 'status'
    $f = $json | Where-Object { $_.path -ne $null }
    if ($f) {
      foreach ($r in $f) { if ($r.status -ne 'valid') { $status = 'FAIL' } }
    } else { if ($raw -match 'Invalid') { $status = 'FAIL' } }
  } catch { if ($raw -match 'Invalid|ERR|FAIL') { $status = 'FAIL' } }
  return @{ gate='schema'; status=$status; details='kubeconform run'; evidence=(Get-RelPath $outAbs $outPath) }
}

function Gate-Policy([string]$file, [string]$evidDir) {
  if (-not $hasConftest) { return @{ gate='policy'; status='SKIP'; details='conftest not found'; evidence='' } }
  New-Dir $evidDir
  $outPath = Join-Path $evidDir 'conftest.json'
  # Use policies colocated under Validations/
  $pol = Join-Path $PSScriptRoot 'policies/opa'
  if (-not (Test-Path $pol)) { return @{ gate='policy'; status='SKIP'; details='policies/opa not present'; evidence='' } }
  $raw = & conftest test --policy $pol --output json $file 2>&1
  $raw | Out-File -Encoding utf8 $outPath
  $status = 'PASS'
  try {
    $j = $raw | Out-String | ConvertFrom-Json -ErrorAction Stop
    $fails = 0
    foreach ($r in $j) { if ($r.failures) { $fails += ($r.failures | Measure-Object).Count } }
    if ($fails -gt 0) { $status = 'FAIL' }
  } catch { if ($raw -match 'FAIL') { $status='FAIL' } }
  return @{ gate='policy'; status=$status; details='conftest run'; evidence=(Get-RelPath $outAbs $outPath) }
}

function Gate-DryRun([string]$file, [string]$evidDir) {
  if (-not $hasKubectl) { return @{ gate='dryrun'; status='SKIP'; details='kubectl not found'; evidence='' } }
  New-Dir $evidDir
  $outPath = Join-Path $evidDir 'dryrun.txt'
  $stderrPath = Join-Path $evidDir 'dryrun.err.txt'
  $cmd = {
    kubectl apply --dry-run=server -f $using:file
  }
  $out = ""; $err = ""; $exit = 0
  try { $out = & $cmd *>&1; $exit = if ($LASTEXITCODE) { $LASTEXITCODE } else { 0 } } catch { $err = $_ | Out-String; $exit = 1 }
  $out | Out-File -Encoding utf8 $outPath
  if ($err) { $err | Out-File -Encoding utf8 $stderrPath }
  $status = if ($exit -eq 0) { 'PASS' } else { 'FAIL' }
  return @{ gate='dryrun'; status=$status; details='kubectl apply --dry-run=server'; evidence=(Get-RelPath $outAbs $outPath) }
}

function Gate-Sandbox([string]$file, [string]$evidDir, [string]$ns) {
  if (-not $EnableSandbox) { return @{ gate='sandbox'; status='SKIP'; details='sandbox disabled'; evidence='' } }
  if (-not $hasKubectl) { return @{ gate='sandbox'; status='SKIP'; details='kubectl not found'; evidence='' } }
  New-Dir $evidDir
  $applyOut = Join-Path $evidDir 'apply.txt'
  try {
    $nsExists = $false
    try { kubectl get ns $ns *>$null 2>&1; $nsExists = ($LASTEXITCODE -eq 0) } catch { $nsExists = $false }
    if (-not $nsExists) { try { kubectl create ns $ns *>$null 2>&1 } catch {} }
  } catch {}
  $cmd = { kubectl apply -n $using:ns -f $using:file }
  $out = & $cmd *>&1; $exit = if ($LASTEXITCODE) { $LASTEXITCODE } else { 0 }
  $out | Out-File -Encoding utf8 $applyOut
  $status = if ($exit -eq 0) { 'PASS' } else { 'FAIL' }
  return @{ gate='sandbox'; status=$status; details=('kubectl apply -n ' + $ns); evidence=(Get-RelPath $outAbs $applyOut) }
}

function Gate-Health([string]$evidDir, [string]$ns, [int]$timeout) {
  if (-not $EnableSandbox) { return @{ gate='health'; status='SKIP'; details='sandbox disabled'; evidence='' } }
  if (-not $hasKubectl) { return @{ gate='health'; status='SKIP'; details='kubectl not found'; evidence='' } }
  New-Dir $evidDir
  $status = 'PASS'
  $ev = @()
  # Best-effort: wait for all deployments/statefulsets/daemonsets in the namespace
  $rolloutTimeout = "--timeout=${timeout}s"
  try {
    $d = & kubectl -n $ns get deploy -o name 2>$null
    foreach ($name in $d) {
      $out = & kubectl -n $ns rollout status $name $rolloutTimeout 2>&1
      $ev += @{ kind='Deployment'; name=$name; output=$out }
      if ($LASTEXITCODE -ne 0) { $status = 'FAIL' }
    }
  } catch { $status = 'FAIL'; $ev += @{ error = ($_ | Out-String) } }
  $evPath = Join-Path $evidDir 'health.json'
  Write-Json $ev $evPath
  return @{ gate='health'; status=$status; details='rollout status'; evidence=(Get-RelPath $outAbs $evPath) }
}

function Gate-Network([string]$evidDir, [string]$ns) {
  if (-not $EnableSandbox) { return @{ gate='network'; status='SKIP'; details='sandbox disabled'; evidence='' } }
  if (-not $hasKubectl) { return @{ gate='network'; status='SKIP'; details='kubectl not found'; evidence='' } }
  # Stub: collect services present as evidence
  New-Dir $evidDir
  $svcJson = Join-Path $evidDir 'services.json'
  try { $j = kubectl -n $ns get svc -o json | ConvertFrom-Json } catch { $j = $null }
  if ($j) { Write-Json $j $svcJson; return @{ gate='network'; status='PASS'; details='services listed'; evidence=(Get-RelPath $outAbs $svcJson) } }
  else { return @{ gate='network'; status='SKIP'; details='no services or cannot list'; evidence='' } }
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
      return @{ gate='e2e'; status='PASS'; details='custom e2e script'; evidence=(Get-RelPath $outAbs $ev) }
    } catch { $ev = Join-Path $evidDir 'e2e.err.txt'; ($_ | Out-String) | Out-File -Encoding utf8 $ev; return @{ gate='e2e'; status='FAIL'; details='custom e2e failed'; evidence=(Get-RelPath $outAbs $ev) } }
  }
  return @{ gate='e2e'; status='SKIP'; details='no e2e script'; evidence='' }
}

# Enumerate files
$files = Get-ChildItem -LiteralPath $inputAbs -Recurse -Include *.yaml,*.yml | Where-Object { -not $_.PSIsContainer }
if (-not $files) { Write-Error "No YAML manifests found in $inputAbs" }

# Optionally ensure namespace up-front when sandboxing
if ($EnableSandbox -and $hasKubectl) {
  try {
    $nsExists = $false
    try { kubectl get ns $Namespace *>$null 2>&1; $nsExists = ($LASTEXITCODE -eq 0) } catch { $nsExists = $false }
    if (-not $nsExists) { try { kubectl create ns $Namespace *>$null 2>&1 } catch {} }
  } catch {}
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
  $g1 = ($results | Where-Object { $_.gate -eq 'schema' }).status
  $g2 = ($results | Where-Object { $_.gate -eq 'policy' }).status
  $g3 = ($results | Where-Object { $_.gate -eq 'dryrun' }).status
  if (-not ($g1 -eq 'PASS' -and $g2 -eq 'PASS' -and $g3 -eq 'PASS')) { $overall = 'FAIL' }

  $perFile = @{ file=$fRel; file_sha256=$sha; gates=$results; overall=$overall }
  $aggregate += $perFile
  Write-Json $perFile (Join-Path $reports ("$fid.json"))
}

# Aggregate proof
$passList = @($aggregate | Where-Object { $_.overall -eq 'PASS' })
$failList = @($aggregate | Where-Object { $_.overall -eq 'FAIL' })
$summary = @{ PASS = $passList.Count; FAIL = $failList.Count }

$kubectx = $null
try { if ($hasKubectl) { $kubectx = (kubectl config current-context) } } catch {}

$proof = [ordered]@{
  version = '1.0'
  generated_at_utc = ([DateTime]::UtcNow.ToString('o'))
  input_dir = (Get-RelPath $root $inputAbs)
  output_dir = (Get-RelPath $root $outAbs)
  kube_context = $kubectx
  namespace = if ($EnableSandbox) { $Namespace } else { $null }
  tools = $toolVersions
  files = $aggregate
  summary = $summary
}

# Canonical string for signing
$canon = ($proof | ConvertTo-Json -Depth 12 -Compress)
if ($SigningKey) {
  $sig = Text-HmacSha256 $canon $SigningKey
  $proof.signature = @{ alg='HMAC-SHA256'; value=$sig }
} else {
  $digest = Text-Sha256 $canon
  $proof.signature = @{ alg='SHA256'; value=$digest }
}

$proofPath = Join-Path $outAbs 'safe_fix_proof.json'
Write-Json $proof $proofPath

Write-Host "Validation complete. Proof:" (Get-RelPath $root $proofPath)
