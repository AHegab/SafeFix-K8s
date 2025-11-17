param(
    [switch]$Run,
    [switch]$UsePayloadFolder,
    [switch]$UseToolSubfolder,
    [string]$FilterFolder = "",
    [int]$DelayBetween = 1
)

# Find all subfolders in Detection/output
$root = "Detection/output"
$folders = Get-ChildItem -Path $root -Directory

foreach ($f in $folders) {
    if ($FilterFolder -and $FilterFolder.Trim()) {
        if ($f.Name -ne $FilterFolder) {
            continue
        }
    }
    $payloadDir = Join-Path $f.FullName 'payload'
    if (-not (Test-Path $payloadDir)) {
        Write-Host "Skipping $($f.Name): no payload folder"
        continue
    }

    $payloads = Get-ChildItem -Path $payloadDir -Filter 'llm_payload_raw_*.json' -File -ErrorAction SilentlyContinue
    if (-not $payloads) {
        Write-Host "No llm payloads found in $($f.Name)"
        continue
    }

    foreach ($p in $payloads) {
        $fileName = $p.Name
        $toolName = $fileName -replace '^llm_payload_raw_', '' -replace '\.json$',''
        if ($UsePayloadFolder) {
            # Place the orchestrator output directly in the detection folder (near the payload)
            # This writes SECURED_*, DIFF_* and REPORT_* files alongside the payload.
            $outDir = $f.FullName
        }
        elseif ($UseToolSubfolder) {
            # Put outputs into a subfolder under the detection output named after the tool
            $outDir = Join-Path $f.FullName $toolName
            if (-not (Test-Path $outDir)) {
                New-Item -ItemType Directory -Path $outDir | Out-Null
            }
        }
        else {
            $outDir = Join-Path "output/llm_fixes" $toolName
        }
        Write-Host "Dry run: Would process $toolName (payload=$($p.FullName)) → out=$outDir"

        if ($Run) {
            Write-Host "Processing $toolName (folder $($f.Name))..."
            python LLMs/multi_llm_orchestrator.py --payload "$($p.FullName)" --tests-dir "$($f.FullName)" --out-dir "$outDir"
            Start-Sleep -Seconds $DelayBetween
            Write-Host "Finished $toolName"
        }
    }
}

Write-Host "Done. Use -Run to actually execute the orchestrator runs."