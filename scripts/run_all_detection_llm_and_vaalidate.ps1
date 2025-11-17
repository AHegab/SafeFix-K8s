param(
    [switch]$Run,
    [switch]$UsePayloadFolder,
    [switch]$UseToolSubfolder,
    [string]$FilterFolder = "",
    [int]$DelayBetween = 2,
    [switch]$ValidationOnly,
    [switch]$RunLLMFirst,
    [switch]$RequireSchema,
    [string]$FailOn = "FAIL"
)

# This script runs the LLM orchestrator for each llm payload found under Detection/output
# then validates the fixed outputs and writes reports under a subfolder named 'validation'

$root = "Detection/output"
$folders = Get-ChildItem -Path $root -Directory

if ($Run -and $RunLLMFirst -and -not $ValidationOnly) {
    Write-Host "Running orchestrator first for all payloads (RunLLMFirst=true). This will create tool outputs and SECURED_* files."
    foreach ($f in $folders) {
        $payloadDir = Join-Path $f.FullName 'payload'
        if (-not (Test-Path $payloadDir)) { continue }
        $payloads = Get-ChildItem -Path $payloadDir -Filter 'llm_payload_raw_*.json' -File -ErrorAction SilentlyContinue
        if (-not $payloads) { continue }

        foreach ($p in $payloads) {
            $fileName = $p.Name
            $toolName = $fileName -replace '^llm_payload_raw_', '' -replace '\.json$',''
            if ($UsePayloadFolder) {
                $outDir = $f.FullName
            }
            elseif ($UseToolSubfolder) {
                $outDir = Join-Path $f.FullName $toolName
                if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
            }
            else {
                $outDir = Join-Path "output/llm_fixes" $toolName
            }

            Write-Host "Orchestrator-first: Processing $toolName (payload=$($p.FullName)) → out=$outDir"
            python LLMs/multi_llm_orchestrator.py --payload "$($p.FullName)" --tests-dir "$($f.FullName)" --out-dir "$outDir"
            Start-Sleep -Seconds $DelayBetween
        }
    }
    Write-Host "Orchestrator-first pass complete. Proceeding to validation loop."
}

foreach ($f in $folders) {
    if ($FilterFolder -and ($f.Name -ne $FilterFolder)) {
        continue
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
            $outDir = $f.FullName
        }
        elseif ($UseToolSubfolder) {
            $outDir = Join-Path $f.FullName $toolName
            if (-not (Test-Path $outDir)) {
                New-Item -ItemType Directory -Path $outDir | Out-Null
            }
        }
        else {
            $outDir = Join-Path "output/llm_fixes" $toolName
        }

        # Orchestrator dry-run text
        Write-Host "DRY: Would run orchestrator for $($f.Name)/$toolName -> $outDir"

        if ($Run -and -not $ValidationOnly) {
            Write-Host "Running orchestrator for $($f.Name)/$toolName -> $outDir"
            python LLMs/multi_llm_orchestrator.py --payload "$($p.FullName)" --tests-dir "$($f.FullName)" --out-dir "$outDir"
            Start-Sleep -Seconds $DelayBetween
            Write-Host "Finished orchestrator for $($f.Name)/$toolName"
        }

        # Prepare validation fixed-dir. If we used tool subfolder, validate the tool subfolder; otherwise validate the detection root
        if ($UseToolSubfolder) { $fixedDir = $outDir } else { $fixedDir = $f.FullName }

        # OutDir for validation will be 'validation' under fixedDir
        $validationOut = Join-Path $fixedDir 'validation'

        # If validation only was requested, don't run the orchestrator — just attempt validation
        if ($ValidationOnly) {
            # Ensure we have content to validate (SECURED_* files or DIFF/SECURED). If not, skip.
            $securedFiles = Get-ChildItem -Path $fixedDir -Filter 'SECURED_*' -File -Recurse -ErrorAction SilentlyContinue
            if (-not $securedFiles) {
                Write-Host "Skipping validation for $($f.Name)/$toolName because no SECURED_* files were found under $fixedDir"
                continue
            }
        }

        if ($Run) {
            Write-Host "Running validation for $($f.Name)/$toolName -> $validationOut"
            $cmd = @(
                'python', 'Validations/validation_gates.py',
                '--tests-dir', "$($f.FullName)",
                '--fixed-dir', "$fixedDir",
                '--payload', "$($p.FullName)",
                '--out-dir', "$validationOut",
                '--fail-on', "$FailOn"
            )
            if ($RequireSchema) { $cmd += '--require-schema' }

            $exe = $cmd[0]
            $args = $cmd[1..($cmd.Count - 1)]
            & $exe @args
            Write-Host "Finished validation for $($f.Name)/$toolName"
            Start-Sleep -Seconds $DelayBetween
        }
        else {
            Write-Host "DRY: Would validate $($f.Name)/$toolName -> $validationOut"
        }
    }
}

Write-Host "Done. Use -Run to actually execute the LLM and validation runs."
