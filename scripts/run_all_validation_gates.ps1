param(
    [switch]$Run,
    [string]$FilterFolder = "",
    [switch]$UseToolSubfolder,
    [switch]$RequireSchema,
    [string]$FailOn = "FAIL",
    [int]$DelayBetween = 1
)

$root = "Detection/output"
$folders = Get-ChildItem -Path $root -Directory

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

        if ($UseToolSubfolder) {
            $fixedDir = Join-Path $f.FullName $toolName
            if (-not (Test-Path $fixedDir)) {
                Write-Host ("Skipping {0}/{1}: no fixed-dir {2}" -f $f.Name, $toolName, $fixedDir)
                continue
            }
        }
        else {
            $fixedDir = $f.FullName
        }

        $outDir = Join-Path $fixedDir 'validation'
        if ($Run) {
            $cmd = @(
                'python', 'Validations/validation_gates.py',
                '--tests-dir', "$($f.FullName)",
                '--fixed-dir', "$fixedDir",
                '--payload', "$($p.FullName)",
                '--out-dir', "$outDir",
                '--fail-on', "$FailOn"
            )
            if ($RequireSchema) { $cmd += '--require-schema' }

            Write-Host "Running validation for $($f.Name)/$toolName -> $outDir"
            $exe = $cmd[0]
            $args = $cmd[1..($cmd.Count - 1)]
            # Use call operator with argument splatting to preserve spaces inside each arg
            & $exe @args
            Write-Host "Finished validation for $($f.Name)/$toolName"
            Start-Sleep -Seconds $DelayBetween
        }
        else {
            Write-Host "Dry run: would validate $($f.Name)/$toolName -> $outDir"
        }
    }
}
Write-Host "Done. Use -Run to actually execute the validation runs."