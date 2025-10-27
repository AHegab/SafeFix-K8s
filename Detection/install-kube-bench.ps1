# install-kube-bench.ps1
# Installation script for kube-bench v0.13.0 on Windows
# This script downloads, verifies, and installs kube-bench

$ErrorActionPreference = "Stop"

# Configuration
$KUBE_BENCH_VERSION = "0.13.0"
$GITHUB_REPO = "aquasecurity/kube-bench"
$INSTALL_DIR = "C:\Program Files\kube-bench"
$BIN_DIR = "$INSTALL_DIR\bin"
$CFG_DIR = "$INSTALL_DIR\cfg"

# URLs
$RELEASE_URL = "https://github.com/$GITHUB_REPO/releases/download/v$KUBE_BENCH_VERSION"
$BINARY_NAME = "kube-bench_${KUBE_BENCH_VERSION}_windows_amd64.tar.gz"
$CHECKSUM_NAME = "kube-bench_${KUBE_BENCH_VERSION}_checksums.txt"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  kube-bench v$KUBE_BENCH_VERSION Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator." -ForegroundColor Yellow
    Write-Host "You may encounter permission issues during installation." -ForegroundColor Yellow
    Write-Host "Consider running PowerShell as Administrator." -ForegroundColor Yellow
    Write-Host ""
    $continue = Read-Host "Continue anyway? (y/n)"
    if ($continue -ne 'y') {
        Write-Host "Installation cancelled." -ForegroundColor Red
        exit 1
    }
}

# Create temporary download directory
$tempDir = Join-Path $env:TEMP "kube-bench-install"
if (Test-Path $tempDir) {
    Write-Host "Cleaning up previous installation attempt..." -ForegroundColor Gray
    Remove-Item -Path $tempDir -Recurse -Force
}
New-Item -ItemType Directory -Path $tempDir | Out-Null
Write-Host "Created temporary directory: $tempDir" -ForegroundColor Gray

try {
    # Step 1: Download binary
    Write-Host "`n[1/6] Downloading kube-bench v$KUBE_BENCH_VERSION..." -ForegroundColor Cyan
    $binaryPath = Join-Path $tempDir $BINARY_NAME
    $binaryUrl = "$RELEASE_URL/$BINARY_NAME"
    Write-Host "  URL: $binaryUrl" -ForegroundColor Gray
    
    try {
        Invoke-WebRequest -Uri $binaryUrl -OutFile $binaryPath -UseBasicParsing
        Write-Host "  Downloaded: $binaryPath" -ForegroundColor Green
        Write-Host "  Size: $([math]::Round((Get-Item $binaryPath).Length / 1MB, 2)) MB" -ForegroundColor Gray
    } catch {
        Write-Host "  ERROR: Failed to download binary" -ForegroundColor Red
        Write-Host "  $_" -ForegroundColor Red
        throw
    }

    # Step 2: Download checksums
    Write-Host "`n[2/6] Downloading checksums..." -ForegroundColor Cyan
    $checksumPath = Join-Path $tempDir $CHECKSUM_NAME
    $checksumUrl = "$RELEASE_URL/$CHECKSUM_NAME"
    Write-Host "  URL: $checksumUrl" -ForegroundColor Gray
    
    try {
        Invoke-WebRequest -Uri $checksumUrl -OutFile $checksumPath -UseBasicParsing
        Write-Host "  Downloaded: $checksumPath" -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: Failed to download checksums" -ForegroundColor Red
        Write-Host "  $_" -ForegroundColor Red
        throw
    }

    # Step 3: Verify checksum
    Write-Host "`n[3/6] Verifying checksum..." -ForegroundColor Cyan
    $checksumContent = Get-Content $checksumPath
    $expectedChecksum = ($checksumContent | Where-Object { $_ -match $BINARY_NAME }).Split()[0]
    
    if (-not $expectedChecksum) {
        Write-Host "  ERROR: Could not find checksum for $BINARY_NAME" -ForegroundColor Red
        Write-Host "  Available checksums:" -ForegroundColor Yellow
        $checksumContent | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        throw "Checksum verification failed"
    }
    
    Write-Host "  Expected SHA256: $expectedChecksum" -ForegroundColor Gray
    
    $actualChecksum = (Get-FileHash -Path $binaryPath -Algorithm SHA256).Hash.ToLower()
    Write-Host "  Actual SHA256:   $actualChecksum" -ForegroundColor Gray
    
    if ($expectedChecksum -eq $actualChecksum) {
        Write-Host "  Checksum verified successfully!" -ForegroundColor Green
    } else {
        Write-Host "  ERROR: Checksum mismatch!" -ForegroundColor Red
        Write-Host "  Expected: $expectedChecksum" -ForegroundColor Red
        Write-Host "  Actual:   $actualChecksum" -ForegroundColor Red
        throw "Checksum verification failed"
    }

    # Step 4: Extract archive
    Write-Host "`n[4/6] Extracting archive..." -ForegroundColor Cyan
    $extractDir = Join-Path $tempDir "extracted"
    New-Item -ItemType Directory -Path $extractDir | Out-Null
    
    # Use tar (available in Windows 10+) to extract tar.gz
    Write-Host "  Extracting with tar..." -ForegroundColor Gray
    try {
        tar -xzf $binaryPath -C $extractDir
        Write-Host "  Extracted successfully" -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: Failed to extract archive" -ForegroundColor Red
        Write-Host "  Make sure you have tar available (Windows 10+)" -ForegroundColor Yellow
        throw
    }
    
    # Find the extracted executable
    $kubeBenchExe = Get-ChildItem -Path $extractDir -Filter "kube-bench.exe" -Recurse -ErrorAction SilentlyContinue
    if (-not $kubeBenchExe) {
        $kubeBenchExe = Get-ChildItem -Path $extractDir -Filter "kube-bench" -Recurse -ErrorAction SilentlyContinue
    }
    
    if (-not $kubeBenchExe) {
        Write-Host "  ERROR: Could not find kube-bench executable in extracted files" -ForegroundColor Red
        Write-Host "  Contents of extracted directory:" -ForegroundColor Yellow
        Get-ChildItem -Path $extractDir -Recurse | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        throw "kube-bench executable not found"
    }
    
    Write-Host "  Found executable: $($kubeBenchExe.FullName)" -ForegroundColor Gray

    # Step 5: Install to target directory
    Write-Host "`n[5/6] Installing to $INSTALL_DIR..." -ForegroundColor Cyan
    
    # Create installation directories
    if (Test-Path $INSTALL_DIR) {
        Write-Host "  Removing existing installation..." -ForegroundColor Gray
        Remove-Item -Path $INSTALL_DIR -Recurse -Force
    }
    
    New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
    New-Item -ItemType Directory -Path $BIN_DIR -Force | Out-Null
    New-Item -ItemType Directory -Path $CFG_DIR -Force | Out-Null
    
    # Copy executable
    $targetExe = Join-Path $BIN_DIR "kube-bench.exe"
    Copy-Item -Path $kubeBenchExe.FullName -Destination $targetExe -Force
    Write-Host "  Installed executable: $targetExe" -ForegroundColor Green
    
    # Copy configuration files if they exist
    $cfgSource = Join-Path $extractDir "cfg"
    if (Test-Path $cfgSource) {
        Write-Host "  Copying configuration files..." -ForegroundColor Gray
        Copy-Item -Path "$cfgSource\*" -Destination $CFG_DIR -Recurse -Force
        Write-Host "  Configuration files copied to: $CFG_DIR" -ForegroundColor Green
    } else {
        Write-Host "  No configuration files found in archive" -ForegroundColor Yellow
        Write-Host "  Configuration files may need to be downloaded separately" -ForegroundColor Yellow
    }

    # Step 6: Add to PATH
    Write-Host "`n[6/6] Configuring PATH..." -ForegroundColor Cyan
    
    # Get current PATH
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    
    if ($currentPath -notlike "*$BIN_DIR*") {
        Write-Host "  Adding $BIN_DIR to system PATH..." -ForegroundColor Gray
        try {
            $newPath = $currentPath + ";" + $BIN_DIR
            [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
            Write-Host "  PATH updated successfully!" -ForegroundColor Green
            Write-Host "  You may need to restart your terminal for changes to take effect." -ForegroundColor Yellow
        } catch {
            Write-Host "  ERROR: Failed to update PATH. You may need to run as Administrator." -ForegroundColor Red
            Write-Host "  Manual step: Add '$BIN_DIR' to your system PATH" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  $BIN_DIR already in PATH" -ForegroundColor Green
    }
    
    # Update current session PATH
    $env:Path = $env:Path + ";" + $BIN_DIR

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "  Installation Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Installation Summary:" -ForegroundColor Cyan
    Write-Host "  Executable:     $targetExe" -ForegroundColor White
    Write-Host "  Configuration:  $CFG_DIR" -ForegroundColor White
    Write-Host "  Version:        v$KUBE_BENCH_VERSION" -ForegroundColor White
    Write-Host ""

    # Step 7: Verify installation
    Write-Host "Verifying installation..." -ForegroundColor Cyan
    try {
        $version = & $targetExe version 2>&1
        Write-Host "  Version check: OK" -ForegroundColor Green
        Write-Host "  $version" -ForegroundColor Gray
    } catch {
        Write-Host "  WARNING: Could not verify version" -ForegroundColor Yellow
        Write-Host "  $_" -ForegroundColor Yellow
    }
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "  1. Restart your terminal or run: `$env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine')" -ForegroundColor White
    Write-Host "  2. Check version: kube-bench version" -ForegroundColor White
    Write-Host "  3. Run basic scan: kube-bench run --targets node" -ForegroundColor White
    Write-Host "  4. For full cluster scan: kube-bench run --targets master,node,etcd,policies" -ForegroundColor White
    Write-Host ""
    Write-Host "Documentation:" -ForegroundColor Cyan
    Write-Host "  https://github.com/aquasecurity/kube-bench" -ForegroundColor White
    Write-Host ""

} catch {
    Write-Host "`nInstallation failed: $_" -ForegroundColor Red
    exit 1
} finally {
    # Cleanup
    Write-Host "Cleaning up temporary files..." -ForegroundColor Gray
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Installation script completed." -ForegroundColor Green
