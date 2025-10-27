# install-rbac-police.ps1
# Installation script for rbac-police (Windows)
# Builds from source or downloads pre-built binary

param(
    [switch]$BuildFromSource,
    [string]$Version = "latest"
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  rbac-police Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$GITHUB_REPO = "PaloAltoNetworks/rbac-police"
$INSTALL_DIR = "C:\Program Files\rbac-police"
$BIN_DIR = "$INSTALL_DIR\bin"
$LIB_DIR = "$INSTALL_DIR\lib"

# Check for Go if building from source
if ($BuildFromSource) {
    Write-Host "[Build Mode] Building from source..." -ForegroundColor Yellow
    
    # Check if Go is installed
    $goCmd = $null
    try {
        $goCmd = Get-Command go -ErrorAction Stop
        $goVersion = & go version
        Write-Host "  Found Go: $goVersion" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Go is not installed" -ForegroundColor Red
        Write-Host "Please install Go from: https://go.dev/doc/install" -ForegroundColor Yellow
        Write-Host "Or run without -BuildFromSource to download pre-built binary" -ForegroundColor Yellow
        exit 1
    }
    
    # Navigate to rbac-police directory
    $rbacPoliceDir = Join-Path $PSScriptRoot "rbac-police"
    if (-not (Test-Path $rbacPoliceDir)) {
        Write-Host "ERROR: rbac-police directory not found at: $rbacPoliceDir" -ForegroundColor Red
        Write-Host "Expected location: SafeFixK8s\rbac-police\" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "  Building rbac-police from: $rbacPoliceDir" -ForegroundColor Gray
    Push-Location $rbacPoliceDir
    
    try {
        Write-Host "  Running: go build..." -ForegroundColor Cyan
        & go build -o rbac-police.exe
        
        if (-not (Test-Path "rbac-police.exe")) {
            throw "Build failed - executable not created"
        }
        
        Write-Host "  Build successful!" -ForegroundColor Green
        $builtExe = Resolve-Path "rbac-police.exe"
        
    } catch {
        Pop-Location
        Write-Host "ERROR: Build failed: $_" -ForegroundColor Red
        exit 1
    }
    
    Pop-Location
    
} else {
    Write-Host "[Download Mode] Downloading pre-built binary..." -ForegroundColor Yellow
    
    # Get latest release info
    try {
        Write-Host "  Fetching release information..." -ForegroundColor Gray
        $releaseInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/$GITHUB_REPO/releases/latest"
        $latestTag = $releaseInfo.tag_name
        Write-Host "  Latest version: $latestTag" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to fetch release information" -ForegroundColor Red
        Write-Host "  $_" -ForegroundColor Red
        Write-Host "Try using -BuildFromSource to build locally" -ForegroundColor Yellow
        exit 1
    }
    
    # Download binary
    $OS = "windows"
    $ARCH = "amd64"
    $BINARY_NAME = "rbac-police_${latestTag}_${OS}_${ARCH}.exe"
    $DOWNLOAD_URL = "https://github.com/$GITHUB_REPO/releases/download/${latestTag}/${BINARY_NAME}"
    
    $tempDir = Join-Path $env:TEMP "rbac-police-install"
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    
    $downloadPath = Join-Path $tempDir "rbac-police.exe"
    
    Write-Host "  Downloading from: $DOWNLOAD_URL" -ForegroundColor Gray
    try {
        Invoke-WebRequest -Uri $DOWNLOAD_URL -OutFile $downloadPath -UseBasicParsing
        Write-Host "  Downloaded successfully" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to download binary" -ForegroundColor Red
        Write-Host "  $_" -ForegroundColor Red
        Write-Host "  URL: $DOWNLOAD_URL" -ForegroundColor Yellow
        Write-Host "Try using -BuildFromSource to build locally" -ForegroundColor Yellow
        exit 1
    }
    
    $builtExe = $downloadPath
}

# Install
Write-Host "`n[Installation]" -ForegroundColor Cyan

# Create installation directories
Write-Host "  Creating directories..." -ForegroundColor Gray
if (Test-Path $INSTALL_DIR) {
    Write-Host "  Removing existing installation..." -ForegroundColor Gray
    Remove-Item -Path $INSTALL_DIR -Recurse -Force
}

New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
New-Item -ItemType Directory -Path $BIN_DIR -Force | Out-Null
New-Item -ItemType Directory -Path $LIB_DIR -Force | Out-Null

# Copy executable
$targetExe = Join-Path $BIN_DIR "rbac-police.exe"
Copy-Item -Path $builtExe -Destination $targetExe -Force
Write-Host "  Installed executable: $targetExe" -ForegroundColor Green

# Copy policy library
$libSource = Join-Path $PSScriptRoot "rbac-police\lib"
if (Test-Path $libSource) {
    Write-Host "  Copying policy library..." -ForegroundColor Gray
    Copy-Item -Path "$libSource\*" -Destination $LIB_DIR -Recurse -Force
    Write-Host "  Policy library copied to: $LIB_DIR" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Policy library not found at: $libSource" -ForegroundColor Yellow
    Write-Host "  You may need to download policies from: https://github.com/$GITHUB_REPO" -ForegroundColor Yellow
}

# Add to PATH
Write-Host "`n[PATH Configuration]" -ForegroundColor Cyan
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")

if ($currentPath -notlike "*$BIN_DIR*") {
    Write-Host "  Adding to system PATH..." -ForegroundColor Gray
    try {
        $newPath = $currentPath + ";" + $BIN_DIR
        [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
        Write-Host "  PATH updated successfully!" -ForegroundColor Green
        Write-Host "  Restart terminal for changes to take effect." -ForegroundColor Yellow
    } catch {
        Write-Host "  ERROR: Failed to update PATH" -ForegroundColor Red
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
Write-Host "  Policy Library: $LIB_DIR" -ForegroundColor White
Write-Host ""

# Verify installation
Write-Host "Verifying installation..." -ForegroundColor Cyan
try {
    $version = & $targetExe --help 2>&1 | Select-Object -First 1
    Write-Host "  Installation verified!" -ForegroundColor Green
} catch {
    Write-Host "  WARNING: Could not verify installation" -ForegroundColor Yellow
}

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "  1. Restart your terminal or run:" -ForegroundColor White
Write-Host "     `$env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine')" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. For cluster-based analysis (requires kubectl access):" -ForegroundColor White
Write-Host "     rbac-police eval `"$LIB_DIR`"" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. For offline manifest analysis:" -ForegroundColor White
Write-Host "     rbac-police collect -o rbac-data.json" -ForegroundColor Gray
Write-Host "     rbac-police eval `"$LIB_DIR`" rbac-data.json" -ForegroundColor Gray
Write-Host ""
Write-Host "  4. Integrate with SafeFixK8s:" -ForegroundColor White
Write-Host "     cd detection" -ForegroundColor Gray
Write-Host "     . .\detectors.ps1" -ForegroundColor Gray
Write-Host "     Det-RBACPolice '..\tests'" -ForegroundColor Gray
Write-Host ""
Write-Host "Documentation:" -ForegroundColor Cyan
Write-Host "  https://github.com/$GITHUB_REPO" -ForegroundColor White
Write-Host ""
