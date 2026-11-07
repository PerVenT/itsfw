<#
.SYNOPSIS
    Installs it's.fw on Windows into ~/.local/bin/itsfw.exe and configures User PATH.
.DESCRIPTION
    Builds the binary via container (Podman in WSL) or uses an existing build,
    copies the executable to ~/.local/bin/itsfw.exe, adds ~/.local/bin to User PATH if missing,
    and checks administrator privilege requirements for Windows Filtering Platform (WFP).
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "        it's.fw Windows Installer         " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$ScriptsDir = $PSScriptRoot
$ProjectRoot = Split-Path $ScriptsDir -Parent
$TargetDir = Join-Path $HOME ".local\bin"
$TargetExe = Join-Path $TargetDir "itsfw.exe"
$BuiltExe = Join-Path $ProjectRoot "target\x86_64-pc-windows-gnu\release\itsfw.exe"
if (-not (Test-Path $BuiltExe)) {
    $LegacyBuiltExe = Join-Path $ProjectRoot "target\x86_64-pc-windows-gnu\release\its-fw.exe"
    if (Test-Path $LegacyBuiltExe) {
        $BuiltExe = $LegacyBuiltExe
    }
}

# 1. Build if requested and not skipped
if (-not $SkipBuild) {
    Write-Host "[1/4] Building Windows release binary via Makefile..." -ForegroundColor Yellow
    $WslRoot = ($ProjectRoot -replace '\\', '/') -replace '^([A-Za-z]):', { '/mnt/' + $_.Groups[1].Value.ToLower() }
    try {
        wsl bash -c "cd '$WslRoot' && make build-windows"
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "make build-windows returned non-zero exit code ($LASTEXITCODE)."
        }
    } catch {
        Write-Warning "Could not run container build via WSL: $_"
    }
}

# 2. Check for binary
Write-Host "[2/4] Verifying binary..." -ForegroundColor Yellow
if (-not (Test-Path $BuiltExe)) {
    if (Test-Path $TargetExe) {
        Write-Host "    Found existing installed binary at $TargetExe." -ForegroundColor DarkGray
    } else {
        Write-Error "Binary not found at $BuiltExe. Please run 'make build-windows' first or omit -SkipBuild."
    }
}

# 3. Stop running itsfw / its-fw instance before updating file
$Running = Get-Process itsfw, its-fw -ErrorAction SilentlyContinue
if ($Running) {
    foreach ($proc in $Running) {
        Write-Host "==> Stopping running process $($proc.ProcessName) (PID: $($proc.Id))..." -ForegroundColor Yellow
        Stop-Process -Id $proc.Id -Force
    }
    Start-Sleep -Milliseconds 500
}

# 4. Copy binary to ~/.local/bin/itsfw.exe
if (Test-Path $BuiltExe) {
    if (-not (Test-Path $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }
    Write-Host "[3/4] Installing it's.fw to $TargetExe..." -ForegroundColor Yellow
    if (-not $WhatIf) {
        Copy-Item $BuiltExe $TargetExe -Force
    }
}

# 5. Clean up redundant old locations if present
$OldRootExes = @(
    (Join-Path $ProjectRoot "itsfw.exe"),
    (Join-Path $ProjectRoot "its-fw.exe"),
    (Join-Path $TargetDir "its-fw.exe")
)
foreach ($old in $OldRootExes) {
    if (Test-Path $old) {
        Write-Host "    Cleaning up redundant binary $old..." -ForegroundColor DarkGray
        Remove-Item $old -Force -ErrorAction SilentlyContinue
    }
}

# 6. Ensure ~/.local/bin is in User PATH
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$TargetDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$TargetDir", "User")
    $env:Path = "$env:Path;$TargetDir"
    Write-Host "    Added $TargetDir to User PATH." -ForegroundColor Green
} else {
    Write-Host "    $TargetDir is already in User PATH." -ForegroundColor DarkGray
}

# 7. Privilege check & launch guidance
Write-Host "[4/4] Verifying administrator capabilities..." -ForegroundColor Yellow
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "     it's.fw installed successfully!      " -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Location: $TargetExe"
if ($IsAdmin) {
    Write-Host "Launch immediately by typing: itsfw" -ForegroundColor Cyan
} else {
    Write-Host "NOTE: it's.fw manages Windows Filtering Platform (WFP) rules and requires elevation." -ForegroundColor Yellow
    Write-Host "To launch with administrative privileges:" -ForegroundColor Yellow
    Write-Host "  powershell -Command ""Start-Process itsfw -Verb RunAs""" -ForegroundColor Cyan
    Write-Host "Or open Windows Terminal as Administrator and run 'itsfw'." -ForegroundColor Cyan
}
