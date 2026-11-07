<#
.SYNOPSIS
    Generates dynamic sandbox.wsb and launches Windows Sandbox with it's.fw.
.DESCRIPTION
    Because Windows Sandbox requires an absolute path in <HostFolder>, this script
    dynamically discovers the host repository directory and generates sandbox.wsb
    before launching WindowsSandbox.exe.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$ScriptsDir = $PSScriptRoot
$ProjectRoot = (Get-Item $ScriptsDir).Parent.FullName
$WsbPath = Join-Path $ProjectRoot "sandbox.wsb"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   [it's.fw] Launching Windows Sandbox E2E Environment    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Host Project Root: $ProjectRoot" -ForegroundColor DarkGray

$wsbContent = @"
<Configuration>
  <VGpu>Default</VGpu>
  <Networking>Default</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$ProjectRoot</HostFolder>
      <SandboxFolder>C:\its.fw</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -NoExit -File "C:\its.fw\scripts\test_sandbox_e2e.ps1"</Command>
  </LogonCommand>
</Configuration>
"@

Set-Content -Path $WsbPath -Value $wsbContent -Encoding UTF8
Write-Host "[✓] sandbox.wsb dynamically configured with absolute host path." -ForegroundColor Green
Write-Host "[*] Starting Windows Sandbox..." -ForegroundColor Cyan

Start-Process -FilePath $WsbPath
