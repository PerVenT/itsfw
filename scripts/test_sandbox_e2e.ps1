# scripts/test_sandbox_e2e.ps1
# Скрипт автоматичної E2E перевірки it's.fw у середовищі Windows Sandbox

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [it's.fw] Windows Sandbox E2E Verification Environment " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Перевірка статусу служби Windows Defender Firewall
$svc = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "[✓] Windows Defender Firewall service (MpsSvc) is RUNNING" -ForegroundColor Green
} else {
    Write-Host "[!] Starting Windows Defender Firewall service..." -ForegroundColor Yellow
    Start-Service -Name MpsSvc
}

# 2. Перевірка наявності скомпільованого бінарника (Release або Debug)
$binaryPath = "C:\its.fw\target\x86_64-pc-windows-gnu\release\itsfw.exe"
if (-not (Test-Path $binaryPath)) {
    $binaryPath = "C:\its.fw\target\x86_64-pc-windows-gnu\debug\itsfw.exe"
}
if (-not (Test-Path $binaryPath)) {
    $binaryPath = "C:\its.fw\target\x86_64-pc-windows-gnu\release\its-fw.exe"
}
if (Test-Path $binaryPath) {
    Write-Host "[✓] Binary found at $binaryPath" -ForegroundColor Green
} else {
    Write-Host "[!] Binary not found at $binaryPath" -ForegroundColor Yellow
}

# 2.1 Автоматичний прогін unit-тестів у безпечному середовищі Sandbox
$testBinary = Get-ChildItem -Path "C:\its.fw\target\x86_64-pc-windows-gnu\debug\deps" -Filter "itsfw-*.exe" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $testBinary) {
    $testBinary = Get-ChildItem -Path "C:\its.fw\target\x86_64-pc-windows-gnu\debug\deps" -Filter "its_fw-*.exe" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
}
if ($testBinary) {
    Write-Host "`n[i] Running isolated unit tests in Sandbox:" -ForegroundColor Cyan
    & $testBinary.FullName
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[✓] All unit tests PASSED cleanly inside Sandbox!" -ForegroundColor Green
    } else {
        Write-Host "[✗] Unit tests FAILED with code $LASTEXITCODE" -ForegroundColor Red
    }
}

# 3. Перевірка поточного профілю брандмауера
Write-Host "`n[i] Current Windows Firewall Outbound Policy:" -ForegroundColor Cyan
netsh advfirewall show allprofiles firewallpolicy

# 4. Перевірка прав адміністратора в Sandbox
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "[✓] Running with full Administrator privileges" -ForegroundColor Green
} else {
    Write-Host "[!] Warning: Not running as Administrator" -ForegroundColor Yellow
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " E2E сценарії готові до виконання:" -ForegroundColor Yellow
Write-Host "   1. Запуск its.fw TUI для живого моніторингу WFP ядра"
Write-Host "   2. Перевірка перехоплення дроп-пакетів (Knocking)"
Write-Host "   3. Перевірка застосування та видалення правил (a/d/l)"
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "`nДля запуску TUI виконайте команду:" -ForegroundColor White
Write-Host "  & '$binaryPath'`n" -ForegroundColor Green
