<#
.SYNOPSIS
    Generates a 13-second choreographed animated demo (GIF & MP4) of it's.fw.
.DESCRIPTION
    Creates vector SVG keyframes matching the exact Monokai Pro Ristretto TUI layout,
    then compiles them via FFmpeg into an optimized assets/demo.gif and assets/demo.mp4.
    Showcases:
      1. Zero-Trust outbound monitoring
      2. Intercepting a knocking background app (telemetry_tracker.exe)
      3. Applying a permanent block with [D]
      4. Smart Port Inspector (/:) and Kill PID [k]
#>
[CmdletBinding()]
param(
    [int]$Fps = 15,
    [int]$Width = 960,
    [int]$Height = 540
)

$ErrorActionPreference = "Stop"

$ProjectRoot = (Get-Item $PSScriptRoot).Parent.FullName
$AssetsDir = Join-Path $ProjectRoot "assets"
$TempDir = Join-Path $ProjectRoot "target\demo_frames"

if (-not (Test-Path $AssetsDir)) { New-Item -ItemType Directory -Path $AssetsDir -Force | Out-Null }
if (-not (Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir -Force | Out-Null }

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "     it's.fw Animated Demo Generator      " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# SVG Templates Generator
# ------------------------------------------------------------------------------
function Get-TerminalSvg {
    param(
        [string]$SceneTitle,
        [string]$FilterActive,
        [string]$TableRowsXml,
        [string]$ProcessDetailsXml,
        [string]$OverlayXml,
        [string]$NotificationBannerXml
    )

    return @"
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 $Width $Height" width="$Width" height="$Height">
  <defs>
    <filter id="shadow" x="-5%" y="-5%" width="110%" height="110%">
      <feDropShadow dx="0" dy="12" stdDeviation="16" flood-color="#000000" flood-opacity="0.6"/>
    </filter>
  </defs>

  <!-- Canvas Backdrop (Ristretto Dark) -->
  <rect width="$Width" height="$Height" fill="#181414"/>

  <!-- Terminal Window with Drop Shadow -->
  <g filter="url(#shadow)">
    <rect x="24" y="20" width="912" height="500" rx="14" fill="#2c2525" stroke="#403e41" stroke-width="2"/>
    
    <!-- Titlebar -->
    <path d="M 24 34 C 24 26 30 20 38 20 L 922 20 C 930 20 936 26 936 34 L 936 56 L 24 56 Z" fill="#211b1b"/>
    <circle cx="46" cy="38" r="6" fill="#fd6883"/>
    <circle cx="66" cy="38" r="6" fill="#f9cc6c"/>
    <circle cx="86" cy="38" r="6" fill="#adda78"/>
    
    <text x="480" y="42" font-family="'JetBrains Mono', 'Fira Code', 'Consolas', monospace" font-size="13" font-weight="600" fill="#72696a" text-anchor="middle">
      Terminal — itsfw (Administrator)
    </text>
  </g>

  <!-- TUI App Header -->
  <g transform="translate(42, 74)">
    <text x="0" y="14" font-family="'JetBrains Mono', monospace" font-size="14" font-weight="700" fill="#f9cc6c">it's.fw</text>
    <text x="64" y="14" font-family="'JetBrains Mono', monospace" font-size="14" fill="#5b5353">│</text>
    <rect x="80" y="0" width="76" height="18" rx="4" fill="#5b5353"/>
    <text x="88" y="13" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700" fill="#adda78">● ADMIN</text>
    <text x="166" y="14" font-family="'JetBrains Mono', monospace" font-size="14" fill="#5b5353">│</text>
    <text x="180" y="14" font-family="'JetBrains Mono', monospace" font-size="13" font-weight="600" fill="#fd6883">● Outbound: BLOCK (Zero-Trust Mode)</text>
    <text x="876" y="14" font-family="'JetBrains Mono', monospace" font-size="12" fill="#72696a" text-anchor="end">WFP v0.1.0</text>
  </g>

  <!-- Main Table Frame with Border Title -->
  <g transform="translate(42, 102)">
    <rect width="876" height="248" rx="8" fill="#2c2525" stroke="#5b5353" stroke-width="1.5"/>
    
    <!-- Inset Filter Header (Border Title) -->
    <rect x="20" y="-10" width="460" height="20" rx="4" fill="#2c2525"/>
    $FilterActive

    <!-- Table Columns Header -->
    <g transform="translate(16, 26)" font-family="'JetBrains Mono', monospace" font-size="11.5" font-weight="700" fill="#72696a">
      <text x="0" y="0">APPLICATION</text>
      <text x="250" y="0">STATUS</text>
      <text x="390" y="0">TRAFFIC</text>
      <text x="530" y="0">PORTS / DEST</text>
      <text x="730" y="0">HITS</text>
    </g>
    <line x1="16" y1="36" x2="860" y2="36" stroke="#403e41" stroke-width="1"/>

    <!-- Table Rows -->
    <g transform="translate(16, 58)">
      $TableRowsXml
    </g>
  </g>

  <!-- Bottom Split 50/50 -->
  <g transform="translate(42, 362)">
    <!-- Left Box: Process Details -->
    <g>
      <rect width="428" height="116" rx="8" fill="#2c2525" stroke="#5b5353" stroke-width="1.5"/>
      <rect x="16" y="-10" width="130" height="18" fill="#2c2525"/>
      <text x="22" y="3" font-family="'JetBrains Mono', monospace" font-size="11.5" font-weight="700" fill="#f9cc6c">┌ Process Details ┐</text>
      
      <g transform="translate(16, 26)" font-family="'JetBrains Mono', monospace" font-size="11" fill="#fff1f3">
        $ProcessDetailsXml
      </g>
    </g>

    <!-- Right Box: Recent Activity -->
    <g transform="translate(448, 0)">
      <rect width="428" height="116" rx="8" fill="#2c2525" stroke="#5b5353" stroke-width="1.5"/>
      <rect x="16" y="-10" width="144" height="18" fill="#2c2525"/>
      <text x="22" y="3" font-family="'JetBrains Mono', monospace" font-size="11.5" font-weight="700" fill="#85dacc">┌ Recent Activity (4) ┐</text>
      
      <g transform="translate(16, 26)" font-family="'JetBrains Mono', monospace" font-size="10.5">
        <text x="0" y="0" fill="#72696a">10:42:15  <tspan fill="#adda78">ALLOW</tspan>  chrome.exe -> 142.250.180.206:443</text>
        <text x="0" y="20" fill="#72696a">10:42:18  <tspan fill="#adda78">ALLOW</tspan>  code.exe -> 20.198.118.150:443</text>
        <text x="0" y="40" fill="#72696a">10:42:22  <tspan fill="#fd6883">DROP </tspan>  telemetry_tracker.exe -> 198.51.100.4:8080</text>
        <text x="0" y="60" fill="#72696a">10:42:25  <tspan fill="#adda78">ALLOW</tspan>  wezterm.exe -> 192.168.1.1:22</text>
      </g>
    </g>
  </g>

  <!-- Footer Help Bar -->
  <g transform="translate(42, 496)" font-family="'JetBrains Mono', monospace" font-size="10.5" fill="#72696a">
    <text x="0" y="0">
      <tspan fill="#f9cc6c" font-weight="700">[Tab]</tspan> Mode   <tspan fill="#f9cc6c" font-weight="700">[1-4]</tspan> Filter   <tspan fill="#f9cc6c" font-weight="700">[/]</tspan> Search/Ports   <tspan fill="#adda78" font-weight="700">[A]</tspan> Allow   <tspan fill="#f38d70" font-weight="700">[L]</tspan> LAN   <tspan fill="#fd6883" font-weight="700">[D]</tspan> Deny   <tspan fill="#85dacc" font-weight="700">[T]</tspan> Theme   <tspan fill="#fff1f3" font-weight="700">[Q]</tspan> Quit
    </text>
  </g>

  <!-- Optional Overlays (Modal or Notification Banner) -->
  $OverlayXml
  $NotificationBannerXml
</svg>
"@
}

# ------------------------------------------------------------------------------
# SCENE 1: Baseline Clean Monitoring
# ------------------------------------------------------------------------------
$filterS1 = @"
<text x="26" y="4" font-family="'JetBrains Mono', monospace" font-size="11.5" font-weight="700">
  <tspan fill="#f9cc6c">● [1] All (7)</tspan>
  <tspan fill="#72696a">   [2] Knocking (0)   [3] Allowed (6)   [4] Blocked (1)</tspan>
</text>
"@

$rowsS1 = @"
<g font-family="'JetBrains Mono', monospace" font-size="11.5">
  <!-- Selected Row: chrome.exe -->
  <rect x="-6" y="-14" width="856" height="24" rx="4" fill="#3a3232"/>
  <text x="0" y="2" font-weight="700" fill="#fff1f3">▸ chrome.exe</text>
  <text x="250" y="2" font-weight="700" fill="#adda78">ALLOWED</text>
  <text x="390" y="2" fill="#85dacc">2.4 MB</text>
  <text x="530" y="2" fill="#a8a9eb">443/TCP (Internet)</text>
  <text x="730" y="2" fill="#fff1f3">142</text>

  <!-- Row 2 -->
  <text x="0" y="32" fill="#c3b7b8">  code.exe</text>
  <text x="250" y="32" font-weight="700" fill="#adda78">ALLOWED</text>
  <text x="390" y="32" fill="#85dacc">418 KB</text>
  <text x="530" y="32" fill="#a8a9eb">443/TCP (Internet)</text>
  <text x="730" y="32" fill="#72696a">38</text>

  <!-- Row 3 -->
  <text x="0" y="62" fill="#c3b7b8">  wezterm-gui.exe</text>
  <text x="250" y="62" font-weight="700" fill="#adda78">ALLOWED</text>
  <text x="390" y="62" fill="#85dacc">92 KB</text>
  <text x="530" y="62" fill="#f9cc6c">22/TCP (LAN Only)</text>
  <text x="730" y="62" fill="#72696a">14</text>

  <!-- Row 4 -->
  <text x="0" y="92" fill="#c3b7b8">  spoolsv.exe</text>
  <text x="250" y="92" font-weight="700" fill="#f9cc6c">LAN ONLY</text>
  <text x="390" y="92" fill="#85dacc">12 KB</text>
  <text x="530" y="92" fill="#f9cc6c">LocalSubnet</text>
  <text x="730" y="92" fill="#72696a">5</text>

  <!-- Row 5 -->
  <text x="0" y="122" fill="#c3b7b8">  cortana_agent.exe</text>
  <text x="250" y="122" font-weight="700" fill="#fd6883">BLOCKED</text>
  <text x="390" y="122" fill="#72696a">0 B</text>
  <text x="530" y="122" fill="#72696a">* / ALL</text>
  <text x="730" y="122" fill="#fd6883">19</text>
</g>
"@

$detailsS1 = @"
<text x="0" y="0"><tspan fill="#72696a">App: </tspan><tspan fill="#f9cc6c" font-weight="700">chrome.exe (PID 4120)</tspan>  <tspan fill="#72696a">Parent: </tspan>explorer.exe (PID 1840)</text>
<text x="0" y="20"><tspan fill="#72696a">Path: </tspan><tspan fill="#fff1f3">C:\Program Files\Google\Chrome\Application\chrome.exe</tspan></text>
<text x="0" y="40"><tspan fill="#72696a">Policy: </tspan><tspan fill="#adda78" font-weight="700">ALLOWED</tspan> <tspan fill="#72696a">(Rule group: itsfw)</tspan></text>
<text x="0" y="60"><tspan fill="#72696a">Protocol: </tspan><tspan fill="#85dacc">TCP / 443</tspan>  <tspan fill="#72696a">Remote IP: </tspan>142.250.180.206 (Google LLC)</text>
"@

# ------------------------------------------------------------------------------
# SCENE 2: Knocking Detected! (telemetry_tracker.exe)
# ------------------------------------------------------------------------------
$filterS2 = @"
<text x="26" y="4" font-family="'JetBrains Mono', monospace" font-size="11.5" font-weight="700">
  <tspan fill="#72696a">  [1] All (8)   </tspan>
  <tspan fill="#f9cc6c" font-weight="800">● [2] Knocking (1)</tspan>
  <tspan fill="#72696a">   [3] Allowed (6)   [4] Blocked (1)</tspan>
</text>
"@

$rowsS2 = @"
<g font-family="'JetBrains Mono', monospace" font-size="11.5">
  <!-- Selected Row: telemetry_tracker.exe (KNOCKING FLASH) -->
  <rect x="-6" y="-14" width="856" height="24" rx="4" fill="#4d352b" stroke="#f38d70" stroke-width="1.5"/>
  <text x="0" y="2" font-weight="700" fill="#f38d70">▸ telemetry_tracker.exe</text>
  <text x="250" y="2" font-weight="800" fill="#f9cc6c">KNOCKING !</text>
  <text x="390" y="2" fill="#72696a">0 B</text>
  <text x="530" y="2" fill="#f9cc6c">8080/TCP (198.51.100.4)</text>
  <text x="730" y="2" font-weight="700" fill="#f9cc6c">1</text>

  <!-- Row 2 -->
  <text x="0" y="32" fill="#c3b7b8">  chrome.exe</text>
  <text x="250" y="32" font-weight="700" fill="#adda78">ALLOWED</text>
  <text x="390" y="32" fill="#85dacc">2.4 MB</text>
  <text x="530" y="32" fill="#a8a9eb">443/TCP</text>
  <text x="730" y="32" fill="#72696a">142</text>

  <!-- Row 3 -->
  <text x="0" y="62" fill="#c3b7b8">  code.exe</text>
  <text x="250" y="62" font-weight="700" fill="#adda78">ALLOWED</text>
  <text x="390" y="62" fill="#85dacc">418 KB</text>
  <text x="530" y="62" fill="#a8a9eb">443/TCP</text>
  <text x="730" y="62" fill="#72696a">38</text>

  <!-- Row 4 -->
  <text x="0" y="92" fill="#c3b7b8">  cortana_agent.exe</text>
  <text x="250" y="92" font-weight="700" fill="#fd6883">BLOCKED</text>
  <text x="390" y="92" fill="#72696a">0 B</text>
  <text x="530" y="92" fill="#72696a">* / ALL</text>
  <text x="730" y="92" fill="#fd6883">19</text>
</g>
"@

$detailsS2 = @"
<text x="0" y="0"><tspan fill="#72696a">App: </tspan><tspan fill="#f38d70" font-weight="700">telemetry_tracker.exe (PID 9412)</tspan>  <tspan fill="#72696a">Parent: </tspan>cmd.exe (PID 3304)</text>
<text x="0" y="20"><tspan fill="#72696a">Path: </tspan><tspan fill="#fff1f3">C:\Users\User\AppData\Local\Temp\telemetry_tracker.exe</tspan></text>
<text x="0" y="40"><tspan fill="#72696a">Status: </tspan><tspan fill="#f9cc6c" font-weight="700">KNOCKING / DROPPED</tspan> <tspan fill="#fd6883">(Blocked by Whitelist)</tspan></text>
<text x="0" y="60"><tspan fill="#72696a">Action: </tspan><tspan fill="#fff1f3">Press </tspan><tspan fill="#fd6883" font-weight="700">[D] Deny</tspan><tspan fill="#fff1f3"> or </tspan><tspan fill="#adda78" font-weight="700">[A] Allow</tspan></text>
"@

$bannerS2 = @"
<!-- Floating Hotkey Callout -->
<g transform="translate(240, 290)">
  <rect width="480" height="42" rx="8" fill="#211b1b" stroke="#f9cc6c" stroke-width="2"/>
  <circle cx="24" cy="21" r="6" fill="#f9cc6c"/>
  <text x="42" y="26" font-family="'JetBrains Mono', monospace" font-size="12" font-weight="700" fill="#fff1f3">
    [KNOCKING] Rogue connection trapped! Press <tspan fill="#fd6883">[D] to Block</tspan>
  </text>
</g>
"@

# ------------------------------------------------------------------------------
# SCENE 3: Permanent Block Applied
# ------------------------------------------------------------------------------
$filterS3 = @"
<text x="26" y="4" font-family="'JetBrains Mono', monospace" font-size="11.5" font-weight="700">
  <tspan fill="#f9cc6c">● [1] All (8)   </tspan>
  <tspan fill="#72696a">[2] Knocking (0)   [3] Allowed (6)   </tspan>
  <tspan fill="#fd6883">● [4] Blocked (2)</tspan>
</text>
"@

$rowsS3 = @"
<g font-family="'JetBrains Mono', monospace" font-size="11.5">
  <!-- telemetry_tracker.exe BLOCKED -->
  <rect x="-6" y="-14" width="856" height="24" rx="4" fill="#3a2529"/>
  <text x="0" y="2" font-weight="700" fill="#fd6883">▸ telemetry_tracker.exe</text>
  <text x="250" y="2" font-weight="800" fill="#fd6883">BLOCKED</text>
  <text x="390" y="2" fill="#72696a">0 B</text>
  <text x="530" y="2" fill="#72696a">8080/TCP (Permanent)</text>
  <text x="730" y="2" font-weight="700" fill="#fd6883">3</text>

  <!-- Row 2 -->
  <text x="0" y="32" fill="#c3b7b8">  chrome.exe</text>
  <text x="250" y="32" font-weight="700" fill="#adda78">ALLOWED</text>
  <text x="390" y="32" fill="#85dacc">2.4 MB</text>
  <text x="530" y="32" fill="#a8a9eb">443/TCP</text>
  <text x="730" y="32" fill="#72696a">142</text>

  <!-- Row 3 -->
  <text x="0" y="62" fill="#c3b7b8">  cortana_agent.exe</text>
  <text x="250" y="62" font-weight="700" fill="#fd6883">BLOCKED</text>
  <text x="390" y="62" fill="#72696a">0 B</text>
  <text x="530" y="62" fill="#72696a">* / ALL</text>
  <text x="730" y="62" fill="#fd6883">19</text>
</g>
"@

$detailsS3 = @"
<text x="0" y="0"><tspan fill="#72696a">App: </tspan><tspan fill="#fd6883" font-weight="700">telemetry_tracker.exe (PID 9412)</tspan></text>
<text x="0" y="20"><tspan fill="#72696a">Path: </tspan><tspan fill="#fff1f3">C:\Users\User\AppData\Local\Temp\telemetry_tracker.exe</tspan></text>
<text x="0" y="40"><tspan fill="#72696a">Policy: </tspan><tspan fill="#fd6883" font-weight="700">PERMANENTLY BLOCKED</tspan> <tspan fill="#adda78">(WFP &amp; Netsh synced)</tspan></text>
<text x="0" y="60"><tspan fill="#72696a">Status: </tspan><tspan fill="#85dacc">Zero-Trust enforcement active — 0 bytes leaked</tspan></text>
"@

$bannerS3 = @"
<!-- Success Toast Notification -->
<g transform="translate(230, 290)">
  <rect width="500" height="42" rx="8" fill="#211b1b" stroke="#adda78" stroke-width="2"/>
  <circle cx="24" cy="21" r="6" fill="#adda78"/>
  <text x="42" y="26" font-family="'JetBrains Mono', monospace" font-size="12" font-weight="700" fill="#fff1f3">
    [RULE CREATED] Block rule added to Windows Defender Firewall (itsfw)
  </text>
</g>
"@

# ------------------------------------------------------------------------------
# SCENE 4: Listening Port Inspector (/:) & Kill PID (k)
# ------------------------------------------------------------------------------
$overlayS4 = @"
<!-- Modal Overlay for Listening Port Inspector -->
<g transform="translate(140, 115)">
  <rect width="680" height="220" rx="10" fill="#211b1b" stroke="#f9cc6c" stroke-width="2" filter="url(#shadow)"/>
  
  <rect x="24" y="-12" width="370" height="22" rx="4" fill="#211b1b"/>
  <text x="32" y="3" font-family="'JetBrains Mono', monospace" font-size="12" font-weight="700" fill="#f9cc6c">
    ┌ Open Ports Inspector [/:80, k: Kill PID, Esc] ┐
  </text>

  <g transform="translate(24, 34)" font-family="'JetBrains Mono', monospace" font-size="11.5">
    <text x="0" y="0" fill="#72696a">PORT      PROTO   PID     PROCESS NAME         COMMAND</text>
    <line x1="0" y1="10" x2="632" y2="10" stroke="#403e41" stroke-width="1"/>

    <text x="0" y="34" fill="#85dacc">:80       TCP     1240    nginx.exe            C:\nginx\nginx.exe</text>
    <text x="0" y="64" fill="#85dacc">:3000     TCP     8812    node.exe             C:\nodejs\node.exe</text>
    
    <!-- Selected Rogue Process -->
    <rect x="-8" y="78" width="648" height="26" rx="4" fill="#4d2b2b" stroke="#fd6883" stroke-width="1"/>
    <text x="0" y="96" font-weight="700" fill="#fd6883">:8080     TCP     9940    rogue_daemon.exe     [SUSPICIOUS LISTENER]</text>
  </g>

  <!-- Action banner inside modal -->
  <g transform="translate(110, 172)">
    <rect width="460" height="34" rx="6" fill="#2c2525" stroke="#fd6883" stroke-width="1"/>
    <text x="230" y="22" font-family="'JetBrains Mono', monospace" font-size="11.5" font-weight="700" fill="#fff1f3" text-anchor="middle">
      Press <tspan fill="#fd6883">[k]</tspan> to instantly terminate PID 9940 (rogue_daemon.exe)
    </text>
  </g>
</g>
"@

# Generate the 4 SVG files
$svg1 = Get-TerminalSvg -SceneTitle "Monitoring" -FilterActive $filterS1 -TableRowsXml $rowsS1 -ProcessDetailsXml $detailsS1 -OverlayXml "" -NotificationBannerXml ""
$svg2 = Get-TerminalSvg -SceneTitle "Knocking" -FilterActive $filterS2 -TableRowsXml $rowsS2 -ProcessDetailsXml $detailsS2 -OverlayXml "" -NotificationBannerXml $bannerS2
$svg3 = Get-TerminalSvg -SceneTitle "Blocked" -FilterActive $filterS3 -TableRowsXml $rowsS3 -ProcessDetailsXml $detailsS3 -OverlayXml "" -NotificationBannerXml $bannerS3
$svg4 = Get-TerminalSvg -SceneTitle "PortInspector" -FilterActive $filterS1 -TableRowsXml $rowsS1 -ProcessDetailsXml $detailsS1 -OverlayXml $overlayS4 -NotificationBannerXml ""

Set-Content -Path (Join-Path $TempDir "frame1.svg") -Value $svg1 -Encoding UTF8
Set-Content -Path (Join-Path $TempDir "frame2.svg") -Value $svg2 -Encoding UTF8
Set-Content -Path (Join-Path $TempDir "frame3.svg") -Value $svg3 -Encoding UTF8
Set-Content -Path (Join-Path $TempDir "frame4.svg") -Value $svg4 -Encoding UTF8

Write-Host "[1/3] Generated 4 SVG vector keyframes in target\demo_frames" -ForegroundColor Green

# ------------------------------------------------------------------------------
# Compile Video & GIF via WSL FFmpeg
# ------------------------------------------------------------------------------
$WslTempDir = "/mnt/d/Projects/apps/its.fw/target/demo_frames"
$WslAssetsDir = "/mnt/d/Projects/apps/its.fw/assets"

Write-Host "[2/3] Rendering MP4 video (13 seconds) via FFmpeg..." -ForegroundColor Yellow

# Render MP4 with timing: Frame 1 (3.0s), Frame 2 (3.5s), Frame 3 (3.0s), Frame 4 (3.5s)
$ffmpegMp4 = "ffmpeg -hide_banner -loglevel warning -y " +
    "-loop 1 -t 3.0 -i $WslTempDir/frame1.svg " +
    "-loop 1 -t 3.5 -i $WslTempDir/frame2.svg " +
    "-loop 1 -t 3.0 -i $WslTempDir/frame3.svg " +
    "-loop 1 -t 3.5 -i $WslTempDir/frame4.svg " +
    "-filter_complex ""[0:v][1:v][2:v][3:v]concat=n=4:v=1:a=0,format=yuv420p[v]"" " +
    "-map ""[v]"" -r $Fps -c:v libx264 -crf 20 $WslAssetsDir/demo.mp4"

wsl bash -c $ffmpegMp4
if ($LASTEXITCODE -ne 0) { Write-Error "FFmpeg MP4 encoding failed" }

Write-Host "[3/3] Generating optimized Monokai Pro Ristretto GIF (<1.5 MB)..." -ForegroundColor Yellow

$ffmpegGif = "ffmpeg -hide_banner -loglevel warning -y -i $WslAssetsDir/demo.mp4 " +
    "-vf ""fps=$Fps,scale=${Width}:-1:flags=lanczos,split[s0][s1];[s0]palettegen=stats_mode=diff:max_colors=128[p];[s1][p]paletteuse=dither=bayer:bayer_scale=4"" " +
    "$WslAssetsDir/demo.gif"

wsl bash -c $ffmpegGif
if ($LASTEXITCODE -ne 0) { Write-Error "FFmpeg GIF encoding failed" }

$gifItem = Get-Item (Join-Path $AssetsDir "demo.gif")
$mp4Item = Get-Item (Join-Path $AssetsDir "demo.mp4")

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "        Demo Generation Successful!       " -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ("GIF:  {0} ({1:N1} KB)" -f $gifItem.FullName, ($gifItem.Length / 1KB)) -ForegroundColor Green
Write-Host ("MP4:  {0} ({1:N1} KB)" -f $mp4Item.FullName, ($mp4Item.Length / 1KB)) -ForegroundColor Green
