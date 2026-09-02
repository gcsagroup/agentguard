<#
.SYNOPSIS
  Install the AgentGuard Native Messaging host manifest on Windows (dev / acceptance helper).

.DESCRIPTION
  install-host.sh 的 Windows 等价。Windows 上 Chromium 系浏览器不是扫目录找 manifest,而是读
  注册表:HKCU\Software\<Vendor>\<Browser>\NativeMessagingHosts\<host name> 的默认值 = manifest
  JSON 的**绝对路径**。所以这里做三件事,和 bash 版一一对应:

    1. 把 manifest 模板里的占位符换成真实值,写到 %LOCALAPPDATA%\AgentGuard\native-host\;
    2. 写注册表键,让浏览器找到它;
    3. 在 guard-nm-host.exe 旁边写 allowed-origin —— 宿主默认 fail-closed,没有它就拒绝启动
       (否则任何本地进程都能说这套协议、把伪造的 source_app 写进签名审计)。

  Windows 真机验收 W7 以前记为 BLOCKED (native-messaging-not-installed),原因之一就是
  STORE.md 里写的"Windows 需手工安装 manifest"。这个脚本把手工步骤变成一条命令。

.PARAMETER ExtensionId
  Chrome/Edge 扩展 ID(chrome://extensions 里"加载已解压"后复制)或 Firefox gecko id
  (manifest.firefox.json 里的 agentguard@agentguard.dev)。

.PARAMETER Browser
  chrome(默认)| edge | firefox。

.PARAMETER HostBin
  guard-nm-host.exe 的路径。默认 <repo>\target\debug\guard-nm-host.exe;不存在则先 cargo build。

.PARAMETER Uninstall
  删注册表键与 manifest(不删 host 二进制与 allowed-origin)。

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File install-host.ps1 abcdefghijklmnopabcdefghijklmnop
  powershell -ExecutionPolicy Bypass -File install-host.ps1 -Browser edge abcdefghijklmnopabcdefghijklmnop
  powershell -ExecutionPolicy Bypass -File install-host.ps1 -Browser firefox agentguard@agentguard.dev
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [string]$ExtensionId,
  [ValidateSet('chrome', 'edge', 'firefox')]
  [string]$Browser = 'chrome',
  [string]$HostBin,
  [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = (Resolve-Path (Join-Path $Here '..\..\..')).Path
$HostName = 'com.agentguard.native'

# 注册表键:每个浏览器各一棵。Firefox 也用注册表(HKCU\Software\Mozilla\NativeMessagingHosts)。
$RegKey = switch ($Browser) {
  'chrome'  { "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName" }
  'edge'    { "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName" }
  'firefox' { "HKCU:\Software\Mozilla\NativeMessagingHosts\$HostName" }
}

$ManifestDir = Join-Path $env:LOCALAPPDATA "AgentGuard\native-host\$Browser"
$ManifestOut = Join-Path $ManifestDir "$HostName.json"

if ($Uninstall) {
  if (Test-Path $RegKey) { Remove-Item -Path $RegKey -Recurse -Force; Write-Host "Removed $RegKey" }
  if (Test-Path $ManifestOut) { Remove-Item -Path $ManifestOut -Force; Write-Host "Removed $ManifestOut" }
  exit 0
}

if (-not $ExtensionId) {
  Write-Host "Usage: install-host.ps1 [-Browser chrome|edge|firefox] <extension-id-or-gecko-id> [-HostBin path] [-Uninstall]"
  Write-Host "  chrome/edge: load unpacked, copy the ID from the extensions page"
  Write-Host "  firefox:     use the gecko id from manifest.firefox.json (agentguard@agentguard.dev)"
  exit 1
}

# 输入形状检查:Chromium 扩展 ID 是 32 个 a-p 小写字母;gecko id 含 @。写进 allowed_origins /
# allowed-origin 的串就是宿主以后比对的串,形状不对宁可现在拒绝。
if ($Browser -eq 'firefox') {
  if ($ExtensionId -notmatch '^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$') {
    throw "Firefox gecko id looks wrong: '$ExtensionId' (expected like agentguard@agentguard.dev)"
  }
} elseif ($ExtensionId -notmatch '^[a-p]{32}$') {
  throw "Chromium extension id looks wrong: '$ExtensionId' (expected 32 lowercase letters a-p)"
}

if (-not $HostBin) {
  $HostBin = Join-Path $Root 'target\debug\guard-nm-host.exe'
  if (-not (Test-Path $HostBin)) {
    Write-Host "Building guard-nm-host…"
    & cargo build -p guard-nm-host --manifest-path (Join-Path $Root 'Cargo.toml')
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
  }
}
$HostBin = (Resolve-Path $HostBin).Path
if (-not (Test-Path $HostBin)) { throw "host binary not found: $HostBin" }

New-Item -ItemType Directory -Force -Path $ManifestDir | Out-Null

# manifest:和 bash 版一样从模板替换占位符;JSON 里的反斜杠要转义。
$HostPathJson = $HostBin -replace '\\', '\\\\'
if ($Browser -eq 'firefox') {
  $Template = Get-Content -Raw (Join-Path $Here 'com.agentguard.native.firefox.json')
  $Manifest = $Template -replace 'HOST_PATH_PLACEHOLDER', $HostPathJson -replace 'GECKO_ID_PLACEHOLDER', $ExtensionId
  $OriginLine = $ExtensionId
} else {
  $Template = Get-Content -Raw (Join-Path $Here 'com.agentguard.native.json')
  $Manifest = $Template -replace 'HOST_PATH_PLACEHOLDER', $HostPathJson -replace 'EXTENSION_ID_PLACEHOLDER', $ExtensionId
  $OriginLine = "chrome-extension://$ExtensionId/"
}
# 写出前再解析一遍:占位符替换出的东西必须还是合法 JSON,否则浏览器会静默不连。
$null = $Manifest | ConvertFrom-Json
[System.IO.File]::WriteAllText($ManifestOut, $Manifest, (New-Object System.Text.UTF8Encoding($false)))

# 注册表默认值 = manifest 绝对路径。
New-Item -Path $RegKey -Force | Out-Null
Set-ItemProperty -Path $RegKey -Name '(default)' -Value $ManifestOut

# 宿主自己那份该接受的调用方 origin(见 install-host.sh 的同名注释)。
$AllowedOriginFile = Join-Path (Split-Path -Parent $HostBin) 'allowed-origin'
[System.IO.File]::WriteAllText($AllowedOriginFile, "$OriginLine`n", (New-Object System.Text.UTF8Encoding($false)))

Write-Host "Installed ($Browser): $ManifestOut"
Write-Host "Registry:  $RegKey -> $ManifestOut"
Write-Host "Host:      $HostBin"
Write-Host "Allowed caller: $AllowedOriginFile ($OriginLine)"
Write-Host ""
Write-Host "Verify: restart the browser, open the extension popup, enable desktop forwarding; then"
Write-Host "        check the host's audit log for a record whose source is this extension."
