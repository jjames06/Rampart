# CODEMAP FILE: tools/publish.ps1
# Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
# Role: Publish Rampart.exe + linux/osx zips into dist/, SHA256SUMS, copy docs. Does not bump 1.9.0.
# Called by: Operator on this Windows PC after dotnet test.
# Calls: dotnet publish App and Desktop. Optional sign-windows.ps1.
# Invariants: Unsigned EXE is acceptable. Do not pay for Authenticode unless asked. Copy dist/Rampart.exe to Desktop for Jesse to run.
# Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
# Map: docs/CODEMAP.md — read that file first for the run/load graph.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dotnet = "C:\Program Files\dotnet\dotnet.exe"
if (-not (Test-Path $dotnet)) { $dotnet = "dotnet" }
Set-Location $root
& $dotnet test tests\SiteCheck.Tests\SiteCheck.Tests.csproj -c Release --nologo
if ($LASTEXITCODE -ne 0) { throw "Tests failed." }
$out = Join-Path $root "dist"
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Path $out | Out-Null

# Single-file self-contained WPF. Compression is on so the public EXE stays a reasonable download.
# SmartScreen is publisher reputation (Authenticode), not this packer flag. Defender scan is clean either way.
& $dotnet publish src\SiteCheck.App\SiteCheck.App.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false `
  -p:EnableCompressionInSingleFile=true -o $out
if ($LASTEXITCODE -ne 0) { throw "Windows publish failed." }
$app = Join-Path $out "SiteCheck.App.exe"
$named = Join-Path $out "Rampart.exe"
if (Test-Path $app) {
  if (Test-Path $named) { Remove-Item $named -Force }
  Rename-Item $app "Rampart.exe"
}

$sign = Join-Path $PSScriptRoot "sign-windows.ps1"
if (Test-Path $named) {
  & $sign -Path $named
  if ($LASTEXITCODE -ne 0) { throw "Windows sign failed." }
}

function Publish-Desktop([string]$rid, [string]$folder) {
  $dest = Join-Path $out $folder
  & $dotnet publish src\SiteCheck.Desktop\SiteCheck.Desktop.csproj -c Release -r $rid --self-contained true -o $dest
  if ($LASTEXITCODE -ne 0) { throw "Publish $rid failed." }
  $targetName = if ($rid -like "win*") { "Rampart.exe" } else { "Rampart" }
  $exe = Join-Path $dest "SiteCheck.Desktop.exe"
  $unix = Join-Path $dest "SiteCheck.Desktop"
  if (Test-Path $exe) {
    Copy-Item $exe (Join-Path $dest $targetName) -Force
    if ($rid -like "win*") {
      & $sign -Path (Join-Path $dest $targetName)
      if ($LASTEXITCODE -ne 0) { throw "Sign $rid failed." }
    }
  } elseif (Test-Path $unix) {
    Copy-Item $unix (Join-Path $dest $targetName) -Force
  }
  foreach ($name in @("LICENSE", "LICENSE.MOBILE", "NOTICE", "THIRD-PARTY.md")) {
    Copy-Item (Join-Path $root $name) $dest -Force
  }
  Copy-Item (Join-Path $root "docs\how-to-use.md") (Join-Path $dest "how-to-use.md") -Force
  Copy-Item (Join-Path $root "docs\lawful-use.md") (Join-Path $dest "lawful-use.md") -Force
  Copy-Item (Join-Path $root "docs\TESTING.txt") (Join-Path $dest "TESTING.txt") -Force
  Copy-Item (Join-Path $root "licenses\APACHE-2.0.txt") $dest -Force
  "Built $dest"
}

Publish-Desktop "linux-x64" "linux-x64"
Publish-Desktop "osx-x64" "osx-x64"
Publish-Desktop "osx-arm64" "osx-arm64"

foreach ($name in @("LICENSE", "LICENSE.MOBILE", "NOTICE", "THIRD-PARTY.md")) {
  Copy-Item (Join-Path $root $name) $out -Force
}
Copy-Item (Join-Path $root "docs\how-to-use.md") (Join-Path $out "how-to-use.md") -Force
Copy-Item (Join-Path $root "docs\lawful-use.md") (Join-Path $out "lawful-use.md") -Force
Copy-Item (Join-Path $root "docs\TESTING.txt") (Join-Path $out "TESTING.txt") -Force
Copy-Item (Join-Path $root "docs\signing.md") (Join-Path $out "signing.md") -Force
Copy-Item (Join-Path $root "licenses\APACHE-2.0.txt") $out -Force

function Zip-Folder([string]$folder, [string]$zipName) {
  $src = Join-Path $out $folder
  $zip = Join-Path $out $zipName
  if (Test-Path $zip) { Remove-Item $zip -Force }
  Compress-Archive -Path (Join-Path $src "*") -DestinationPath $zip -Force
  "Zipped $zip"
}
Zip-Folder "linux-x64" "Rampart-linux-x64.zip"
Zip-Folder "osx-x64" "Rampart-osx-x64.zip"
Zip-Folder "osx-arm64" "Rampart-osx-arm64.zip"

$sums = Join-Path $out "SHA256SUMS.txt"
$lines = @()
Get-ChildItem $out -File | Where-Object { $_.Name -match "^(Rampart\.exe|Rampart-.*\.zip)$" } | Sort-Object Name | ForEach-Object {
  $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  $lines += "$hash  $($_.Name)"
}
$lines -join "`n" | Set-Content -LiteralPath $sums -Encoding ascii
"Wrote $sums"

Get-ChildItem $out -Filter Rampart.exe | ForEach-Object {
  $sig = Get-AuthenticodeSignature -LiteralPath $_.FullName
  "Built $($_.FullName) ($([math]::Round($_.Length/1MB,1)) MB) Authenticode=$($sig.Status)"
}
Get-ChildItem $out -Filter *.zip | ForEach-Object { "Zip $($_.Name) ($([math]::Round($_.Length/1MB,1)) MB)" }
