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

function Publish-Desktop([string]$rid, [string]$folder) {
  $dest = Join-Path $out $folder
  & $dotnet publish src\SiteCheck.Desktop\SiteCheck.Desktop.csproj -c Release -r $rid --self-contained true -o $dest
  if ($LASTEXITCODE -ne 0) { throw "Publish $rid failed." }
  $built = Get-ChildItem $dest -File | Where-Object { $_.Name -like "SiteCheck.Desktop*" -and $_.Extension -in @("", ".exe", ".dll") } | Select-Object -First 1
  $targetName = if ($rid -like "win*") { "Rampart.exe" } else { "Rampart" }
  $exe = Join-Path $dest "SiteCheck.Desktop.exe"
  $unix = Join-Path $dest "SiteCheck.Desktop"
  if (Test-Path $exe) {
    Copy-Item $exe (Join-Path $dest $targetName) -Force
  } elseif (Test-Path $unix) {
    Copy-Item $unix (Join-Path $dest $targetName) -Force
  }
  foreach ($name in @("LICENSE", "LICENSE.MOBILE", "NOTICE", "THIRD-PARTY.md")) {
    Copy-Item (Join-Path $root $name) $dest -Force
  }
  Copy-Item (Join-Path $root "docs\how-to-use.md") (Join-Path $dest "how-to-use.md") -Force
  Copy-Item (Join-Path $root "docs\lawful-use.md") (Join-Path $dest "lawful-use.md") -Force
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
Copy-Item (Join-Path $root "licenses\APACHE-2.0.txt") $out -Force
Get-ChildItem $out -Filter Rampart.exe | ForEach-Object { "Built $($_.FullName) ($([math]::Round($_.Length/1MB,1)) MB)" }
Get-ChildItem $out -Directory | ForEach-Object { "Folder $($_.FullName)" }
