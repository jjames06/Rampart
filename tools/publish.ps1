$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dotnet = "C:\Program Files\dotnet\dotnet.exe"
if (-not (Test-Path $dotnet)) { $dotnet = "dotnet" }
Set-Location $root
& $dotnet test tests\SiteCheck.Tests\SiteCheck.Tests.csproj -c Release --nologo
if ($LASTEXITCODE -ne 0) { throw "Tests failed." }
$out = Join-Path $root "dist"
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
& $dotnet publish src\SiteCheck.App\SiteCheck.App.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false `
  -p:EnableCompressionInSingleFile=true -o $out
Get-ChildItem $out -Filter *.exe | ForEach-Object { "Built $($_.FullName) ($([math]::Round($_.Length/1MB,1)) MB)" }
