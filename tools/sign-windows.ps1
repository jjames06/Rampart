# Authenticode-sign a Windows Rampart binary.
# SmartScreen "unrecognized app" is publisher reputation. Defender reports no threats.
#
# Sources, first match wins:
#   1. Microsoft Artifact Signing (Azure Trusted Signing)
#        RAMPART_SIGNING_ACCOUNT, RAMPART_SIGNING_PROFILE
#        optional RAMPART_SIGNING_ENDPOINT (default East US)
#        requires: az login, Windows SDK signtool, Trusted Signing client tools
#   2. RAMPART_SIGN_PFX + RAMPART_SIGN_PFX_PASSWORD
#   3. RAMPART_SIGN_THUMBPRINT or a Code Signing cert in CurrentUser\My
#
# Optional: RAMPART_REQUIRE_SIGN=1 fails when nothing can sign.

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$Path
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $Path)) { throw "Nothing to sign: $Path" }

function Find-SignTool {
  $kits = "C:\Program Files (x86)\Windows Kits\10\bin"
  if (Test-Path $kits) {
    $found = Get-ChildItem $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
      Sort-Object FullName -Descending |
      Select-Object -First 1
    if ($found) { return $found.FullName }
  }
  $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  return $null
}

function Find-SigningDlib {
  if ($env:RAMPART_SIGNING_DLIB -and (Test-Path -LiteralPath $env:RAMPART_SIGNING_DLIB)) {
    return $env:RAMPART_SIGNING_DLIB
  }
  $guess = Join-Path $env:LOCALAPPDATA "Microsoft\MicrosoftTrustedSigningClientTools\Azure.CodeSigning.Dlib.dll"
  if (Test-Path -LiteralPath $guess) { return $guess }
  $hit = Get-ChildItem "$env:LOCALAPPDATA\Microsoft" -Recurse -Filter "Azure.CodeSigning.Dlib.dll" -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if ($hit) { return $hit.FullName }
  return $null
}

function Get-CodeSigningCert {
  $thumb = $env:RAMPART_SIGN_THUMBPRINT
  $stores = @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")
  foreach ($store in $stores) {
    $certs = Get-ChildItem $store -ErrorAction SilentlyContinue | Where-Object { $_.HasPrivateKey }
    if ($thumb) {
      $hit = $certs | Where-Object { $_.Thumbprint -eq $thumb }
      if ($hit) { return $hit }
    }
    $code = $certs | Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" }
    if ($code) { return $code | Select-Object -First 1 }
  }
  return $null
}

$digicertTs = "http://timestamp.digicert.com"
$acsTs = "http://timestamp.acs.microsoft.com"
$description = "Rampart"
$productUrl = "https://www.operationlockedin.com/rampart"
$require = $env:RAMPART_REQUIRE_SIGN -eq "1"
$pfx = $env:RAMPART_SIGN_PFX
$pfxPass = $env:RAMPART_SIGN_PFX_PASSWORD
$account = $env:RAMPART_SIGNING_ACCOUNT
$profile = $env:RAMPART_SIGNING_PROFILE
$endpoint = if ($env:RAMPART_SIGNING_ENDPOINT) { $env:RAMPART_SIGNING_ENDPOINT } else { "https://eus.codesigning.azure.net/" }
$signtool = Find-SignTool
$signed = $false

if ($account -and $profile) {
  if (-not $signtool) { throw "signtool.exe is required for Artifact Signing. Install the Windows 10/11 SDK." }
  $dlib = Find-SigningDlib
  if (-not $dlib) { throw "Azure.CodeSigning.Dlib.dll not found. Install Microsoft.Azure.TrustedSigningClientTools." }
  $meta = Join-Path $env:TEMP "rampart-artifact-signing.json"
  $payload = @{
    Endpoint = $endpoint
    CodeSigningAccountName = $account
    CertificateProfileName = $profile
  } | ConvertTo-Json
  Set-Content -LiteralPath $meta -Value $payload -Encoding utf8
  & $signtool sign /fd SHA256 /td SHA256 /tr $acsTs /dlib $dlib /dmdf $meta /d $description /du $productUrl $Path
  if ($LASTEXITCODE -ne 0) { throw "signtool Artifact Signing failed. Sign in with az login first, then retry." }
  $signed = $true
} elseif ($pfx) {
  if (-not (Test-Path -LiteralPath $pfx)) { throw "RAMPART_SIGN_PFX not found: $pfx" }
  if (-not $signtool) { throw "signtool.exe is required to sign with a PFX. Install the Windows 10/11 SDK." }
  $passArgs = @()
  if ($pfxPass) { $passArgs = @("/p", $pfxPass) }
  & $signtool sign /fd SHA256 /td SHA256 /tr $digicertTs /f $pfx @passArgs /d $description /du $productUrl $Path
  if ($LASTEXITCODE -ne 0) { throw "signtool PFX sign failed." }
  $signed = $true
} else {
  $cert = Get-CodeSigningCert
  if ($cert) {
    $result = Set-AuthenticodeSignature -FilePath $Path -Certificate $cert -TimestampServer $digicertTs -HashAlgorithm SHA256
    if ($result.Status -ne "Valid") {
      throw "Authenticode status $($result.Status): $($result.StatusMessage)"
    }
    $signed = $true
  }
}

if ($signed) {
  $check = Get-AuthenticodeSignature -LiteralPath $Path
  "Signed $Path status=$($check.Status) subject=$($check.SignerCertificate.Subject)"
  exit 0
}

$msg = "UNSIGNED $Path. This PC has signtool and the Artifact Signing client, but no publisher identity yet. Complete Azure Artifact Signing identity validation (docs/signing.md), set RAMPART_SIGNING_ACCOUNT and RAMPART_SIGNING_PROFILE, run az login, then publish again."
if ($require) { throw $msg }
Write-Warning $msg
exit 0
