# Authenticode-sign a Windows Rampart binary if a publisher certificate is present.
# SmartScreen "unrecognized app" is publisher reputation, not a Defender malware hit.
# MpCmdRun on the public EXE reports no threats. An unsigned EXE still gets SmartScreen.
#
# Sources, first match wins:
#   1. RAMPART_SIGN_PFX + RAMPART_SIGN_PFX_PASSWORD  (PFX file)
#   2. RAMPART_SIGN_THUMBPRINT                       (cert in CurrentUser\My or LocalMachine\My)
#   3. A Code Signing EKU certificate already in CurrentUser\My
#
# Optional: RAMPART_REQUIRE_SIGN=1 fails the script when nothing can sign.

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

function Get-CodeSigningCert {
  $thumb = $env:RAMPART_SIGN_THUMBPRINT
  $stores = @(
    "Cert:\CurrentUser\My",
    "Cert:\LocalMachine\My"
  )
  foreach ($store in $stores) {
    $certs = Get-ChildItem $store -ErrorAction SilentlyContinue | Where-Object { $_.HasPrivateKey }
    if ($thumb) {
      $hit = $certs | Where-Object { $_.Thumbprint -eq $thumb }
      if ($hit) { return $hit }
    }
    $code = $certs | Where-Object {
      $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing"
    }
    if ($code) { return $code | Select-Object -First 1 }
  }
  return $null
}

$timestamp = "http://timestamp.digicert.com"
$description = "Rampart"
$productUrl = "https://www.operationlockedin.com/rampart"
$require = $env:RAMPART_REQUIRE_SIGN -eq "1"
$pfx = $env:RAMPART_SIGN_PFX
$pfxPass = $env:RAMPART_SIGN_PFX_PASSWORD
$signtool = Find-SignTool
$signed = $false

if ($pfx) {
  if (-not (Test-Path -LiteralPath $pfx)) { throw "RAMPART_SIGN_PFX not found: $pfx" }
  if (-not $signtool) { throw "signtool.exe is required to sign with a PFX. Install the Windows 10/11 SDK." }
  $passArgs = @()
  if ($pfxPass) { $passArgs = @("/p", $pfxPass) }
  & $signtool sign /fd SHA256 /td SHA256 /tr $timestamp /f $pfx @passArgs /d $description /du $productUrl $Path
  if ($LASTEXITCODE -ne 0) { throw "signtool PFX sign failed." }
  $signed = $true
} else {
  $cert = Get-CodeSigningCert
  if ($cert) {
    $result = Set-AuthenticodeSignature -FilePath $Path -Certificate $cert -TimestampServer $timestamp -HashAlgorithm SHA256
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

$msg = "UNSIGNED $Path. SmartScreen will treat Rampart as an unrecognized app until an Authenticode certificate is used (RAMPART_SIGN_PFX or a Code Signing cert in the Windows store)."
if ($require) { throw $msg }
Write-Warning $msg
exit 0
