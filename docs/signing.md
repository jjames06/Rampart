# Signing Rampart so Windows SmartScreen and Gatekeeper stop blocking it

## What the grey “Windows protected your PC” box is

That box is **Microsoft Defender SmartScreen**, not a malware detection.

A scan of the public `Rampart.exe` with Windows Defender (`MpCmdRun -Scan -ScanType 3`) reports **no threats**. SmartScreen still blocks **first run of an unrecognized publisher**. Rampart 1.9.0 was shipped **without an Authenticode signature** (`Get-AuthenticodeSignature` status `NotSigned`). Windows then has no trusted publisher to attach reputation to.

Choosing **More info**, then **Run anyway**, is the correct path for a copy from this repository or from https://www.operationlockedin.com/rampart until a signed build is on the v1.9.0 release.

A self-signed certificate does **not** fix SmartScreen. The certificate has to come from a public code-signing CA, or from Microsoft Trusted Signing.

## Windows (WPF `Rampart.exe`, version 1.9.0)

Keep the product version at **1.9.0**. Sign the same version; do not bump it for a signature-only republish.

1. Obtain an OV or EV Authenticode certificate in Jesse’s or the practice’s name, or a Microsoft Trusted Signing account. EV and Trusted Signing get SmartScreen reputation immediately. OV needs download reputation to build.
2. Put the PFX on this PC (not in git) and set:

```
RAMPART_SIGN_PFX=C:\path\to\rampart-code-sign.pfx
RAMPART_SIGN_PFX_PASSWORD=...
```

Or import the certificate into `CurrentUser\My` and set `RAMPART_SIGN_THUMBPRINT`.

3. Install the Windows 10/11 SDK so `signtool.exe` exists (needed for a PFX). PowerShell can sign from the certificate store without signtool.
4. From the repository root:

```
powershell -File tools\publish.ps1
```

`tools\sign-windows.ps1` runs after the Windows EXE is named `Rampart.exe`. `RAMPART_REQUIRE_SIGN=1` makes a missing certificate fail the publish instead of warning.

5. Replace the `Rampart.exe` asset on the **existing** GitHub release `v1.9.0`. Do not create v1.10.0 for a signature.

Timestamp uses `http://timestamp.digicert.com` so the signature stays valid after the certificate expires.

## macOS (Avalonia testing zips, version 1.9.0)

Gatekeeper is the macOS equivalent. It fires because the testing zip has **no Developer ID** and is **not notarized**.

On a Mac, with Apple Developer Program:

```
codesign --deep --force --options runtime --sign "Developer ID Application: Jesse Mosier-Bowers (TEAMID)" Rampart
xcrun notarytool submit Rampart-osx-arm64.zip --apple-id YOUR_APPLE_ID --team-id TEAMID --wait
xcrun stapler staple Rampart
```

Until that is done, `docs/TESTING.txt` in each zip tells the tester to open from Finder or drop the quarantine attribute. Keep version **1.9.0**.

This Windows PC cannot codesign or notarize a Mac binary.

## Linux (Avalonia testing zip, version 1.9.0)

There is no SmartScreen. The usual first-run friction is the execute bit and, on some desktops, “untrusted download”. `chmod +x Rampart` then `./Rampart`. Checksums are `SHA256SUMS.txt` on the GitHub release.

## iPhone and Android (MAUI, version 1.9.0)

Store review is the gate, not SmartScreen. Play Protect can still nag an sideloaded APK. Ship through App Store and Google Play with the upload keys in [stores/SUBMIT.md](stores/SUBMIT.md). Application version stays **1.9.0**.

## After a signed Windows build exists

Update the SmartScreen paragraph on `/rampart` so it no longer says the file is unsigned. Leave “Run anyway” copy in the handbook until SmartScreen reputation actually clears for that hash.
