# Signing Rampart so Windows SmartScreen and Gatekeeper stop blocking it

## What the grey “Windows protected your PC” box is

That box is **Microsoft Defender SmartScreen**, not a malware detection.

A scan of the public `Rampart.exe` with Windows Defender (`MpCmdRun -Scan -ScanType 3`) reports **no threats**. SmartScreen still blocks **first run of an unrecognized publisher**. Rampart 1.9.0 was shipped **without an Authenticode signature** (`Get-AuthenticodeSignature` status `NotSigned`). Windows then has no trusted publisher to attach reputation to.

Choosing **More info**, then **Run anyway**, is the correct path for a copy from this repository or from https://www.operationlockedin.com/rampart until a signed build is on the v1.9.0 release.

A self-signed certificate does **not** fix SmartScreen. The certificate has to come from a public code-signing CA, or from Microsoft Artifact Signing (formerly Trusted Signing).

Signing does **not** instantly silence SmartScreen on a brand-new hash. Microsoft now treats OV, EV, and Artifact Signing the same: the publisher name appears, then reputation builds from clean downloads. An unsigned file never gets that publisher name.

## Windows (WPF `Rampart.exe`, version 1.9.0)

Keep the product version at **1.9.0**. Sign the same version; do not bump it for a signature-only republish.

This PC already has:

- Windows SDK `signtool.exe`
- Microsoft Trusted Signing client (`Azure.CodeSigning.Dlib.dll`)
- Azure CLI (`az`)

It does **not** yet have a publisher identity. Only Jesse can finish identity validation. Canada is an allowed country for individual Public Trust.

### What you do once (Azure Artifact Signing)

1. Create or use an Azure subscription billed as an **Individual**, with the legal name and sold-to address matching your government ID (Ontario licence or passport). Courtice / Ontario / Canada is fine.
2. Open https://portal.azure.com/ and register the resource provider **Microsoft.CodeSigning** on that subscription (Subscriptions, then Resource providers, then Register).
3. Search for **Artifact Signing Accounts**, then Create. Region **East US**. Account name something like `oplockedin` (3–24 letters and numbers, globally unique). Basic SKU is enough.
4. On that account: Identity validations, then Individual, then Public, then New Identity. Use the same name as your ID. Primary email should be the mailbox you will use for the verification link (Info@operationlockedin.com or the Microsoft account mail).
5. When the request is **Action Required**, complete the AU10TIX / Verified ID walk on your phone (government photo ID, then Microsoft Authenticator). Processing can take from one to several business days.
6. When status is **Completed**, create a certificate profile: Certificate profiles, then Create, type **Public Trust**, name `rampart`, select the verified identity.
7. Assign yourself the **Trusted Signing Certificate Profile Signer** role on that account if the portal asks.
8. In a terminal on this PC:

```
az login
```

Then set (User environment, or a private `.env` you do not commit):

```
RAMPART_SIGNING_ACCOUNT=oplockedin
RAMPART_SIGNING_PROFILE=rampart
RAMPART_SIGNING_ENDPOINT=https://eus.codesigning.azure.net/
```

9. Tell the agent, or run:

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\publish.ps1
```

`tools\sign-windows.ps1` will Authenticode-sign `Rampart.exe` and we replace the **existing** GitHub `v1.9.0` asset. Do not create v1.10.0 for a signature.

Artifact Signing timestamps at `http://timestamp.acs.microsoft.com`.

### PFX alternative

If you already bought an OV Authenticode certificate instead:

```
RAMPART_SIGN_PFX=C:\path\to\rampart-code-sign.pfx
RAMPART_SIGN_PFX_PASSWORD=...
```

Do not put the PFX in git. `RAMPART_REQUIRE_SIGN=1` makes a missing certificate fail the publish.

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
