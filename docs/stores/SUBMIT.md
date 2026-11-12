# Store and extra-desktop builds

The **recommended public product** is the Windows EXE on the GitHub release. Testing zips for Linux and macOS are on that same release and on the Rampart page. They are still under test. The iPhone and Android copies are ready. They still need to be submitted to the App Store and Google Play. Do not upload store binaries until signing, privacy labels, and a Mac (for iOS) are in place.

Rampart’s checker is `SiteCheck.Core`. How-to-fix copy lives there (`FixGuides`, `FindingGuide`). Every UI must call `FindingGuide.ShowsHowTo` / `ShowsWhen` so Windows, Linux, macOS, iPhone, and Android stay in lockstep. Do not add How-to-fix wording in only one UI.

UIs:

| UI | Platforms | Licence for that binary |
|---|---|---|
| `SiteCheck.App` (WPF) | Windows | GPLv3 |
| `SiteCheck.Desktop` (Avalonia) | Windows, macOS, Linux | GPLv3 |
| `SiteCheck.Maui` | iOS, Android | Apache-2.0 **and** GPLv3 (dual grant) |

## Why two licences

GPLv3 is the right copyleft for Bastion and for desktop Rampart. Apple’s App Store terms add extra restrictions GPLv3 does not allow, so a GPLv3-only iOS build cannot be submitted in good faith. Jesse, as copyright holder, additionally licenses the **mobile store binaries** under Apache License 2.0 (`LICENSE.MOBILE` and `licenses/APACHE-2.0.txt`). The source stays public. You may take either grant.

## Privacy (all platforms)

Rampart does not create an account and does not phone home. A check talks only to the hostname you typed (public DNS + HTTPS). Reports stay on the device. Public policy: https://www.operationlockedin.com/privacy

The product-specific statement is [docs/privacy.md](../privacy.md). GitHub copy: https://github.com/jjames06/Rampart/blob/main/docs/privacy.md

App Store privacy nutrition / Play Data safety: **no data collected**. No advertising ID. Network: the operator-typed hostname only.

Exact form answers: [privacy-label.md](privacy-label.md).

## What this Windows PC cannot finish

- Sign or upload an iOS IPA. That needs a Mac, Xcode, and an Apple Developer Program membership (paid, in Jesse’s name or the practice’s).
- Upload an Android AAB. That needs a Google Play Console account and an upload key Jesse holds.
- `dotnet workload install maui` is required before `SiteCheck.Maui` will compile.

The MAUI project in `src/SiteCheck.Maui` is the store app: same permission boxes, same checker, INTERNET-only on Android, App Transport Security on iOS, privacy manifest with no collected data types.

## Build desktop (Linux and macOS)

From the repository root, with the .NET 8 SDK:

```
dotnet publish src/SiteCheck.Desktop/SiteCheck.Desktop.csproj -c Release -r linux-x64 --self-contained true -o dist/linux-x64
dotnet publish src/SiteCheck.Desktop/SiteCheck.Desktop.csproj -c Release -r osx-x64 --self-contained true -o dist/osx-x64
dotnet publish src/SiteCheck.Desktop/SiteCheck.Desktop.csproj -c Release -r osx-arm64 --self-contained true -o dist/osx-arm64
```

`tools/publish.ps1` runs those after the Windows EXE. Rename the output to `Rampart` (no extension on Linux and macOS).

On a Mac, notarize with a Developer ID before distributing outside the Mac App Store:

```
codesign --deep --force --options runtime --sign "Developer ID Application: Jesse Mosier-Bowers (TEAMID)" Rampart
xcrun notarytool submit Rampart.zip --apple-id YOUR_APPLE_ID --team-id TEAMID --wait
xcrun stapler staple Rampart
```

On Linux, `chmod +x Rampart` then run it. GTK/X11 or Wayland is enough; no extra .NET runtime. There is no SmartScreen on Linux.

Windows SmartScreen on `Rampart.exe` is an unsigned-publisher warning. Defender antivirus reports no threats. Sign the Windows EXE with Authenticode and keep version 1.9.0: [signing.md](../signing.md).

## Build Android (Windows or Mac, after the MAUI workload)

```
dotnet workload install maui-android
dotnet publish src/SiteCheck.Maui/SiteCheck.Maui.csproj -c Release -f net8.0-android -p:AndroidPackageFormat=aab
```

The AAB lands under `bin/Release/net8.0-android/publish/`. Sign it with the upload keystore Jesse creates once and stores offline:

```
keytool -genkey -v -keystore rampart-upload.jks -keyalg RSA -keysize 4096 -validity 10000 -alias rampart
```

Do not commit that keystore.

## Build iOS (Mac only)

```
dotnet workload install maui-ios
dotnet publish src/SiteCheck.Maui/SiteCheck.Maui.csproj -c Release -f net8.0-ios -p:RuntimeIdentifier=ios-arm64 -p:CodesignKey="Apple Distribution: Jesse Mosier-Bowers (TEAMID)" -p:CodesignProvision="Rampart App Store"
```

Then upload the IPA with Transporter or `xcrun altool`.

## Store listing (short)

Name: Rampart  
Subtitle: Public-surface hostname check  
Category: Developer tools / Productivity  
Age: 4+  
Price: Free  
Bundle ID / applicationId: `com.operationlockedin.rampart`  
Support URL: https://www.operationlockedin.com/support  
Privacy URL: https://www.operationlockedin.com/privacy  
Marketing URL: https://www.operationlockedin.com/rampart  

Permission boxes in the app are the same as Windows. No background location. No contacts. No advertising ID.

## Export compliance (Apple)

Rampart uses HTTPS (TLS) as provided by the operating system. It does not implement its own crypto. In App Store Connect, that is usually **exempt** encryption (HTTPS only). Confirm the current questionnaire when you upload; do not invent a CCATS number.

## Review notes to paste

Rampart is a read-only public-surface checker. The reviewer should:

1. Tick both permission boxes.
2. Enter a hostname they operate, or `example.com` only if they have permission.
3. Tap Check this hostname.
4. Confirm the report stays on the device (Copy / Save). There is no account and no cloud.

The app will refuse private addresses, localhost, and IP literals. That is intentional.
