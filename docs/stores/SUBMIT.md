# Store and extra-desktop builds

Rampart’s checker is `SiteCheck.Core`. UIs:

| UI | Platforms | Licence for that binary |
|---|---|---|
| `SiteCheck.App` (WPF) | Windows | GPLv3 |
| `SiteCheck.Desktop` (Avalonia) | Windows, macOS, Linux | GPLv3 |
| `SiteCheck.Maui` (when the MAUI workload is installed) | iOS, Android | Apache-2.0 **and** GPLv3 (dual grant) |

## Why two licences

GPLv3 is the right copyleft for Bastion and for desktop Rampart. Apple’s App Store terms add extra restrictions GPLv3 does not allow, so a GPLv3-only iOS build cannot be submitted in good faith. Jesse, as copyright holder, additionally licenses the **mobile store binaries** under Apache License 2.0 (`licenses/APACHE-2.0.txt`). The source stays public. You may take either grant.

## Privacy (all platforms)

Rampart does not create an account and does not phone home. A check talks only to the hostname you typed (public DNS + HTTPS). Reports stay on the device. Public policy: https://www.operationlockedin.com/privacy

App Store privacy nutrition / Play Data safety: **no data collected**. No advertising ID. Network: the operator-typed hostname only.

## What this machine cannot do

- Sign or upload an iOS IPA (needs a Mac, Xcode, Apple Developer Program).
- Upload an Android AAB (needs Google Play Console and a signing key you hold).
- `dotnet workload install maui` is not installed here. Install it on the Mac/CI you use for store builds.

## Avalonia (Linux and macOS)

```
dotnet publish src/SiteCheck.Desktop/SiteCheck.Desktop.csproj -c Release -r linux-x64 --self-contained
dotnet publish src/SiteCheck.Desktop/SiteCheck.Desktop.csproj -c Release -r osx-x64 --self-contained
dotnet publish src/SiteCheck.Desktop/SiteCheck.Desktop.csproj -c Release -r osx-arm64 --self-contained
```

Notarize macOS builds with your Apple Developer ID before distributing outside the App Store.

## Store listing (short)

Name: Rampart  
Subtitle: Public-surface hostname check  
Category: Developer tools / Productivity  
Age: 4+  
Price: Free  
Support URL: https://www.operationlockedin.com/support  
Privacy URL: https://www.operationlockedin.com/privacy  

Permission boxes in the app are the same as Windows. No background location. No contacts.
