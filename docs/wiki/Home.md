# Rampart

A rampart is the defensive wall of a fortress. **Bastion** hardens a Windows PC you administer. **Rampart** inspects a public hostname you operate.

The recommended download is **Rampart 1.9.0** for 64-bit Windows (`Rampart.exe`). Testing copies for Linux and macOS are on the same GitHub release. The iPhone and Android copies are being submitted to the App Store and Google Play soon. They are not listed there yet.

Rampart is a read-only public-surface check. Tick both permission boxes. Check only a hostname you operate, or for which you have written permission.

## Start here

- [How to use](How-to-use)
- [What is checked](What-is-checked)
- [Lawful use](Lawful-use)
- [Licence](Licence)
- [CVE catalogue](https://github.com/jjames06/oli-site-check/blob/main/docs/cve-catalogue.md)

## Download

[Rampart 1.9.0 on GitHub Releases](https://github.com/jjames06/oli-site-check/releases/tag/v1.9.0)

- Windows: `Rampart.exe` (recommended)
- Linux x64 testing: `Rampart-linux-x64.zip`
- macOS Apple silicon testing: `Rampart-osx-arm64.zip`
- macOS Intel testing: `Rampart-osx-x64.zip`

The listing on [operationlockedin.com](https://www.operationlockedin.com/rampart) points at the same files. Desktop copies are GNU GPLv3. Store binaries, when they ship, use an additional Apache License 2.0 grant.

## What it does

After you attest permission, it resolves public addresses, reads TLS, requests a small set of public HTTPS paths (homepage plus common sign-in URLs), classifies the public edge, and compares advertised versions with a local CVE catalogue. Findings that need work include How to fix this with copyable lines.

It does not send exploit traffic, guess passwords, or crawl.

## Source

https://github.com/jjames06/oli-site-check
