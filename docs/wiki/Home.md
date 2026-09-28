# Rampart

A rampart is the defensive wall of a fortress. **Bastion** hardens a Windows PC you administer. **Rampart** inspects a public hostname you operate.

The public download is **Rampart 1.9.0** for 64-bit Windows (`Rampart.exe`). Builds for other operating systems are in testing and are not offered on the release page.

Rampart is a read-only public-surface check. Tick both permission boxes. Check only a hostname you operate, or for which you have written permission.

## Start here

- [How to use](How-to-use)
- [What is checked](What-is-checked)
- [Lawful use](Lawful-use)
- [Licence](Licence)
- [CVE catalogue](https://github.com/jjames06/oli-site-check/blob/main/docs/cve-catalogue.md)

## Download

[Rampart 1.9.0 on GitHub Releases](https://github.com/jjames06/oli-site-check/releases/tag/v1.9.0)

The listing on [operationlockedin.com](https://www.operationlockedin.com/rampart) points at the same EXE.

## What it does

After you attest permission, it resolves public addresses, reads TLS, requests a small set of public HTTPS paths (homepage plus common sign-in URLs), classifies the public edge, and compares advertised versions with a local CVE catalogue. Findings that need work include How to fix this with copyable lines.

It does not send exploit traffic, guess passwords, or crawl.

## Source

https://github.com/jjames06/oli-site-check
