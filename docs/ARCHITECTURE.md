# Architecture

Rampart is a .NET 8 solution. **SiteCheck.Core** runs every check. Three shells present the same report:

| Project | Binary | Platforms |
|---|---|---|
| `SiteCheck.App` | `Rampart.exe` | Windows (recommended) |
| `SiteCheck.Desktop` | `Rampart` | Linux and macOS testing zips |
| `SiteCheck.Maui` | store packages | iPhone and Android, not listed yet |

Checks are GET or HEAD on an allowlist, sockets pinned to a resolved public address, redirects off, bodies capped. How-to-fix text lives in `FixGuides` and `FindingGuide` so a card cannot appear on only one UI.

Public version pin: **1.9.0**. Publish with `tools/publish.ps1`.
