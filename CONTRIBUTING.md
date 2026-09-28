# Contributing to Rampart

Rampart is a read-only public-surface checker. Issues and pull requests are welcome when they keep that promise.

## Before you open an issue

- Check only a hostname you operate or have written permission to test.
- Do not attach exploit proof-of-concept traffic.
- Name the Rampart version (the window title and User-Agent use 1.9.0) and the operating system.
- Use the Bug or Question templates.

Private security reports: see [SECURITY.md](SECURITY.md).

## Pull requests

- Keep checks as GET or HEAD on an allowlist, sockets pinned to a public address, redirects off, bodies capped.
- Add or update tests in `tests/SiteCheck.Tests`.
- How-to-fix copy lives in `SiteCheck.Core` (`FixGuides`, `FindingGuide`). Do not add that wording in only one UI.
- Windows, Linux/macOS (Avalonia), and MAUI all consume Core. Card behaviour belongs in Core first.
- Do not bump the public version in a documentation-only change. The public pin is 1.9.0 until a deliberate release.

`dotnet test tests\SiteCheck.Tests\SiteCheck.Tests.csproj -c Release` must pass on Windows.

## Licence

Desktop contributions are GNU GPLv3. Mobile store binaries also carry Apache License 2.0. See `LICENSE` and `LICENSE.MOBILE`.
