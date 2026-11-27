# Rampart changelog

## 1.9.2 (November 26, 2026)

Security and catalogue release. No change to what Rampart requests from a host.

- Rebuilt the local CVE catalogue (`data/advisories.json`) on November 26, 2026: 72 products and 1111 advisories, up from 71 and 975 (built September 28, 2026). New ranges cover Next.js, Nuxt, axios, DOMPurify, Handlebars, Lodash, moment, TinyMCE, highcharts, markdown-it, CKEditor 5 and dojox.
- Added WordPress core CVE-2026-119977 (upgrade-window code execution, CISA Known Exploited since November 3, 2026). Fixed in 7.1.4; older branches match below their newest release.
- Enterprise portal cards now name the CISA Known Exploited rows added since the last catalogue build: VMware vCenter CVE-2026-123890 and SAP NetWeaver CVE-2025-42884 (both added November 20, 2026), Ivanti Connect Secure CVE-2026-104935, CVE-2026-111357 and CVE-2026-118527, GitLab CVE-2026-97229, Adobe Commerce CVE-2026-48356, PAN-OS CVE-2026-0322, NetScaler CVE-2026-88779, Fortinet CVE-2025-61624, and Atlassian CVE-2026-21589 (Confluence and Jira cards).
- Build: `global.json` now pins the .NET SDK 10.0.404 feature band floor, so the self-contained Windows build always bundles the .NET 8.0.34 runtime (the November 10, 2026 security release). v1.9.1 already shipped 8.0.34; this makes it a floor rather than a runner default.
- No NuGet package in the solution has a known advisory (`dotnet list package --vulnerable --include-transitive`, November 26, 2026).
- Status display fix (rebuilt November 26, 2026, same version): the status line under the buttons (progress messages and the result summary) is now teal and semibold so it stands out, and a spinner, a "Check in progress" label and a thicker progress bar show while a check runs. They hide when the check finishes, fails or is stopped. The spinner stays still when Windows animations are turned off.

## 1.9.1 (November 12, 2026)

Dependency security patches, Avalonia 12.1.x, .NET 10 SDK for builds, and the manual Windows release build workflow.
