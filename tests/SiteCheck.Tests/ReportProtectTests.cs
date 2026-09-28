// CODEMAP FILE: tests/SiteCheck.Tests/ReportProtectTests.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Locks DPAPI round-trip on Windows and no-op/skip elsewhere.
// Called by: dotnet test.
// Calls: ReportProtect.
// Invariants: Must not throw on non-Windows CI.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using SiteCheck.Core;

namespace SiteCheck.Tests;

public class ReportProtectTests
{
    [Fact]
    public void Plaintext_is_not_marked_protected()
    {
        Assert.False(ReportProtect.LooksProtected("Rampart report\nexample.com"));
    }

    [Fact]
    public void Windows_roundtrip_protects_and_opens()
    {
        if (!ReportProtect.WindowsUserProtectAvailable) return;
        var plain = "Rampart report\nwww.example.com\nCVE-2024-0000";
        var stored = ReportProtect.ProtectForCurrentWindowsUser(plain);
        Assert.True(ReportProtect.LooksProtected(stored));
        Assert.DoesNotContain("CVE-2024-0000", stored);
        Assert.Equal(plain, ReportProtect.UnprotectForCurrentWindowsUser(stored));
    }
}
