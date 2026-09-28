// CODEMAP FILE: tests/SiteCheck.Tests/ReportTextTests.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Locks plaintext report sections: hostname, findings, limits, authorization.
// Called by: dotnet test.
// Calls: ReportText.
// Invariants: A saved report must still say this is not a pentest.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using SiteCheck.Core;

namespace SiteCheck.Tests;

public class ReportTextTests
{
    [Fact]
    public void Format_includes_hostname_limits_and_state_labels()
    {
        var report = new CheckReport(
            "example.com",
            new DateTimeOffset(2026, 9, 27, 12, 0, 0, TimeSpan.Zero),
            new[] { "93.184.216.34" },
            new[]
            {
                new Finding("HTTPS", FindingState.Present, "ok", "head", "caveat")
            },
            new[] { new NextStep("Add a header", "Do the work.", "CSP") },
            Array.Empty<StackHint>(),
            new[] { "This is a short read-only check." },
            LawfulUse.Record(CheckScope.Standard, new DateTimeOffset(2026, 9, 27, 12, 0, 0, TimeSpan.Zero)));
        var text = ReportText.Format(report);
        Assert.Contains("Rampart", text, StringComparison.Ordinal);
        Assert.Contains("example.com", text, StringComparison.Ordinal);
        Assert.Contains("What to do next", text, StringComparison.Ordinal);
        Assert.Contains("Present", text, StringComparison.Ordinal);
        Assert.Contains("This is a short read-only check.", text, StringComparison.Ordinal);
        Assert.Contains("Criminal Code section 342.1", text, StringComparison.Ordinal);
        Assert.Contains("does not authorize", text, StringComparison.Ordinal);
        Assert.Contains("Methods this program will not use", text, StringComparison.Ordinal);
        Assert.Contains("Exploit payloads", text, StringComparison.Ordinal);
        Assert.Contains("need attention", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Json_report_includes_summary_and_findings()
    {
        var report = new CheckReport(
            "example.com",
            new DateTimeOffset(2026, 9, 27, 12, 0, 0, TimeSpan.Zero),
            new[] { "93.184.216.34" },
            new[] { new Finding("HTTPS", FindingState.Present, "ok", "head", "caveat") },
            Array.Empty<NextStep>(),
            Array.Empty<StackHint>(),
            new[] { "limit" },
            LawfulUse.Record(CheckScope.Standard, new DateTimeOffset(2026, 9, 27, 12, 0, 0, TimeSpan.Zero)));
        var json = ReportJson.Format(report);
        Assert.Contains("\"hostname\": \"example.com\"", json, StringComparison.Ordinal);
        Assert.Contains("\"present\": 1", json, StringComparison.Ordinal);
        Assert.Contains("operation-locked-in-rampart/1.9.0", json, StringComparison.Ordinal);
    }
}
