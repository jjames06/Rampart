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
            new[] { "This is a short read-only check." });
        var text = ReportText.Format(report);
        Assert.Contains("example.com", text, StringComparison.Ordinal);
        Assert.Contains("What to do next", text, StringComparison.Ordinal);
        Assert.Contains("Present", text, StringComparison.Ordinal);
        Assert.Contains("This is a short read-only check.", text, StringComparison.Ordinal);
        Assert.DoesNotContain("password", text, StringComparison.OrdinalIgnoreCase);
    }
}
