// CODEMAP FILE: tests/SiteCheck.Tests/EnterpriseSurfaceMoreTests.cs
// Role: Locks Exchange, Jira, Jenkins, actuator, and Grafana false-positive guards.
// Map: docs/CODEMAP.md

using SiteCheck.Core;

namespace SiteCheck.Tests;

public class EnterpriseSurfaceMoreTests
{
    [Fact]
    public void Exchange_owa_is_attention()
    {
        var hits = new[] { new FileHit("/owa/", 200, "<html>Outlook Web App</html>") };
        var f = Assert.Single(EnterpriseSurface.Findings(hits, "", Array.Empty<string>(), null).Where(x => x.Title == "Microsoft Exchange"));
        Assert.Equal(FindingState.Attention, f.State);
        Assert.Contains("does not send", f.Caveat, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Jenkins_header_is_attention()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["X-Jenkins"] = "2.492.1" };
        var f = Assert.Single(EnterpriseSurface.Findings(Array.Empty<FileHit>(), "", Array.Empty<string>(), headers).Where(x => x.Title == "Jenkins"));
        Assert.Contains("response header", f.Observation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Generic_jsessionid_is_not_jenkins()
    {
        var findings = EnterpriseSurface.Findings(Array.Empty<FileHit>(), "", new[] { "JSESSIONID=abc" }, new Dictionary<string, string>());
        Assert.DoesNotContain(findings, x => x.Title == "Jenkins");
    }

    [Fact]
    public void Generic_api_health_is_not_grafana()
    {
        var hits = new[] { new FileHit("/api/health", 200, "{\"ok\":true}") };
        var findings = EnterpriseSurface.Findings(hits, "<html>North Shore IT</html>", Array.Empty<string>(), null);
        Assert.DoesNotContain(findings, x => x.Title == "Grafana");
    }

    [Fact]
    public void Actuator_env_is_private_file()
    {
        var hit = new FileHit("/actuator/env", 200, "{\"propertySources\":[]}");
        Assert.True(ExposedSurface.LooksLeaked(hit));
    }
}
