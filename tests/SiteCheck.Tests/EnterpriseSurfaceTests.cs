// CODEMAP FILE: tests/SiteCheck.Tests/EnterpriseSurfaceTests.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Locks enterprise portal allowlists, brochure silence, and KEV patch-prompt wording (not RCE proof).
// Called by: dotnet test.
// Calls: EnterpriseSurface.
// Invariants: No exploit assertions. WAF-only is not the patch. Brochure HTML that names "SharePoint" in marketing copy must not fire the SharePoint card.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront.
// Map: docs/CODEMAP.md

using SiteCheck.Core;

namespace SiteCheck.Tests;

public class EnterpriseSurfaceTests
{
    [Fact]
    public void Brochure_emits_no_attention_cards()
    {
        var hits = EnterpriseSurface.AllPaths.Select(p => new FileHit(p, 404, "not found")).ToArray();
        var findings = EnterpriseSurface.Findings(
            hits,
            "<html><body>North Shore IT. We can talk about SharePoint migrations.</body></html>",
            Array.Empty<string>(),
            new Dictionary<string, string>());
        Assert.Empty(findings);
    }

    [Fact]
    public void SharePoint_layout_path_is_attention_without_exploit_claim()
    {
        var hits = new[] { new FileHit("/_layouts/15/start.aspx", 200, "<html>start</html>") };
        var findings = EnterpriseSurface.Findings(hits, "", Array.Empty<string>(), null);
        var f = Assert.Single(findings);
        Assert.Equal("Microsoft SharePoint", f.Title);
        Assert.Equal(FindingState.Attention, f.State);
        Assert.Contains("CVE-2025-53770", f.Observation);
        Assert.Contains("CVE-2026-65660", f.Observation);
        Assert.Contains("does not send exploit", f.Caveat, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ToolPane", string.Join(" ", EnterpriseSurface.AllPaths), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NetScaler_logon_is_attention()
    {
        var hits = new[] { new FileHit("/vpn/index.html", 302, "") };
        var f = Assert.Single(EnterpriseSurface.Findings(hits, "", Array.Empty<string>(), null));
        Assert.Equal("Citrix NetScaler", f.Title);
        Assert.Contains("CVE-2026-88771", f.Observation);
    }

    [Fact]
    public void Magento_header_is_attention_without_extra_path()
    {
        var hits = EnterpriseSurface.AllPaths.Select(p => new FileHit(p, 404, "")).ToArray();
        var headers = new Dictionary<string, string> { ["X-Magento-Vary"] = "1" };
        var f = Assert.Single(EnterpriseSurface.Findings(hits, "", Array.Empty<string>(), headers));
        Assert.Equal("Adobe Commerce", f.Title);
        Assert.Contains("CVE-2026-71362", f.Observation);
    }

    [Fact]
    public void FortiGate_login_how_to_names_vendor_and_cisa()
    {
        var lines = EnterpriseSurface.FixLines("Fortinet FortiGate");
        Assert.NotNull(lines);
        var text = string.Join(" ", lines!.Select(l => l.Text + " " + l.Copy));
        Assert.Contains("FG-IR-25-084", text);
        Assert.Contains("known-exploited-vulnerabilities-catalog", text);
        Assert.Contains("/remote/login", string.Join(" ", EnterpriseSurface.AllPaths));
        Assert.DoesNotContain("fgt_lang", string.Join(" ", EnterpriseSurface.AllPaths));
    }

    [Fact]
    public void WebLogic_allowlist_omits_wsat_exploit_path()
    {
        Assert.Contains("/console/login/LoginForm.jsp", EnterpriseSurface.AllPaths);
        Assert.DoesNotContain(EnterpriseSurface.AllPaths, p => p.Contains("wls-wsat", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(EnterpriseSurface.AllPaths, p => p.Contains("/mgmt/tm/util/bash", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PeopleSoft_hits_do_not_mark_sharepoint()
    {
        var hits = new[] { new FileHit("/psp/", 302, "") };
        Assert.Empty(EnterpriseSurface.Findings(hits, "", Array.Empty<string>(), null));
    }
}
