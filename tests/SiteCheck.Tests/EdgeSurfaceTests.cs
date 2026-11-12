// CODEMAP FILE: tests/SiteCheck.Tests/EdgeSurfaceTests.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Locks Cloudflare NS vs CF-Ray vs Vercel vs origin classification.
// Called by: dotnet test.
// Calls: EdgeSurface.
// Invariants: Wrong edge class would send FixGuides to the wrong dashboard.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using SiteCheck.Core;

namespace SiteCheck.Tests;

public class EdgeSurfaceTests
{
    [Fact]
    public void Cloudflare_ray_is_proxied()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["cf-ray"] = "abc-YYZ"
        };
        var edge = EdgeSurface.Classify("ada.ns.cloudflare.com, bob.ns.cloudflare.com", headers, Array.Empty<StackHint>());
        Assert.Equal(EdgeKind.CloudflareProxied, edge.Kind);
        Assert.Equal(FindingState.Present, EdgeSurface.PublicEdgeFinding(edge).State);
    }

    [Fact]
    public void Cloudflare_nameservers_without_ray_are_dns_only()
    {
        var edge = EdgeSurface.Classify("ada.ns.cloudflare.com", new Dictionary<string, string>(), Array.Empty<StackHint>());
        Assert.Equal(EdgeKind.CloudflareDnsOnly, edge.Kind);
        Assert.Equal(FindingState.Attention, EdgeSurface.PublicEdgeFinding(edge).State);
    }

    [Fact]
    public void Vercel_without_cloudflare_is_vercel_only()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["x-vercel-id"] = "1"
        };
        var edge = EdgeSurface.Classify("ns1.vercel-dns.com", headers, Array.Empty<StackHint>());
        Assert.Equal(EdgeKind.VercelOnly, edge.Kind);
        var step = FixGuides.PublicEdgeStep("www.example.com", edge, true, true);
        Assert.NotNull(step);
        Assert.Contains(step!.Lines!, l => l.Copy == "https://dash.cloudflare.com/");
    }

    [Fact]
    public void Email_obfuscation_script_is_attention_on_proxied_cloudflare()
    {
        var edge = new EdgeProfile(EdgeKind.CloudflareProxied, "Cloudflare", true, true, true);
        var findings = EdgeSurface.CloudflareSurface("""<script src="/cdn-cgi/scripts/email-decode.min.js"></script>""", new Dictionary<string, string>(), edge).ToArray();
        Assert.Contains(findings, f => f.Title == "Cloudflare email obfuscation" && f.State == FindingState.Attention);
    }

    [Fact]
    public void Caa_guide_uses_cloudflare_copy_lines()
    {
        var steps = new[]
        {
            new NextStep("Fix CAA", "Add CAA.", "CAA", "DNS host")
        };
        var edge = new EdgeProfile(EdgeKind.CloudflareProxied, "Cloudflare", true, true, true);
        var filled = FixGuides.WithLines(steps, "www.example.com", edge, true, false, true, true);
        Assert.Contains(filled[0].Lines!, l => l.Copy == "letsencrypt.org");
        Assert.Contains(filled[0].Lines!, l => l.Copy == "pki.goog");
    }

    [Fact]
    public void Admin_not_found_gets_copyable_how_to_lines()
    {
        var findings = new[]
        {
            new Finding(
                "Admin pages",
                FindingState.NotFound,
                "Common public admin paths did not answer 2xx or 3xx: /wp-admin/, /admin.",
                "GET each allowlisted admin path.",
                "A custom admin URL is not found this way.")
        };
        var edge = new EdgeProfile(EdgeKind.CloudflareProxied, "Cloudflare", true, true, true);
        var steps = Advice.Build("www.operationlockedin.com", findings, new[] { new StackHint("Next.js", "15", "x-powered-by") }, Array.Empty<string>(), 200, "Tls12", 301, "https://www.operationlockedin.com/", edge);
        var admin = Assert.Single(steps, s => s.Related == "Admin pages");
        Assert.NotNull(admin.Lines);
        Assert.Contains(admin.Lines!, l => l.Copy == "https://www.operationlockedin.com/wp-admin/");
        Assert.Contains(admin.Lines!, l => l.Copy == "https://www.operationlockedin.com/admin");
        Assert.Contains(admin.Lines!, l => l.Copy != null && l.Copy.Contains("wp-admin"));
        Assert.Contains("Next.js", admin.WhenNot);
        var finding = findings[0];
        Assert.True(FindingGuide.ShowsHowTo(finding, admin));
        Assert.True(FindingGuide.ShowsWhen(admin));
    }

    [Fact]
    public void Present_hsts_does_not_show_how_to()
    {
        var f = new Finding("Strict-Transport-Security", FindingState.Present, "obs", "method", "caveat");
        var step = new NextStep("Fix HSTS", "body", "Strict-Transport-Security", Lines: new[] { new FixLine("Set the header.") });
        Assert.False(FindingGuide.ShowsHowTo(f, step));
    }

    [Fact]
    public void Present_admin_does_not_show_how_to()
    {
        var f = new Finding("Admin pages", FindingState.Present, "obs", "method", "caveat");
        var step = new NextStep("Address Admin pages", "body", "Admin pages", Lines: new[] { new FixLine("x") });
        Assert.False(FindingGuide.ShowsHowTo(f, step));
    }
}
