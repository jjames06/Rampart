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
}
