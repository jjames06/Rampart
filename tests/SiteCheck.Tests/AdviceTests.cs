using SiteCheck.Core;

namespace SiteCheck.Tests;

public class AdviceTests
{
    private static Finding F(string title, FindingState state) =>
        new(title, state, "obs", "method", "caveat");

    [Fact]
    public void Omits_steps_when_everything_is_present()
    {
        var findings = new[]
        {
            F("HTTPS", FindingState.Present),
            F("Certificate", FindingState.Present),
            F("Strict-Transport-Security", FindingState.Present),
            F("Content-Security-Policy", FindingState.Present),
            F("X-Content-Type-Options", FindingState.Present),
            F("X-Frame-Options", FindingState.Present),
            F("Referrer-Policy", FindingState.Present),
            F("Permissions-Policy", FindingState.Present),
            F("SPF", FindingState.Present),
            F("DMARC", FindingState.Present),
            F("Cookie flags", FindingState.Present),
            F("Server disclosure", FindingState.Present),
        };
        var steps = Advice.Build("example.com", findings, Array.Empty<StackHint>(), Array.Empty<string>(), 200, "Tls12", null, null);
        Assert.Empty(steps);
    }

    [Fact]
    public void Hsts_step_uses_next_config_when_Next_is_advertised()
    {
        var findings = new[] { F("Strict-Transport-Security", FindingState.NotFound) };
        var stack = new[] { new StackHint("Next.js", "15.5.26", "X-Powered-By") };
        var steps = Advice.Build("example.com", findings, stack, Array.Empty<string>(), 200, "Tls12", null, null);
        var hsts = Assert.Single(steps, s => s.Related == "Strict-Transport-Security");
        Assert.Contains("next.config.ts", hsts.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("WordPress", hsts.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void Does_not_advise_Hsts_when_present()
    {
        var findings = new[]
        {
            F("Strict-Transport-Security", FindingState.Present),
            F("SPF", FindingState.NotFound),
        };
        var steps = Advice.Build("example.com", findings, Array.Empty<StackHint>(), Array.Empty<string>(), 200, "Tls12", null, null);
        Assert.DoesNotContain(steps, s => s.Related == "Strict-Transport-Security");
        Assert.Contains(steps, s => s.Related == "SPF");
    }

    [Fact]
    public void Security_txt_missing_gets_a_step()
    {
        var findings = new[] { F("security.txt", FindingState.NotFound) };
        var steps = Advice.Build("example.com", findings, Array.Empty<StackHint>(), Array.Empty<string>(), 200, "Tls12", null, null);
        Assert.Contains(steps, s => s.Related == "security.txt");
    }

    [Fact]
    public void Incomplete_headers_do_not_spawn_header_fixes()
    {
        var findings = new[]
        {
            F("HTTPS", FindingState.Incomplete),
            F("Strict-Transport-Security", FindingState.Incomplete),
            F("Content-Security-Policy", FindingState.Incomplete),
            F("SPF", FindingState.NotFound),
        };
        var steps = Advice.Build("example.com", findings, Array.Empty<StackHint>(), Array.Empty<string>(), null, null, null, null);
        Assert.Contains(steps, s => s.Related == "HTTPS");
        Assert.DoesNotContain(steps, s => s.Related == "Strict-Transport-Security");
        Assert.DoesNotContain(steps, s => s.Related == "Content-Security-Policy");
        Assert.Contains(steps, s => s.Related == "SPF");
    }

    [Fact]
    public void Dns_gaps_are_not_described_as_vercel_headers()
    {
        var findings = new[]
        {
            F("CAA", FindingState.NotFound),
            F("DNSSEC", FindingState.NotFound),
        };
        var stack = new[] { new StackHint("Vercel", null, "header"), new StackHint("Cloudflare", null, "header") };
        var steps = Advice.Build("example.com", findings, stack, Array.Empty<string>(), 200, "Tls12", null, null);
        Assert.DoesNotContain(steps, s => s.Body.Contains("usually a header in next.config", StringComparison.Ordinal));
        Assert.Contains(steps, s => s.Related == "CAA" && s.Environment == "DNS host");
        Assert.Contains(steps, s => s.Related == "DNSSEC" && s.Environment == "DNS host");
    }

    [Fact]
    public void Csp_attention_is_tighten_not_add()
    {
        var findings = new[] { F("Content-Security-Policy", FindingState.Attention) };
        var stack = new[] { new StackHint("Next.js", "15.5.26", "header") };
        var steps = Advice.Build("example.com", findings, stack, Array.Empty<string>(), 200, "Tls12", null, null);
        Assert.Contains(steps, s => s.Title.StartsWith("Tighten", StringComparison.Ordinal));
        Assert.DoesNotContain(steps, s => s.Title.StartsWith("Fix Content-Security-Policy", StringComparison.Ordinal));
    }

    [Fact]
    public void Hsts_attention_still_gets_a_fix_step()
    {
        var findings = new[] { F("Strict-Transport-Security", FindingState.Attention) };
        var steps = Advice.Build("example.com", findings, Array.Empty<StackHint>(), Array.Empty<string>(), 200, "Tls12", null, null);
        Assert.Contains(steps, s => s.Related == "Strict-Transport-Security");
    }

    [Fact]
    public void Cloudflare_obfuscation_is_not_described_as_a_vercel_header()
    {
        var findings = new[] { F("Cloudflare email obfuscation", FindingState.Attention) };
        var stack = new[]
        {
            new StackHint("Vercel", null, "header"),
            new StackHint("Cloudflare", null, "header"),
            new StackHint("Next.js", "15.5.26", "header"),
        };
        var steps = Advice.Build("www.example.com", findings, stack, Array.Empty<string>(), 200, "Tls12", null, null);
        var step = Assert.Single(steps, s => s.Related == "Cloudflare email obfuscation");
        Assert.DoesNotContain("usually a header in next.config", step.Body, StringComparison.Ordinal);
        Assert.Contains(step.Lines!, l => l.Text.Contains("Email Address Obfuscation", StringComparison.Ordinal));
    }

    [Fact]
    public void Mixed_content_attention_gets_a_fix_step()
    {
        var findings = new[] { F("Mixed content", FindingState.Attention) };
        var steps = Advice.Build("example.com", findings, Array.Empty<StackHint>(), Array.Empty<string>(), 200, "Tls12", null, null);
        Assert.Contains(steps, s => s.Related == "Mixed content");
    }

    [Fact]
    public void Permissive_spf_is_tighten_not_add()
    {
        var findings = new[] { F("SPF", FindingState.Attention) };
        var steps = Advice.Build("example.com", findings, Array.Empty<StackHint>(), Array.Empty<string>(), 200, "Tls12", null, null);
        Assert.Contains(steps, s => s.Title.StartsWith("Tighten the SPF", StringComparison.Ordinal));
        Assert.DoesNotContain(steps, s => s.Title.StartsWith("Fix SPF", StringComparison.Ordinal));
    }

    [Fact]
    public void Mta_sts_steps_only_when_mx_is_present()
    {
        var withoutMx = Advice.Build("example.com", new[] { F("MTA-STS policy", FindingState.NotFound) }, Array.Empty<StackHint>(), Array.Empty<string>(), 200, "Tls12", null, null);
        var withMx = Advice.Build("example.com", new[]
        {
            F("MX", FindingState.Present),
            F("MTA-STS policy", FindingState.NotFound),
        }, Array.Empty<StackHint>(), Array.Empty<string>(), 200, "Tls12", null, null);
        Assert.DoesNotContain(withoutMx, s => s.Related == "MTA-STS policy");
        Assert.Contains(withMx, s => s.Related == "MTA-STS policy");
    }

    [Fact]
    public void Coep_is_optional_unless_coop_is_already_present()
    {
        var lonely = Advice.Build("example.com", new[] { F("Cross-Origin-Embedder-Policy", FindingState.NotFound) }, Array.Empty<StackHint>(), Array.Empty<string>(), 200, "Tls12", null, null);
        var together = Advice.Build("example.com", new[]
        {
            F("Cross-Origin-Opener-Policy", FindingState.Present),
            F("Cross-Origin-Embedder-Policy", FindingState.NotFound),
        }, Array.Empty<StackHint>(), Array.Empty<string>(), 200, "Tls12", null, null);
        Assert.DoesNotContain(lonely, s => s.Related == "Cross-Origin-Embedder-Policy");
        Assert.Contains(together, s => s.Related == "Cross-Origin-Embedder-Policy");
    }

    [Fact]
    public void Certificate_renewal_only_when_days_are_low()
    {
        var findings = new[] { F("Certificate", FindingState.Present) };
        var soon = Advice.Build("example.com", findings, Array.Empty<StackHint>(), Array.Empty<string>(), 10, "Tls12", null, null);
        var plenty = Advice.Build("example.com", findings, Array.Empty<StackHint>(), Array.Empty<string>(), 200, "Tls12", null, null);
        Assert.Contains(soon, s => s.Title.Contains("Renew", StringComparison.Ordinal));
        Assert.DoesNotContain(plenty, s => s.Title.Contains("Renew", StringComparison.Ordinal));
    }
}

public class FingerprintTests
{
    [Fact]
    public void Reads_wordpress_generator_and_plugin_paths()
    {
        const string html = """
            <meta name="generator" content="WordPress 6.4.2">
            <script src="/wp-content/plugins/akismet/script.js"></script>
            """;
        var stack = Fingerprint.FromPublicSurface(new Dictionary<string, string>(), html);
        Assert.Contains(stack, s => s.Product == "WordPress" && s.Version == "6.4.2");
        Assert.Equal(new[] { "akismet" }, Fingerprint.WordPressPluginSlugs(html));
    }

    [Fact]
    public void Reads_next_from_powered_by()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["X-Powered-By"] = "Next.js"
        };
        var stack = Fingerprint.FromPublicSurface(headers, null);
        Assert.Contains(stack, s => s.Product == "Next.js");
    }

    [Fact]
    public void Reads_next_from_homepage_markup()
    {
        var stack = Fingerprint.FromPublicSurface(new Dictionary<string, string>(), """<script src="/_next/static/chunks/main.js"></script>""");
        Assert.Contains(stack, s => s.Product == "Next.js");
    }

    [Fact]
    public void Reads_cloudfront_from_headers()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["x-amz-cf-id"] = "abc"
        };
        var stack = Fingerprint.FromPublicSurface(headers, null);
        Assert.Contains(stack, s => s.Product == "Amazon CloudFront");
    }
}

public class CveCatalogTests
{
    [Fact]
    public void Matches_next_16_3_5_image_response_and_not_15_5_26()
    {
        var bad = new[] { new StackHint("Next.js", "16.3.5", "header") };
        var good = new[] { new StackHint("Next.js", "15.5.26", "header") };
        Assert.Contains(CveCatalog.Match(bad), h => h.Entry.Id == "GHSA-vcvr-r3jv-pc5j");
        Assert.DoesNotContain(CveCatalog.Match(good), h => h.Entry.Id == "GHSA-vcvr-r3jv-pc5j");
    }
}
