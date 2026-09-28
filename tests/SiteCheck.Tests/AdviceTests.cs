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
    public void Hsts_attention_still_gets_a_fix_step()
    {
        var findings = new[] { F("Strict-Transport-Security", FindingState.Attention) };
        var steps = Advice.Build("example.com", findings, Array.Empty<StackHint>(), Array.Empty<string>(), 200, "Tls12", null, null);
        Assert.Contains(steps, s => s.Related == "Strict-Transport-Security");
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
}

public class CveCatalogTests
{
    [Fact]
    public void Matches_next_16_3_5_and_not_15_5_26()
    {
        var bad = new[] { new StackHint("Next.js", "16.3.5", "header") };
        var good = new[] { new StackHint("Next.js", "15.5.26", "header") };
        Assert.NotEmpty(CveCatalog.Match(bad));
        Assert.Empty(CveCatalog.Match(good));
    }
}
