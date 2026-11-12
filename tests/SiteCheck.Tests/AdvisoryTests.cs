// CODEMAP FILE: tests/SiteCheck.Tests/AdvisoryTests.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Locks catalogue matching: version in range hits, unknown product misses, plugin slug is not a version.
// Called by: dotnet test.
// Calls: AdvisoryDb, VersionCmp.
// Invariants: Tests use fixtures, not live NVD.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using SiteCheck.Core;

namespace SiteCheck.Tests;

public class AdvisoryTests
{
    [Fact]
    public void Catalogue_is_embedded_and_non_trivial()
    {
        Assert.True(AdvisoryDb.ProductCount >= 50);
        Assert.True(AdvisoryDb.AdvisoryCount >= 500);
        Assert.False(string.IsNullOrWhiteSpace(AdvisoryDb.Built));
    }

    [Fact]
    public void Jquery_1_12_4_from_homepage_url_matches_known_cves()
    {
        const string html = """<script src="/js/jquery-1.12.4.min.js"></script>""";
        var stack = Fingerprint.FromPublicSurface(new Dictionary<string, string>(), html);
        Assert.Contains(stack, s => s.Product == "jQuery" && s.Version == "1.12.4");
        var hits = CveCatalog.Match(stack);
        Assert.Contains(hits, h => h.Entry.Id == "CVE-2015-9251");
        Assert.Contains(hits, h => h.Entry.Id == "CVE-2019-11358");
    }

    [Fact]
    public void Jquery_3_7_1_is_outside_the_1_x_2_x_and_pre_3_5_ranges()
    {
        var stack = new[] { new StackHint("jQuery", "3.7.1", "test") };
        var hits = CveCatalog.Match(stack);
        Assert.DoesNotContain(hits, h => h.Entry.Id == "CVE-2015-9251");
        Assert.DoesNotContain(hits, h => h.Entry.Id == "CVE-2020-11022");
    }

    [Fact]
    public void Next_16_3_5_matches_image_response_rce_and_15_5_26_does_not()
    {
        var bad = new[] { new StackHint("Next.js", "16.3.5", "header") };
        var good = new[] { new StackHint("Next.js", "15.5.26", "header") };
        Assert.Contains(CveCatalog.Match(bad), h => h.Entry.Id == "GHSA-vcvr-r3jv-pc5j");
        Assert.DoesNotContain(CveCatalog.Match(good), h => h.Entry.Id == "GHSA-vcvr-r3jv-pc5j");
    }

    [Fact]
    public void Php_7_is_end_of_life_php_8_3_is_not()
    {
        var old = new[] { new StackHint("PHP", "7.4.33", "header") };
        var cur = new[] { new StackHint("PHP", "8.3.0", "header") };
        Assert.Contains(CveCatalog.Match(old), h => h.Entry.Id == "PHP-EOL");
        Assert.DoesNotContain(CveCatalog.Match(cur), h => h.Entry.Id == "PHP-EOL");
    }

    [Fact]
    public void Version_compare_orders_dotted_numbers()
    {
        Assert.True(VersionCmp.Compare("16.3.5", "16.3.6") < 0);
        Assert.True(VersionCmp.Satisfies("16.3.5", ">=", "16.2.0"));
        Assert.True(VersionCmp.Satisfies("16.3.5", "<", "16.3.6"));
        Assert.False(VersionCmp.Satisfies("16.3.6", "<", "16.3.6"));
    }
}
