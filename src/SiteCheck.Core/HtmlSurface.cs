// CODEMAP FILE: src/SiteCheck.Core/HtmlSurface.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Homepage HTML (capped) for mixed content, missing SRI on third-party scripts, target=_blank without rel, form action, canonical host.
// Called by: Checker after the GET / body.
// Calls: Models.Finding.
// Invariants: Do not download linked plugin files. Do not execute the HTML. Cap is Checker's MaxBodyBytes.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using System.Text.RegularExpressions;

namespace SiteCheck.Core;

/// <summary>
/// See docs/CODEMAP.md.
/// Read-only observations from the capped homepage HTML.
/// Looks only at markup already fetched for GET /. Does not download scripts.
/// </summary>
public static class HtmlSurface
{
    private static readonly Regex HttpResource = new(
        @"(?:src|href)\s*=\s*[""'](http://[^""']+)[""']",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex ExternalScript = new(
        @"<script[^>]+src\s*=\s*[""'](https://[^""']+)[""'][^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex BlankTarget = new(
        @"<a\b[^>]*target\s*=\s*[""']_blank[""'][^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex HttpForm = new(
        @"<form\b[^>]*action\s*=\s*[""'](http://[^""']+)[""']",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static Finding MixedContent(string? html)
    {
        if (string.IsNullOrEmpty(html))
        {
            return new Finding(
                "Mixed content",
                FindingState.Incomplete,
                "The homepage body was not read, so mixed http:// resources were not checked.",
                "Search the capped GET / HTML for src= or href= values that start with http://.",
                "Scripts loaded after the first 256 KB are not shown.");
        }

        var hits = HttpResource.Matches(html)
            .Select(m => m.Groups[1].Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToArray();
        if (hits.Length == 0)
        {
            return new Finding(
                "Mixed content",
                FindingState.Present,
                "No http:// script or link URLs were found in the homepage HTML.",
                "Search the capped GET / HTML for src= or href= values that start with http://.",
                "Inline CSS url() values and resources loaded by later JavaScript are not shown.");
        }

        return new Finding(
            "Mixed content",
            FindingState.Attention,
            "The homepage HTML named http:// resources: " + string.Join(", ", hits) + ".",
            "Search the capped GET / HTML for src= or href= values that start with http://.",
            "Browsers may block these on an HTTPS page. This is not a scan of every subresource.");
    }

    public static Finding SubresourceIntegrity(string? html)
    {
        if (string.IsNullOrEmpty(html))
        {
            return new Finding(
                "Subresource Integrity",
                FindingState.Incomplete,
                "The homepage body was not read, so script integrity attributes were not checked.",
                "Read script src=https:// tags in the capped GET / HTML.",
                "Only the homepage markup is examined.");
        }

        var scripts = ExternalScript.Matches(html).Cast<Match>().ToArray();
        if (scripts.Length == 0)
        {
            return new Finding(
                "Subresource Integrity",
                FindingState.Present,
                "No https:// script URLs were found on the homepage.",
                "Read script tags with an https src in the capped GET / HTML.",
                "Bundled same-origin scripts often have no src=https:// URL. That is expected on Next.js.");
        }

        var missing = scripts.Where(m =>
                m.Value.IndexOf("integrity=", StringComparison.OrdinalIgnoreCase) < 0)
            .Select(m => m.Groups[1].Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToArray();
        if (missing.Length == 0)
        {
            return new Finding(
                "Subresource Integrity",
                FindingState.Present,
                "External https:// scripts on the homepage included an integrity attribute.",
                "Read script tags with an https src in the capped GET / HTML.",
                "Integrity on the homepage does not prove every later request is covered.");
        }

        return new Finding(
            "Subresource Integrity",
            FindingState.NotFound,
            "External scripts without integrity: " + string.Join(", ", missing) + ".",
            "Read script tags with an https src in the capped GET / HTML.",
            "Same-origin bundles (for example /_next/static) often omit integrity. Prefer fixing third-party CDNs first.");
    }

    public static Finding Tabnabbing(string? html)
    {
        if (string.IsNullOrEmpty(html))
        {
            return new Finding(
                "Tabnabbing",
                FindingState.Incomplete,
                "The homepage body was not read, so target=_blank links were not checked.",
                "Read <a> tags with target=_blank in the capped GET / HTML.",
                "Links added later by JavaScript are not shown.");
        }

        var blanks = BlankTarget.Matches(html).Cast<Match>().ToArray();
        if (blanks.Length == 0)
        {
            return new Finding(
                "Tabnabbing",
                FindingState.Present,
                "No target=_blank links were found on the homepage.",
                "Read <a> tags with target=_blank in the capped GET / HTML.",
                "This does not inspect every page or every script-inserted link.");
        }

        var risky = blanks
            .Where(m =>
                m.Value.IndexOf("noopener", StringComparison.OrdinalIgnoreCase) < 0
                && m.Value.IndexOf("noreferrer", StringComparison.OrdinalIgnoreCase) < 0)
            .Take(8)
            .ToArray();
        if (risky.Length == 0)
        {
            return new Finding(
                "Tabnabbing",
                FindingState.Present,
                $"All {blanks.Length} target=_blank link(s) on the homepage included rel=noopener or noreferrer.",
                "Read <a> tags with target=_blank in the capped GET / HTML.",
                "rel must be on the same opening tag. This is not a crawl of every page.");
        }

        return new Finding(
            "Tabnabbing",
            FindingState.Attention,
            $"{risky.Length} of {blanks.Length} target=_blank link(s) on the homepage omitted rel=noopener and rel=noreferrer.",
            "Read <a> tags with target=_blank in the capped GET / HTML. A match requires the rel token on that same opening tag.",
            "The opened page can rewrite window.opener. This is markup on GET /, not a proof of an in-the-wild attack.");
    }

    public static Finding InsecureForms(string? html)
    {
        if (string.IsNullOrEmpty(html))
        {
            return new Finding(
                "Form action",
                FindingState.Incomplete,
                "The homepage body was not read, so form actions were not checked.",
                "Read <form action=http://> in the capped GET / HTML.",
                "Forms built later by JavaScript are not shown.");
        }

        var hits = HttpForm.Matches(html)
            .Select(m => m.Groups[1].Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToArray();
        if (hits.Length == 0)
        {
            return new Finding(
                "Form action",
                FindingState.Present,
                "No form on the homepage posted to an http:// URL.",
                "Read <form action=http://> in the capped GET / HTML.",
                "Relative and https actions are accepted. JavaScript-submitted forms are not shown.");
        }

        return new Finding(
            "Form action",
            FindingState.Attention,
            "The homepage HTML posted a form to http://: " + string.Join(", ", hits) + ".",
            "Read <form action=http://> in the capped GET / HTML.",
            "Credentials or form fields on that action would travel without TLS. This is not a crawl of every page.");
    }

    public static Finding HttpCanonical(string? html)
    {
        if (string.IsNullOrEmpty(html))
        {
            return new Finding(
                "Canonical URL",
                FindingState.Incomplete,
                "The homepage body was not read, so the canonical link was not checked.",
                "Read <link rel=canonical> in the capped GET / HTML.",
                "Canonical tags on other paths are not shown.");
        }

        var m = Regex.Match(
            html,
            @"<link\b[^>]*rel\s*=\s*[""']canonical[""'][^>]*href\s*=\s*[""'](http://[^""']+)[""']|<link\b[^>]*href\s*=\s*[""'](http://[^""']+)[""'][^>]*rel\s*=\s*[""']canonical[""']",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (!m.Success)
        {
            return new Finding(
                "Canonical URL",
                FindingState.Present,
                "No http:// canonical URL was found on the homepage.",
                "Read <link rel=canonical> in the capped GET / HTML.",
                "A missing canonical tag is a search-engine choice, not a TLS failure. This check only flags an http:// canonical.");
        }

        var url = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
        return new Finding(
            "Canonical URL",
            FindingState.Attention,
            "The homepage canonical URL is http://: " + url + ".",
            "Read <link rel=canonical> in the capped GET / HTML.",
            "Search engines may treat the HTTP URL as the preferred address. Change the canonical to https://.");
    }
}
