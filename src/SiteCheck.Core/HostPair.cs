// CODEMAP FILE: src/SiteCheck.Core/HostPair.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: HEAD www vs apex so a split (one live, one parking, mismatched cert) is visible.
// Called by: Checker after the primary host run.
// Calls: PrivateIp (skip if the pair is private).
// Invariants: One extra HEAD each, no crawl. Missing www is not always a bug (apex-only shops exist); Advice/FixGuides word it as optional when appropriate.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

namespace SiteCheck.Core;

/// <summary>
/// See docs/CODEMAP.md.
/// www versus apex on the same zone. One extra HEAD, redirects not followed.
/// </summary>
public static class HostPair
{
    public static string? Sibling(string hostname)
    {
        if (hostname.StartsWith("www.", StringComparison.OrdinalIgnoreCase) && hostname.Length > 4)
            return hostname[4..];
        var apex = Hostname.Apex(hostname);
        if (string.Equals(hostname, apex, StringComparison.OrdinalIgnoreCase))
            return "www." + apex;
        return null;
    }

    public static Finding Summary(string hostname, string? sibling, int? status, string? location, bool siblingPublic)
    {
        if (sibling is null)
        {
            return new Finding(
                "WWW and apex",
                FindingState.Present,
                "This hostname is not a simple www or apex pair, so a sibling name was not requested.",
                "Derive www from apex or apex from www, then HEAD / on that sibling if it has a public address.",
                "Other hostnames in the zone are not requested.");
        }

        if (!siblingPublic)
        {
            return new Finding(
                "WWW and apex",
                FindingState.Present,
                "No public Internet address was published for " + sibling + ".",
                "Resolve A and AAAA for the sibling name, then HEAD / only if a public address exists.",
                "A missing www record is common. It is not a TLS failure on the name you typed.");
        }

        if (status is null)
        {
            return new Finding(
                "WWW and apex",
                FindingState.Incomplete,
                "HTTPS HEAD / on " + sibling + " did not complete.",
                "HEAD / on the sibling hostname, redirects disabled, same timeout as the main check.",
                "A timeout on the sibling is not a finding about " + hostname + ".");
        }

        var loc = string.IsNullOrWhiteSpace(location) ? "no Location header" : "Location " + location;
        var state = FindingState.Present;
        if (status is >= 300 and < 400 && location != null && location.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            state = FindingState.Attention;

        return new Finding(
            "WWW and apex",
            state,
            "Sibling " + sibling + " answered HTTP " + status + " with " + loc + ".",
            "HEAD / on https://" + sibling + "/ with redirects disabled.",
            "This is one sibling name, not a full zone walk.");
    }
}
