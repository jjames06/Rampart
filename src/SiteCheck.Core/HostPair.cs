namespace SiteCheck.Core;

/// <summary>
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
