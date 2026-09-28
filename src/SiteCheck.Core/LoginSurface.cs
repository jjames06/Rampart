namespace SiteCheck.Core;

/// <summary>
/// Public sign-in URLs only. GET, no body, no passwords, no extra ports.
/// Paths are an allowlist of common login addresses, not a crawl.
/// </summary>
public static class LoginSurface
{
    public static readonly string[] Paths =
    {
        "/account/sign-in",
        "/login",
        "/signin",
        "/sign-in",
        "/wp-login.php",
        "/user/login"
    };

    public static Finding Summary(IReadOnlyList<(string Path, int? Status, string? Location, string? Body)> hits)
    {
        var live = hits
            .Where(h => h.Status is >= 200 and < 400)
            .Select(h => h.Path + " HTTP " + h.Status)
            .Take(8)
            .ToArray();
        if (live.Length == 0)
        {
            return new Finding(
                "Sign-in pages",
                FindingState.NotFound,
                "None of the common public sign-in paths answered 2xx or 3xx: " + string.Join(", ", Paths) + ".",
                "GET each allowlisted path on the same public address, redirects disabled, body capped.",
                "A custom login URL is not found this way. That is not proof the site has no accounts.");
        }

        return new Finding(
            "Sign-in pages",
            FindingState.Present,
            "Public sign-in paths that answered: " + string.Join("; ", live) + ".",
            "GET allowlisted login paths on the same public address. Redirects are not followed. Passwords are not sent.",
            "This is not a login test and not a credential check.");
    }

    public static IEnumerable<Finding> FormAndRedirectIssues(IReadOnlyList<(string Path, int? Status, string? Location, string? Body)> hits)
    {
        foreach (var hit in hits)
        {
            if (hit.Location != null && hit.Location.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                yield return new Finding(
                    "Sign-in redirect",
                    FindingState.Attention,
                    hit.Path + " sent Location to http://: " + hit.Location,
                    "Read the Location header on GET " + hit.Path + " with redirects disabled.",
                    "The next hop would leave TLS. Change that Location to https://.");
            }
        }

        var httpForms = hits
            .Where(h => !string.IsNullOrEmpty(h.Body))
            .Select(h => (h.Path, Form: HtmlSurface.InsecureForms(h.Body)))
            .Where(x => x.Form.State == FindingState.Attention)
            .Take(6)
            .ToArray();
        foreach (var row in httpForms)
        {
            yield return new Finding(
                "Sign-in form",
                FindingState.Attention,
                row.Path + ": " + row.Form.Observation,
                "Read <form action=http://> in the capped GET body of " + row.Path + ".",
                "A login form that posts to http:// sends credentials without TLS.");
        }
    }
}
