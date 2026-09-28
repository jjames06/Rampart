namespace SiteCheck.Core;

/// <summary>
/// Public account, sign-in, and admin URLs only. GET, no body, no passwords, no extra ports.
/// Paths are an allowlist of common addresses, not a crawl and not a credential test.
/// </summary>
public static class LoginSurface
{
    public static readonly string[] AccountPaths =
    {
        "/account/sign-in",
        "/account/sign-up",
        "/account",
        "/login",
        "/signin",
        "/sign-in",
        "/signup",
        "/register",
        "/wp-login.php",
        "/user/login",
        "/auth/login"
    };

    public static readonly string[] AdminPaths =
    {
        "/wp-admin/",
        "/admin"
    };

    public static readonly string[] Paths = AccountPaths.Concat(AdminPaths).ToArray();

    public static Finding Summary(IReadOnlyList<LoginHit> hits, bool wordpressAdvertised = false)
    {
        var live = hits
            .Where(h => AccountPaths.Contains(h.Path) && h.Alive)
            .Select(h => h.Path + " HTTP " + h.Status)
            .Take(8)
            .ToArray();
        if (live.Length == 0)
        {
            if (wordpressAdvertised)
            {
                return new Finding(
                    "Sign-in pages",
                    FindingState.NotFound,
                    "This hostname advertised WordPress, but none of the common public sign-in paths answered 2xx or 3xx.",
                    "GET each allowlisted account path on the same public address, redirects disabled, body capped at 64 KB.",
                    "A renamed wp-login.php is not found this way.");
            }

            return new Finding(
                "Sign-in pages",
                FindingState.Present,
                "None of the common public sign-in paths answered 2xx or 3xx. That is expected on a hostname with no public accounts.",
                "GET each allowlisted account path on the same public address, redirects disabled, body capped at 64 KB.",
                "A custom login URL is not found this way. That is not proof the site has no accounts.");
        }

        return new Finding(
            "Sign-in pages",
            FindingState.Present,
            "Public sign-in or account paths that answered: " + string.Join("; ", live) + ".",
            "GET allowlisted account paths on the same public address. Redirects are not followed. Passwords are not sent.",
            "This is not a login test and not a credential check. Only GET is used.");
    }

    public static Finding AdminSummary(IReadOnlyList<LoginHit> hits)
    {
        var live = hits.Where(h => AdminPaths.Contains(h.Path) && h.Alive).ToArray();
        if (live.Length == 0)
        {
            return new Finding(
                "Admin pages",
                FindingState.Present,
                "Common public admin paths did not answer 2xx or 3xx: " + string.Join(", ", AdminPaths)
                    + ". Those dashboards are not published on this hostname.",
                "GET each allowlisted admin path on the same public address, redirects disabled, body capped.",
                "A custom admin URL is not found this way. That is not proof there is no admin.");
        }

        var exposed = live.Where(LooksLikeOpenAdmin).ToArray();
        if (exposed.Length > 0)
        {
            return new Finding(
                "Admin pages",
                FindingState.Attention,
                "An admin path answered 200 with markup that looks like a dashboard rather than a login wall: "
                    + string.Join("; ", exposed.Select(h => h.Path + " HTTP " + h.Status)) + ".",
                "GET allowlisted admin paths. Redirects are not followed. No password is sent.",
                "This is a hint from the HTML. Confirm in a browser while signed out. A 302 to a login page is the usual protection.");
        }

        return new Finding(
            "Admin pages",
            FindingState.Present,
            "Admin paths that answered: " + string.Join("; ", live.Select(h => h.Path + " HTTP " + h.Status))
                + ". Those responses look like a login wall or a redirect, not an open dashboard.",
            "GET allowlisted admin paths on the same public address. Redirects are not followed.",
            "A 302 to a login page is expected. This is not a privilege check.");
    }

    public static IEnumerable<Finding> Issues(IReadOnlyList<LoginHit> hits)
    {
        foreach (var hit in hits.Where(h => AccountPaths.Contains(h.Path)))
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
            .Where(h => AccountPaths.Contains(h.Path) && !string.IsNullOrEmpty(h.Body))
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

        var mixed = hits
            .Where(h => AccountPaths.Contains(h.Path) && h.Html)
            .Select(h => (h.Path, Mix: HtmlSurface.MixedContent(h.Body)))
            .Where(x => x.Mix.State == FindingState.Attention)
            .Take(4)
            .ToArray();
        foreach (var row in mixed)
        {
            yield return new Finding(
                "Sign-in mixed content",
                FindingState.Attention,
                row.Path + ": " + row.Mix.Observation,
                "Search the capped GET body of " + row.Path + " for src= or href= values that start with http://.",
                "A sign-in page should not load scripts or styles over http://.");
        }

        var htmlHits = hits.Where(h => AccountPaths.Contains(h.Path) && h.Html).ToArray();
        var unframed = htmlHits.Where(h => !HasFrameProtection(h.Headers)).Take(6).ToArray();
        if (unframed.Length > 0)
        {
            yield return new Finding(
                "Sign-in framing",
                FindingState.Attention,
                "These sign-in pages answered 200 without X-Frame-Options and without CSP frame-ancestors: "
                    + string.Join(", ", unframed.Select(h => h.Path)) + ".",
                "Read X-Frame-Options and Content-Security-Policy on GET of each live account path.",
                "A login page that can be framed is easier to clickjack. Homepage headers are not proof the account route sends the same headers.");
        }
        else if (htmlHits.Length > 0)
        {
            yield return new Finding(
                "Sign-in framing",
                FindingState.Present,
                "Live sign-in HTML responses included X-Frame-Options or CSP frame-ancestors.",
                "Read X-Frame-Options and Content-Security-Policy on GET of each live account path.",
                "This is the account route, not every page.");
        }

        var cookieHits = hits
            .Where(h => AccountPaths.Contains(h.Path) && h.Cookies.Count > 0)
            .ToArray();
        var weakCookies = cookieHits
            .SelectMany(h => h.Cookies.Select(c => (h.Path, Cookie: c)))
            .Where(x => HeaderFacts.CookieMissingRequiredFlags(x.Cookie))
            .Take(8)
            .ToArray();
        if (weakCookies.Length > 0)
        {
            yield return new Finding(
                "Sign-in cookies",
                FindingState.Attention,
                "A sign-in response set a cookie without both HttpOnly and Secure: "
                    + string.Join("; ", weakCookies.Select(x => x.Path).Distinct()) + ".",
                "Read each Set-Cookie value on GET of allowlisted account paths.",
                "GET often does not set a session cookie until the form is posted. This finding only applies when Set-Cookie was already present.");
        }
        else if (cookieHits.Length > 0)
        {
            var noSite = cookieHits
                .SelectMany(h => h.Cookies)
                .Where(c => c.IndexOf("SameSite", StringComparison.OrdinalIgnoreCase) < 0)
                .Any();
            yield return new Finding(
                "Sign-in cookies",
                noSite ? FindingState.Attention : FindingState.Present,
                noSite
                    ? "HttpOnly and Secure were present on sign-in Set-Cookie headers. SameSite was missing on at least one of them."
                    : "Sign-in Set-Cookie headers included HttpOnly and Secure.",
                "Read each Set-Cookie value on GET of allowlisted account paths.",
                "Cookies set only after a successful POST are not shown. Passwords are never sent.");
        }

        var cached = htmlHits
            .Where(IsPubliclyCacheable)
            .Take(6)
            .ToArray();
        if (cached.Length > 0)
        {
            yield return new Finding(
                "Sign-in cache",
                FindingState.Attention,
                "These sign-in pages sent Cache-Control: public without no-store: "
                    + string.Join(", ", cached.Select(h => h.Path)) + ".",
                "Read Cache-Control on GET of each live account path.",
                "A shared cache should not store a login page that might include a CSRF token or a personalized form.");
        }
    }

    public static bool HasFrameProtection(IReadOnlyDictionary<string, string> headers)
    {
        if (headers.TryGetValue("X-Frame-Options", out var xfo) && !string.IsNullOrWhiteSpace(xfo))
            return true;
        if (headers.TryGetValue("Content-Security-Policy", out var csp)
            && csp.IndexOf("frame-ancestors", StringComparison.OrdinalIgnoreCase) >= 0)
            return true;
        return false;
    }

    public static bool IsPubliclyCacheable(LoginHit hit)
    {
        if (!hit.Headers.TryGetValue("Cache-Control", out var cc) || string.IsNullOrWhiteSpace(cc))
            return false;
        if (cc.IndexOf("no-store", StringComparison.OrdinalIgnoreCase) >= 0)
            return false;
        if (cc.IndexOf("private", StringComparison.OrdinalIgnoreCase) >= 0)
            return false;
        return cc.IndexOf("public", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    public static bool LooksLikeOpenAdmin(LoginHit hit)
    {
        if (hit.Status != 200 || string.IsNullOrEmpty(hit.Body)) return false;
        var body = hit.Body;
        if (body.Contains("loginform", StringComparison.OrdinalIgnoreCase)) return false;
        if (body.Contains("wp-login", StringComparison.OrdinalIgnoreCase)) return false;
        if (body.Contains("name=\"log\"", StringComparison.OrdinalIgnoreCase)) return false;
        var dashboard = body.Contains("wp-admin/css", StringComparison.OrdinalIgnoreCase)
            || body.Contains("id=\"wpadminbar\"", StringComparison.OrdinalIgnoreCase)
            || body.Contains("Dashboard", StringComparison.OrdinalIgnoreCase);
        return dashboard;
    }
}

/// <summary>
/// One GET of an allowlisted account or admin path. Redirects are not followed.
/// </summary>
public sealed record LoginHit(
    string Path,
    int? Status,
    string? Location,
    string? Body,
    IReadOnlyDictionary<string, string> Headers,
    IReadOnlyList<string> Cookies)
{
    public bool Alive => Status is >= 200 and < 400;

    public bool Html => Status is >= 200 and < 300 && !string.IsNullOrEmpty(Body);
}
