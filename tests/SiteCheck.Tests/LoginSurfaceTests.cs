using SiteCheck.Core;

namespace SiteCheck.Tests;

public class LoginSurfaceTests
{
    private static LoginHit Hit(
        string path,
        int? status,
        string? location = null,
        string? body = null,
        IReadOnlyDictionary<string, string>? headers = null,
        IReadOnlyList<string>? cookies = null) =>
        new(
            path,
            status,
            location,
            body,
            headers ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            cookies ?? Array.Empty<string>());

    [Fact]
    public void Summary_is_not_found_when_every_path_misses()
    {
        var hits = LoginSurface.Paths.Select(p => Hit(p, 404)).ToArray();
        var f = LoginSurface.Summary(hits);
        Assert.Equal(FindingState.NotFound, f.State);
    }

    [Fact]
    public void Summary_is_present_when_a_login_path_answers()
    {
        var hits = new[] { Hit("/account/sign-in", 200, body: "<form action=\"/x\">") };
        var f = LoginSurface.Summary(hits);
        Assert.Equal(FindingState.Present, f.State);
        Assert.Contains("/account/sign-in", f.Observation);
    }

    [Fact]
    public void Http_location_is_attention()
    {
        var hits = new[] { Hit("/login", 302, location: "http://example.com/login") };
        var issues = LoginSurface.Issues(hits).ToArray();
        Assert.Contains(issues, i => i.Title == "Sign-in redirect" && i.State == FindingState.Attention);
    }

    [Fact]
    public void Http_form_action_is_attention()
    {
        var hits = new[] { Hit("/account/sign-in", 200, body: "<form action=\"http://evil.example/steal\">") };
        var issues = LoginSurface.Issues(hits).ToArray();
        Assert.Contains(issues, i => i.Title == "Sign-in form" && i.State == FindingState.Attention);
    }

    [Fact]
    public void Missing_frame_protection_on_html_login_is_attention()
    {
        var hits = new[] { Hit("/account/sign-in", 200, body: "<html><form></form></html>") };
        var issues = LoginSurface.Issues(hits).ToArray();
        Assert.Contains(issues, i => i.Title == "Sign-in framing" && i.State == FindingState.Attention);
    }

    [Fact]
    public void Frame_ancestors_counts_as_protection()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        };
        var hits = new[] { Hit("/account/sign-in", 200, body: "<html><form></form></html>", headers: headers) };
        var issues = LoginSurface.Issues(hits).ToArray();
        Assert.Contains(issues, i => i.Title == "Sign-in framing" && i.State == FindingState.Present);
    }

    [Fact]
    public void Weak_signin_cookie_is_attention()
    {
        var hits = new[] { Hit("/login", 200, body: "<html/>", cookies: new[] { "sid=abc" }) };
        var issues = LoginSurface.Issues(hits).ToArray();
        Assert.Contains(issues, i => i.Title == "Sign-in cookies" && i.State == FindingState.Attention);
    }

    [Fact]
    public void Public_cache_on_login_html_is_attention()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Cache-Control"] = "public, max-age=600"
        };
        var hits = new[] { Hit("/account/sign-in", 200, body: "<html><form></form></html>", headers: headers) };
        var issues = LoginSurface.Issues(hits).ToArray();
        Assert.Contains(issues, i => i.Title == "Sign-in cache" && i.State == FindingState.Attention);
    }

    [Fact]
    public void Admin_dashboard_html_is_attention()
    {
        var hits = new[] { Hit("/wp-admin/", 200, body: "<html id=\"wpadminbar\">Dashboard</html>") };
        var f = LoginSurface.AdminSummary(hits);
        Assert.Equal(FindingState.Attention, f.State);
    }

    [Fact]
    public void Admin_login_form_is_present()
    {
        var hits = new[] { Hit("/wp-admin/", 200, body: "<form name=\"loginform\"></form>") };
        var f = LoginSurface.AdminSummary(hits);
        Assert.Equal(FindingState.Present, f.State);
    }

    [Fact]
    public void Account_paths_include_operation_locked_in_sign_in()
    {
        Assert.Contains("/account/sign-in", LoginSurface.AccountPaths);
        Assert.Contains("/account/sign-up", LoginSurface.AccountPaths);
    }
}
