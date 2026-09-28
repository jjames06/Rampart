using SiteCheck.Core;

namespace SiteCheck.Tests;

public class LoginSurfaceTests
{
    [Fact]
    public void Summary_is_not_found_when_every_path_misses()
    {
        var hits = LoginSurface.Paths.Select(p => (p, (int?)404, (string?)null, (string?)null)).ToArray();
        var f = LoginSurface.Summary(hits);
        Assert.Equal(FindingState.NotFound, f.State);
    }

    [Fact]
    public void Summary_is_present_when_a_login_path_answers()
    {
        var hits = new[] { ("/account/sign-in", (int?)200, (string?)null, "<form action=\"/x\">") };
        var f = LoginSurface.Summary(hits);
        Assert.Equal(FindingState.Present, f.State);
    }

    [Fact]
    public void Http_location_is_attention()
    {
        var hits = new[] { ("/login", (int?)302, "http://example.com/login", (string?)null) };
        var issues = LoginSurface.FormAndRedirectIssues(hits).ToArray();
        Assert.Contains(issues, i => i.Title == "Sign-in redirect" && i.State == FindingState.Attention);
    }
}
