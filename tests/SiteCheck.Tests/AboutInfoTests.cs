// CODEMAP FILE: tests/SiteCheck.Tests/AboutInfoTests.cs
// Product: Rampart, read-only public-surface hostname checker, public pin 1.9.2
// Role: Locks the About Rampart text: clean version, publisher, licence, website, house style.
// Called by: dotnet test.
// Calls: AboutInfo.
// Map: docs/CODEMAP.md

using SiteCheck.Core;

namespace SiteCheck.Tests;

public class AboutInfoTests
{
    [Theory]
    [InlineData("1.9.2", "1.9.2")]
    [InlineData("1.9.2+ef9278d", "1.9.2")]
    [InlineData("v1.9.2", "1.9.2")]
    [InlineData(null, "unknown")]
    [InlineData("  ", "unknown")]
    public void Cleans_the_version(string? input, string expected)
    {
        Assert.Equal(expected, AboutInfo.CleanVersion(input));
    }

    [Fact]
    public void Text_names_version_publisher_licence_and_website()
    {
        var text = AboutInfo.Text("1.9.2+abc");
        Assert.StartsWith("Rampart 1.9.2", text);
        Assert.Contains("Operation Locked In", text);
        Assert.Contains("Greater Toronto Area", text);
        Assert.Contains("GNU General Public License version 3", text);
        Assert.Contains("https://www.operationlockedin.com/rampart", text);
        Assert.Contains("SHA256SUMS.txt", text);
        Assert.Contains("Info@operationlockedin.com", text);
    }

    [Fact]
    public void Text_has_no_em_dashes()
    {
        Assert.DoesNotContain('\u2014', AboutInfo.Text("1.9.2"));
    }
}
