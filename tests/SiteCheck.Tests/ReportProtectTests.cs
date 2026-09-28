using SiteCheck.Core;

namespace SiteCheck.Tests;

public class ReportProtectTests
{
    [Fact]
    public void Plaintext_is_not_marked_protected()
    {
        Assert.False(ReportProtect.LooksProtected("Rampart report\nexample.com"));
    }

    [Fact]
    public void Windows_roundtrip_protects_and_opens()
    {
        if (!ReportProtect.WindowsUserProtectAvailable) return;
        var plain = "Rampart report\nwww.example.com\nCVE-2024-0000";
        var stored = ReportProtect.ProtectForCurrentWindowsUser(plain);
        Assert.True(ReportProtect.LooksProtected(stored));
        Assert.DoesNotContain("CVE-2024-0000", stored);
        Assert.Equal(plain, ReportProtect.UnprotectForCurrentWindowsUser(stored));
    }
}
