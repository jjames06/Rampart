// CODEMAP FILE: tests/SiteCheck.Tests/LawfulUseTests.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Locks authorization MethodsUsed/MethodsRefused so saved reports name enterprise GETs and refused exploit paths.
// Called by: dotnet test.
// Calls: LawfulUse.
// Invariants: Dual attestations. No ToolPane in MethodsUsed.
// Map: docs/CODEMAP.md

using SiteCheck.Core;

namespace SiteCheck.Tests;

public class LawfulUseTests
{
    [Fact]
    public void Standard_methods_name_private_files_and_enterprise_portals()
    {
        var used = string.Join(" ", LawfulUse.MethodsUsed(CheckScope.Standard));
        Assert.Contains("/.env", used, StringComparison.Ordinal);
        Assert.Contains("PeopleSoft", used, StringComparison.Ordinal);
        Assert.Contains("enterprise-portal", used, StringComparison.Ordinal);
        Assert.DoesNotContain("ToolPane", used, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("security.txt", used, StringComparison.Ordinal);
    }

    [Fact]
    public void Authorized_adds_rfc_files()
    {
        var used = string.Join(" ", LawfulUse.MethodsUsed(CheckScope.AuthorizedAssessment));
        Assert.Contains("security.txt", used, StringComparison.Ordinal);
        Assert.Contains("CAA", used, StringComparison.Ordinal);
    }

    [Fact]
    public void Refused_names_exploit_paths()
    {
        var refused = string.Join(" ", LawfulUse.MethodsRefused());
        Assert.Contains("ToolPane", refused, StringComparison.Ordinal);
        Assert.Contains("wls-wsat", refused, StringComparison.Ordinal);
        Assert.Contains("Exploit payloads", refused, StringComparison.Ordinal);
    }
}
