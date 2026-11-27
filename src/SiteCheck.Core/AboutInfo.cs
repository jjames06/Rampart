// CODEMAP FILE: src/SiteCheck.Core/AboutInfo.cs
// Product: Rampart, read-only public-surface hostname checker, public pin 1.9.2
// Role: Text for the About Rampart window: version, publisher, licence, website, how to check the download.
// Called by: SiteCheck.App MainWindow (About_Click). Any other shell can reuse it.
// Calls: nothing.
// Invariants: Plain words. No em dashes. Do not bump the public version here; the shell passes its own assembly version.
// Map: docs/CODEMAP.md

using System.Text;

namespace SiteCheck.Core;

public static class AboutInfo
{
    public const string ProductName = "Rampart";
    public const string Publisher = "Operation Locked In";
    public const string Owner = "Jesse Mosier-Bowers";
    public const string Website = "https://www.operationlockedin.com/rampart";
    public const string Releases = "https://github.com/jjames06/Rampart/releases";
    public const string Email = "Info@operationlockedin.com";

    /// <summary>Trims build metadata such as "+abc123" so the window shows "1.9.2".</summary>
    public static string CleanVersion(string? informationalVersion)
    {
        if (string.IsNullOrWhiteSpace(informationalVersion)) return "unknown";
        var v = informationalVersion.Trim();
        var plus = v.IndexOf('+');
        if (plus > 0) v = v[..plus];
        return v.TrimStart('v', 'V');
    }

    /// <summary>Full About text shown in the About Rampart window.</summary>
    public static string Text(string? informationalVersion)
    {
        var version = CleanVersion(informationalVersion);
        var sb = new StringBuilder();
        sb.AppendLine($"{ProductName} {version}");
        sb.AppendLine("A read-only check of what a public hostname you operate shows the world.");
        sb.AppendLine();
        sb.AppendLine($"Published by {Owner}, operating as {Publisher}, based in the Greater Toronto Area, Ontario.");
        sb.AppendLine();
        sb.AppendLine("What Rampart does not do");
        sb.AppendLine("It sends only ordinary read requests. It does not send exploit traffic, does not follow redirects, and does not contact private addresses. Reports stay on your computer unless you save or copy them.");
        sb.AppendLine();
        sb.AppendLine("Licence");
        sb.AppendLine("Free software under the GNU General Public License version 3. There is no warranty, to the extent permitted by law. Choose Licence and warranty for the full text.");
        sb.AppendLine();
        sb.AppendLine("Check your copy");
        sb.AppendLine($"Official downloads and their SHA-256 fingerprints are on {Website}/get and in SHA256SUMS.txt on {Releases}.");
        sb.AppendLine();
        sb.AppendLine("Help and contact");
        sb.AppendLine($"Website: {Website}");
        sb.AppendLine($"Email: {Email}");
        return sb.ToString();
    }
}
