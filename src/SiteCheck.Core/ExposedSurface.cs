namespace SiteCheck.Core;

/// <summary>
/// GET-only allowlist of paths that should not be public on a finished site.
/// No POST, no directory brute force, no exploit payloads.
/// </summary>
public static class ExposedSurface
{
    public static readonly string[] Paths =
    {
        "/.env",
        "/.git/HEAD",
        "/wp-config.php",
        "/phpinfo.php",
        "/server-status"
    };

    public static Finding Summary(IReadOnlyList<FileHit> hits)
    {
        var leaked = hits.Where(LooksLeaked).Select(h => h.Path + " HTTP " + h.Status).Take(8).ToArray();
        if (leaked.Length > 0)
        {
            return new Finding(
                "Private files",
                FindingState.Attention,
                "These paths answered 200 with a short non-HTML body: " + string.Join(", ", leaked) + ".",
                "GET each allowlisted path on the same public address, redirects disabled, body capped at 8 KB.",
                "A custom backup name is not found this way. HTML 404 pages that still return 200 are treated as not leaked.");
        }

        if (hits.All(h => h.Status is null))
        {
            return new Finding(
                "Private files",
                FindingState.Incomplete,
                "None of the private-file paths completed.",
                "GET each allowlisted path on the same public address, redirects disabled, body capped at 8 KB.",
                "A timeout is not proof a file is present.");
        }

        return new Finding(
            "Private files",
            FindingState.Present,
            "Common private-file paths did not return a short 200 body: " + string.Join(", ", Paths) + ".",
            "GET each allowlisted path on the same public address, redirects disabled, body capped at 8 KB.",
            "A custom backup filename is not found this way.");
    }

    public static bool LooksLeaked(FileHit hit)
    {
        if (hit.Status != 200 || string.IsNullOrWhiteSpace(hit.Body)) return false;
        var body = hit.Body.TrimStart();
        if (body.StartsWith("<", StringComparison.Ordinal) && body.Length > 400) return false;
        return true;
    }
}

public sealed record FileHit(string Path, int? Status, string? Body);
