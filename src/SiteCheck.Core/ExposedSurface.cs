// CODEMAP FILE: src/SiteCheck.Core/ExposedSurface.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Allowlisted GET of paths that should 404: /.env, /.git/HEAD, phpinfo, wp-config, server-status, etc. Kits bake these 404s in @oli/site-kit blocked-paths.
// Called by: Checker. Tests in ExposedSurfaceTests.
// Calls: Shared ProbeNamedPathsAsync.
// Invariants: GET only. A 200 with secret-shaped body is Attention. A 403 is not proof of absence. Never follow to an open directory index exploit.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

namespace SiteCheck.Core;

/// <summary>
/// See docs/CODEMAP.md.
/// GET-only allowlist of paths that should not be public on a finished site.
/// No POST, no directory brute force, no exploit payloads.
/// </summary>
public static class ExposedSurface
{
    public static readonly string[] Paths =
    {
        "/.env",
        "/.env.local",
        "/.git/HEAD",
        "/wp-config.php",
        "/phpinfo.php",
        "/server-status",
        "/composer.json",
        "/package.json",
        "/.git/config",
        "/actuator/env",
        "/actuator/configprops"
    };

    public static Finding Summary(IReadOnlyList<FileHit> hits)
    {
        var mine = hits.Where(h => Paths.Contains(h.Path, StringComparer.Ordinal)).ToArray();
        var leaked = mine.Where(LooksLeaked).Select(h => h.Path + " HTTP " + h.Status).Take(8).ToArray();
        if (leaked.Length > 0)
        {
            return new Finding(
                "Private files",
                FindingState.Attention,
                "These paths answered 200 with a non-HTML body: " + string.Join(", ", leaked) + ".",
                "GET each allowlisted path on the same public address, redirects disabled, body capped at 8 KB.",
                "A custom backup name is not found this way. HTML responses, including HTML 404 pages that still return 200, are treated as not leaked.");
        }

        if (mine.Length == 0 || mine.All(h => h.Status is null))
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
        if (body.StartsWith("<", StringComparison.Ordinal)) return false;
        return true;
    }
}

public sealed record FileHit(string Path, int? Status, string? Body, string? Location = null);
