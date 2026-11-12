// CODEMAP FILE: src/SiteCheck.Core/WellKnownIdpSurface.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: GET-only fingerprint of a public OpenID Provider at /.well-known/openid-configuration. Attention only when advertised.
// Called by: Checker. Tests in WellKnownIdpSurfaceTests.
// Calls: Shared ProbeNamedPathsAsync.
// Invariants: GET only. No token request. Brochure 404 stays silent. issuer must be https.
// Map: docs/CODEMAP.md

namespace SiteCheck.Core;

/// <summary>
/// Read-only hint that this hostname publishes an OpenID Provider metadata document.
/// A match is a prompt to confirm the IdP is meant to be public. Not a login test.
/// </summary>
public static class WellKnownIdpSurface
{
    public static readonly string[] Paths =
    {
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server"
    };

    public static IReadOnlyList<Finding> Findings(IReadOnlyList<FileHit> hits)
    {
        var live = hits.Where(LooksLikeMetadata).Take(4).ToArray();
        if (live.Length == 0) return Array.Empty<Finding>();

        var httpIssuer = live.Any(h =>
            (h.Body ?? "").Contains("\"issuer\":\"http://", StringComparison.OrdinalIgnoreCase)
            || (h.Body ?? "").Contains("\"issuer\": \"http://", StringComparison.OrdinalIgnoreCase));

        var paths = string.Join("; ", live.Select(h => h.Path + " HTTP " + h.Status));
        return new[]
        {
            new Finding(
                "OpenID Provider",
                FindingState.Attention,
                "This hostname advertised OpenID Connect or OAuth authorization-server metadata (" + paths + ")."
                    + (httpIssuer
                        ? " The issuer value used http://. That is not a public identity provider people should trust."
                        : " Confirm this identity provider is meant to be on the public internet."),
                "GET RFC 8414 / OpenID Discovery documents on the same public address, redirects disabled, body capped. No token request.",
                "This is not a login test and not proof of a broken IdP. Absence of these files is normal on a brochure site, so Rampart does not show a Present card.")
        };
    }

    public static bool LooksLikeMetadata(FileHit hit)
    {
        if (hit.Status is not (>= 200 and < 400)) return false;
        var body = (hit.Body ?? "").TrimStart();
        if (body.Length == 0 || body.StartsWith("<", StringComparison.Ordinal)) return false;
        return body.Contains("\"issuer\"", StringComparison.OrdinalIgnoreCase)
            && (body.StartsWith("{", StringComparison.Ordinal) || body.Contains("\"authorization_endpoint\"", StringComparison.OrdinalIgnoreCase));
    }
}
