// CODEMAP FILE: src/SiteCheck.Core/CveCatalog.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Thin facade over AdvisoryDb so call sites read as 'catalogue' not 'json file'.
// Called by: Checker.
// Calls: AdvisoryDb.
// Invariants: Same local-only rule as AdvisoryDb.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

namespace SiteCheck.Core;

/// <summary>
/// See docs/CODEMAP.md.
/// Facade over the local advisory catalogue. Matching is version-range comparison
/// against advertised versions, not exploit traffic and not a live NVD query.
/// </summary>
public static class CveCatalog
{
    public sealed record Entry(
        string Product,
        string Id,
        string Summary,
        string SourceUrl,
        Func<string?, bool> Matches);

    public static IReadOnlyList<(Entry Entry, StackHint Hint)> Match(IEnumerable<StackHint> stack) =>
        AdvisoryDb.Match(stack);
}
