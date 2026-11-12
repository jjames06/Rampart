// CODEMAP FILE: src/SiteCheck.Core/FindingGuide.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Single place for 'does this card show How to fix this'. All shells must call this so a copy change cannot land on Windows only.
// Called by: MainWindow (WPF), MainWindow (Avalonia), MainPage (MAUI).
// Calls: Finding + NextStep match on Title/Related.
// Invariants: ShowsHowTo is false for Present even if a step exists. Empty Lines means no panel.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

namespace SiteCheck.Core;

/// <summary>
/// See docs/CODEMAP.md.
/// One place for which finding cards show How to fix this.
/// Windows WPF, Avalonia desktop, and MAUI must all call these helpers
/// so a copy change cannot land on one UI only.
/// </summary>
public static class FindingGuide
{
    public static NextStep? For(Finding finding, IEnumerable<NextStep> steps) =>
        steps.FirstOrDefault(s => s.Related.Equals(finding.Title, StringComparison.OrdinalIgnoreCase));

    public static bool ShowsHowTo(Finding finding, NextStep? step) =>
        step?.Lines is { Count: > 0 } && finding.State != FindingState.Present;

    public static bool ShowsWhen(NextStep? step) =>
        step != null
        && (!string.IsNullOrWhiteSpace(step.WhenTo) || !string.IsNullOrWhiteSpace(step.WhenNot));
}
