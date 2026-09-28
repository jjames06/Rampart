namespace SiteCheck.Core;

/// <summary>
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
