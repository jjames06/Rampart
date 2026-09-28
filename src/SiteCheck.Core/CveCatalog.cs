namespace SiteCheck.Core;

/// <summary>
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
