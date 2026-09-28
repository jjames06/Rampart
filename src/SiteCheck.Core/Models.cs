namespace SiteCheck.Core;

public enum FindingState
{
    Present,
    NotFound,
    Incomplete,
    Attention
}

/// <summary>
/// One observation with the method used and a caveat so the UI cannot overclaim.
/// </summary>
public sealed record Finding(
    string Title,
    FindingState State,
    string Observation,
    string Method,
    string Caveat);

public sealed record NextStep(
    string Title,
    string Body,
    string Related);

public sealed record StackHint(
    string Product,
    string? Version,
    string Evidence);

public sealed record CheckReport(
    string Hostname,
    DateTimeOffset CheckedAt,
    IReadOnlyList<string> PublicAddresses,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<NextStep> NextSteps,
    IReadOnlyList<StackHint> Stack,
    IReadOnlyList<string> Limits,
    AuthorizationRecord Authorization);

public sealed class CheckException : Exception
{
    public CheckException(string message) : base(message) { }
}
