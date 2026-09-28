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

/// <summary>
/// One sentence of a how-to. Copy is an optional line the operator can put on the clipboard
/// (a DNS record, a header value, or a dashboard path).
/// </summary>
public sealed record FixLine(string Text, string? Copy = null);

/// <summary>
/// A fix that applies to this run. Environment names the stack the wording was written for
/// (Next.js, WordPress, Cloudflare, Vercel, or this hostname).
/// Lines are the full, copyable steps shown when the operator opens How to fix this.
/// </summary>
public sealed record NextStep(
    string Title,
    string Body,
    string Related,
    string Environment = "This hostname",
    IReadOnlyList<FixLine>? Lines = null);

public enum EdgeKind
{
    Origin,
    VercelOnly,
    CloudflareDnsOnly,
    CloudflareProxied,
    OtherCdn
}

public sealed record EdgeProfile(
    EdgeKind Kind,
    string Provider,
    bool CloudflareNameservers,
    bool CloudflareRay,
    bool VercelOrigin);

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
