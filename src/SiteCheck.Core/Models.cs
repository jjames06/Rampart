// CODEMAP FILE: src/SiteCheck.Core/Models.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Shared types for one run: FindingState, Finding, FixLine, NextStep, EdgeProfile, StackHint, CheckReport, authorization record.
// Called by: Every Core module and all three UI shells. UIs display these; they must not invent findings.
// Calls: None (pure records/enums).
// Invariants: Present means the healthy case (including 'correctly absent'). Incomplete is neither all-clear nor a confirmed gap. How-to lines live on NextStep, not on Finding.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

namespace SiteCheck.Core;

/// <summary>
/// Shared types for one Rampart run. See docs/CODEMAP.md.
/// UI shells only display these; they do not invent findings.
/// </summary>
public enum FindingState
{
    /// <summary>The check completed and the public surface matches the healthy case (including “this thing is correctly absent”).</summary>
    Present,
    /// <summary>The check completed and the record or path was not there. Not always a chore; Advice decides.</summary>
    NotFound,
    /// <summary>The network or parser step did not finish. Do not treat as all-clear or as a confirmed gap.</summary>
    Incomplete,
    /// <summary>The check completed and the operator should read How to fix this.</summary>
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
    IReadOnlyList<FixLine>? Lines = null,
    bool Optional = false,
    string? WhenTo = null,
    string? WhenNot = null);

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
