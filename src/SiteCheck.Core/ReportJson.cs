using System.Text.Json;

namespace SiteCheck.Core;

/// <summary>
/// Machine-readable copy of a report for a job folder. Same observations as the text report.
/// </summary>
public static class ReportJson
{
    public static string Format(CheckReport report)
    {
        var dto = new Dictionary<string, object?>
        {
            ["product"] = "Rampart",
            ["userAgent"] = Checker.UserAgent,
            ["hostname"] = report.Hostname,
            ["checkedAtUtc"] = report.CheckedAt.ToString("o"),
            ["publicAddresses"] = report.PublicAddresses,
            ["scope"] = report.Authorization.ScopeName,
            ["authorization"] = new Dictionary<string, object?>
            {
                ["acceptedAtUtc"] = report.Authorization.AcceptedAtUtc.ToString("o"),
                ["attestations"] = report.Authorization.Attestations,
                ["methodsUsed"] = report.Authorization.MethodsUsed,
                ["methodsRefused"] = report.Authorization.MethodsRefused
            },
            ["summary"] = new Dictionary<string, int>
            {
                ["attention"] = report.Findings.Count(f => f.State == FindingState.Attention),
                ["notFound"] = report.Findings.Count(f => f.State == FindingState.NotFound),
                ["incomplete"] = report.Findings.Count(f => f.State == FindingState.Incomplete),
                ["present"] = report.Findings.Count(f => f.State == FindingState.Present),
                ["nextSteps"] = report.NextSteps.Count
            },
            ["stack"] = report.Stack.Select(s => new Dictionary<string, string?>
            {
                ["product"] = s.Product,
                ["version"] = s.Version,
                ["evidence"] = s.Evidence
            }).ToArray(),
            ["nextSteps"] = report.NextSteps.Select(s => new Dictionary<string, string>
            {
                ["title"] = s.Title,
                ["body"] = s.Body,
                ["related"] = s.Related,
                ["environment"] = s.Environment
            }).ToArray(),
            ["findings"] = report.Findings.Select(f => new Dictionary<string, string>
            {
                ["title"] = f.Title,
                ["state"] = ReportText.StateLabel(f.State),
                ["observation"] = f.Observation,
                ["method"] = f.Method,
                ["caveat"] = f.Caveat
            }).ToArray(),
            ["limits"] = report.Limits
        };
        return JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true });
    }
}
