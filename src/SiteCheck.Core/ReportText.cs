using System.Text;

namespace SiteCheck.Core;

public static class ReportText
{
    public static string Format(CheckReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Site Check  ·  Operation Locked In");
        sb.AppendLine($"Hostname: {report.Hostname}");
        sb.AppendLine($"Checked: {report.CheckedAt:yyyy-MM-dd HH:mm} UTC");
        sb.AppendLine("Public addresses used: " + string.Join(", ", report.PublicAddresses));
        sb.AppendLine("Scope: " + report.Authorization.ScopeName);
        sb.AppendLine("Authorization recorded: " + report.Authorization.AcceptedAtUtc.ToString("yyyy-MM-dd HH:mm") + " UTC");
        sb.AppendLine();
        sb.AppendLine("Authorization");
        foreach (var line in report.Authorization.Attestations)
            sb.AppendLine("  " + line);
        sb.AppendLine();
        sb.AppendLine("Methods used");
        foreach (var line in report.Authorization.MethodsUsed)
            sb.AppendLine("  · " + line);
        sb.AppendLine();
        sb.AppendLine("Methods this program will not use");
        foreach (var line in report.Authorization.MethodsRefused)
            sb.AppendLine("  · " + line);
        sb.AppendLine();
        sb.AppendLine("Operation Locked In does not authorize, condone, or accept use of this program against a hostname without the operator's permission. This report is not legal advice and is not a certificate of security.");
        sb.AppendLine();
        if (report.Stack.Count > 0)
        {
            sb.AppendLine("Advertised stack (from headers and homepage only)");
            foreach (var s in report.Stack)
            {
                sb.AppendLine($"  {s.Product}" + (s.Version is null ? "" : " " + s.Version) + "  (" + s.Evidence + ")");
            }
            sb.AppendLine();
        }
        if (report.NextSteps.Count > 0)
        {
            sb.AppendLine("What to do next (only items that apply to this run)");
            foreach (var step in report.NextSteps)
            {
                sb.AppendLine($"  {step.Title}");
                sb.AppendLine("  " + step.Body);
                sb.AppendLine();
            }
        }
        foreach (var f in report.Findings)
        {
            sb.AppendLine($"{f.Title}  ({StateLabel(f.State)})");
            sb.AppendLine(f.Observation);
            sb.AppendLine("How this was gathered: " + f.Method);
            sb.AppendLine("What this does not mean: " + f.Caveat);
            sb.AppendLine();
        }
        sb.AppendLine("Limits");
        foreach (var line in report.Limits)
        {
            sb.AppendLine("· " + line);
        }
        return sb.ToString();
    }

    public static string StateLabel(FindingState state) => state switch
    {
        FindingState.Present => "Present",
        FindingState.NotFound => "Not found",
        FindingState.Incomplete => "Could not complete",
        FindingState.Attention => "Needs attention",
        _ => state.ToString()
    };
}
