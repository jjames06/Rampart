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
        sb.AppendLine();
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
        _ => state.ToString()
    };
}
