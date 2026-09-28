using System.Reflection;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using SiteCheck.Core;

namespace SiteCheck.Desktop;

public partial class MainWindow : Window
{
    private CheckReport? _report;
    private CancellationTokenSource? _runCts;

    public MainWindow()
    {
        InitializeComponent();
        PermissionBox.IsCheckedChanged += Consent_Changed;
        LawBox.IsCheckedChanged += Consent_Changed;
        UpdateRunEnabled();
        HostBox.Focus();
    }

    private void Consent_Changed(object? sender, RoutedEventArgs e) => UpdateRunEnabled();

    private void UpdateRunEnabled()
    {
        RunButton.IsEnabled = PermissionBox.IsChecked == true && LawBox.IsChecked == true && _runCts is null;
    }

    private CheckScope SelectedScope() =>
        AssessmentScope.IsChecked == true ? CheckScope.AuthorizedAssessment : CheckScope.Standard;

    private async void Run_Click(object? sender, RoutedEventArgs e)
    {
        if (PermissionBox.IsChecked != true || LawBox.IsChecked != true)
        {
            StatusText.Text = "Tick both permission boxes. Operation Locked In does not authorize use against a hostname without the operator's permission.";
            return;
        }

        var host = HostBox.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(host))
        {
            StatusText.Text = "Enter a public hostname such as www.example.com.";
            HostBox.Focus();
            return;
        }

        _runCts?.Cancel();
        _runCts?.Dispose();
        _runCts = new CancellationTokenSource();
        var ct = _runCts.Token;
        SetBusy(true);
        StatusText.Text = "Resolving public Internet addresses.";
        SectionList.ItemsSource = null;
        SummaryBox.IsVisible = false;
        _report = null;
        var progress = new Progress<string>(msg => StatusText.Text = msg);
        try
        {
            var report = await Checker.RunAsync(host, progress, ct, SelectedScope());
            _report = report;
            SectionList.ItemsSource = ToSections(report.Findings, report.NextSteps);
            SummaryTitle.Text = report.Hostname;
            SummaryScope.Text = report.Authorization.ScopeName;
            var attn = report.Findings.Count(f => f.State == FindingState.Attention);
            var missing = report.Findings.Count(f => f.State == FindingState.NotFound);
            var incomplete = report.Findings.Count(f => f.State == FindingState.Incomplete);
            var present = report.Findings.Count(f => f.State == FindingState.Present);
            var extra = report.NextSteps.Count == 0
                ? "No further steps were generated for this run."
                : $"{report.NextSteps.Count} next step{(report.NextSteps.Count == 1 ? "" : "s")} apply to this run.";
            SummaryBody.Text = $"Checked {report.CheckedAt:yyyy-MM-dd HH:mm} UTC using {string.Join(", ", report.PublicAddresses)}. {attn} need attention, {missing} not found, {incomplete} could not complete, {present} present. {extra}";
            SummaryBox.IsVisible = true;
            StatusText.Text = SummaryBody.Text;
            CopyButton.IsEnabled = true;
            SaveButton.IsEnabled = true;
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "The check was stopped. Nothing further was requested from the hostname.";
        }
        catch (CheckException ex)
        {
            StatusText.Text = ex.Message;
        }
        catch (Exception)
        {
            StatusText.Text = "The check did not finish. Confirm the hostname is public, that you have permission, and try again.";
        }
        finally
        {
            SetBusy(false);
            _runCts?.Dispose();
            _runCts = null;
            UpdateRunEnabled();
        }
    }

    private void Cancel_Click(object? sender, RoutedEventArgs e)
    {
        try { _runCts?.Cancel(); }
        catch (ObjectDisposedException) { }
        StatusText.Text = "Stopping this check.";
    }

    private void SetBusy(bool busy)
    {
        HostBox.IsEnabled = !busy;
        PermissionBox.IsEnabled = !busy;
        LawBox.IsEnabled = !busy;
        StandardScope.IsEnabled = !busy;
        AssessmentScope.IsEnabled = !busy;
        RunButton.IsEnabled = !busy && PermissionBox.IsChecked == true && LawBox.IsChecked == true;
        CancelButton.IsVisible = busy;
        if (busy)
        {
            CopyButton.IsEnabled = false;
            SaveButton.IsEnabled = false;
        }
    }

    private async void Copy_Click(object? sender, RoutedEventArgs e)
    {
        if (_report is null) return;
        var top = TopLevel.GetTopLevel(this);
        if (top?.Clipboard is null) return;
        await top.Clipboard.SetTextAsync(ReportText.Format(_report));
        StatusText.Text = "Report copied. It is not a certificate of security.";
    }

    private async void Save_Click(object? sender, RoutedEventArgs e)
    {
        if (_report is null) return;
        var safeHost = string.Concat(_report.Hostname.Select(ch => Path.GetInvalidFileNameChars().Contains(ch) ? '-' : ch));
        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Save Rampart report",
            SuggestedFileName = $"site-check-{safeHost}-{_report.CheckedAt:yyyyMMdd}.txt",
            DefaultExtension = "txt",
            FileTypeChoices =
            [
                new FilePickerFileType("Text file") { Patterns = ["*.txt"] },
                new FilePickerFileType("JSON") { Patterns = ["*.json"] }
            ]
        });
        if (file is null) return;
        var json = file.Name.EndsWith(".json", StringComparison.OrdinalIgnoreCase);
        var body = json ? ReportJson.Format(_report) : ReportText.Format(_report);
        await using var stream = await file.OpenWriteAsync();
        await using var writer = new StreamWriter(stream);
        await writer.WriteAsync(body);
        StatusText.Text = "Report saved on this computer. Rampart does not upload it.";
    }

    private void Lawful_Click(object? sender, RoutedEventArgs e) =>
        ShowText("Lawful use  ·  Rampart", LoadEmbedded("LAWFUL-USE.md") ?? "See docs/lawful-use.md in the repository.");

    private void Licence_Click(object? sender, RoutedEventArgs e) =>
        ShowText("Licence and warranty  ·  Rampart", LoadEmbedded("LICENSE") ?? "GNU GPLv3. See LICENSE in the repository.");

    private void ShowText(string title, string text)
    {
        var box = new TextBox
        {
            Text = text,
            IsReadOnly = true,
            TextWrapping = TextWrapping.Wrap,
            AcceptsReturn = true,
            FontFamily = new FontFamily("Consolas, Menlo, monospace"),
            FontSize = 12,
            Padding = new Thickness(20),
            Background = new SolidColorBrush(Color.Parse("#0C1220")),
            Foreground = new SolidColorBrush(Color.Parse("#F8FAFC"))
        };
        var window = new Window
        {
            Title = title,
            Width = 760,
            Height = 640,
            Background = new SolidColorBrush(Color.Parse("#070B14")),
            Content = box,
            WindowStartupLocation = WindowStartupLocation.CenterOwner
        };
        window.Show(this);
    }

    private async void CopyLine_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button button) return;
        var text = button.Tag as string;
        if (string.IsNullOrWhiteSpace(text)) return;
        var top = TopLevel.GetTopLevel(this);
        if (top?.Clipboard is null) return;
        await top.Clipboard.SetTextAsync(text);
        StatusText.Text = "Copied a how-to line. Paste it where the steps say to use it.";
    }

    private static string? LoadEmbedded(string suffix)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var name = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith(suffix, StringComparison.OrdinalIgnoreCase));
        if (name is null) return null;
        using var stream = assembly.GetManifestResourceStream(name);
        if (stream is null) return null;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static List<FindingSectionView> ToSections(IReadOnlyList<Finding> findings, IReadOnlyList<NextStep> nextSteps)
    {
        var sections = new List<FindingSectionView>();
        FindingState? last = null;
        foreach (var f in findings.OrderBy(x => ReportText.Rank(x.State)))
        {
            if (last != f.State)
            {
                sections.Add(new FindingSectionView { Title = ReportText.SectionName(f.State) });
                last = f.State;
            }
            sections[^1].Cards.Add(ToView(f, FindingGuide.For(f, nextSteps)));
        }
        return sections;
    }

    private static FindingView ToView(Finding f, NextStep? step)
    {
        var teal = new SolidColorBrush(Color.Parse("#2DD4BF"));
        var muted = new SolidColorBrush(Color.Parse("#C5D0DE"));
        var amber = new SolidColorBrush(Color.Parse("#FBBF24"));
        var label = f.State switch
        {
            FindingState.Present => teal,
            FindingState.NotFound => amber,
            FindingState.Attention => amber,
            _ => muted
        };
        var hasFix = FindingGuide.ShowsHowTo(f, step);
        var hasWhen = FindingGuide.ShowsWhen(step);
        var lines = new List<FixLineView>();
        if (hasFix && step!.Lines != null)
        {
            foreach (var line in step.Lines)
            {
                lines.Add(new FixLineView
                {
                    Text = line.Text,
                    Copy = line.Copy ?? "",
                    HasCopy = !string.IsNullOrWhiteSpace(line.Copy)
                });
            }
        }

        return new FindingView
        {
            Title = f.Title,
            State = ReportText.StateLabel(f.State),
            StateBrush = label,
            Observation = f.Observation,
            Method = f.Method,
            Caveat = f.Caveat,
            HasFix = hasFix,
            HasWhen = hasWhen,
            FixTitle = step?.Title ?? "",
            FixBody = step?.Body ?? "",
            FixLines = lines,
            WhenTo = step?.WhenTo ?? "",
            WhenNot = step?.WhenNot ?? ""
        };
    }
}

public sealed class FixLineView
{
    public string Text { get; set; } = "";
    public string Copy { get; set; } = "";
    public bool HasCopy { get; set; }
}

public sealed class FindingSectionView
{
    public string Title { get; set; } = "";
    public List<FindingView> Cards { get; set; } = new();
}

public sealed class FindingView
{
    public string Title { get; set; } = "";
    public string State { get; set; } = "";
    public IBrush StateBrush { get; set; } = Brushes.White;
    public string Observation { get; set; } = "";
    public string Method { get; set; } = "";
    public string Caveat { get; set; } = "";
    public bool HasFix { get; set; }
    public bool HasWhen { get; set; }
    public string FixTitle { get; set; } = "";
    public string FixBody { get; set; } = "";
    public List<FixLineView> FixLines { get; set; } = new();
    public string WhenTo { get; set; } = "";
    public string WhenNot { get; set; } = "";
}
