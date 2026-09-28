using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using SiteCheck.Core;

namespace SiteCheck.App;

public partial class MainWindow : Window
{
    private CheckReport? _report;
    private CancellationTokenSource? _runCts;

    public MainWindow()
    {
        InitializeComponent();
        HostBox.Focus();
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape && _runCts != null)
        {
            e.Handled = true;
            Cancel_Click(sender, e);
            return;
        }
        if (e.Key == Key.Enter && RunButton.IsEnabled)
        {
            e.Handled = true;
            Run_Click(sender, e);
        }
    }

    private void Consent_Changed(object sender, RoutedEventArgs e) => UpdateRunEnabled();

    private void Scope_Changed(object sender, RoutedEventArgs e) => UpdateRunEnabled();

    private void UpdateRunEnabled()
    {
        if (PermissionBox is null || LawBox is null || RunButton is null) return;
        var ok = PermissionBox.IsChecked == true && LawBox.IsChecked == true && _runCts is null;
        RunButton.IsEnabled = ok;
    }

    private CheckScope SelectedScope() =>
        AssessmentScope?.IsChecked == true ? CheckScope.AuthorizedAssessment : CheckScope.Standard;

    private async void Run_Click(object sender, RoutedEventArgs e)
    {
        if (PermissionBox.IsChecked != true || LawBox.IsChecked != true)
        {
            StatusText.Text = "Tick both permission boxes. Operation Locked In does not authorize use against a hostname without the operator's permission.";
            return;
        }

        if (string.IsNullOrWhiteSpace(HostBox.Text))
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
        NextList.ItemsSource = null;
        StackList.ItemsSource = null;
        LimitsBox.Visibility = Visibility.Collapsed;
        NextBox.Visibility = Visibility.Collapsed;
        SummaryBox.Visibility = Visibility.Collapsed;
        _report = null;

        var progress = new Progress<string>(msg => StatusText.Text = msg);
        try
        {
            var report = await Checker.RunAsync(HostBox.Text, progress, ct, SelectedScope());
            _report = report;
            SectionList.ItemsSource = ToSections(report.Findings, report.NextSteps);
            if (report.NextSteps.Count > 0)
            {
                NextList.ItemsSource = report.NextSteps;
                NextBox.Visibility = Visibility.Visible;
            }
            LimitsList.ItemsSource = report.Limits;
            LimitsBox.Visibility = Visibility.Visible;
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
            StackList.ItemsSource = report.Stack
                .Select(s => s.Version is null ? s.Product : $"{s.Product} {s.Version}")
                .ToList();
            SummaryBox.Visibility = Visibility.Visible;
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
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _runCts?.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // The run already finished.
        }
        StatusText.Text = "Stopping this check.";
    }

    private void SetBusy(bool busy)
    {
        HostBox.IsEnabled = !busy;
        if (PermissionBox != null) PermissionBox.IsEnabled = !busy;
        if (LawBox != null) LawBox.IsEnabled = !busy;
        if (StandardScope != null) StandardScope.IsEnabled = !busy;
        if (AssessmentScope != null) AssessmentScope.IsEnabled = !busy;
        if (!busy) UpdateRunEnabled();
        else RunButton.IsEnabled = false;
        BusyBar.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        CancelButton.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        if (busy)
        {
            CopyButton.IsEnabled = false;
            SaveButton.IsEnabled = false;
        }
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        if (_report is null) return;
        try
        {
            Clipboard.SetText(ReportText.Format(_report));
            StatusText.Text = "Report copied. It contains observations, methods, caveats, and only the next steps that apply. It is not a certificate of security.";
        }
        catch (Exception)
        {
            StatusText.Text = "The clipboard was busy. Try Copy report again, or save the report to a file instead.";
        }
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (_report is null) return;
        var safeHost = string.Concat(_report.Hostname.Select(ch => Path.GetInvalidFileNameChars().Contains(ch) ? '-' : ch));
        var dialog = new SaveFileDialog
        {
            Filter = "Text file (*.txt)|*.txt|JSON (*.json)|*.json",
            FileName = $"site-check-{safeHost}-{_report.CheckedAt:yyyyMMdd}.txt"
        };
        if (dialog.ShowDialog() != true) return;
        try
        {
            var json = string.Equals(Path.GetExtension(dialog.FileName), ".json", StringComparison.OrdinalIgnoreCase);
            var body = json ? ReportJson.Format(_report) : ReportText.Format(_report);
            var protect = ProtectFileBox?.IsChecked == true && ReportProtect.WindowsUserProtectAvailable;
            if (protect) body = ReportProtect.ProtectForCurrentWindowsUser(body);
            File.WriteAllText(dialog.FileName, body, Encoding.UTF8);
            StatusText.Text = protect
                ? "Report saved and protected for this Windows user only. Rampart does not upload it. Other accounts on this PC cannot read the file."
                : json
                    ? "JSON report saved on this computer. Rampart does not upload it. Keep it on a disk you already protect if it names versions you have not yet updated."
                    : "Report saved on this computer. Rampart does not upload it. The file is ordinary text; keep it on a disk you already protect if it names versions you have not yet updated.";
        }
        catch (Exception)
        {
            StatusText.Text = "The report could not be saved at that location. Choose another folder, or copy the report instead.";
        }
    }

    private void Open_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Text or JSON (*.txt;*.json)|*.txt;*.json|All files (*.*)|*.*"
        };
        if (dialog.ShowDialog() != true) return;
        try
        {
            var raw = File.ReadAllText(dialog.FileName, Encoding.UTF8);
            var text = ReportProtect.LooksProtected(raw)
                ? ReportProtect.UnprotectForCurrentWindowsUser(raw)
                : raw;
            ShowTextWindow("Saved report  ·  Rampart", text);
            StatusText.Text = ReportProtect.LooksProtected(raw)
                ? "Opened a file protected for this Windows user."
                : "Opened a saved report. It is not a live check.";
        }
        catch (CryptographicException)
        {
            StatusText.Text = "This Windows user cannot open that protected file. Save it again while signed in as the account that created it.";
        }
        catch (Exception)
        {
            StatusText.Text = "That file could not be opened. Confirm it is a Rampart report from this computer.";
        }
    }

    private void Lawful_Click(object sender, RoutedEventArgs e)
    {
        ShowTextWindow("Lawful use  ·  Rampart", LoadEmbedded("LAWFUL-USE.md") ?? LoadEmbedded("lawful-use.md") ?? "See docs/lawful-use.md in the repository.");
    }

    private void Licence_Click(object sender, RoutedEventArgs e)
    {
        var text = LoadLicenceText();
        ShowTextWindow("Licence and warranty  ·  Rampart", text);
    }

    private void ShowTextWindow(string title, string text)
    {
        var window = new Window
        {
            Title = title,
            Owner = this,
            Width = 760,
            Height = 640,
            MinWidth = 520,
            MinHeight = 400,
            Background = (Brush)FindResource("NavyBrush"),
            WindowStartupLocation = WindowStartupLocation.CenterOwner
        };
        var box = new System.Windows.Controls.TextBox
        {
            Text = text,
            IsReadOnly = true,
            TextWrapping = TextWrapping.Wrap,
            AcceptsReturn = true,
            BorderThickness = new Thickness(0),
            Background = (Brush)FindResource("Navy900Brush"),
            Foreground = (Brush)FindResource("TextBrush"),
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,
            Padding = new Thickness(20),
            VerticalScrollBarVisibility = System.Windows.Controls.ScrollBarVisibility.Auto
        };
        window.Content = box;
        window.ShowDialog();
    }

    private void Email_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "mailto:Info@operationlockedin.com?subject=Rampart",
                UseShellExecute = true
            });
        }
        catch (Exception)
        {
            StatusText.Text = "Email Info@operationlockedin.com from your own mail program.";
        }
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

    private static string LoadLicenceText()
    {
        var text = LoadEmbedded("LICENSE");
        if (text != null) return text;
        return """
            Rampart
            Copyright (C) 2026 Jesse Mosier-Bowers, operating as Operation Locked In

            This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU General Public License as published by
            the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.

            This program is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU General Public License for more details.

            You should have received a copy of the GNU General Public License
            along with this program. If not, see https://www.gnu.org/licenses/.
            """;
    }

    private void CopyLine_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Button button) return;
        var text = button.Tag as string;
        if (string.IsNullOrWhiteSpace(text)) return;
        try
        {
            Clipboard.SetText(text);
            StatusText.Text = "Copied a how-to line. Paste it where the steps say to use it.";
        }
        catch (Exception)
        {
            StatusText.Text = "The clipboard was busy. Select the teal line and copy it yourself, or copy the whole report.";
        }
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
        var teal = (Brush)Application.Current.Resources["TealBrush"];
        var muted = (Brush)Application.Current.Resources["MutedBrush"];
        var amber = (Brush)Application.Current.Resources["AmberBrush"];
        var incomplete = (Brush)Application.Current.Resources["RailIncomplete"];
        var (labelBrush, rail) = f.State switch
        {
            FindingState.Present => (teal, (Brush)Application.Current.Resources["RailPresent"]),
            FindingState.NotFound => (amber, (Brush)Application.Current.Resources["RailAttention"]),
            FindingState.Attention => (amber, (Brush)Application.Current.Resources["RailAttention"]),
            _ => (muted, incomplete)
        };
        var hasFix = FindingGuide.ShowsHowTo(f, step);
        var hasWhen = FindingGuide.ShowsWhen(step);
        var lines = new List<FixLineView>();
        if (hasFix && step!.Lines != null)
        {
            foreach (var line in step.Lines)
            {
                var hasCopy = !string.IsNullOrWhiteSpace(line.Copy);
                lines.Add(new FixLineView
                {
                    Text = line.Text,
                    Copy = line.Copy ?? "",
                    CopyVisibility = hasCopy ? Visibility.Visible : Visibility.Collapsed
                });
            }
        }
        return new FindingView
        {
            Title = f.Title,
            State = ReportText.StateLabel(f.State),
            StateBrush = labelBrush,
            AccentBrush = rail,
            Observation = f.Observation,
            Method = f.Method,
            Caveat = f.Caveat,
            HasFix = hasFix,
            FixVisibility = hasFix ? Visibility.Visible : Visibility.Collapsed,
            FixTitle = step?.Title ?? "",
            FixBody = step?.Body ?? "",
            FixLines = lines,
            WhenTo = step?.WhenTo ?? "",
            WhenNot = step?.WhenNot ?? "",
            WhenVisibility = hasWhen ? Visibility.Visible : Visibility.Collapsed
        };
    }
}

public sealed class FixLineView
{
    public string Text { get; set; } = "";
    public string Copy { get; set; } = "";
    public Visibility CopyVisibility { get; set; } = Visibility.Collapsed;
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
    public Brush StateBrush { get; set; } = Brushes.White;
    public Brush AccentBrush { get; set; } = Brushes.White;
    public string Observation { get; set; } = "";
    public string Method { get; set; } = "";
    public string Caveat { get; set; } = "";
    public bool HasFix { get; set; }
    public Visibility FixVisibility { get; set; } = Visibility.Collapsed;
    public string FixTitle { get; set; } = "";
    public string FixBody { get; set; } = "";
    public List<FixLineView> FixLines { get; set; } = new();
    public string WhenTo { get; set; } = "";
    public string WhenNot { get; set; } = "";
    public Visibility WhenVisibility { get; set; } = Visibility.Collapsed;
}
