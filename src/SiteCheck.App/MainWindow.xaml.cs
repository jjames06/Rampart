using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Windows;
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
        var ok = PermissionBox.IsChecked == true && LawBox.IsChecked == true && _runCts is null;
        RunButton.IsEnabled = ok;
    }

    private CheckScope SelectedScope() =>
        AssessmentScope.IsChecked == true ? CheckScope.AuthorizedAssessment : CheckScope.Standard;

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
        FindingsList.ItemsSource = null;
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
            FindingsList.ItemsSource = ToViews(report.Findings);
            if (report.NextSteps.Count > 0)
            {
                NextList.ItemsSource = report.NextSteps;
                NextBox.Visibility = Visibility.Visible;
            }
            LimitsList.ItemsSource = report.Limits;
            LimitsBox.Visibility = Visibility.Visible;
            SummaryTitle.Text = report.Hostname;
            SummaryScope.Text = report.Authorization.ScopeName;
            var extra = report.NextSteps.Count == 0
                ? "No further steps were generated for this run."
                : $"{report.NextSteps.Count} next step{(report.NextSteps.Count == 1 ? "" : "s")} apply to this run.";
            SummaryBody.Text = $"Checked {report.CheckedAt:yyyy-MM-dd HH:mm} UTC using {string.Join(", ", report.PublicAddresses)}. {extra}";
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
        PermissionBox.IsEnabled = !busy;
        LawBox.IsEnabled = !busy;
        StandardScope.IsEnabled = !busy;
        AssessmentScope.IsEnabled = !busy;
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
            Filter = "Text file (*.txt)|*.txt",
            FileName = $"site-check-{safeHost}-{_report.CheckedAt:yyyyMMdd}.txt"
        };
        if (dialog.ShowDialog() != true) return;
        try
        {
            File.WriteAllText(dialog.FileName, ReportText.Format(_report), Encoding.UTF8);
            StatusText.Text = "Report saved on this computer. Site Check does not upload it. The file is ordinary text; keep it on a disk you already protect if it names versions you have not yet updated.";
        }
        catch (Exception)
        {
            StatusText.Text = "The report could not be saved at that location. Choose another folder, or copy the report instead.";
        }
    }

    private void Lawful_Click(object sender, RoutedEventArgs e)
    {
        ShowTextWindow("Lawful use  ·  Site Check", LoadEmbedded("LAWFUL-USE.md") ?? LoadEmbedded("lawful-use.md") ?? "See docs/lawful-use.md in the repository.");
    }

    private void Licence_Click(object sender, RoutedEventArgs e)
    {
        var text = LoadLicenceText();
        ShowTextWindow("Licence and warranty  ·  Site Check", text);
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
                FileName = "mailto:Info@operationlockedin.com?subject=Site%20Check",
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
            Site Check
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

    private static List<FindingView> ToViews(IReadOnlyList<Finding> findings)
    {
        var list = new List<FindingView>();
        FindingState? last = null;
        foreach (var f in findings.OrderBy(x => ReportText.Rank(x.State)))
        {
            var view = ToView(f);
            view.Section = last == f.State ? "" : ReportText.SectionName(f.State);
            last = f.State;
            list.Add(view);
        }
        return list;
    }

    private static FindingView ToView(Finding f)
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
        return new FindingView
        {
            Title = f.Title,
            State = ReportText.StateLabel(f.State),
            StateBrush = labelBrush,
            AccentBrush = rail,
            Observation = f.Observation,
            Method = f.Method,
            Caveat = f.Caveat
        };
    }
}

public sealed class FindingView
{
    public string Section { get; set; } = "";
    public string Title { get; set; } = "";
    public string State { get; set; } = "";
    public Brush StateBrush { get; set; } = Brushes.White;
    public Brush AccentBrush { get; set; } = Brushes.White;
    public string Observation { get; set; } = "";
    public string Method { get; set; } = "";
    public string Caveat { get; set; } = "";
}
