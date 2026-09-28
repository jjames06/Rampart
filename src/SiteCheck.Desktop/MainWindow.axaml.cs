using Avalonia.Controls;
using Avalonia.Interactivity;
using SiteCheck.Core;

namespace SiteCheck.Desktop;

public partial class MainWindow : Window
{
    private CheckReport? _report;

    public MainWindow() => InitializeComponent();

    private async void Run_Click(object? sender, RoutedEventArgs e)
    {
        if (PermissionBox.IsChecked != true || LawBox.IsChecked != true)
        {
            StatusText.Text = "Tick both permission boxes.";
            return;
        }
        var host = HostBox.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(host))
        {
            StatusText.Text = "Enter a public hostname.";
            return;
        }
        RunButton.IsEnabled = false;
        StatusText.Text = "Checking…";
        try
        {
            _report = await Checker.RunAsync(host, null, CancellationToken.None, CheckScope.AuthorizedAssessment);
            ReportBox.Text = ReportText.Format(_report);
            StatusText.Text = $"{_report.Findings.Count} findings. Save stays on this computer.";
        }
        catch (Exception ex)
        {
            StatusText.Text = ex.Message;
        }
        finally
        {
            RunButton.IsEnabled = true;
        }
    }

    private async void Save_Click(object? sender, RoutedEventArgs e)
    {
        if (_report is null) return;
        var dlg = new SaveFileDialog { DefaultExtension = "txt", InitialFileName = "rampart-report.txt" };
        var path = await dlg.ShowAsync(this);
        if (string.IsNullOrWhiteSpace(path)) return;
        await File.WriteAllTextAsync(path, ReportText.Format(_report));
        StatusText.Text = "Report saved on this computer.";
    }
}
