using System.IO;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using SiteCheck.Core;

namespace SiteCheck.App;

public partial class MainWindow : Window
{
    private CheckReport? _report;

    public MainWindow()
    {
        InitializeComponent();
        HostBox.GotFocus += (_, _) =>
        {
            if (HostBox.Text == "www.example.com") HostBox.Clear();
        };
    }

    private async void Run_Click(object sender, RoutedEventArgs e)
    {
        if (PermissionBox.IsChecked != true)
        {
            StatusText.Text = "Tick the permission box only if you operate this hostname or have written permission.";
            return;
        }

        RunButton.IsEnabled = false;
        CopyButton.IsEnabled = false;
        SaveButton.IsEnabled = false;
        StatusText.Text = "Looking up public addresses, then reading TLS and DNS. This stays on this computer.";
        FindingsList.ItemsSource = null;
        NextList.ItemsSource = null;
        LimitsBox.Visibility = Visibility.Collapsed;
        NextBox.Visibility = Visibility.Collapsed;
        _report = null;

        try
        {
            var report = await Checker.RunAsync(HostBox.Text);
            _report = report;
            FindingsList.ItemsSource = report.Findings.Select(ToView).ToList();
            if (report.NextSteps.Count > 0)
            {
                NextList.ItemsSource = report.NextSteps;
                NextBox.Visibility = Visibility.Visible;
            }
            LimitsList.ItemsSource = report.Limits;
            LimitsBox.Visibility = Visibility.Visible;
            StatusText.Text = $"Checked {report.Hostname} at {report.CheckedAt:yyyy-MM-dd HH:mm} UTC using {string.Join(", ", report.PublicAddresses)}.";
            CopyButton.IsEnabled = true;
            SaveButton.IsEnabled = true;
        }
        catch (CheckException ex)
        {
            StatusText.Text = ex.Message;
        }
        catch (Exception)
        {
            StatusText.Text = "The check did not finish. Confirm the hostname is public and try again.";
        }
        finally
        {
            RunButton.IsEnabled = true;
        }
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        if (_report is null) return;
        Clipboard.SetText(ReportText.Format(_report));
        StatusText.Text = "Report copied. It contains observations, methods, and caveats. It is not a certificate of security.";
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (_report is null) return;
        var dialog = new SaveFileDialog
        {
            Filter = "Text file (*.txt)|*.txt",
            FileName = $"site-check-{_report.Hostname}-{_report.CheckedAt:yyyyMMdd}.txt"
        };
        if (dialog.ShowDialog() == true)
        {
            File.WriteAllText(dialog.FileName, ReportText.Format(_report));
            StatusText.Text = "Report saved on this computer.";
        }
    }

    private static FindingView ToView(Finding f)
    {
        var teal = (Brush)Application.Current.Resources["TealBrush"];
        var muted = (Brush)Application.Current.Resources["MutedBrush"];
        var amber = new SolidColorBrush(Color.FromRgb(0xF5, 0xD0, 0x8A));
        var brush = f.State switch
        {
            FindingState.Present => teal,
            FindingState.NotFound => amber,
            FindingState.Attention => amber,
            _ => muted
        };
        return new FindingView
        {
            Title = f.Title,
            State = ReportText.StateLabel(f.State),
            StateBrush = brush,
            Observation = f.Observation,
            Method = f.Method,
            Caveat = f.Caveat
        };
    }
}

public sealed class FindingView
{
    public string Title { get; set; } = "";
    public string State { get; set; } = "";
    public Brush StateBrush { get; set; } = Brushes.White;
    public string Observation { get; set; } = "";
    public string Method { get; set; } = "";
    public string Caveat { get; set; } = "";
}
