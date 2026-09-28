using SiteCheck.Core;

namespace SiteCheck.Maui;

public partial class MainPage : ContentPage
{
    private CheckReport? _report;

    public MainPage()
    {
        InitializeComponent();
    }

    private void Consent_Changed(object? sender, CheckedChangedEventArgs e)
    {
        RunButton.IsEnabled = PermissionBox.IsChecked && LawBox.IsChecked;
    }

    private async void Run_Clicked(object? sender, EventArgs e)
    {
        if (!PermissionBox.IsChecked || !LawBox.IsChecked)
        {
            StatusText.Text = "Tick both permission boxes.";
            return;
        }

        var host = HostBox.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(host))
        {
            StatusText.Text = "Enter a public hostname such as www.example.com.";
            return;
        }

        RunButton.IsEnabled = false;
        SaveButton.IsEnabled = false;
        FindingsHost.Children.Clear();
        SummaryText.IsVisible = false;
        StatusText.Text = "Resolving public Internet addresses.";
        var progress = new Progress<string>(msg => MainThread.BeginInvokeOnMainThread(() => StatusText.Text = msg));
        try
        {
            _report = await Task.Run(() => Checker.RunAsync(host, progress, CancellationToken.None, CheckScope.AuthorizedAssessment));
            var attn = _report.Findings.Count(f => f.State == FindingState.Attention);
            var missing = _report.Findings.Count(f => f.State == FindingState.NotFound);
            var incomplete = _report.Findings.Count(f => f.State == FindingState.Incomplete);
            var present = _report.Findings.Count(f => f.State == FindingState.Present);
            SummaryText.Text =
                $"{_report.Hostname}  ·  {attn} need attention, {missing} not found, {incomplete} could not complete, {present} present. {_report.NextSteps.Count} next step{(_report.NextSteps.Count == 1 ? "" : "s")}.";
            SummaryText.IsVisible = true;
            StatusText.Text = SummaryText.Text;
            foreach (var f in _report.Findings.OrderBy(x => ReportText.Rank(x.State)))
            {
                FindingsHost.Children.Add(BuildCard(f, FindingGuide.For(f, _report.NextSteps)));
            }
            SaveButton.IsEnabled = true;
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
            RunButton.IsEnabled = PermissionBox.IsChecked && LawBox.IsChecked;
        }
    }

    private View BuildCard(Finding f, NextStep? step)
    {
        var stack = new VerticalStackLayout { Padding = 16, Spacing = 8 };
        stack.Children.Add(new Label { Text = f.Title, FontAttributes = FontAttributes.Bold, FontSize = 18 });
        stack.Children.Add(new Label { Text = ReportText.StateLabel(f.State), TextColor = Color.FromArgb("#2DD4BF"), FontSize = 12 });
        stack.Children.Add(new Label { Text = f.Observation, TextColor = Color.FromArgb("#C5D0DE"), LineBreakMode = LineBreakMode.WordWrap });

        stack.Children.Add(new Label { Text = "How this was gathered", TextColor = Color.FromArgb("#5EEAD4"), FontAttributes = FontAttributes.Bold, FontSize = 12, Margin = new Thickness(0, 8, 0, 0) });
        stack.Children.Add(new Label { Text = f.Method, TextColor = Color.FromArgb("#C5D0DE"), LineBreakMode = LineBreakMode.WordWrap });
        stack.Children.Add(new Label { Text = "What this does not mean", TextColor = Color.FromArgb("#5EEAD4"), FontAttributes = FontAttributes.Bold, FontSize = 12, Margin = new Thickness(0, 8, 0, 0) });
        stack.Children.Add(new Label { Text = f.Caveat, TextColor = Color.FromArgb("#C5D0DE"), LineBreakMode = LineBreakMode.WordWrap });

        if (FindingGuide.ShowsWhen(step) && step != null)
        {
            stack.Children.Add(new Label { Text = "When to do this / when to skip", TextColor = Color.FromArgb("#5EEAD4"), FontAttributes = FontAttributes.Bold, Margin = new Thickness(0, 8, 0, 0) });
            if (!string.IsNullOrWhiteSpace(step.WhenTo))
                stack.Children.Add(new Label { Text = step.WhenTo, LineBreakMode = LineBreakMode.WordWrap });
            if (!string.IsNullOrWhiteSpace(step.WhenNot))
                stack.Children.Add(new Label { Text = step.WhenNot, TextColor = Color.FromArgb("#C5D0DE"), LineBreakMode = LineBreakMode.WordWrap });
        }

        if (FindingGuide.ShowsHowTo(f, step) && step != null)
        {
            stack.Children.Add(new Label { Text = "How to fix this", TextColor = Color.FromArgb("#5EEAD4"), FontAttributes = FontAttributes.Bold, Margin = new Thickness(0, 8, 0, 0) });
            stack.Children.Add(new Label { Text = step.Title, FontAttributes = FontAttributes.Bold, LineBreakMode = LineBreakMode.WordWrap });
            stack.Children.Add(new Label { Text = step.Body, TextColor = Color.FromArgb("#C5D0DE"), LineBreakMode = LineBreakMode.WordWrap });
            foreach (var line in step.Lines!)
            {
                var row = new VerticalStackLayout { Spacing = 6, Padding = 10, BackgroundColor = Color.FromArgb("#0C1220") };
                row.Children.Add(new Label { Text = line.Text, LineBreakMode = LineBreakMode.WordWrap });
                if (!string.IsNullOrWhiteSpace(line.Copy))
                {
                    row.Children.Add(new Label { Text = line.Copy, TextColor = Color.FromArgb("#5EEAD4"), FontFamily = "Courier", LineBreakMode = LineBreakMode.WordWrap });
                    var copy = line.Copy;
                    var btn = new Button { Text = "Copy", BackgroundColor = Colors.Transparent, TextColor = Color.FromArgb("#5EEAD4"), Padding = new Thickness(10, 6) };
                    btn.Clicked += async (_, _) =>
                    {
                        await Clipboard.Default.SetTextAsync(copy);
                        StatusText.Text = "Copied a how-to line.";
                    };
                    row.Children.Add(btn);
                }
                stack.Children.Add(row);
            }
        }

        return new Border
        {
            Stroke = Color.FromArgb("#243247"),
            BackgroundColor = Color.FromArgb("#162033"),
            StrokeShape = new Microsoft.Maui.Controls.Shapes.RoundRectangle { CornerRadius = 16 },
            Content = stack
        };
    }

    private async void Save_Clicked(object? sender, EventArgs e)
    {
        if (_report is null) return;
        var text = ReportText.Format(_report);
        await Share.Default.RequestAsync(new ShareTextRequest
        {
            Title = "Rampart report",
            Text = text
        });
    }
}
