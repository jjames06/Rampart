// CODEMAP FILE: src/SiteCheck.App/App.xaml.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: WPF Application subclass. DispatcherUnhandledException so a failed check does not vanish the window.
// Called by: WPF entry (App.xaml).
// Calls: MainWindow.
// Invariants: Unhandled UI exceptions become a dialog, not a silent close.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using System.Windows;
using System.Windows.Threading;

namespace SiteCheck.App;

/// <summary>
/// WPF Application. Last-chance UI for unhandled exceptions so a failed check
/// does not vanish. See docs/CODEMAP.md.
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception ex)
                ShowError(ex);
        };
        base.OnStartup(e);
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        ShowError(e.Exception);
        e.Handled = true;
    }

    private static void ShowError(Exception ex)
    {
        MessageBox.Show(
            "Rampart stopped the last action. Nothing was sent off this computer except the check you started, if one had begun.\n\n" +
            ex.GetType().Name + ": " + ex.Message + "\n\nYou can try again. If it keeps happening, email Info@operationlockedin.com with this text.",
            "Rampart",
            MessageBoxButton.OK,
            MessageBoxImage.None);
    }
}
