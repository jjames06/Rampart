using System.Windows;
using System.Windows.Threading;

namespace SiteCheck.App;

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
            "Lockwatch stopped the last action. Nothing was sent off this computer except the check you started, if one had begun.\n\n" +
            ex.GetType().Name + ": " + ex.Message + "\n\nYou can try again. If it keeps happening, email Info@operationlockedin.com with this text.",
            "Lockwatch",
            MessageBoxButton.OK,
            MessageBoxImage.None);
    }
}
