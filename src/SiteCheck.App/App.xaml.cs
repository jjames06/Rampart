using System.Windows;
using System.Windows.Threading;

namespace SiteCheck.App;

public partial class App : Application
{
    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(
            "Site Check hit an unexpected error and stopped the last action. Nothing was sent off this computer except the check you started. You can try again.",
            "Site Check",
            MessageBoxButton.OK,
            MessageBoxImage.None);
        e.Handled = true;
    }
}
