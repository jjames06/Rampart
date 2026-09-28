namespace SiteCheck.Maui;

public partial class App : Application
{
    public App()
    {
        InitializeComponent();
        MainPage = new NavigationPage(new MainPage())
        {
            BarBackgroundColor = Color.FromArgb("#0C1220"),
            BarTextColor = Color.FromArgb("#F8FAFC")
        };
    }
}
