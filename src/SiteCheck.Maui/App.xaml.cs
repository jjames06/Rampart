// CODEMAP FILE: src/SiteCheck.Maui/App.xaml.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: MAUI Application. Sets MainPage.
// Called by: MauiProgram.
// Calls: MainPage.
// Invariants: No extra services. Reports leave the device only through the OS share sheet.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

namespace SiteCheck.Maui;

/// <summary>
/// MAUI Application. Navigation chrome only. See docs/CODEMAP.md.
/// </summary>
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
