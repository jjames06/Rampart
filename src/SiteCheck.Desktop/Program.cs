// CODEMAP FILE: src/SiteCheck.Desktop/Program.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Avalonia process entry. [STAThread] required on Windows if this project is ever run there.
// Called by: dotnet / published native host.
// Calls: AppBuilder → App.
// Invariants: Keep STAThread. Do not start a check before the window shows consent.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using Avalonia;

namespace SiteCheck.Desktop;

/// <summary>
/// Avalonia entry. STAThread required on Windows. See docs/CODEMAP.md.
/// </summary>
internal static class Program
{
    [STAThread]
    public static void Main(string[] args) =>
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
