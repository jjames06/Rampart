// CODEMAP FILE: src/SiteCheck.Maui/MauiProgram.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: MAUI host builder. Fonts and the single MainPage.
// Called by: Platform entry (Android MainApplication, iOS AppDelegate).
// Calls: UseMauiApp<App>().
// Invariants: See docs/encryption.md: TLS in transit; no extra on-device vault.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

namespace SiteCheck.Maui;

/// <summary>
/// MAUI host builder. Fonts and the single MainPage. See docs/CODEMAP.md and docs/encryption.md.
/// </summary>

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder.UseMauiApp<App>();
        return builder.Build();
    }
}
