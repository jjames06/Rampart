// CODEMAP FILE: src/SiteCheck.Maui/Platforms/Android/MainActivity.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Android launcher activity. Required MAUI host; no extra logic.
// Called by: Android OS.
// Calls: MauiApp.
// Invariants: Do not add INTERNET-unrelated permissions. HTTPS only through Core's HttpClient.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using Android.App;
using Android.Content.PM;

namespace SiteCheck.Maui;

/// <summary>
/// Android launcher activity. Required MAUI host; no extra logic. See docs/CODEMAP.md.
/// </summary>
[Activity(
    Theme = "@style/Maui.SplashTheme",
    MainLauncher = true,
    ConfigurationChanges = ConfigChanges.ScreenSize
        | ConfigChanges.Orientation
        | ConfigChanges.UiMode
        | ConfigChanges.ScreenLayout
        | ConfigChanges.SmallestScreenSize
        | ConfigChanges.Density)]
public class MainActivity : MauiAppCompatActivity
{
}
