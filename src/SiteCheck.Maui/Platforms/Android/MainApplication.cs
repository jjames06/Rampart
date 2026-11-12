// CODEMAP FILE: src/SiteCheck.Maui/Platforms/Android/MainApplication.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Android Application subclass. Boots MauiProgram.
// Called by: Android OS.
// Calls: MauiProgram.CreateMauiApp().
// Invariants: No background scanning.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using Android.App;
using Android.Runtime;

namespace SiteCheck.Maui;

/// <summary>
/// Android Application subclass. Boots MauiProgram. See docs/CODEMAP.md.
/// </summary>
[Application]
public class MainApplication : MauiApplication
{
    public MainApplication(IntPtr handle, JniHandleOwnership ownership)
        : base(handle, ownership)
    {
    }

    protected override MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();
}
