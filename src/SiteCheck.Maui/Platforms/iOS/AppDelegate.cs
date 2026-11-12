// CODEMAP FILE: src/SiteCheck.Maui/Platforms/iOS/AppDelegate.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: iOS app delegate. Boots MauiProgram. Store licence is LICENSE.MOBILE.
// Called by: iOS.
// Calls: MauiProgram.CreateMauiApp().
// Invariants: ATS (App Transport Security) stays on. Core already uses HTTPS.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using Foundation;

namespace SiteCheck.Maui;

/// <summary>
/// iOS app delegate. Boots MauiProgram. See docs/CODEMAP.md and LICENSE.MOBILE.
/// </summary>
[Register("AppDelegate")]
public class AppDelegate : MauiUIApplicationDelegate
{
    protected override MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();
}
