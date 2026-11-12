// CODEMAP FILE: src/SiteCheck.Maui/Platforms/iOS/Program.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: iOS process entry (UIApplication.Main).
// Called by: iOS runtime.
// Calls: AppDelegate.
// Invariants: Boilerplate. Keep the delegate type in sync with AppDelegate.cs.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using UIKit;

namespace SiteCheck.Maui;

/// <summary>
/// iOS process entry. See docs/CODEMAP.md.
/// </summary>
public class Program
{
    static void Main(string[] args)
    {
        UIApplication.Main(args, null, typeof(AppDelegate));
    }
}
