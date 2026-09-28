# Licence

Rampart uses **two grants**, on purpose.

The recommended public download is the Windows program. Testing copies for Linux and macOS are on the same GitHub release, still under GNU GPLv3. iPhone and Android applications are in testing and will be listed on the App Store and Google Play when they are ready. Those store binaries will use the additional Apache License 2.0 grant below.

## Desktop (Windows, macOS, Linux): GNU GPLv3

The Windows WPF app and the Avalonia app for macOS and Linux are licensed under the **GNU General Public License version 3**, or, at your option, any later version published by the Free Software Foundation. The complete legal text is `LICENSE`. A short copyright notice is in `NOTICE`.

Jesse Mosier-Bowers already publishes **Bastion** under GPLv3. Rampart is the same kind of work: a free program for a home or small office, not a paid product SKU. GPLv3 keeps the source available, requires the same freedom when someone redistributes a modified desktop build, and matches the warranty disclaimer already used on Bastion.

Apache License 2.0 or MIT on the desktop checker would have allowed a later proprietary fork of the tool itself. That does not fit this program. GPLv3 is the fit for Windows, Mac, and Linux.

## App Store and Google Play: Apache License 2.0 (additional grant)

Apple’s App Store terms add restrictions that **GPLv3 does not allow**. The Free Software Foundation’s published position is that you cannot submit a GPLv3-only iOS app to the App Store in good faith, because the store forbids reverse engineering and adding extra restrictions GPLv3 section 7 does not permit. Google Play is less strict, but one mobile licence that both stores accept is simpler.

Jesse Mosier-Bowers, as copyright holder, **additionally licenses** the Rampart iOS and Android **store binaries** under the **Apache License 2.0**. The grant is the file `LICENSE.MOBILE`. The Apache text is `licenses/APACHE-2.0.txt`. The same source remains available under GPLv3. You may use either grant.

Apache-2.0 includes an express patent licence and does not forbid the extra terms those stores require.

## Third-party

DnsClient.NET (TXT lookups) remains Apache License 2.0 in every build. Apache-2.0 code may be combined with a GPLv3 program. The combination as a whole, for desktop, is distributed under GPLv3. DnsClient itself is still Apache-2.0.

Retire.js advisory data is Apache-2.0. GitHub Advisory ranges for npm `next` are CC BY 4.0. See `THIRD-PARTY.md`.

Avalonia (macOS and Linux UI) is MIT. .NET MAUI (iOS and Android UI) is MIT. Those UI toolkits stay under their own licences; they do not relicense SiteCheck.Core.

## What you may do

You may run Rampart for any lawful purpose. You may study the source, change it, and share original or modified copies under the grant you chose. If you convey a **desktop** executable, you must also provide the corresponding source as GPLv3 requires. If you convey a **store** binary under Apache-2.0, follow Apache-2.0’s notice rules (keep NOTICE, state changes).

## What the licence does not do

The licence does not grant permission to use a computer system without authorization. Canadian Criminal Code section 342.1 and similar laws elsewhere still apply. The licence does not create a paid support contract. Paid website work from Operation Locked In still begins after a written quote.

## Warranty

There is no warranty. Sections 15 and 16 of GPLv3 apply to GPLv3 copies. Apache-2.0 sections 7, 8, and 9 apply to Apache-2.0 copies. The program is offered as-is. A quiet report is not a guarantee that a hostname is safe.

## Notices in the program

The window footer states the copyright, that the desktop program is free software under GPLv3, and that there is no warranty. **Licence and warranty** shows the full GPLv3 text shipped inside the desktop executable. Mobile store listings point at `LICENSE.MOBILE` and the public privacy page.
