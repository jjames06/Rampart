# Encryption and licences, per Rampart build

This is the professional answer for a business tool. It is not a packer for the executable.

## What we do not encrypt

We do **not** encrypt or obfuscate `Rampart.exe` or the Linux/macOS testing binaries.

Desktop Rampart is GNU GPLv3. The source is public. Hiding the binary would not hide the source, and self-extracting packers make Microsoft Defender SmartScreen more suspicious, not less. Authenticode signing (publisher identity) is a separate question; see [signing.md](signing.md).

TLS 1.2 or 1.3 to the hostname you typed is the encryption **in transit**. Sockets are pinned to a public address. Redirects are not followed.

## Windows (recommended, GPLv3)

**Licence:** GNU GPLv3 (`LICENSE`).

**In transit:** TLS to the target hostname.

**At rest:** Optional. When you save a report, you may tick **Protect this file for this Windows user only**. Rampart then uses Windows DPAPI (`DataProtectionScope.CurrentUser`). Only that Windows account on that PC can open it. There is no password to recover and no Operation Locked In key desk. If you skip the box, the file is ordinary UTF-8 so you can open it in Notepad.

Use BitLocker on the disk as well if the PC leaves the office.

## Linux testing zip (GPLv3)

**Licence:** GNU GPLv3.

**In transit:** TLS, same Core as Windows.

**At rest:** The zip does not wrap reports in a vault. Save to a home directory you already protect (LUKS, encrypted home). A homemade password file in a testing build would be easy to get wrong and hard to recover.

## macOS testing zip (GPLv3)

**Licence:** GNU GPLv3.

**In transit:** TLS.

**At rest:** Save to a FileVault volume. Gatekeeper is not encryption; it is publisher trust. Notarize later with a Developer ID if you treat the Mac copy as finished.

## iPhone and Android (GPLv3 source, Apache-2.0 additional grant for store binaries)

**Licence:** Source under GPLv3. Store binaries also under Apache License 2.0 (`LICENSE.MOBILE`) so App Store terms can sit beside the grant. See [licence.md](licence.md).

**In transit:** TLS, same Core.

**At rest:** Reports stay in the app sandbox (or the share sheet you pick). On a locked iPhone, Data Protection encrypts app files. On Android, app-private storage is not world-readable. Do not put reports on a public share. Store listings are not public yet.

## What a report contains

A report names a hostname, public addresses, advertised product versions, and CVE identifiers. It does not contain your passwords. Still treat it as a job record: do not post it on a public ticket without redaction.
