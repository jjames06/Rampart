# Privacy

Rampart runs on the device in front of you. The recommended copy is the Windows desktop executable. Testing copies for Linux and macOS are on the GitHub release. iPhone and Android applications will be listed on the App Store and Google Play when they are ready. The program does not create an account. It does not phone home to Operation Locked In, GitHub, or an analytics service.

## What leaves this computer

During a check, and only after you tick the permission box, the program sends:

- DNS queries through the **system resolver** for the hostname you typed, for the parent name when you typed `www`, and for `_dmarc.` plus the apex.
- TLS and HTTP requests to the **public addresses** of that hostname, on port 443 and a single HEAD on port 80.

The User-Agent is `operation-locked-in-rampart/1.9.0`. On an authorized assessment, the program also requests RFC public files and extra DNS. Common public sign-in, account, and admin paths are requested with GET only. No passwords are sent. No other application hostnames are contacted. DnsClient does not send TXT queries to a third-party DNS API; it uses the resolver Windows already uses. CVE matching uses a catalogue baked into the executable. Advertised versions are not sent to NVD, GitHub, Retire.js, or Cloudflare.

The program does not send the report to Operation Locked In.

## What stays here

Results live in the window until you close it. If you choose Copy, they go to the clipboard. If you choose Save, they go to a text file you pick. The executable does not write a hidden log of hostnames.

## Encryption

TLS 1.2 or TLS 1.3 is used to speak to the target site on port 443. That is the encryption that protects the check in transit.

Reports on disk are ordinary UTF-8 text because you chose to save them and you need to be able to read them. Rampart does not wrap the file in a password vault. A vault would stop you opening the report in Notepad, and this program does not have a key-recovery desk. If you need the file protected at rest, save it to a BitLocker volume or another encrypted disk you already use.

The program stores no passwords, no session cookies of yours, and no API keys. Do not paste access tokens into the hostname field. The field accepts a DNS name only.

## Personal information

Hosting logs on the **target site** may record the check as they would record any HTTPS client, including your public IP address as the client. That is the site you said you operate. Rampart does not bind anything to that IP on Jesse's side, because nothing is sent to Jesse.

If you email a report to Info@operationlockedin.com, that mail is a job record. Keep passwords out of it.

## PIPEDA in one paragraph

This program is a local tool. Operation Locked In is not the processor of the check while it stays on your computer. If you later send a report to Jesse as part of paid work, that report is handled under the practice privacy pages on https://www.operationlockedin.com/privacy, not under a separate Rampart cloud.
