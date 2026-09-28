# App Store and Play privacy labels

Use these answers. They match `docs/privacy.md`.

## App Store Connect → App Privacy

- Data collection: **No, we do not collect data from this app**
- Tracking: **No**
- Used for tracking: none
- Linked to identity: none
- Used for third-party advertising: no
- Used for analytics: no

Rampart does not create an account. It does not phone home. DNS and HTTPS during a check go to the hostname the operator typed, which is the site they said they operate.

Privacy policy URL: https://www.operationlockedin.com/privacy

## Google Play → Data safety

- Does your app collect or share user data? **No**
- Is the app encrypted in transit? HTTPS to the target hostname uses the OS TLS stack. Play still wants an answer: **Yes, data is encrypted in transit** (the check itself is HTTPS).
- Can users request data deletion? **Not applicable** (nothing is stored by Operation Locked In).
- Data types: none selected.
- Security practices: the app does not use advertising ID.

## Permissions

Android: `INTERNET` only. Cleartext (http://) traffic is disabled for the app’s own requests except the single port-80 HEAD the checker already does through .NET, which is an explicit HTTP URL to the typed hostname.

iOS: no photo, camera, contacts, location, or tracking usage strings. `PrivacyInfo.xcprivacy` lists no collected data types and tracking = false.
