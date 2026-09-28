# Known issues

## Windows SmartScreen

`Rampart.exe` is not Authenticode-signed. Microsoft Defender reports no threats. SmartScreen still shows **Windows protected your PC** on first run. For a copy from this repository or from https://www.operationlockedin.com/rampart, choose **More info**, then **Run anyway**. Signing notes: [signing.md](signing.md).

## GitHub wiki remote

`tools/publish-wiki.ps1` needs a first wiki page created in the GitHub UI. After that, the script syncs `docs/wiki/`.

## Linux and macOS

The zips on the v1.9.0 release are testing copies. Linux needs `chmod +x Rampart`. macOS Gatekeeper may ask to open from Finder. [TESTING.txt](TESTING.txt).

## iPhone and Android

Source is in `src/SiteCheck.Maui`. Store listings are not public yet. [stores/SUBMIT.md](stores/SUBMIT.md).
