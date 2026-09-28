# Building Barbican

You need the .NET 8 SDK (64-bit) and 64-bit Windows.

Rebuild the local CVE catalogue (needs network once per release):

```
node tools\build-advisories.mjs
```

Then from the repository root:

```
dotnet test tests\SiteCheck.Tests\SiteCheck.Tests.csproj -c Release
dotnet publish src\SiteCheck.App\SiteCheck.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false -p:EnableCompressionInSingleFile=true -o dist
```

`tools\publish.ps1` runs both commands, names the result `Barbican.exe`, and copies `LICENSE`, `NOTICE`, `THIRD-PARTY.md`, and `docs/how-to-use.md` into `dist` so an object-code copy is accompanied by the licence text GPLv3 requires.

The executable is self-contained. The person who runs it does not install the .NET runtime. The program requests no administrative elevation (`asInvoker`). Per-monitor DPI awareness is set in the application manifest.

Do not enable `PublishTrimmed`. Trimming has broken WPF resource lookup on this project before. Compression of the single file is on.

## Tests

Unit tests cover hostname parsing (including international names and userinfo stripping), private-address refusal (including NAT64 and 6to4 embeddings), cookie flag reading that does not split on Expires commas, HSTS `max-age=0` and short max-age, DMARC `p=none`, SPF `+all`, TLS cipher helpers, homepage tabnabbing and http forms, advice that does not invent header fixes when HTTPS never finished, fingerprints (including Next.js from `/_next/static`), and the CVE catalogue.

```
dotnet test tests\SiteCheck.Tests\SiteCheck.Tests.csproj -c Release
```

## Signing

Release builds are not Authenticode-signed yet. Windows SmartScreen may warn. The operator handbook explains **More info**, then **Run anyway**, for copies that came from this private repository.
