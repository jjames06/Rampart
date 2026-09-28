# Building Site Check

You need the .NET 8 SDK (64-bit) and 64-bit Windows.

From the repository root:

```
dotnet test tests\SiteCheck.Tests\SiteCheck.Tests.csproj -c Release
dotnet publish src\SiteCheck.App\SiteCheck.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false -p:EnableCompressionInSingleFile=true -o dist
```

`tools\publish.ps1` runs both commands, names the result `SiteCheck.exe`, and copies `LICENSE`, `NOTICE`, `THIRD-PARTY.md`, and `docs/how-to-use.md` into `dist` so an object-code copy is accompanied by the licence text GPLv3 requires.

The executable is self-contained. The person who runs it does not install the .NET runtime. The program requests no administrative elevation (`asInvoker`). Per-monitor DPI awareness is set in the application manifest.

Do not enable `PublishTrimmed`. Trimming has broken WPF resource lookup on this project before. Compression of the single file is on.

## Tests

Unit tests cover hostname parsing (including international names and userinfo stripping), private-address refusal (including NAT64 and 6to4 embeddings), cookie flag reading that does not split on Expires commas, HSTS `max-age=0`, DMARC `p=none`, advice that does not invent header fixes when HTTPS never finished, fingerprints, and the CVE catalogue.

```
dotnet test tests\SiteCheck.Tests\SiteCheck.Tests.csproj -c Release
```

## Signing

Release builds are not Authenticode-signed yet. Windows SmartScreen may warn. The operator handbook explains **More info**, then **Run anyway**, for copies that came from this private repository.
