# Third-party software

Site Check includes **DnsClient** (the version referenced in `src/SiteCheck.Core/SiteCheck.Core.csproj`), used only to request DNS TXT records through the system resolver.

DnsClient is copyright MichaCo and contributors, licensed under the Apache License, Version 2.0. You may obtain a copy of that licence at https://www.apache.org/licenses/LICENSE-2.0

Apache-2.0 code may be combined with this GPLv3 program. The combination as a whole is distributed under GPLv3. DnsClient itself remains under Apache-2.0. See `NOTICE` for the required attribution.

No other third-party packages are referenced by the application projects at the time of this writing. Test projects may use xUnit and the Visual Studio test SDK under their own licences. Those packages are not shipped inside `SiteCheck.exe`.
