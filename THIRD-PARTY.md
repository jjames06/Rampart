# Third-party software

Rampart includes **DnsClient** (the version referenced in `src/SiteCheck.Core/SiteCheck.Core.csproj`), used only to request DNS TXT records through the system resolver.

DnsClient is copyright MichaCo and contributors, licensed under the Apache License, Version 2.0. You may obtain a copy of that licence at https://www.apache.org/licenses/LICENSE-2.0

This program also ships **advisory data** derived from:

- **Retire.js** `jsrepository.json` (Apache License 2.0), used to match JavaScript library versions that appear on the homepage. Rampart does not ship the Retire.js scanner program. The matching code is original C#. See https://github.com/RetireJS/retire.js
- **GitHub Advisory Database** ranges for npm packages next, react, react-dom, vue, nuxt, jquery, and bootstrap, and for WordPress core when a version is advertised (Creative Commons Attribution 4.0). See https://github.com/advisories

Apache-2.0 code and data may be combined with this GPLv3 program. The combination as a whole is distributed under GPLv3. DnsClient and Retire.js data remain under Apache-2.0. GitHub Advisory Database content remains under CC BY 4.0. See `NOTICE` for attribution.

Cloudflare Radar URL Scanner, Cloudflare Observatory, and Flan Scan are **not** included. Radar is a hosted service whose API data is CC BY-NC 4.0. Flan Scan is an Nmap wrapper and would change this program into a port scanner. Details are in `docs/cve-catalogue.md`.

Test projects may use xUnit and the Visual Studio test SDK under their own licences. Those packages are not shipped inside `Rampart.exe`.
