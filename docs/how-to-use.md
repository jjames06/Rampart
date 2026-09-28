# How to use Lockwatch

This is the operator handbook for Site Check, a Windows program written by Jesse Mosier-Bowers, operating as Operation Locked In in Courtice, Ontario. Read this page before you run the executable against a hostname that is not a machine you already operate.

Site Check is a **read-only** look at a **public hostname you operate**, or for which you have **written permission**. It is not a red-team engagement. It is not a penetration test. It is not a crawl of every URL on the site. It is not a substitute for a written quote for paid website work. A quiet report is not a certificate that the site is safe.

## What you need

You need a 64-bit computer running Windows 10 or Windows 11. You need the file `SiteCheck.exe` from the private GitHub release, or a copy you built yourself with `tools\publish.ps1`. You need the public hostname of the site, for example `www.example.com`.

You do not need an Operation Locked In account. You do not need a browser plugin. You do not need a cloud login. You do not need administrative rights. The program runs as a standard user (`asInvoker`). It will not ask Windows for elevation.

## Lawful use, in full

Before the program will talk to a hostname, you must tick the permission box. By ticking it you state two things: that you operate the hostname, or that you have written permission to check it; and that you understand unauthorized use of a computer system can be a criminal offence in Canada under Criminal Code section 342.1, and under similar laws in other countries.

Do not type a hostname you do not control. Do not use this program as a scanner for other people's sites. Do not treat a client's staging hostname as yours unless the client has asked you, in writing, to check it. If Operation Locked In built the site, you already have that permission for the duration of the job; still tick the box so the record of consent is in the run itself.

## Start the program

1. Double-click `SiteCheck.exe` on your Desktop, or in the `dist` folder if you built from source.
2. Windows SmartScreen may warn that the file is not Authenticode-signed. If you built it yourself, or downloaded it from the Operation Locked In private repository `jjames06/oli-site-check`, choose **More info**, then **Run anyway**.
3. A navy window titled **Site Check · Operation Locked In** should open, with the teal hairline under the title, matching the colours used on https://www.operationlockedin.com.

If nothing opens, confirm you are on 64-bit Windows and that antivirus did not quarantine the file. Rebuild with `tools\publish.ps1` if you have the source. Email Info@operationlockedin.com if a rebuilt copy still will not start, and include the Windows version, not a screenshot of unrelated software.

## Run a check

1. Click the hostname field.
2. Type the public hostname. You may paste a full `https://` address, including a path. The program keeps only the hostname. International names (for example a name with accents) are converted to ASCII (punycode) before anything is queried.
3. Examples that work: `example.com`, `www.example.com`, `https://www.example.com/about`.
4. Examples that are refused, on purpose: `127.0.0.1`, `localhost`, `router.local`, `192.168.0.1`, a home-network name ending in `.lan` or `.home`, a name with a port such as `example.com:443`, and a bare word with no dot. The program will not contact private, loopback, link-local, CGNAT, documentation, or multicast addresses. If a name has both a public address and a private address, only the public address is used.
5. Choose **Standard public-surface check**, or **Authorized public-surface assessment** if you also want RFC public files (`security.txt`, `robots.txt`) and extra DNS (CAA, common DKIM selectors). Both modes are read-only. Neither sends exploit traffic.
6. Tick **both** permission boxes. The first box is that you operate the hostname or have written permission from the person who does. The second box is that you will not use the program against a hostname you are not authorized to check, and that Operation Locked In does not authorize that use. Canadian Criminal Code section 342.1 is named on that box. The boxes are not legal advice.
7. Choose **Check this hostname**, or press Enter. The primary button stays off until both boxes are ticked.

The status line describes the current step: resolving public addresses, opening TLS, then reading HTTPS, the homepage, mail records, and HTTP on port 80. A thin teal bar shows that work is in progress. You cannot start a second check until this one finishes. To stop a check that is taking too long, choose **Stop this check** or press Escape. Stopping cancels further requests; it cannot unsend the packets already on the wire.

A check usually finishes in a few seconds. If you are on a VPN, it can take longer, up to about eight seconds per network step. That is expected.

## Read the result

A **This run** card names the hostname, the time in UTC, the public addresses that were used, and any product names the homepage or headers advertised (for example Next.js, WordPress, Cloudflare). Those product names come only from what the host already published. The program did not log in and did not download plugin files.

**What to do next** appears only when this run found something that needs work. If HTTPS, the certificate, headers, SPF, and DMARC already look complete for this catalogue, that block stays hidden. Do not look for a generic twelve-step list. The list is built from this hostname and this run. Next.js wording appears only when Next.js was advertised. WordPress wording appears only when WordPress was advertised.

Each finding card has four parts, in this order:

1. The title and a state: **Present**, **Not found**, **Could not complete**, or **Needs attention**.
2. **Observation**: what the program actually saw.
3. **How this was gathered**: DNS, TLS handshake, HTTP HEAD or GET, or TXT lookup.
4. **What this does not mean**: the caveat, so a missing header is not reported as a breach.

Read the states as follows:

- **Present** means this check saw the control or record on the paths it requested.
- **Not found** means this check did not see it on those paths. It does not mean the rest of the site is broken.
- **Could not complete** means the network step timed out or failed. Try again, confirm the host is reachable from this computer, and confirm you are not blocked by a firewall that only allows browsers.
- **Needs attention** means an advertised version matched a sourced catalogue entry, a certificate name did not match, HSTS is present with `max-age` at or below zero, DMARC is published as monitor-only (`p=none`), or the homepage disclosed plugin directory names.

The left-hand colour on each card follows the state: teal for Present, amber for Not found and Needs attention, and slate for Could not complete.

## Copy or save a report

**Copy report** places a plain-text report on the clipboard. **Save report** writes a `.txt` file where you choose. Site Check does not upload that file. It does not create an account. It does not phone home to Operation Locked In.

The saved file is ordinary text. It is not encrypted by this program, because you chose the location and you may need to open it in Notepad, email it to yourself, or attach it to a job note. If the report names plugin versions you have not yet updated, keep it on a disk you already protect (BitLocker on the system drive, or an encrypted working folder you already use). Do not post the report on a public ticket or a public git issue.

The report is not a certificate of security. It is a dated observation of one hostname from this computer.

## After a kit website goes live

If Operation Locked In built the brochure site, run Site Check on the live hostname after DNS points at the host. Use the next steps together with the fourteen-day aftercare window in the Website Kit Operator Guide. Site Check does not replace the local security review that happens before DNS is pointed. It is the first public-surface read after the name is live.

## When to email Jesse

Email Info@operationlockedin.com if a next step names the wrong stack (for example it talks about WordPress on a Next.js site), if a certificate day count looks wrong, or if the program reports a catalogue match you believe is a false positive. Include the hostname you typed and a saved report. Do not attach passwords, cookies, or access tokens.

You can also choose **Info@operationlockedin.com** in the window footer. That opens your own mail program. Mail still leaves from your computer, not from Site Check.

## Licence and warranty

The footer of the window states the copyright and that there is no warranty. **Licence and warranty** shows the GNU General Public License version 3, which is also the file `LICENSE` in the repository. Site Check is free software. It is not a paid SKU. Paid website work still begins after a written quote.

## What the program will never do

It will not crawl every URL. It will not follow redirects. It will not open `wp-admin`, `xmlrpc.php`, or `version.php`. It will not download plugin zip files. It will not guess passwords. It will not send exploit traffic. It will not contact private or home-network addresses. It will not scrape the National Vulnerability Database live. Absence of a catalogue match is not clearance.

## Keeping the CVE catalogue current

The catalogue is the file `data/advisories.json`, rebuilt at release time from Retire.js (JavaScript libraries) and the GitHub Advisory Database (Next.js). When you need newer ranges, run `node tools\build-advisories.mjs`, run the tests, and ship a new private release. See [cve-catalogue.md](cve-catalogue.md). Matching is local. The program does not query NVD or Cloudflare when you click Check this hostname. Do not claim the catalogue is every CVE on the internet. It is every advisory in that file for versions the homepage and headers actually advertised.
