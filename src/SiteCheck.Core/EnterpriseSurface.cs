// CODEMAP FILE: src/SiteCheck.Core/EnterpriseSurface.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: GET-only fingerprints for internet-facing enterprise portals (SharePoint, NetScaler, FortiGate, and peers). Each advertised product becomes an Attention card that names the CISA KEV CVE as a patch prompt, not RCE proof.
// Called by: Checker after PeopleSoft. Tests in EnterpriseSurfaceTests.
// Calls: Shared ProbeNamedPathsAsync via Checker; homepage HTML, cookies, and headers already read.
// Invariants: GET/HEAD only. No POST, no WAF-bypass, no ToolPane/wls-wsat/fgt_lang exploit paths. Brochure hosts emit no extra Present cards. WAF-only is not the patch.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 these paths.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

namespace SiteCheck.Core;

/// <summary>
/// See docs/CODEMAP.md.
/// Read-only public-surface hints that a known-exploited enterprise product is internet-facing.
/// One card per advertised product. Absence is silent so a brochure is not eighteen Present cards.
/// PeopleSoft stays in <see cref="PeopleSoftSurface"/> (always-on card, already shipped).
/// </summary>
public static class EnterpriseSurface
{
    public sealed record Product(
        string Title,
        string[] Paths,
        string[] HtmlNeedles,
        string[] CookiePrefixes,
        string[] HeaderNames,
        string CveLine,
        string VendorUrl,
        string VendorLabel,
        string WhenTo,
        string PatchLine);

    public static readonly Product[] Products =
    {
        new(
            "Microsoft SharePoint",
            ["/_layouts/15/start.aspx", "/_layouts/16/start.aspx", "/_vti_bin/"],
            ["_spPageContextInfo", "MicrosoftSharePointTeamServices"],
            ["FedAuth", "rtFa"],
            ["MicrosoftSharePointTeamServices", "SPRequestGuid", "X-SharePointHealthScore"],
            "CISA lists CVE-2025-53770 (ToolShell) and CVE-2026-65660 as known exploited against on-premises SharePoint Server.",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65660",
            "Microsoft Security Update Guide for CVE-2026-65660:",
            "this hostname advertised on-premises SharePoint (layout paths, MicrosoftSharePointTeamServices, or FedAuth).",
            "Install Microsoft's SharePoint Server updates for CVE-2025-53770 and CVE-2026-65660, then rotate ASP.NET machine keys. A WAF rule that only blocks ToolPane is not the patch. Microsoft 365 SharePoint Online is a different product."),
        new(
            "Citrix NetScaler",
            ["/vpn/index.html", "/logon/LogonPoint/index.html"],
            ["LogonPoint", "NSC_AAAC"],
            ["NSC_"],
            [],
            "CISA lists CVE-2026-88771, CVE-2026-88772, and CVE-2026-19490 as known exploited against NetScaler ADC and Gateway.",
            "https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096",
            "Citrix bulletin CTX697096:",
            "this hostname advertised a public NetScaler Gateway or ADC logon point.",
            "Install Citrix's NetScaler ADC and Gateway builds that cover CVE-2026-88771 through CVE-2026-88778 and CVE-2026-19490. Follow Citrix's forensic triage if the appliance was internet-facing before the patch. A WAF in front is not the firmware patch."),
        new(
            "Fortinet FortiGate",
            ["/remote/login"],
            ["fgt_lang", "sslvpn"],
            [],
            [],
            "CISA lists CVE-2025-25249 as known exploited against FortiOS, FortiSwitchManager, and FortiSASE. Earlier SSL-VPN issues such as CVE-2024-21762 remain on the same catalogue.",
            "https://fortiguard.fortinet.com/psirt/FG-IR-25-084",
            "FortiGuard PSIRT FG-IR-25-084:",
            "this hostname advertised a public FortiGate SSL-VPN login.",
            "Upgrade FortiOS to the FortiGuard build that covers CVE-2025-25249. Take SSL-VPN off the public internet if it does not need to be there. Rampart only GETs /remote/login; it does not send the crafted packets used in exploitation."),
        new(
            "F5 BIG-IP",
            ["/tmui/login.jsp", "/my.policy"],
            ["tmui", "F5_ST", "BIGIPAuthCookie"],
            ["BIGIPAuthCookie", "F5_ST", "MRHSession"],
            ["Server"],
            "CISA lists CVE-2026-94127 as known exploited against BIG-IP APM. Earlier management-interface issues such as CVE-2022-1388 remain on the same catalogue.",
            "https://my.f5.com/manage/s/article/K000162605",
            "F5 article K000162605:",
            "this hostname advertised BIG-IP TMUI or APM.",
            "Install F5's BIG-IP APM fix for CVE-2026-94127. Do not leave the management interface (TMUI) on the public internet. Rampart does not call /mgmt/tm/util/bash."),
        new(
            "Ivanti Connect Secure",
            ["/dana-na/auth/url_default/welcome.cgi"],
            ["DSID", "welcome.cgi", "dana-na/auth"],
            ["DSID", "DSFirstAccess"],
            [],
            "CISA lists CVE-2025-22457, CVE-2025-0282, CVE-2024-21887, and CVE-2024-21893 as known exploited against Ivanti Connect Secure and related gateways.",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "CISA Known Exploited Vulnerabilities catalogue:",
            "this hostname advertised Ivanti Connect Secure (Pulse) on /dana-na/.",
            "Install Ivanti's Connect Secure builds that cover the CISA KEV rows for this product, then follow Ivanti's integrity checks. A WAF rule is not the appliance patch."),
        new(
            "Palo Alto GlobalProtect",
            ["/global-protect/login.esp", "/global-protect/portal/portal.esp"],
            ["global-protect/login", "PAN_LOGIN"],
            [],
            [],
            "CISA lists CVE-2026-0257 and CVE-2024-3400 as known exploited against PAN-OS, including GlobalProtect portals.",
            "https://security.paloaltonetworks.com/",
            "Palo Alto Networks security advisories:",
            "this hostname advertised a public GlobalProtect portal.",
            "Upgrade PAN-OS to the advisory build for CVE-2026-0257 and confirm CVE-2024-3400 is not still open on this appliance. Take the portal off the public internet if staff can use an internal path."),
        new(
            "Atlassian Confluence",
            ["/login.action", "/dologin.action"],
            ["ajs-version-number", "confluence-base-url"],
            ["seraph.confluence"],
            [],
            "CISA still lists CVE-2023-22527, CVE-2023-22518, and CVE-2023-22515 as known exploited against Confluence Data Center and Server.",
            "https://www.atlassian.com/trust/security/advisories",
            "Atlassian security advisories:",
            "this hostname advertised on-premises Confluence (/login.action).",
            "Upgrade Confluence Data Center or Server to a currently supported release that includes those KEV fixes. Atlassian Cloud is a different product. Do not leave /setup/ reachable."),
        new(
            "Progress MOVEit",
            ["/human.aspx", "/moveitisapi/moveitisapi.dll"],
            ["moveitisapi", "MOVEit Transfer"],
            [],
            [],
            "CISA lists CVE-2023-34362 as known exploited against MOVEit Transfer. Confirm later Progress advisories are installed on this host.",
            "https://www.progress.com/security",
            "Progress security page:",
            "this hostname advertised Progress MOVEit Transfer.",
            "Install Progress's MOVEit Transfer patches for CVE-2023-34362 and every later advisory Progress published for this product. Take the transfer portal off the public internet if partners can use a private path."),
        new(
            "ConnectWise ScreenConnect",
            ["/SetupWizard.aspx"],
            ["ScreenConnect.Client", "SetupWizard.aspx"],
            [],
            [],
            "CISA lists CVE-2026-84869 and CVE-2024-1709 as known exploited against ScreenConnect.",
            "https://www.connectwise.com/company/trust/security-bulletins/2026-09-08-screenconnect-bulletin",
            "ConnectWise ScreenConnect bulletin:",
            "this hostname advertised ScreenConnect (SetupWizard.aspx or product HTML).",
            "Upgrade ScreenConnect to the ConnectWise build that covers CVE-2026-84869. SetupWizard.aspx should not stay reachable on a finished server. CVE-2024-1709 was an authentication bypass; confirm that older build is gone."),
        new(
            "JFrog Artifactory",
            ["/artifactory/webapp/", "/artifactory/ui/login"],
            ["artifactory/webapp", "X-JFrog-Version"],
            [],
            ["X-JFrog-Version", "X-Artifactory-Id"],
            "CISA lists CVE-2026-42016 and CVE-2026-42018 as known exploited against JFrog Artifactory.",
            "https://jfrog.com/help/r/jfrog-release-information/jfrog-security-advisories",
            "JFrog security advisories:",
            "this hostname advertised Artifactory (webapp, login UI, or X-JFrog-Version).",
            "Upgrade self-managed Artifactory to the JFrog release that covers CVE-2026-42016 and CVE-2026-42018. Do not leave anonymous token endpoints on the public internet."),
        new(
            "GitLab",
            ["/users/sign_in"],
            ["gon.gitlab", "GitLab Community Edition", "GitLab Enterprise Edition"],
            ["_gitlab_session"],
            ["X-Gitlab-Meta"],
            "CISA lists CVE-2026-85706 as known exploited against GitLab Community Edition and Enterprise Edition (unauthenticated file read).",
            "https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-3-2-released/",
            "GitLab 19.3.2 patch release:",
            "this hostname advertised GitLab (/users/sign_in, _gitlab_session, or X-Gitlab-Meta).",
            "Upgrade GitLab CE/EE to 19.3.2 or the patch GitLab named for CVE-2026-85706. gitlab.com is a different service. Do not leave this instance on the public internet without the patch."),
        new(
            "Adobe Commerce",
            [],
            ["mage/cookies", "Magento_Ui", "Magento_Catalog"],
            ["mage-cache-storage", "mage-messages"],
            ["X-Magento-Vary"],
            "CISA lists CVE-2026-71362 and CVE-2026-75650 as known exploited against Adobe Commerce and Magento Open Source.",
            "https://helpx.adobe.com/security/products/magento/apsb26-92.html",
            "Adobe APSB26-92:",
            "this hostname advertised Adobe Commerce or Magento (X-Magento-Vary, mage cookies, or Magento HTML).",
            "Apply Adobe's Commerce/Magento security patches APSB26-92 and APSB26-146 (CVE-2026-71362 and CVE-2026-75650). A WAF rule is not the application patch."),
        new(
            "Oracle WebLogic",
            ["/console/login/LoginForm.jsp"],
            ["LoginForm.jsp", "WebLogic Server"],
            [],
            [],
            "CISA lists CVE-2024-21182 and older WebLogic rows (including CVE-2017-10271) as known exploited. Oracle publishes fixes in the Critical Patch Update.",
            "https://www.oracle.com/security-alerts/",
            "Oracle security alerts:",
            "this hostname advertised the WebLogic administration console on the public internet.",
            "Install the Oracle Critical Patch Update that covers this WebLogic version, and take /console off the public internet. Rampart does not GET /wls-wsat/ (that path was used in past exploits)."),
        new(
            "Oracle E-Business Suite",
            ["/OA_HTML/AppsLocalLogin.jsp", "/OA_HTML/AppsLogin"],
            ["AppsLocalLogin", "OA_HTML"],
            [],
            [],
            "CISA lists CVE-2025-61882, CVE-2025-61884, and CVE-2026-46817 as known exploited against Oracle E-Business Suite.",
            "https://www.oracle.com/security-alerts/",
            "Oracle security alerts:",
            "this hostname advertised Oracle E-Business Suite login (OA_HTML).",
            "Install the Oracle Critical Patch Update that covers CVE-2025-61882 and CVE-2026-46817. A WAF workaround is not the CPU. Take the Apps login off the public internet if staff can use VPN."),
        new(
            "SAP NetWeaver",
            ["/sap/bc/gui/sap/its/webgui", "/irj/portal"],
            ["sap-system-login", "sap-usercontext"],
            ["sap-usercontext", "SAP_SESSIONID"],
            [],
            "CISA lists CVE-2025-31324 and CVE-2025-42999 as known exploited against SAP NetWeaver.",
            "https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html",
            "SAP Security Notes:",
            "this hostname advertised SAP NetWeaver (Web GUI, portal, or SAP session cookies).",
            "Apply the SAP Security Notes for CVE-2025-31324 and CVE-2025-42999. Visual Composer and related public ICM services should not stay on the internet without those notes."),
        new(
            "SonicWall SMA",
            ["/cgi-bin/welcome"],
            ["SonicWALL", "sslvpnauth"],
            [],
            [],
            "CISA lists CVE-2026-83548 and CVE-2026-83549 as known exploited against SonicWall SMA1000 appliances.",
            "https://www.sonicwall.com/support/product-notification",
            "SonicWall product notifications:",
            "this hostname advertised a SonicWall SMA welcome path.",
            "Install SonicWall's SMA1000 firmware that covers CVE-2026-83548 and CVE-2026-83549. Take the appliance off the public internet if remote access can move to a supported path."),
        new(
            "VMware vCenter",
            ["/vsphere-client/"],
            ["vsphere-client", "vSphere Client"],
            [],
            [],
            "CISA lists CVE-2026-59310 as known exploited against VMware vCenter.",
            "https://www.broadcom.com/support/vmware-security-advisories",
            "Broadcom VMware security advisories:",
            "this hostname advertised vSphere Client or vCenter login.",
            "Apply Broadcom's vCenter patch for CVE-2026-59310. The vCenter UI should not be on the public internet. Rampart does not send the path-traversal payload."),
        new(
            "Zimbra Collaboration",
            ["/zimbraAdmin/", "/js/zimbraMail/"],
            ["zimbraMail", "ZM_AUTH_TOKEN"],
            ["ZM_AUTH_TOKEN"],
            [],
            "CISA lists CVE-2026-73570 and earlier Zimbra rows as known exploited against Zimbra Collaboration Suite.",
            "https://wiki.zimbra.com/wiki/Security_Center",
            "Zimbra Security Center:",
            "this hostname advertised Zimbra (admin UI, zimbraMail scripts, or ZM_AUTH_TOKEN).",
            "Upgrade Zimbra Collaboration Suite to the Security Center build that covers CVE-2026-73570. Do not leave /zimbraAdmin on the public internet."),
        new(
            "Microsoft Exchange",
            ["/owa/", "/ecp/"],
            ["Outlook Web App", "OutlookWebApp"],
            ["cadata", "X-BackEndCookie"],
            [],
            "CISA lists multiple Exchange Server rows as known exploited, including ProxyLogon-class and later Outlook Web App issues. On-premises OWA on the public internet is a patch-priority surface.",
            "https://msrc.microsoft.com/update-guide",
            "Microsoft Security Update Guide:",
            "this hostname advertised Outlook Web App or Exchange Control Panel (/owa/ or /ecp/).",
            "Install the current Exchange Server security update from Microsoft. Take OWA and ECP off the public internet if staff can use a VPN. Microsoft 365 Exchange Online is a different product. Rampart does not send ProxyLogon or ProxyShell traffic."),
        new(
            "Atlassian Jira",
            ["/secure/Dashboard.jspa"],
            ["jira-setup"],
            [],
            [],
            "CISA lists CVE-2019-11581 and CVE-2021-26086 as known exploited against Jira Server and Data Center.",
            "https://www.atlassian.com/trust/security/advisories",
            "Atlassian security advisories:",
            "this hostname advertised Jira Server or Data Center (/secure/Dashboard.jspa).",
            "Upgrade Jira Server or Data Center to a currently supported release that includes those KEV fixes. Atlassian Cloud is a different product."),
        new(
            "Jenkins",
            [],
            ["Jenkins-Crumb"],
            [],
            ["X-Jenkins"],
            "CISA and vendor advisories list Jenkins CLI and controller issues, including CVE-2024-23897. An internet-facing controller is a patch-priority surface.",
            "https://www.jenkins.io/security/advisories/",
            "Jenkins security advisories:",
            "this hostname advertised Jenkins (X-Jenkins header or controller HTML).",
            "Upgrade the Jenkins controller to the weekly or LTS line named in the current Jenkins security advisory. Do not leave the controller on the public internet."),
        new(
            "WSO2",
            ["/carbon/admin/login.jsp"],
            ["carbon/admin/login", "WSO2 Carbon"],
            [],
            [],
            "CISA lists CVE-2026-5430 and CVE-2022-29464 as known exploited against WSO2 products.",
            "https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/",
            "WSO2 security advisories:",
            "this hostname advertised a WSO2 Carbon admin login.",
            "Apply the WSO2 security advisory that covers CVE-2026-5430. Take /carbon off the public internet."),
        new(
            "phpMyAdmin",
            ["/phpmyadmin/", "/phpMyAdmin/"],
            ["pmahomme", "pma_username"],
            ["phpMyAdmin"],
            [],
            "A public phpMyAdmin login is a database-admin surface. Treat it as internet-facing management, not a brochure page.",
            "https://www.phpmyadmin.net/security/",
            "phpMyAdmin security:",
            "this hostname advertised phpMyAdmin.",
            "Take phpMyAdmin off the public internet. Restrict it to VPN or localhost. Upgrade to a current phpMyAdmin release from phpmyadmin.net/security."),
        new(
            "Grafana",
            [],
            ["grafanaBootData", "grafana-app"],
            ["grafana_session"],
            [],
            "CISA lists Grafana directory-traversal and authentication issues (including CVE-2021-43798). An internet-facing Grafana login is a patch-priority surface.",
            "https://grafana.com/security/security-advisories/",
            "Grafana security advisories:",
            "this hostname advertised Grafana (API health JSON, grafanaBootData, or grafana_session).",
            "Upgrade Grafana to the advisory build. Do not leave Grafana on the public internet without SSO and current patches. Rampart does not request plugin pluginId traversal paths."),
    };

    public static IReadOnlyList<string> AllPaths { get; } = Products
        .SelectMany(p => p.Paths)
        .Distinct(StringComparer.Ordinal)
        .ToArray();

    public static IReadOnlyList<string> Titles { get; } = Products.Select(p => p.Title).ToArray();

    public static IReadOnlyList<Finding> Findings(
        IReadOnlyList<FileHit> hits,
        string? homepageHtml,
        IReadOnlyList<string> cookies,
        IReadOnlyDictionary<string, string>? headers)
    {
        return Products
            .Select(p => Summary(p, hits, homepageHtml, cookies, headers))
            .Where(f => f.State == FindingState.Attention)
            .ToArray();
    }

    public static Finding Summary(
        Product product,
        IReadOnlyList<FileHit> hits,
        string? homepageHtml,
        IReadOnlyList<string> cookies,
        IReadOnlyDictionary<string, string>? headers)
    {
        var live = hits
            .Where(h => product.Paths.Contains(h.Path, StringComparer.Ordinal) && AdvertisedMatch.PathLooksLike(h, product.HtmlNeedles))
            .Select(h => h.Path + " HTTP " + h.Status)
            .Take(8)
            .ToArray();

        var html = homepageHtml ?? "";
        var htmlHint = !AdvertisedMatch.IsGenericWebAppShell(html)
            && AdvertisedMatch.ContainsAny(html, product.HtmlNeedles);
        var cookieHint = cookies.Any(c =>
            product.CookiePrefixes.Any(p => c.StartsWith(p, StringComparison.OrdinalIgnoreCase)));
        var headerHint = false;
        if (headers != null)
        {
            foreach (var name in product.HeaderNames)
            {
                if (headers.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value))
                {
                    if (name.Equals("Server", StringComparison.OrdinalIgnoreCase)
                        && value.IndexOf("BigIP", StringComparison.OrdinalIgnoreCase) < 0
                        && value.IndexOf("BIG-IP", StringComparison.OrdinalIgnoreCase) < 0)
                    {
                        continue;
                    }
                    headerHint = true;
                    break;
                }
            }
        }

        if (live.Length == 0 && !htmlHint && !cookieHint && !headerHint)
        {
            return new Finding(
                product.Title,
                FindingState.Present,
                "No common public " + product.Title + " paths answered, and the homepage did not advertise that product.",
                "GET allowlisted " + product.Title + " paths on the same public address, redirects disabled. Homepage HTML, cookies, and headers were also read.",
                "A renamed URL is not found this way. Absence is not clearance for other products.");
        }

        var bits = new List<string>();
        if (live.Length > 0) bits.Add("Paths: " + string.Join("; ", live));
        if (htmlHint) bits.Add("Homepage HTML named " + product.Title + ".");
        if (cookieHint) bits.Add("A " + product.Title + " cookie name was present.");
        if (headerHint) bits.Add("A " + product.Title + " response header was present.");

        return new Finding(
            product.Title,
            FindingState.Attention,
            "This hostname advertised internet-facing " + product.Title + ". " + string.Join(" ", bits) + " "
                + product.CveLine + " Confirm the vendor patch is installed. A WAF rule alone is not the patch.",
            "GET allowlisted " + product.Title + " paths. No POST and no exploit payload. Version is taken only if the public surface named it.",
            "This is not proof the host is unpatched and not proof of access. Rampart does not send exploit traffic.");
    }

    public static string AdviceBody(string title)
    {
        var p = Products.FirstOrDefault(x => x.Title.Equals(title, StringComparison.OrdinalIgnoreCase));
        if (p is null) return "Internet-facing " + title + " was advertised. Install the vendor patch named on the card. A WAF rule is not the patch. Rampart does not send exploit traffic.";
        return "Internet-facing " + p.Title + " was advertised. " + p.PatchLine + " Rampart does not send exploit traffic.";
    }

    public static IReadOnlyList<FixLine>? FixLines(string related)
    {
        var p = Products.FirstOrDefault(x => x.Title.Equals(related, StringComparison.OrdinalIgnoreCase));
        if (p is null) return null;
        return new[]
        {
            new FixLine("When to do this: " + p.WhenTo),
            new FixLine("When not to: those paths 404 and the homepage does not name this product. Then Rampart does not show this card."),
            new FixLine(p.PatchLine),
            new FixLine(p.VendorLabel, p.VendorUrl),
            new FixLine("CISA Known Exploited Vulnerabilities catalogue:", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
            new FixLine("Take this portal off the public internet if it does not need to be there. Rampart does not send exploit traffic and cannot see whether the patch is installed."),
        };
    }
}
