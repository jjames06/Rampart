/**
 * CODEMAP FILE: tools/build-advisories.mjs
 * Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
 * Role: Release-time builder for data/advisories.json from Retire.js jsrepository.json and GitHub Advisory npm packages (next, react, vue, …).
 * Called by: Human/CI before publish: node tools/build-advisories.mjs from repo root.
 * Calls: HTTPS GET to Retire.js raw + GitHub Advisory API at build time only.
 * Invariants: Runtime Rampart never runs this. Do not add Cloudflare Radar (CC BY-NC). WordPress core ranges only when a version is advertised.
 * Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
 * Map: docs/CODEMAP.md — read that file first for the run/load graph.
 */
/**
 * Builds data/advisories.json from:
 * - Retire.js jsrepository.json (Apache-2.0) for JavaScript libraries
 * - GitHub Advisory API for npm packages this checker can actually see on a
 *   public homepage or in Server / X-Powered-By / generator (next, react, vue,
 *   jquery, bootstrap, lodash, axios, svelte, angular, and peers)
 *
 * Run from the repository root: node tools/build-advisories.mjs
 * The resulting file is shipped inside SiteCheck.exe. Runtime checks do not
 * call NVD, GitHub, or Retire.js.
 */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outPath = join(root, "data", "advisories.json");

const RETIRE_URL =
  "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json";
const GHSA_NPM = [
  ["next", "Next.js"],
  ["react", "React"],
  ["react-dom", "React"],
  ["vue", "Vue.js"],
  ["nuxt", "Nuxt"],
  ["jquery", "jQuery"],
  ["bootstrap", "Bootstrap"],
  ["lodash", "Lodash"],
  ["axios", "axios"],
  ["svelte", "svelte"],
  ["handlebars", "Handlebars"],
  ["ember-source", "Ember.js"],
  ["@angular/core", "@angular/core"],
  ["moment", "moment.js"],
  ["marked", "marked"],
  ["dompurify", "DOMPurify"],
  ["tinymce", "tinyMCE"],
  ["underscore", "underscore.js"],
  ["three", "threejs"],
];

function displayName(key, rec) {
  if (key === "jquery") return "jQuery";
  if (key === "jquery-migrate") return "jQuery Migrate";
  if (key === "jquery-ui") return "jQuery UI";
  if (key === "angularjs") return "AngularJS";
  if (key === "angular") return "Angular";
  if (key === "bootstrap") return "Bootstrap";
  if (key === "lodash") return "Lodash";
  if (key === "moment") return "Moment.js";
  if (key === "handlebars") return "Handlebars";
  if (key === "backbone") return "Backbone.js";
  if (key === "ember") return "Ember.js";
  if (key === "vue") return "Vue.js";
  if (key === "react") return "React";
  if (key === "next") return "Next.js";
  if (rec?.npmname === "next") return "Next.js";
  return key;
}

function retireVulns(rec) {
  const list = rec.vulnerabilities || [];
  const out = [];
  for (const v of list) {
    const ids = v.identifiers || {};
    const id =
      (Array.isArray(ids.CVE) && ids.CVE[0]) ||
      ids.githubID ||
      ids.bug ||
      ids.issue ||
      ids.retid ||
      null;
    if (!id) continue;
    const summary = (ids.summary || rec.summary || String(id)).replace(/\s+/g, " ").trim();
    const info = Array.isArray(v.info) ? v.info : [];
    const source =
      info.find((u) => typeof u === "string" && u.includes("github.com/advisories")) ||
      info.find((u) => typeof u === "string" && u.includes("nvd.nist.gov")) ||
      info[0] ||
      "https://github.com/RetireJS/retire.js";
    const ranges = [];
    if (Array.isArray(v.ranges)) {
      for (const r of v.ranges) {
        ranges.push({ atOrAbove: r.atOrAbove || null, below: r.below || null });
      }
    } else {
      ranges.push({ atOrAbove: v.atOrAbove || null, below: v.below || null });
    }
    out.push({
      id: String(id),
      summary: summary.slice(0, 280),
      source: String(source).slice(0, 200),
      severity: v.severity || null,
      ranges,
    });
  }
  return out;
}

function extractors(rec) {
  const ex = rec.extractors || {};
  const uri = [...(ex.uri || []), ...(ex.filename || [])]
    .filter((s) => typeof s === "string" && s.includes("§§version§§"))
    .slice(0, 8);
  return uri;
}

async function fetchJson(url, headers = {}) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const res = await fetch(url, {
    headers: {
      "User-Agent": "operation-locked-in-site-check-advisory-build",
      Accept: "application/vnd.github+json",
      ...(token ? { Authorization: "Bearer " + token } : {}),
      ...headers,
    },
  });
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return { json: await res.json(), res };
}

function parseGhsaRange(range) {
  // ">= 16.0.0, < 16.3.3"
  if (!range || typeof range !== "string") return [];
  const parts = range.split(",").map((s) => s.trim()).filter(Boolean);
  const constraints = [];
  for (const p of parts) {
    const m = p.match(/^(>=|<=|>|<|=)\s*([0-9][0-9A-Za-z.+\-]*)/);
    if (m) constraints.push({ op: m[1], version: m[2] });
  }
  return constraints;
}

async function ghsaNpm(pkg, display) {
  const vulns = [];
  let url =
    "https://api.github.com/advisories?ecosystem=npm&affects=" +
    encodeURIComponent(pkg) +
    "&per_page=100";
  for (let page = 0; page < 4 && url; page++) {
    const { json, res } = await fetchJson(url);
    const items = Array.isArray(json) ? json : [];
    for (const adv of items) {
      if (adv.withdrawn_at) continue;
      const id = adv.ghsa_id || (adv.identifiers || []).find((i) => i.type === "GHSA")?.value;
      if (!id) continue;
      const ranges = [];
      for (const vul of adv.vulnerabilities || []) {
        if (vul.package?.name !== pkg) continue;
        const constraints = parseGhsaRange(vul.vulnerable_version_range);
        if (constraints.length) ranges.push({ constraints });
      }
      if (ranges.length === 0) continue;
      vulns.push({
        id,
        summary: String(adv.summary || id).replace(/\s+/g, " ").trim().slice(0, 280),
        source: adv.html_url || `https://github.com/advisories/${id}`,
        severity: adv.severity || null,
        ranges,
      });
    }
    const link = res.headers.get("link") || "";
    const next = link.match(/<([^>]+)>;\s*rel="next"/);
    url = next ? next[1] : null;
  }
  return {
    name: display,
    aliases: [pkg, display],
    extractors: [],
    vulns,
  };
}

async function ghsaWordpress() {
  const vulns = [];
  let url = "https://api.github.com/advisories?search=wordpress&type=reviewed&per_page=100";
  try {
    for (let page = 0; page < 3 && url; page++) {
      const { json, res } = await fetchJson(url);
      const items = Array.isArray(json) ? json : [];
      for (const adv of items) {
        if (adv.withdrawn_at) continue;
        const id = adv.ghsa_id;
        if (!id) continue;
        const ranges = [];
        for (const vul of adv.vulnerabilities || []) {
          const name = String(vul.package?.name || "").toLowerCase();
          if (name !== "wordpress" && name !== "wordpress/wordpress") continue;
          const constraints = parseGhsaRange(vul.vulnerable_version_range);
          if (constraints.length) ranges.push({ constraints });
        }
        if (ranges.length === 0) continue;
        vulns.push({
          id,
          summary: String(adv.summary || id).replace(/\s+/g, " ").trim().slice(0, 280),
          source: adv.html_url || `https://github.com/advisories/${id}`,
          severity: adv.severity || null,
          ranges,
        });
      }
      const link = res.headers.get("link") || "";
      const next = link.match(/<([^>]+)>;\s*rel="next"/);
      url = next ? next[1] : null;
    }
  } catch (err) {
    console.error("WordPress GHSA fetch failed:", err.message);
  }
  if (vulns.length === 0) return [];
  return [
    {
      name: "WordPress",
      aliases: ["WordPress", "wordpress"],
      extractors: [],
      vulns,
    },
  ];
}

const extras = [
  {
    name: "PHP",
    aliases: ["PHP"],
    extractors: [],
    vulns: [
      {
        id: "PHP-EOL",
        summary:
          "PHP 5, 7, 8.0, and 8.1 are past end of life. Public CVE volume on those lines is large. Move to a currently supported PHP 8.2 or later release from php.net.",
        source: "https://www.php.net/supported-versions.php",
        severity: "high",
        ranges: [{ atOrAbove: "5.0.0", below: "8.2.0" }],
      },
    ],
  },
  {
    name: "WordPress",
    aliases: ["WordPress", "wordpress"],
    extractors: [],
    vulns: [
      {
        id: "CVE-2026-87902",
        summary:
          "WordPress core page-template resolution could include a chosen local PHP file (GHSA-7hp8-65ch-5whp). CISA lists this as known exploited. Upgrade to the patched branch (7.1.2, 7.0.6, 6.9.9, or the matching older-branch floor). This is a prompt from an advertised generator version, not RCE proof.",
        source: "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp",
        severity: "critical",
        ranges: [
          ["4.7.0", "4.7.37"], ["4.8.0", "4.8.32"], ["4.9.0", "4.9.33"],
          ["5.0.0", "5.0.29"], ["5.1.0", "5.1.26"], ["5.2.0", "5.2.28"],
          ["5.3.0", "5.3.25"], ["5.4.0", "5.4.23"], ["5.5.0", "5.5.22"],
          ["5.6.0", "5.6.21"], ["5.7.0", "5.7.19"], ["5.8.0", "5.8.17"],
          ["5.9.0", "5.9.18"], ["6.0.0", "6.0.16"], ["6.1.0", "6.1.14"],
          ["6.2.0", "6.2.13"], ["6.3.0", "6.3.12"], ["6.4.0", "6.4.12"],
          ["6.5.0", "6.5.12"], ["6.6.0", "6.6.9"], ["6.7.0", "6.7.9"],
          ["6.8.0", "6.8.10"], ["6.9.0", "6.9.9"], ["7.0.0", "7.0.6"],
          ["7.1.0", "7.1.2"],
        ].map(([atOrAbove, below]) => ({ atOrAbove, below })),
      },
    ],
  },
  {
    name: "Oracle PeopleSoft",
    aliases: ["Oracle PeopleSoft", "PeopleSoft", "PeopleTools"],
    extractors: [],
    vulns: [
      {
        id: "CVE-2026-35273",
        summary:
          "Oracle PeopleSoft Enterprise PeopleTools 8.61 and 8.62. Critical remote issue. Oracle published a patch in the June 2026 Critical Patch Update. CISA added this CVE to the Known Exploited Vulnerabilities catalogue. A WAF workaround is not the patch.",
        source: "https://nvd.nist.gov/vuln/detail/CVE-2026-35273",
        severity: "critical",
        ranges: [
          { constraints: [{ op: ">=", version: "8.61.0" }, { op: "<", version: "8.63.0" }] },
        ],
      },
    ],
  },
  {
    name: "Next.js",
    aliases: ["Next.js", "next"],
    extractors: [],
    vulns: [
      {
        id: "GHSA-vcvr-r3jv-pc5j",
        summary:
          "Next.js 16.2.0 through 16.3.5 Node ImageResponse can lead to remote code execution when untrusted input is rendered. 15.x is not in that RCE range. Floor is 16.3.6.",
        source: "https://github.com/vercel/next.js/security/advisories/GHSA-vcvr-r3jv-pc5j",
        severity: "critical",
        ranges: [{ constraints: [{ op: ">=", version: "16.2.0" }, { op: "<", version: "16.3.6" }] }],
      },
    ],
  },
];

function mergeProducts(products) {
  const map = new Map();
  for (const p of products) {
    const key = String(p.name).toLowerCase();
    if (!map.has(key)) {
      map.set(key, {
        name: p.name,
        aliases: [...new Set(p.aliases || [])],
        extractors: [...(p.extractors || [])],
        vulns: [...(p.vulns || [])],
      });
      continue;
    }
    const e = map.get(key);
    e.aliases = [...new Set([...e.aliases, ...(p.aliases || [])])];
    e.extractors = [...new Set([...e.extractors, ...(p.extractors || [])])];
    const seen = new Set(e.vulns.map((v) => v.id));
    for (const v of p.vulns || []) {
      if (!seen.has(v.id)) {
        seen.add(v.id);
        e.vulns.push(v);
      }
    }
  }
  return [...map.values()];
}

const retire = await fetchJson(RETIRE_URL);
const jsRepo = retire.json;
const jsProducts = [];
for (const [key, rec] of Object.entries(jsRepo)) {
  if (key === "retire-example") continue;
  const vulns = retireVulns(rec);
  const ex = extractors(rec);
  if (vulns.length === 0) continue;
  jsProducts.push({
    name: displayName(key, rec),
    aliases: [key, displayName(key, rec), rec.npmname].filter(Boolean),
    extractors: ex,
    vulns,
  });
}

const ghsaProducts = [];
for (const [pkg, display] of GHSA_NPM) {
  try {
    ghsaProducts.push(await ghsaNpm(pkg, display));
  } catch (err) {
    console.error("GHSA fetch failed for", pkg, err.message);
  }
}
try {
  ghsaProducts.push(...(await ghsaWordpress()));
} catch (err) {
  console.error("WordPress GHSA failed:", err.message);
}

const file = {
  built: new Date().toISOString().slice(0, 10),
  sources: [
    "https://github.com/RetireJS/retire.js (Apache-2.0 jsrepository.json)",
    "https://github.com/advisories (GitHub Advisory Database: npm packages this checker can fingerprint on a public homepage, plus WordPress core when the generator names a version)",
  ],
  products: mergeProducts([...jsProducts, ...ghsaProducts, ...extras]),
};

writeFileSync(outPath, JSON.stringify(file));
const nVuln = file.products.reduce((n, p) => n + p.vulns.length, 0);
console.log(
  `Wrote ${outPath} (${Math.round(Buffer.byteLength(JSON.stringify(file)) / 1024)} KB, ${file.products.length} products, ${nVuln} advisories, built ${file.built})`
);
