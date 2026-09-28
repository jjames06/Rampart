/**
 * Builds data/advisories.json from:
 * - Retire.js jsrepository.json (Apache-2.0) for JavaScript libraries
 * - GitHub Advisory API for npm package "next"
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
const GHSA_NEXT =
  "https://api.github.com/advisories?ecosystem=npm&affects=next&per_page=100";

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
  const res = await fetch(url, {
    headers: {
      "User-Agent": "operation-locked-in-site-check-advisory-build",
      Accept: "application/json",
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

async function ghsaNext() {
  const products = [];
  const vulns = [];
  let url = GHSA_NEXT;
  for (let page = 0; page < 5 && url; page++) {
    const { json, res } = await fetchJson(url);
    const items = Array.isArray(json) ? json : [];
    for (const adv of items) {
      if (adv.withdrawn_at) continue;
      const id = adv.ghsa_id || (adv.identifiers || []).find((i) => i.type === "GHSA")?.value;
      if (!id) continue;
      const ranges = [];
      for (const vul of adv.vulnerabilities || []) {
        if (vul.package?.name !== "next") continue;
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
  products.push({
    name: "Next.js",
    aliases: ["next", "Next.js"],
    extractors: [],
    vulns,
  });
  return products;
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
          "PHP 5 and 7.x are past end of life. Public CVE volume on those lines is large. Move to a currently supported PHP 8 release from php.net.",
        source: "https://www.php.net/supported-versions.php",
        severity: "high",
        ranges: [{ atOrAbove: "5.0.0", below: "8.0.0" }],
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

let nextProducts = [];
try {
  nextProducts = await ghsaNext();
} catch (err) {
  console.error("GHSA fetch failed, continuing with Retire.js only:", err.message);
}

const file = {
  built: new Date().toISOString().slice(0, 10),
  sources: [
    "https://github.com/RetireJS/retire.js (Apache-2.0 jsrepository.json)",
    "https://github.com/advisories (GitHub Advisory Database, npm package next)",
  ],
  products: mergeProducts([...jsProducts, ...nextProducts, ...extras]),
};

writeFileSync(outPath, JSON.stringify(file));
const nVuln = file.products.reduce((n, p) => n + p.vulns.length, 0);
console.log(
  `Wrote ${outPath} (${Math.round(Buffer.byteLength(JSON.stringify(file)) / 1024)} KB, ${file.products.length} products, ${nVuln} advisories, built ${file.built})`
);
