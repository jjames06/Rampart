# CODEMAP FILE: tools/publish-wiki.ps1
# Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
# Role: Push docs/wiki/* to the GitHub wiki remote.
# Called by: Operator after handbook edits.
# Calls: git clone of the .wiki repo.
# Invariants: Wiki is a separate git remote. Do not put secrets in handbook pages.
# Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
# Map: docs/CODEMAP.md — read that file first for the run/load graph.
# Publish docs/wiki to the GitHub Wiki remote.
# GitHub creates owner/repo.wiki.git only after the first page exists in the website UI.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $root "docs\wiki\Home.md"))) {
    throw "docs/wiki/Home.md not found."
}

$wikiDir = Join-Path $env:TEMP "Rampart.wiki-publish"
if (Test-Path $wikiDir) { Remove-Item $wikiDir -Recurse -Force }

$remote = "https://github.com/jjames06/Rampart.wiki.git"
try {
    git clone $remote $wikiDir
} catch {
    throw @"
Could not clone the wiki remote.
Open https://github.com/jjames06/Rampart/wiki and click Create the first page
(title: Home, any short body), Save once. Then re-run this script.
"@
}

$pages = @(
    "Home.md",
    "How-to-use.md",
    "What-is-checked.md",
    "Lawful-use.md",
    "Licence.md",
    "Privacy.md",
    "_Sidebar.md",
    "_Footer.md"
)
foreach ($p in $pages) {
    Copy-Item (Join-Path $root "docs\wiki\$p") (Join-Path $wikiDir $p) -Force
}

Push-Location $wikiDir
try {
    git config user.email "jjames06@users.noreply.github.com"
    git config user.name "jjames06"
    git add $pages
    if (git status --porcelain) {
        git commit -m "Sync Rampart 1.9.0 handbook from docs/wiki"
        git push
        Write-Host "Wiki published: https://github.com/jjames06/Rampart/wiki"
    } else {
        Write-Host "Wiki already up to date."
    }
} finally {
    Pop-Location
}
