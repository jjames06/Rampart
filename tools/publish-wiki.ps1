# Publish docs/wiki to the GitHub Wiki remote.
# GitHub creates owner/repo.wiki.git only after the first page exists in the website UI.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $root "docs\wiki\Home.md"))) {
    throw "docs/wiki/Home.md not found."
}

$wikiDir = Join-Path $env:TEMP "oli-site-check.wiki-publish"
if (Test-Path $wikiDir) { Remove-Item $wikiDir -Recurse -Force }

$remote = "https://github.com/jjames06/oli-site-check.wiki.git"
try {
    git clone $remote $wikiDir
} catch {
    throw @"
Could not clone the wiki remote.
Open https://github.com/jjames06/oli-site-check/wiki and click Create the first page
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
        Write-Host "Wiki published: https://github.com/jjames06/oli-site-check/wiki"
    } else {
        Write-Host "Wiki already up to date."
    }
} finally {
    Pop-Location
}
