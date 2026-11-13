#!/usr/bin/env python3
"""Build the secskills website: shared chrome around pages/*.html -> _out/.

No dependencies. Run from anywhere: python3 site/build.py
"""
import html
import pathlib
import re
import shutil

SITE = pathlib.Path(__file__).resolve().parent
ROOT = SITE.parent
OUT = SITE / "_out"
REPO = "https://github.com/gleicon/secskills"

PAGES = [
    ("index", "Overview", "secskills", "One binary for authorized security assessment: discover, test, and report on a repo, a sandboxed build, or a live target."),
    ("install", "Install", "Install secskills", "Install with go install or a checksummed release binary, add optional tools, and connect Claude Code, opencode, or any MCP client."),
    ("usage", "Usage", "Using secskills", "Concepts, every command, test profiles, files, and environment variables."),
    ("cases", "Common cases", "Common cases", "Copy-paste recipes for code review, web app assessment, retests, CI export, network blocks, and offline capture."),
    ("safety", "Safety", "Safety model", "How secskills enforces authorization, stays non-destructive, and contains engagement data."),
]

VERSION = re.search(r'Version = "([^"]+)"', (ROOT / "version.go").read_text()).group(1)

FAVICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E"
           "%3Crect width='32' height='32' rx='6' fill='%231a2233'/%3E"
           "%3Crect x='7' y='14' width='18' height='5' fill='%23f4d35e'/%3E%3C/svg%3E")


def toc(body):
    items = re.findall(r'<h2 id="([^"]+)">(.*?)</h2>', body)
    if not items:
        return ""
    lis = "".join(f'<li><a href="#{i}">{re.sub("<[^>]+>", "", t)}</a></li>' for i, t in items)
    return f'<ul class="toc">{lis}</ul>'


def render(slug, label, title, desc, body, base=""):
    nav = []
    for s, l, _, _ in PAGES:
        href = "./" if s == "index" else f"{s}.html"
        cur = ' aria-current="page"' if s == slug else ""
        sub = toc(body) if s == slug else ""
        nav.append(f'<li><a href="{href}"{cur}>{l}</a>{sub}</li>')
    page_title = title if slug == "index" else f"{title} · secskills"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
{f'<base href="{base}">' if base else ""}
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(page_title)}</title>
<meta name="description" content="{html.escape(desc)}">
<link rel="icon" href="{FAVICON}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Fragment+Mono&family=Schibsted+Grotesk:wght@400;500;700&display=swap">
<link rel="stylesheet" href="style.css">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="bar">
  <a class="name" href="./">secskills</a>
  <span class="ver">v{VERSION}</span>
  <span class="ext"><a href="{REPO}/releases/latest">Download</a><a href="{REPO}">Source</a></span>
</header>
<div class="frame">
<nav class="pages" aria-label="Pages"><ul>{''.join(nav)}</ul></nav>
<main id="main">
{body.strip()}
</main>
</div>
<footer class="site">
  <p>secskills v{VERSION}. Code under MIT; the bundled OWASP knowledge base under CC BY-SA 4.0.</p>
  <p>Only test systems you have written authorization to test.</p>
</footer>
</body>
</html>
"""


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir()
    shutil.copy(SITE / "style.css", OUT / "style.css")
    for slug, label, title, desc in PAGES:
        body = (SITE / "pages" / f"{slug}.html").read_text().replace("{{VERSION}}", VERSION)
        (OUT / f"{slug}.html").write_text(render(slug, label, title, desc, body))
    (OUT / "404.html").write_text(render("404", "", "Not found", "Page not found.",
        '<h1>Not found</h1><p class="lede">That page does not exist. Start from the <a href="./">overview</a>.</p>',
        base="/secskills/"))
    print(f"built {len(PAGES) + 1} pages -> {OUT} (v{VERSION})")


if __name__ == "__main__":
    main()
