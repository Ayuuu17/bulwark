"""What the page itself loads: mixed content, insecure forms, SRI, outdated JS libraries."""

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

from .. import osv
from ..models import Finding, Report, Severity
from .context import ScanContext

VERSION = r"(?P<version>\d+\.\d+(?:\.\d+)?)"
KNOWN_LIBS = "jquery|jquery-ui|bootstrap|angular|lodash|moment|vue|react|react-dom|handlebars|underscore|knockout|dompurify"
LIBRARY_PATTERNS = [
    re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/(?P<name>[^/]+)/" + VERSION + r"/"),
    re.compile(r"(?:cdn\.jsdelivr\.net/npm|unpkg\.com)/(?P<name>(?:@[^/@]+/)?[^/@]+)@" + VERSION),
    re.compile(r"ajax\.googleapis\.com/ajax/libs/(?P<name>[^/]+)/" + VERSION + r"/"),
    re.compile(r"code\.jquery\.com/(?P<name>jquery(?:-ui)?)-" + VERSION),
    re.compile(r"/(?P<name>" + KNOWN_LIBS + r")[.-]" + VERSION + r"(?:[.-]min)?\.js", re.I),
    re.compile(r"/(?P<name>" + KNOWN_LIBS + r")(?:\.min)?\.js\?ver=" + VERSION, re.I),
]
CDN_NAME_TO_NPM = {
    "angular.js": "angular",
    "angularjs": "angular",
    "twitter-bootstrap": "bootstrap",
    "jqueryui": "jquery-ui",
    "lodash.js": "lodash",
    "moment.js": "moment",
    "underscore.js": "underscore",
    "handlebars.js": "handlebars",
    "knockout": "knockout",
}

SRI_SNIPPETS = {
    "HTML": '<script src="https://cdn.example.com/lib.min.js"\n'
            '        integrity="sha384-…hash from the CDN…"\n'
            '        crossorigin="anonymous"></script>',
    "Generate a hash": "curl -s https://cdn.example.com/lib.min.js | openssl dgst -sha384 -binary | openssl base64 -A",
}


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts: list[dict] = []
        self.styles: list[dict] = []
        self.iframes: list[str] = []
        self.media: list[str] = []
        self.forms: list[str] = []
        self.password_fields = 0

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.scripts.append(a)
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower() and a.get("href"):
            self.styles.append(a)
        elif tag == "iframe" and a.get("src"):
            self.iframes.append(a["src"])
        elif tag in ("img", "audio", "video", "source") and a.get("src"):
            self.media.append(a["src"])
        elif tag == "form":
            self.forms.append(a.get("action", ""))
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.password_fields += 1


def detect_libraries(script_urls: list[str]) -> list[osv.Package]:
    found = {}
    for url in script_urls:
        for pattern in LIBRARY_PATTERNS:
            match = pattern.search(url)
            if not match:
                continue
            name = match.group("name").lower()
            name = CDN_NAME_TO_NPM.get(name, name)
            version = match.group("version")
            if version.count(".") == 1:
                version += ".0"
            found[(name, version)] = osv.Package(name, version, "npm")
            break
    return list(found.values())


async def check(ctx: ScanContext, report: Report) -> None:
    page = _PageParser()
    try:
        page.feed(ctx.primary.body)
    except Exception:
        pass  # malformed HTML: use whatever was parsed
    base = ctx.primary.url
    page_host = urlsplit(base).hostname

    def absolute(urls):
        return [urljoin(base, u) for u in urls]

    script_urls = absolute(s["src"] for s in page.scripts)
    style_urls = absolute(s["href"] for s in page.styles)

    if ctx.is_https:
        active = [u for u in script_urls + style_urls + absolute(page.iframes) if u.startswith("http://")]
        passive = [u for u in absolute(page.media) if u.startswith("http://")]
        if active or passive:
            report.add(Finding(
                id="mixed-content",
                title="Page loads resources over insecure HTTP (mixed content)",
                severity=Severity.MEDIUM if active else Severity.LOW,
                category="Page content",
                description="Your HTTPS page pulls in files over plain HTTP.",
                evidence="\n".join((active + passive)[:15]),
                impact="Scripts/styles loaded over HTTP can be swapped by an attacker on the network, giving them "
                       "control of the page. Browsers block many of these, which can also break your site.",
                fix="Change these URLs to https:// (or make them relative). As a safety net you can add "
                    "`upgrade-insecure-requests` to your CSP.",
                snippets={"CSP": "Content-Security-Policy: upgrade-insecure-requests"},
            ))
        else:
            report.ok("No mixed content on the page")

    insecure_forms = [a for a in absolute(page.forms) if a.startswith("http://")]
    if page.password_fields and not ctx.is_https:
        report.add(Finding(
            id="password-over-http",
            title="Password field on an unencrypted page",
            severity=Severity.HIGH,
            category="Page content",
            description="This page asks for a password but isn't served over HTTPS.",
            impact="Passwords typed here can be read by anyone on the same network.",
            fix="Serve the whole site, and especially log-in pages, over HTTPS.",
        ))
    elif insecure_forms:
        report.add(Finding(
            id="insecure-form-action",
            title="Form submits data over plain HTTP",
            severity=Severity.HIGH if page.password_fields else Severity.MEDIUM,
            category="Page content",
            description="A form on this page sends what users type to an http:// address.",
            evidence="\n".join(insecure_forms[:10]),
            impact="Everything submitted (including passwords if present) travels unencrypted.",
            fix="Point the form's action at an https:// URL (or a relative path).",
        ))

    third_party = [
        s for s in page.scripts + page.styles
        if (url := urljoin(base, s.get("src") or s.get("href")))
        and urlsplit(url).hostname not in (None, page_host)
        and not s.get("integrity")
    ]
    if third_party:
        report.add(Finding(
            id="no-sri",
            title="Third-party scripts/styles load without integrity checks (SRI)",
            severity=Severity.LOW,
            category="Page content",
            description="Files from other domains are loaded without an integrity hash.",
            evidence="\n".join(urljoin(base, s.get("src") or s.get("href")) for s in third_party[:15]),
            impact="If that CDN or domain is ever compromised, malicious code runs on your site with full access "
                   "to your users' sessions (this has happened to real CDNs).",
            fix="Add integrity and crossorigin attributes to pinned-version CDN files. (Skip SRI for scripts that "
                "change constantly, like analytics — instead limit them with your CSP.)",
            snippets=SRI_SNIPPETS,
        ))

    libraries = detect_libraries(script_urls)
    if not libraries:
        return
    try:
        vulnerable = await osv.lookup(libraries)
    except httpx.HTTPError:
        report.add(Finding(
            id="osv-unavailable",
            title="Couldn't check JavaScript libraries for known vulnerabilities",
            severity=Severity.INFO,
            category="Vulnerable library",
            description="The vulnerability database didn't respond. Try the scan again later.",
            evidence="\n".join(f"{p.name} {p.version}" for p in libraries),
            impact="Outdated libraries are one of the most common real-world weaknesses.",
            fix="Re-run the scan.",
        ))
        return
    for pkg, vulns in vulnerable.items():
        report.add(osv.finding_for(pkg, vulns, category="Vulnerable library", snippets={
            "npm": f"npm install {pkg.name}@{{version}}",
            "CDN": f"Update the <script> URL to use {pkg.name} version {{version}} (or newer), then re-test your site.",
        }))
    safe = [p for p in libraries if p not in vulnerable]
    if safe:
        report.ok("No known vulnerabilities in: " + ", ".join(f"{p.name} {p.version}" for p in safe))
