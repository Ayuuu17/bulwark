"""Browser security headers and server information leaks."""

import re

from ..fixes import header_snippets
from ..models import Finding, Report, Severity
from .context import ScanContext

RECOMMENDED_CSP = (
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
)
HSTS_VALUE = "max-age=31536000; includeSubDomains"
SIX_MONTHS = 15_552_000


def parse_csp(value: str) -> dict[str, list[str]]:
    directives = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def check_hsts(ctx: ScanContext, report: Report) -> None:
    if not ctx.is_https:
        return  # browsers ignore HSTS over plain HTTP; the transport check covers this
    value = ctx.primary.headers.get("strict-transport-security")
    if not value:
        report.add(Finding(
            id="hsts-missing",
            title="Strict-Transport-Security (HSTS) header is missing",
            severity=Severity.MEDIUM,
            category="Security headers",
            description="Your site doesn't tell browsers to always use HTTPS.",
            impact="A user's very first request (or any typed http:// link) can be downgraded to plain HTTP by an "
                   "attacker on the network, who can then steal cookies or inject content.",
            fix=f"Send `Strict-Transport-Security: {HSTS_VALUE}` on every HTTPS response. Only add includeSubDomains "
                "if all your subdomains support HTTPS.",
            snippets=header_snippets("Strict-Transport-Security", HSTS_VALUE),
            references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"],
        ))
        return
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    max_age = int(match.group(1)) if match else 0
    if max_age < SIX_MONTHS:
        report.add(Finding(
            id="hsts-short",
            title="HSTS max-age is too short",
            severity=Severity.LOW,
            category="Security headers",
            description=f"HSTS is enabled, but only for {max_age} seconds.",
            evidence=f"Strict-Transport-Security: {value}",
            impact="Protection lapses quickly, so returning visitors can be downgraded to HTTP again.",
            fix="Use a max-age of at least 6 months; one year (31536000) is the common choice.",
            snippets=header_snippets("Strict-Transport-Security", HSTS_VALUE),
        ))
    else:
        report.ok("HSTS is enabled")


def check_csp(ctx: ScanContext, report: Report) -> dict[str, list[str]]:
    headers = ctx.primary.headers
    value = headers.get("content-security-policy")
    if not value:
        report_only = headers.get("content-security-policy-report-only")
        report.add(Finding(
            id="csp-missing" if not report_only else "csp-report-only",
            title="Content-Security-Policy header is missing" if not report_only
                  else "Content-Security-Policy is only in report-only mode",
            severity=Severity.MEDIUM if not report_only else Severity.LOW,
            category="Security headers",
            description="Browsers aren't told which scripts are allowed to run on your pages."
                        if not report_only else "Violations are reported but nothing is actually blocked.",
            impact="CSP is the main safety net against cross-site scripting (XSS): if an attacker manages to inject "
                   "a script, a good policy stops it from running or sending data out.",
            fix="Start with a strict policy, test it in report-only mode, then enforce it. Allow-list only the "
                "domains you actually load scripts from.",
            snippets=header_snippets("Content-Security-Policy", RECOMMENDED_CSP),
            references=["https://developer.mozilla.org/docs/Web/HTTP/CSP", "https://csp-evaluator.withgoogle.com/"],
        ))
        return {}

    directives = parse_csp(value)
    scripts = directives.get("script-src", directives.get("default-src", []))
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in scripts)
    problems = []
    if "'unsafe-inline'" in scripts and not has_nonce_or_hash:
        problems.append("'unsafe-inline' lets any injected <script> run")
    if "'unsafe-eval'" in scripts:
        problems.append("'unsafe-eval' allows eval() and similar")
    if any(s in ("*", "http:", "https:", "data:") for s in scripts):
        problems.append("a wildcard/scheme source lets scripts load from anywhere")
    if not scripts:
        problems.append("no script-src or default-src, so scripts aren't restricted at all")

    if problems:
        report.add(Finding(
            id="csp-weak",
            title="Content-Security-Policy allows unsafe scripts",
            severity=Severity.MEDIUM if "'unsafe-inline'" in scripts or not scripts else Severity.LOW,
            category="Security headers",
            description="Your CSP exists but has gaps: " + "; ".join(problems) + ".",
            evidence=f"Content-Security-Policy: {value}",
            impact="These gaps undo most of the XSS protection a CSP is meant to give.",
            fix="Move inline scripts into .js files (or use nonces/hashes), drop 'unsafe-eval', and list specific "
                "domains instead of wildcards.",
            snippets=header_snippets("Content-Security-Policy", RECOMMENDED_CSP),
            references=["https://csp-evaluator.withgoogle.com/"],
        ))
    else:
        report.ok("Content-Security-Policy restricts scripts")
    return directives


def check_simple_headers(ctx: ScanContext, report: Report, csp: dict[str, list[str]]) -> None:
    headers = ctx.primary.headers

    xfo = (headers.get("x-frame-options") or "").strip().upper()
    if xfo in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp:
        report.ok("Clickjacking protection (frame-ancestors / X-Frame-Options)")
    else:
        report.add(Finding(
            id="clickjacking",
            title="Pages can be embedded by other sites (clickjacking)",
            severity=Severity.MEDIUM,
            category="Security headers",
            description="Neither X-Frame-Options nor CSP frame-ancestors is set.",
            impact="An attacker can load your site in an invisible frame and trick users into clicking buttons "
                   "(e.g. \"delete account\", \"transfer\") while they think they're clicking something else.",
            fix="Send `X-Frame-Options: SAMEORIGIN` (or `DENY`), and/or `frame-ancestors 'self'` in your CSP.",
            snippets=header_snippets("X-Frame-Options", "SAMEORIGIN"),
        ))

    if (headers.get("x-content-type-options") or "").strip().lower() == "nosniff":
        report.ok("X-Content-Type-Options: nosniff")
    else:
        report.add(Finding(
            id="nosniff-missing",
            title="X-Content-Type-Options header is missing",
            severity=Severity.LOW,
            category="Security headers",
            description="Browsers may guess (\"sniff\") file types instead of trusting the declared type.",
            impact="An uploaded file that looks like HTML or JavaScript could be executed as code.",
            fix="Send `X-Content-Type-Options: nosniff` on every response.",
            snippets=header_snippets("X-Content-Type-Options", "nosniff"),
        ))

    referrer = (headers.get("referrer-policy") or "").strip().lower()
    if referrer and "unsafe-url" not in referrer:
        report.ok("Referrer-Policy is set")
    else:
        report.add(Finding(
            id="referrer-policy",
            title="Referrer-Policy is missing or unsafe",
            severity=Severity.LOW,
            category="Security headers",
            description="Full page URLs may be sent to other sites when users click links.",
            evidence=f"Referrer-Policy: {referrer}" if referrer else "",
            impact="URLs often contain private data (reset tokens, search terms, IDs) that then leaks to third parties.",
            fix="Send `Referrer-Policy: strict-origin-when-cross-origin`.",
            snippets=header_snippets("Referrer-Policy", "strict-origin-when-cross-origin"),
        ))

    if headers.get("permissions-policy"):
        report.ok("Permissions-Policy is set")
    else:
        report.add(Finding(
            id="permissions-policy",
            title="Permissions-Policy header is missing",
            severity=Severity.INFO,
            category="Security headers",
            description="You aren't limiting which browser features (camera, microphone, location…) pages can use.",
            impact="If a third-party script or injected code runs on your page, it can ask for these permissions.",
            fix="Turn off features you don't use.",
            snippets=header_snippets("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        ))


def check_disclosure(ctx: ScanContext, report: Report) -> None:
    headers = ctx.primary.headers
    leaks = []
    server = headers.get("server", "")
    if re.search(r"\d", server):
        leaks.append(f"Server: {server}")
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        if headers.get(name):
            leaks.append(f"{name.title()}: {headers[name]}")
    if not leaks:
        report.ok("No server version details in headers")
        return
    report.add(Finding(
        id="version-disclosure",
        title="Server software and versions are exposed",
        severity=Severity.LOW,
        category="Information disclosure",
        description="Response headers reveal what software (and which versions) you run.",
        evidence="\n".join(leaks),
        impact="Attackers use this to look up known vulnerabilities for your exact versions. Hiding it doesn't "
               "fix anything by itself, but it stops you from advertising targets.",
        fix="Turn off version banners, and keep the underlying software updated.",
        snippets={
            "Nginx": "# http { } block\nserver_tokens off;",
            "Apache": "ServerTokens Prod\nServerSignature Off",
            "Express": "app.disable('x-powered-by');\n// or: app.use(require('helmet')())",
            "PHP": "; php.ini\nexpose_php = Off",
            "ASP.NET": (
                "<!-- web.config -->\n<system.web><httpRuntime enableVersionHeader=\"false\" /></system.web>\n"
                "<system.webServer><httpProtocol><customHeaders>\n"
                "  <remove name=\"X-Powered-By\" />\n</customHeaders></httpProtocol></system.webServer>"
            ),
        },
    ))


async def check(ctx: ScanContext, report: Report) -> None:
    check_hsts(ctx, report)
    csp = check_csp(ctx, report)
    check_simple_headers(ctx, report, csp)
    check_disclosure(ctx, report)
