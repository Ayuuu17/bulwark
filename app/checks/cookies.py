"""Cookie flags (Secure, HttpOnly, SameSite) on cookies set without logging in."""

import re

from ..models import Finding, Report, Severity
from .context import ScanContext

SENSITIVE = re.compile(r"sess|sid|auth|token|jwt|login|remember|user", re.I)
READABLE_BY_DESIGN = re.compile(r"csrf|xsrf", re.I)  # frameworks read these from JS on purpose

COOKIE_SNIPPETS = {
    "Express": "res.cookie('session', value, { httpOnly: true, secure: true, sameSite: 'lax' });\n"
               "// express-session: cookie: { httpOnly: true, secure: true, sameSite: 'lax' }",
    "Django": "# settings.py\nSESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\n"
              "SESSION_COOKIE_SAMESITE = 'Lax'\nCSRF_COOKIE_SECURE = True",
    "Flask": "app.config.update(\n    SESSION_COOKIE_SECURE=True,\n    SESSION_COOKIE_HTTPONLY=True,\n"
             "    SESSION_COOKIE_SAMESITE='Lax',\n)",
    "PHP": "session_set_cookie_params([\n  'secure' => true,\n  'httponly' => true,\n  'samesite' => 'Lax',\n]);",
    "Nginx (proxy)": "# nginx >= 1.19.3, in the location that proxies your app\nproxy_cookie_flags ~ secure httponly samesite=lax;",
}


def parse_set_cookie(raw: str) -> tuple[str, dict[str, str]]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
    return name, attrs


async def check(ctx: ScanContext, report: Report) -> None:
    cookies = [parse_set_cookie(raw) for raw in ctx.primary.set_cookies]
    if not cookies:
        report.ok("No cookies set on first visit (log-in cookies aren't checked without an account)")
        return

    no_secure, no_httponly, no_samesite, none_insecure = [], [], [], []
    for name, attrs in cookies:
        sensitive = bool(SENSITIVE.search(name))
        samesite = attrs.get("samesite", "").lower()
        if ctx.is_https and "secure" not in attrs:
            no_secure.append((name, sensitive))
        if sensitive and "httponly" not in attrs and not READABLE_BY_DESIGN.search(name):
            no_httponly.append(name)
        if not samesite:
            no_samesite.append(name)
        elif samesite == "none" and "secure" not in attrs:
            none_insecure.append(name)

    if no_secure:
        any_sensitive = any(s for _, s in no_secure)
        report.add(Finding(
            id="cookie-no-secure",
            title="Cookies are missing the Secure flag",
            severity=Severity.HIGH if any_sensitive else Severity.MEDIUM,
            category="Cookies",
            description="These cookies can also be sent over unencrypted HTTP connections.",
            evidence=", ".join(name for name, _ in no_secure),
            impact="If a user ever loads an http:// URL on your domain, an attacker on the network can capture "
                   "these cookies — for session cookies that means taking over the account.",
            fix="Add the Secure attribute to every cookie on an HTTPS site.",
            snippets=COOKIE_SNIPPETS,
        ))
    if no_httponly:
        report.add(Finding(
            id="cookie-no-httponly",
            title="Session-like cookies are readable by JavaScript",
            severity=Severity.MEDIUM,
            category="Cookies",
            description="These look like session/auth cookies but don't have the HttpOnly flag.",
            evidence=", ".join(no_httponly),
            impact="If any script injection (XSS) happens, the attacker's code can read the cookie and hijack the "
                   "user's session.",
            fix="Add HttpOnly to any cookie your front-end JavaScript doesn't need to read.",
            snippets=COOKIE_SNIPPETS,
        ))
    if none_insecure:
        report.add(Finding(
            id="cookie-samesite-none-insecure",
            title="SameSite=None cookies without Secure",
            severity=Severity.MEDIUM,
            category="Cookies",
            description="Browsers reject SameSite=None cookies that aren't also marked Secure.",
            evidence=", ".join(none_insecure),
            impact="These cookies are silently dropped, which can break log-in or embedded features.",
            fix="Add Secure, or use SameSite=Lax if the cookie isn't needed in cross-site requests.",
            snippets=COOKIE_SNIPPETS,
        ))
    if no_samesite:
        report.add(Finding(
            id="cookie-no-samesite",
            title="Cookies don't set SameSite",
            severity=Severity.LOW,
            category="Cookies",
            description="Without an explicit SameSite value you rely on browser defaults, which differ.",
            evidence=", ".join(no_samesite),
            impact="SameSite is a key defence against cross-site request forgery (CSRF).",
            fix="Set SameSite=Lax on most cookies (Strict for highly sensitive ones).",
            snippets=COOKIE_SNIPPETS,
        ))
    if not (no_secure or no_httponly or no_samesite or none_insecure):
        report.ok(f"All {len(cookies)} cookie(s) have safe flags")
