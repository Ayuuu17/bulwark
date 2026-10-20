"""HTTPS availability, HTTP->HTTPS redirect, and TLS certificate health."""

import asyncio
import socket
import ssl
import time

from ..models import Finding, Report, Severity
from .context import ScanContext

HTTPS_SNIPPETS = {
    "Certbot (Nginx)": "sudo certbot --nginx -d example.com -d www.example.com",
    "Certbot (Apache)": "sudo certbot --apache -d example.com -d www.example.com",
    "Cloudflare": "Dashboard → SSL/TLS → Overview → set encryption mode to \"Full (strict)\"",
    "Vercel / Netlify": "HTTPS is automatic — make sure your custom domain's DNS points at the platform.",
}

REDIRECT_SNIPPETS = {
    "Nginx": (
        "server {\n"
        "    listen 80;\n"
        "    server_name example.com www.example.com;\n"
        "    return 301 https://$host$request_uri;\n"
        "}"
    ),
    "Apache": (
        "RewriteEngine On\n"
        "RewriteCond %{HTTPS} off\n"
        "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]"
    ),
    "Express": (
        "app.enable('trust proxy');\n"
        "app.use((req, res, next) => {\n"
        "  if (req.secure) return next();\n"
        "  res.redirect(301, 'https://' + req.headers.host + req.url);\n"
        "});"
    ),
    "Cloudflare": "Dashboard → SSL/TLS → Edge Certificates → turn on \"Always Use HTTPS\"",
}


def _tls_probe(ip: str, host: str, port: int) -> tuple[str, dict]:
    context = ssl.create_default_context()
    with socket.create_connection((ip, port), timeout=8) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.version() or "", tls.getpeercert()


async def check(ctx: ScanContext, report: Report) -> None:
    tls_port = ctx.port if ctx.port and ctx.scheme == "https" else (None if ctx.port else 443)

    if tls_port is None:
        report.add(Finding(
            id="https-not-used",
            title="Site is served over plain HTTP",
            severity=Severity.HIGH,
            category="Encryption",
            description=f"{ctx.target} uses http://, so traffic is not encrypted.",
            impact="Anyone on the same network (public Wi-Fi, ISP, a compromised router) can read or change "
                   "what your users send and receive — including passwords and session cookies.",
            fix="Serve the site over HTTPS with a free certificate (e.g. Let's Encrypt), then redirect HTTP to HTTPS.",
            snippets=HTTPS_SNIPPETS,
        ))
        return

    try:
        version, cert = await asyncio.to_thread(_tls_probe, ctx.ips[0], ctx.host, tls_port)
    except ssl.SSLCertVerificationError as exc:
        report.add(Finding(
            id="tls-cert-invalid",
            title="TLS certificate is not trusted",
            severity=Severity.HIGH,
            category="Encryption",
            description=f"Browsers will show a security warning for {ctx.host}.",
            evidence=exc.verify_message or str(exc),
            impact="Visitors see a full-page warning, and anyone who clicks through is exposed to "
                   "man-in-the-middle attacks. It also trains users to ignore real warnings.",
            fix="Install a certificate from a trusted authority that covers this exact hostname, and include the "
                "full certificate chain. Let's Encrypt certificates are free and renew automatically.",
            snippets=HTTPS_SNIPPETS,
        ))
        return
    except (OSError, ssl.SSLError) as exc:
        report.add(Finding(
            id="https-missing",
            title="Site is not available over HTTPS",
            severity=Severity.HIGH,
            category="Encryption",
            description=f"We couldn't open a secure connection to {ctx.host}:{tls_port}.",
            evidence=str(exc),
            impact="Without HTTPS, anyone on the same network can read or change traffic, including "
                   "passwords and session cookies. Browsers also label the site \"Not secure\".",
            fix="Get a free TLS certificate (Let's Encrypt) or turn on HTTPS in your host/CDN, and serve the whole "
                "site over HTTPS.",
            snippets=HTTPS_SNIPPETS,
        ))
        return

    report.ok(f"Valid TLS certificate ({version})")

    days_left = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
    if days_left <= 30:
        report.add(Finding(
            id="tls-cert-expiring",
            title=f"TLS certificate expires in {days_left} days",
            severity=Severity.HIGH if days_left <= 14 else Severity.MEDIUM,
            category="Encryption",
            description=f"The certificate for {ctx.host} expires on {cert['notAfter']}.",
            impact="When it expires, every visitor gets a security warning and most will leave.",
            fix="Renew the certificate now and set up automatic renewal so this never depends on someone remembering.",
            snippets={
                "Certbot": "sudo certbot renew --dry-run   # confirm auto-renew works\nsudo systemctl list-timers | grep certbot",
            },
        ))
    else:
        report.ok(f"TLS certificate valid for {days_left} more days")

    if version in ("TLSv1", "TLSv1.1"):
        report.add(Finding(
            id="tls-old-protocol",
            title=f"Server negotiates outdated {version}",
            severity=Severity.MEDIUM,
            category="Encryption",
            description=f"Our connection used {version}, which was deprecated in 2021 (RFC 8996).",
            impact="Old TLS versions have known weaknesses and are rejected by modern browsers.",
            fix="Enable TLS 1.2 and TLS 1.3 only.",
            snippets={
                "Nginx": "ssl_protocols TLSv1.2 TLSv1.3;",
                "Apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
            },
        ))

    if ctx.port is None and ctx.http is not None:
        if ctx.http.url.startswith("https://"):
            report.ok("HTTP redirects to HTTPS")
        else:
            report.add(Finding(
                id="no-https-redirect",
                title="HTTP doesn't redirect to HTTPS",
                severity=Severity.MEDIUM,
                category="Encryption",
                description=f"http://{ctx.host} serves the page without sending visitors to the secure version.",
                evidence=f"http://{ctx.host} → {ctx.http.url} (status {ctx.http.status})",
                impact="Anyone who types your address without https:// (or follows an old link) uses an unencrypted "
                       "connection that can be read or tampered with.",
                fix="Permanently redirect (301) every HTTP request to the same path on HTTPS.",
                snippets=REDIRECT_SNIPPETS,
            ))
