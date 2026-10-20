"""security.txt: tells researchers how to report vulnerabilities to you (RFC 9116)."""

from ..http_client import FetchError, fetch
from ..models import Finding, Report, Severity
from .context import ScanContext


async def check(ctx: ScanContext, report: Report) -> None:
    if not ctx.is_https:
        return
    origin = ctx.primary.url.split("/", 3)[:3]
    try:
        result = await fetch("/".join(origin) + "/.well-known/security.txt", same_host_only=True)
        found = result.status == 200 and "contact:" in result.body.lower()
    except FetchError:
        found = False
    if found:
        report.ok("security.txt is published")
        return
    report.add(Finding(
        id="security-txt-missing",
        title="No security.txt file",
        severity=Severity.INFO,
        category="Disclosure policy",
        description="There's no /.well-known/security.txt telling people how to report security problems.",
        impact="People who find a vulnerability in your site may not know how to reach you, so it goes "
               "unreported (or gets posted publicly).",
        fix="Publish a security.txt with a contact address and an expiry date.",
        snippets={
            "/.well-known/security.txt": "Contact: mailto:security@example.com\n"
                                         "Expires: 2027-12-31T23:59:59Z\n"
                                         "Preferred-Languages: en",
        },
        references=["https://securitytxt.org/"],
    ))
