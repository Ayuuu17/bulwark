"""Email spoofing protection (SPF, DMARC) and CAA, from public DNS records."""

import ipaddress
import re

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..models import Finding, Report, Severity
from .context import ScanContext

# Common two-part public suffixes; good enough without shipping the full Public Suffix List.
TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.in", "co.jp",
    "co.za", "com.br", "com.mx", "com.sg", "com.tr", "com.cn", "com.hk", "co.kr",
}


def org_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


async def txt_records(resolver, name: str) -> list[str]:
    try:
        answer = await resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    return [b"".join(r.strings).decode(errors="replace") for r in answer]


async def has_record(resolver, name: str, rtype: str) -> bool:
    try:
        await resolver.resolve(name, rtype)
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return False


async def check(ctx: ScanContext, report: Report) -> None:
    try:
        ipaddress.ip_address(ctx.host)
        return  # bare IP: no domain to check
    except ValueError:
        pass
    if "." not in ctx.host or ctx.host.endswith((".localhost", ".local", ".internal")):
        return

    domain = org_domain(ctx.host)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6
    try:
        spf = [r for r in await txt_records(resolver, domain) if r.lower().startswith("v=spf1")]
        dmarc = [r for r in await txt_records(resolver, f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
        has_caa = await has_record(resolver, domain, "CAA")
    except dns.exception.DNSException as exc:
        report.add(Finding(
            id="dns-lookup-failed",
            title="DNS checks couldn't complete",
            severity=Severity.INFO,
            category="Email security",
            description=f"We couldn't read DNS records for {domain}.",
            evidence=str(exc),
            impact="SPF/DMARC weren't verified.",
            fix="Re-run the scan; if this keeps happening, check that your DNS provider is responding.",
        ))
        return

    spf_snippets = {
        "DNS (sends email)": f'{domain}.  TXT  "v=spf1 include:_spf.google.com -all"\n'
                             "; replace the include with your email provider's",
        "DNS (never sends email)": f'{domain}.  TXT  "v=spf1 -all"',
    }
    if not spf:
        report.add(Finding(
            id="spf-missing",
            title="No SPF record — anyone can send email as your domain",
            severity=Severity.MEDIUM,
            category="Email security",
            description=f"{domain} doesn't publish which servers may send its email.",
            impact=f"Scammers can send phishing emails that appear to come from @{domain}, and your real email is "
                   "more likely to land in spam.",
            fix="Publish an SPF TXT record listing your email providers and ending in -all (or ~all while testing). "
                "If the domain never sends email, publish \"v=spf1 -all\".",
            snippets=spf_snippets,
        ))
    elif len(spf) > 1:
        report.add(Finding(
            id="spf-multiple",
            title="Multiple SPF records (makes SPF invalid)",
            severity=Severity.MEDIUM,
            category="Email security",
            description="Only one SPF record is allowed; with several, receivers treat SPF as broken.",
            evidence="\n".join(spf),
            impact="Spoofing protection effectively doesn't work.",
            fix="Merge them into a single record with all the include: entries.",
            snippets=spf_snippets,
        ))
    else:
        record = spf[0].lower()
        if re.search(r"(^|\s)\+?all(\s|$)", record) and not re.search(r"[-~?]all", record):
            report.add(Finding(
                id="spf-pass-all",
                title="SPF record allows every server on the internet (+all)",
                severity=Severity.HIGH,
                category="Email security",
                description="Your SPF ends in +all, which authorizes anyone to send as your domain.",
                evidence=spf[0],
                impact="This is worse than having no SPF: spoofed emails will pass SPF checks.",
                fix="Replace +all with -all (or ~all while testing).",
                snippets=spf_snippets,
            ))
        elif "?all" in record or not re.search(r"[-~]all", record):
            report.add(Finding(
                id="spf-weak",
                title="SPF record doesn't reject unauthorized senders",
                severity=Severity.LOW,
                category="Email security",
                description="Your SPF ends neutrally (?all) or has no 'all' rule.",
                evidence=spf[0],
                impact="Receivers get no instruction to distrust mail from other servers.",
                fix="End the record with -all (or ~all).",
                snippets=spf_snippets,
            ))
        else:
            report.ok("SPF record is set")

    dmarc_snippets = {
        "DNS (start)": f'_dmarc.{domain}.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@{domain}"',
        "DNS (enforce)": f'_dmarc.{domain}.  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"',
    }
    if not dmarc:
        report.add(Finding(
            id="dmarc-missing",
            title="No DMARC record",
            severity=Severity.MEDIUM,
            category="Email security",
            description=f"_dmarc.{domain} has no DMARC policy.",
            impact="Receivers aren't told to reject email that fails SPF/DKIM, so spoofed emails using your exact "
                   "domain in the From: line can still get delivered.",
            fix="Publish a DMARC record. Start with p=none to collect reports, then move to p=quarantine and p=reject "
                "once your legitimate email passes.",
            snippets=dmarc_snippets,
        ))
    elif re.search(r"\bp\s*=\s*none", dmarc[0], re.I):
        report.add(Finding(
            id="dmarc-none",
            title="DMARC is in monitor-only mode (p=none)",
            severity=Severity.LOW,
            category="Email security",
            description="DMARC is set up, but it doesn't ask receivers to block anything.",
            evidence=dmarc[0],
            impact="Spoofed emails are reported but still delivered.",
            fix="Once your reports show your real email passing, change to p=quarantine, then p=reject.",
            snippets=dmarc_snippets,
        ))
    else:
        report.ok("DMARC policy enforces rejection/quarantine")

    if has_caa:
        report.ok("CAA record limits who can issue certificates")
    else:
        report.add(Finding(
            id="caa-missing",
            title="No CAA record",
            severity=Severity.INFO,
            category="DNS",
            description="Any certificate authority is allowed to issue certificates for your domain.",
            impact="A CAA record reduces the chance of a certificate being mis-issued for your domain.",
            fix="Add a CAA record naming the authority you use.",
            snippets={"DNS": f'{domain}.  CAA  0 issue "letsencrypt.org"'},
        ))
