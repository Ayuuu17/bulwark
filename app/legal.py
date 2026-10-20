"""Legal pages, rendered from Markdown-ish text with the business details filled in from config.

These are a starting point written in plain language, not legal advice. A lawyer in your
jurisdiction should review them before you take real customers or payments.
"""

import html
import re

from . import config

PAGES = {
    "terms": ("Terms of Service", """
# Terms of Service

These terms are an agreement between you and {entity} ("we", "us") covering your use of {app}
(the "Service"), a security scanning tool for websites, source code and mobile applications.

By creating an account or using the Service, you accept these terms. If you don't agree, don't use
the Service.

## 1. Who may use the Service

You must be at least 16 years old and able to enter a contract. If you use the Service for an
organization, you confirm you're authorized to accept these terms on its behalf.

## 2. What you may scan

You may only scan systems you own or are clearly authorized to test. For websites, we require proof
of control over the domain before scanning. For uploaded code and applications, you confirm at upload
that you own the code or are authorized by its owner.

Scanning systems without authorization may be a crime in many countries and is prohibited by our
[Acceptable Use Policy](/acceptable-use). You are responsible for having permission, and you
indemnify us against claims arising from scans you run without it.

## 3. Your account

Keep your password confidential and tell us promptly at {contact} if you believe your account has been
accessed by someone else. You are responsible for activity under your account.

## 4. What the Service does and does not do

The Service runs automated checks and, if you enable it, an AI-assisted review. It is designed to find
common misconfigurations, known-vulnerable components and well-understood code weaknesses.

**It is not a guarantee of security.** Automated scanning cannot find every vulnerability, and it may
report issues that turn out not to be exploitable in your environment (false positives). Results are
information to help you make decisions, not professional security certification, and they do not replace
a manual penetration test, a code audit by a qualified professional, or a compliance assessment.

You remain responsible for your own systems and for reviewing and testing any suggested fix before
applying it.

## 5. Acceptable use

Your use of the Service is subject to our [Acceptable Use Policy](/acceptable-use), which is part of
these terms.

## 6. Your content

You keep all rights to the code, applications and data you upload ("Your Content"). You grant us a
limited licence to process Your Content solely to run the scan you requested and to produce your
report. Uploaded archives are processed in memory and are not stored after the scan finishes; reports
retain short excerpts so findings make sense. See the [Privacy Policy](/privacy) for details.

## 7. Service availability and changes

We may change, suspend or discontinue parts of the Service. We'll give reasonable notice of material
changes where we can. The Service may be unavailable during maintenance or due to issues outside our
control.

## 8. Fees

Paid plans, if offered, are described at the point of purchase. Free use may be rate-limited.

## 9. Termination

You can delete your account at any time from your dashboard, which permanently deletes your data. We
may suspend or terminate accounts that breach these terms or the Acceptable Use Policy, or where we
reasonably believe use is unlawful.

## 10. Disclaimers

To the maximum extent permitted by law, the Service is provided "as is" and "as available", without
warranties of any kind, express or implied, including fitness for a particular purpose, accuracy, or
non-infringement.

## 11. Limitation of liability

To the maximum extent permitted by law, we are not liable for indirect, incidental, special,
consequential or punitive damages, or for lost profits, revenue, data or goodwill. Our total liability
for any claim relating to the Service is limited to the greater of (a) the amount you paid us in the
twelve months before the claim, or (b) 100 USD.

Nothing in these terms excludes liability that cannot be excluded by law, including for death or
personal injury caused by negligence, or for fraud. Some jurisdictions do not allow certain
limitations, so parts of this section may not apply to you, and you may have statutory rights that
these terms do not affect.

## 12. Changes to these terms

We may update these terms. If changes are material, we'll notify you (for example by email or a notice
in the app) before they take effect. Continuing to use the Service after that means you accept the new
terms.

## 13. Governing law

These terms are governed by the laws of {law}, without regard to conflict-of-law rules. Consumers may
also have the protection of mandatory laws of their country of residence.

## 14. Contact

Questions about these terms: {contact}
"""),

    "privacy": ("Privacy Policy", """
# Privacy Policy

This policy explains what {entity} collects when you use {app}, why, and what rights you have. We've
written it in plain language on purpose.

## Who is responsible

{entity} is the data controller for personal data processed through the Service. Contact: {privacy}

## What we collect

| What | Why | How long we keep it |
|---|---|---|
| Your email address | To create your account, let you log in and send password resets | Until you delete your account |
| Your password (hashed, never in plain text) | To authenticate you | Until you delete your account |
| Verified domains | To prove you may scan a site | 30 days per verification, or until you remove it |
| Scan reports | So you can read and revisit your results | {retention}, or until you delete them |
| Server logs (IP address, time, request) | Security, abuse prevention and debugging | Up to 30 days |

We don't sell your data, we don't use it for advertising, and we don't run third-party trackers or
advertising cookies.

## Uploaded code and applications

Archives you upload are read **in memory** and discarded when the scan ends. We don't write them to
disk and we don't keep them.

Your report keeps what's needed to act on the findings: file paths, line numbers and short single-line
excerpts. Anything matching a secret pattern is redacted before it's stored (for example `AKIA…45`).

## AI deep review (optional)

If you enable AI deep review, the most security-relevant files from your upload are sent to our AI
provider{ai_provider} to be analyzed, and the findings are returned to us. They are processed to perform
the review you requested. You can turn this off for any scan, and the rest of the scan still runs.

## Third parties that process data for us

- **{hosting}** — hosting and infrastructure.
- **OSV.dev (Open Source Vulnerabilities)** — we send **package names and version numbers only** to look
  up known vulnerabilities. We never send your code or personal data.
- **{email_provider}** — sending password-reset emails.
- **Our AI provider**{ai_provider_clause}

## Cookies

We use one strictly necessary cookie to keep you logged in (`session`). It is `HttpOnly`,
`SameSite=Lax` and `Secure` in production. We don't use analytics or advertising cookies, so there's
no consent banner to click.

## Legal bases (UK/EU GDPR)

- **Contract**: running your account and the scans you request.
- **Legitimate interests**: keeping the Service secure, preventing abuse, and debugging. We balance this
  against your rights.
- **Legal obligation**: where we must keep records or respond to lawful requests.

## Your rights

Depending on where you live, you may have the right to access, correct, delete, export, or restrict
processing of your data, and to object to processing. You can:

- **Export** everything we hold: Dashboard → Account & privacy → Download my data.
- **Delete** your account and all its data: Dashboard → Account & privacy → Delete account.
- Or email {privacy} and we'll help.

UK/EU residents may complain to their data protection authority. California residents have rights under
the CCPA/CPRA, including to know, delete and correct personal information, and not to be discriminated
against for exercising them; we do not sell or share personal information as those terms are defined.

## International transfers

Our providers may process data outside your country. Where required, we rely on appropriate safeguards
such as Standard Contractual Clauses.

## Children

The Service isn't intended for people under 16, and we don't knowingly collect their data.

## Security

Passwords are hashed with scrypt. Sessions are random tokens stored only as hashes. Traffic is
encrypted with HTTPS in production. No system is perfectly secure, but we take this seriously — see our
[Security Policy](/security-policy).

## Changes

We'll post updates here and change the date below. Material changes will be notified to you directly.

## Contact

{privacy}
"""),

    "acceptable-use": ("Acceptable Use Policy", """
# Acceptable Use Policy

This policy keeps {app} safe for everyone and keeps you on the right side of the law. It's part of our
[Terms of Service](/terms).

## The core rule

**Only scan what you own or are authorized to test.**

Running security scans against systems without the owner's permission is illegal in many places,
including under the US Computer Fraud and Abuse Act and the UK Computer Misuse Act. That's why we
require domain verification before a website scan, and why you confirm ownership before uploading code.

## You must not

- Scan a website, application or codebase you don't own or lack written authorization to test.
- Pretend to control a domain you don't, or try to work around domain verification.
- Upload code or applications you obtained without permission.
- Use findings from our Service to attack, extort or gain unauthorized access to any system.
- Try to break, overload or circumvent limits on the Service, including automated scraping, sharing
  accounts to avoid rate limits, or probing our own infrastructure outside our
  [Security Policy](/security-policy).
- Upload malware, or content that is unlawful.
- Use the Service to build a competing product by bulk-extracting our rules or report content.

## Reasonable use

Free accounts have a limit on scans per hour. Don't try to evade it with multiple accounts. If you need
higher volume, get in touch at {contact}.

## What happens if you breach this policy

We may suspend or terminate your account, delete your data, and where appropriate report the activity
to the relevant authorities.

## Reporting abuse

If you believe someone is using {app} against your systems without authorization, email {security}
with the details and we'll investigate.
"""),

    "security-policy": ("Security Policy", """
# Security Policy

## Reporting a vulnerability

If you find a security issue in {app} itself, please tell us before telling anyone else. Email
{security} with enough detail to reproduce the issue.

We'll acknowledge your report, keep you updated while we investigate, and credit you when we fix it, if
you'd like us to.

**Please do:** test only against your own account, use minimal data, and stop as soon as you've proven
an issue exists.

**Please don't:** access other people's data, degrade the service for others, run automated
high-volume scans against us, or use social engineering or physical attacks against our staff or
providers.

We won't pursue legal action against researchers who follow this policy in good faith.

## How we protect your data

- **Passwords** are hashed with scrypt and never stored or logged in plain text.
- **Sessions** are random tokens; only a SHA-256 hash is stored, so a database leak can't be used to log in.
  Cookies are `HttpOnly`, `SameSite=Lax` and `Secure` in production.
- **Uploads** are processed in memory and discarded after the scan. Archive contents are never written to disk.
- **Secrets we find** in your code are redacted before being stored in a report.
- **Our own scanner** can't be used to reach internal networks: every target and redirect is resolved and
  private, loopback and link-local addresses are refused.
- **Cross-site protection**: state-changing requests check `Sec-Fetch-Site`/`Origin`, and the app sends a
  strict Content-Security-Policy. Report content is rendered as text, never as HTML.
- **Rate limits** on sign-ups, log-ins and scans.

## Scope

In scope: this web application and its API. Out of scope: findings produced by scans of *your* systems
(those are yours to fix), reports from automated scanners without a demonstrated impact, and
best-practice suggestions with no security impact.
"""),
}


def _format(text: str) -> str:
    ai_provider = f" ({config.AI_PROVIDER_NAME})" if config.AI_PROVIDER_NAME else ""
    provider_clause = (f" {config.AI_PROVIDER_NAME} processes files you submit for AI review."
                       if config.AI_PROVIDER_NAME else
                       " — named in our AI review section; files you submit for AI review are processed by them.")
    if not config.AI_ENABLED:
        provider_clause = " — not currently enabled."
    retention = f"{config.RETENTION_DAYS} days" if config.RETENTION_DAYS > 0 else "Until you delete them"
    return text.format(
        app=config.APP_NAME, entity=config.LEGAL_ENTITY, contact=config.CONTACT_EMAIL,
        privacy=config.PRIVACY_EMAIL, security=config.SECURITY_EMAIL, law=config.GOVERNING_LAW,
        hosting=config.HOSTING_PROVIDER, email_provider=config.EMAIL_PROVIDER,
        ai_provider=ai_provider, ai_provider_clause=provider_clause, retention=retention,
    )


def _inline(text: str) -> str:
    """Escape HTML, then re-enable **bold**, `code` and [links](/path)."""
    out = html.escape(text)
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    return re.sub(r"\[([^\]]+)\]\((/[a-z-]*)\)", r'<a href="\2">\1</a>', out)


def _render_markdown(text: str) -> str:
    """Tiny renderer for the subset used above: headings, paragraphs, lists and one table shape."""
    blocks, lines = [], text.strip().splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        if not line:
            i += 1
        elif line.startswith("#"):
            level = len(line) - len(line.lstrip("#"))
            blocks.append(f"<h{level}>{_inline(line.lstrip('# '))}</h{level}>")
            i += 1
        elif line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(set(c) <= set("-: ") for c in cells):
                    rows.append(cells)
                i += 1
            head, *body = rows
            thead = "".join(f"<th>{_inline(c)}</th>" for c in head)
            tbody = "".join("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>" for r in body)
            blocks.append(f"<table><thead><tr>{thead}</tr></thead><tbody>{tbody}</tbody></table>")
        elif line.startswith("- "):
            items = []
            while i < len(lines) and lines[i].startswith("- "):
                item = lines[i][2:]
                i += 1
                while i < len(lines) and lines[i].startswith("  ") and lines[i].strip():
                    item += " " + lines[i].strip()
                    i += 1
                items.append(f"<li>{_inline(item)}</li>")
            blocks.append("<ul>" + "".join(items) + "</ul>")
        else:
            paragraph = []
            while i < len(lines) and lines[i].strip() and not lines[i].startswith(("#", "-", "|")):
                paragraph.append(lines[i].strip())
                i += 1
            blocks.append(f"<p>{_inline(' '.join(paragraph))}</p>")
    return "\n".join(blocks)


def page_html(slug: str) -> str | None:
    entry = PAGES.get(slug)
    if entry is None:
        return None
    title, body = entry
    app = html.escape(config.APP_NAME)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} — {app}</title>
<meta name="robots" content="index, follow">
<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/static/styles.css">
</head>
<body>
<div class="bg-grid" aria-hidden="true"></div>
<div class="bg-glow" aria-hidden="true"></div>
<header class="topbar"><div class="wrap topbar-inner">
  <a href="/" class="brand"><span class="logo" aria-hidden="true"></span><span>{app}</span></a>
  <nav class="nav"><a href="/" class="btn ghost small">Back to {app}</a></nav>
</div></header>
<main class="wrap"><article class="legal">
{_render_markdown(_format(body))}
<p class="meta">Last updated: {html.escape(config.LEGAL_EFFECTIVE_DATE)} · Version {html.escape(config.TERMS_VERSION)}</p>
<p class="meta">This document is provided as a starting point and is not legal advice.</p>
</article></main>
<footer class="footer"><div class="wrap footer-inner">
  <p class="muted small">© {app}</p>
  <nav class="footer-links" aria-label="Legal">
    <a href="/terms">Terms</a><a href="/privacy">Privacy</a>
    <a href="/acceptable-use">Acceptable use</a><a href="/security-policy">Security</a>
  </nav>
</div></footer>
</body>
</html>"""
