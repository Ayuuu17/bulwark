"""Finds credentials committed to code or bundled into apps. Matches are redacted in reports."""

import re
from dataclasses import dataclass

from ..models import Finding, Report, Severity

SECRET_SNIPPETS = {
    "1. Rotate": "Revoke this key in the provider's dashboard and create a new one.\n"
                 "Assume the old one was copied: deleting it from the code is not enough.",
    "2. Move to env": "# .env (add .env to .gitignore)\nSTRIPE_SECRET_KEY=sk_live_...\n\n"
                      "# code\nimport os\nkey = os.environ[\"STRIPE_SECRET_KEY\"]   # Python\n"
                      "const key = process.env.STRIPE_SECRET_KEY;  // Node",
    "3. Clean history": "# The key stays in old commits until you rewrite history:\n"
                        "pip install git-filter-repo\ngit filter-repo --replace-text <(echo 'THE_OLD_KEY==>REMOVED')",
}


@dataclass(frozen=True)
class SecretRule:
    id: str
    name: str
    pattern: re.Pattern
    severity: Severity
    note: str = ""


RULES = [
    SecretRule("aws-access-key", "AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    SecretRule("aws-secret-key", "AWS secret key",
               re.compile(r"(?i)aws_?secret_?(?:access_?)?key\s*[=:]\s*[\"']?([A-Za-z0-9/+]{40})"), Severity.CRITICAL),
    SecretRule("private-key", "Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
               Severity.CRITICAL),
    SecretRule("stripe-live", "Stripe live secret key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"), Severity.CRITICAL),
    SecretRule("github-token", "GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
               Severity.CRITICAL),
    SecretRule("slack-token", "Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), Severity.HIGH),
    SecretRule("slack-webhook", "Slack webhook URL",
               re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), Severity.MEDIUM),
    SecretRule("openai-key", "OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}\b"), Severity.CRITICAL),
    SecretRule("anthropic-key", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{40,}\b"), Severity.CRITICAL),
    SecretRule("sendgrid-key", "SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), Severity.HIGH),
    SecretRule("twilio-key", "Twilio API key", re.compile(r"\bSK[0-9a-f]{32}\b"), Severity.HIGH),
    SecretRule("mailgun-key", "Mailgun API key", re.compile(r"\bkey-[0-9a-f]{32}\b"), Severity.HIGH),
    SecretRule("db-url-password", "Database URL with password",
               re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql)://[^\s:/@\"']+:([^\s@\"'/]{3,})@[^\s\"']+"),
               Severity.HIGH),
    SecretRule("google-api-key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.LOW,
               note="Google/Firebase keys in apps are often public by design. Make sure this one is restricted "
                    "to your app and only the APIs it needs in Google Cloud Console → Credentials."),
    SecretRule("generic-secret", "Hardcoded password or secret",
               re.compile(r"(?i)\b[\w.-]*(?:password|passwd|pwd|secret|api_?key|access_?token|auth_?token|private_?key)"
                          r"[\w.-]*\s*(?:=|:|=>)\s*[\"']([^\"'\s]{8,})[\"']"),
               Severity.HIGH),
]

PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|\*+|\.+|changeme|change_me|password\d*|secret|your[_-]|example|test|dummy|sample|placeholder|"
    r"todo|fixme|null|none|undefined|<|\$\{|\{\{|%\(|process\.env|os\.environ|getenv|env\(|config\.|settings\.)"
)


def redact(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "…"
    return f"{value[:4]}…{value[-2:]}"


def _looks_real(rule: SecretRule, match: re.Match) -> bool:
    value = match.group(match.lastindex or 0)
    if rule.id != "generic-secret":
        return True
    if PLACEHOLDER.match(value) or len(set(value)) < 5:
        return False
    return not re.search(r"(?i)example|placeholder|changeme|your_|dummy", value)


def scan_text(path: str, text: str, hits: dict[str, list[str]], *, binary: bool = False,
              skip_generic: bool = False) -> None:
    """`skip_generic` drops the password=... heuristic (used for test files, where fake values are normal)."""
    rules = [r for r in RULES if not (skip_generic and r.id == "generic-secret")]
    lines = text.splitlines() if not binary else [text]
    for number, line in enumerate(lines, 1):
        if len(line) > 5000 and not binary:
            line = line[:5000]
        for rule in rules:
            for match in rule.pattern.finditer(line):
                if not _looks_real(rule, match):
                    continue
                secret = match.group(match.lastindex or 0)
                shown = line.strip().replace(secret, redact(secret))[:160] if not binary else redact(secret)
                where = path if binary else f"{path}:{number}"
                hits.setdefault(rule.id, []).append(f"{where}  {shown}")


def is_env_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return name.startswith(".env") and not name.endswith((".example", ".sample", ".template", ".dist"))


def report_hits(hits: dict[str, list[str]], report: Report, env_files: list[str]) -> None:
    for rule in RULES:
        locations = hits.get(rule.id)
        if not locations:
            continue
        report.add(Finding(
            id=f"secret-{rule.id}",
            title=f"{rule.name} found in your code" if len(locations) == 1
                  else f"{rule.name}s found in your code ({len(locations)})",
            severity=rule.severity,
            category="Leaked secret",
            description=f"We found what looks like a real {rule.name.lower()} (shown redacted below).",
            evidence="\n".join(dict.fromkeys(locations[:25])),
            impact=rule.note or "Anyone who can see this code or decompile the app can use the credential: bots "
                   "scan public repos and app stores for keys within minutes, and leaked cloud keys get used for "
                   "data theft or expensive crypto-mining.",
            fix="Rotate (revoke and replace) the credential now, then load it from an environment variable or "
                "secrets manager. Mobile apps can't keep secrets: call your own backend, which holds the key.",
            snippets=SECRET_SNIPPETS,
        ))
    if env_files:
        report.add(Finding(
            id="env-file-committed",
            title=".env file included in the project",
            severity=Severity.HIGH,
            category="Leaked secret",
            description="Environment files usually hold production credentials and shouldn't be in the repo or upload.",
            evidence="\n".join(env_files[:20]),
            impact="Anyone with access to the code gets every credential in these files.",
            fix="Remove them from git, add them to .gitignore, rotate the values, and commit a .env.example with "
                "placeholder values instead.",
            snippets={".gitignore": ".env\n.env.*\n!.env.example",
                      "Remove from git": "git rm --cached .env\ngit commit -m \"Stop tracking .env\""},
        ))
