"""Settings, read from environment variables so nothing secret lives in the code."""

import os
import re
import secrets
from pathlib import Path

APP_NAME = os.getenv("APP_NAME", "Bulwark")
APP_SLUG = re.sub(r"[^a-z0-9]", "", APP_NAME.lower()) or "bulwark"

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "app.db"  # fixed name, so renaming the product doesn't orphan the data

# Lets you scan localhost / private IPs while developing. Never enable in production:
# it would let anyone use your server to reach your internal network.
ALLOW_PRIVATE_TARGETS = os.getenv("ALLOW_PRIVATE_TARGETS", "0") == "1"

SCANS_PER_HOUR = int(os.getenv("SCANS_PER_HOUR", "20"))
VERIFICATION_TTL_DAYS = int(os.getenv("VERIFICATION_TTL_DAYS", "30"))

MAX_CODE_UPLOAD_BYTES = int(os.getenv("MAX_CODE_UPLOAD_MB", "100")) * 1_000_000

# AI deep code review. Works with any OpenAI-compatible chat API, e.g.
#   OpenAI      AI_BASE_URL=https://api.openai.com/v1
#   Gemini      AI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
#   OpenRouter  AI_BASE_URL=https://openrouter.ai/api/v1
#   Ollama      AI_BASE_URL=http://localhost:11434/v1   (no key; code never leaves your server)
# Leave AI_MODEL empty to turn AI review off.
AI_BASE_URL = os.getenv("AI_BASE_URL", "").rstrip("/")
AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_MODEL = os.getenv("AI_MODEL", "")
AI_ENABLED = bool(AI_BASE_URL and AI_MODEL)
AI_MAX_FILES = int(os.getenv("AI_MAX_FILES", "20"))  # files reviewed per scan (cost control)
AI_BATCH_CHARS = int(os.getenv("AI_BATCH_CHARS", "24000"))  # code per request; lower it for small local models
AI_CONCURRENCY = int(os.getenv("AI_CONCURRENCY", "2"))
AI_TIMEOUT = float(os.getenv("AI_TIMEOUT", "300"))

AI_PROVIDER_NAME = os.getenv("AI_PROVIDER_NAME", "")  # shown in the Privacy Policy, e.g. "OpenAI"

# Public address of the site (used in password-reset emails and security.txt).
PUBLIC_URL = os.getenv("PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/")

# Business details shown in the Terms, Privacy Policy and security.txt. Fill these in before launch.
LEGAL_ENTITY = os.getenv("LEGAL_ENTITY", "[Your company name]")
CONTACT_EMAIL = os.getenv("CONTACT_EMAIL", "[contact email]")
SECURITY_EMAIL = os.getenv("SECURITY_EMAIL", CONTACT_EMAIL)
PRIVACY_EMAIL = os.getenv("PRIVACY_EMAIL", CONTACT_EMAIL)
GOVERNING_LAW = os.getenv("GOVERNING_LAW", "[your state / country]")
LEGAL_EFFECTIVE_DATE = os.getenv("LEGAL_EFFECTIVE_DATE", "[effective date]")
HOSTING_PROVIDER = os.getenv("HOSTING_PROVIDER", "[hosting provider]")
EMAIL_PROVIDER = os.getenv("EMAIL_PROVIDER", "[email provider]")
TERMS_VERSION = os.getenv("TERMS_VERSION", "2026-10-20")  # bump when the Terms change; stored per user

# Reports older than this are deleted automatically (0 keeps them until the user deletes them).
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "90"))

# Outgoing email for password resets (any SMTP provider: Postmark, Resend, SES, Mailgun...).
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
MAIL_FROM = os.getenv("MAIL_FROM", "")

USER_AGENT = f"{APP_NAME}-Scanner/1.0 (security configuration check)"
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "10"))
MAX_BODY_BYTES = 2_000_000
MAX_UPLOAD_BYTES = 5_000_000


def _load_secret() -> str:
    env = os.getenv("SECRET_KEY")
    if env:
        return env
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    key_file = DATA_DIR / "secret.key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
        key_file.chmod(0o600)
    return key_file.read_text().strip()


SECRET_KEY = _load_secret()

# Production = anything not served from localhost. Set PUBLIC_URL and the app checks itself on boot.
IS_PRODUCTION = not any(host in PUBLIC_URL for host in ("localhost", "127.0.0.1", "[::1]"))


def startup_problems() -> list[str]:
    """Settings that are unsafe or incomplete for a public deployment."""
    problems = []
    if not IS_PRODUCTION:
        return problems
    if ALLOW_PRIVATE_TARGETS:
        problems.append("ALLOW_PRIVATE_TARGETS is on. Anyone could use your scanner to reach your internal "
                        "network. Remove it before going live.")
    if not os.getenv("SECRET_KEY"):
        problems.append("SECRET_KEY isn't set, so it was generated into DATA_DIR. That's fine for one server "
                        "with a persistent disk, but set it explicitly before scaling to several.")
    if not PUBLIC_URL.startswith("https://"):
        problems.append("PUBLIC_URL isn't https://. Login cookies need HTTPS to be marked Secure.")
    for name, value in (("LEGAL_ENTITY", LEGAL_ENTITY), ("CONTACT_EMAIL", CONTACT_EMAIL),
                        ("GOVERNING_LAW", GOVERNING_LAW), ("LEGAL_EFFECTIVE_DATE", LEGAL_EFFECTIVE_DATE)):
        if value.startswith("["):
            problems.append(f"{name} is still a placeholder; it appears in your public legal pages.")
    if not (SMTP_HOST and MAIL_FROM):
        problems.append("Email isn't configured (SMTP_HOST, MAIL_FROM), so password resets can't be sent.")
    if AI_ENABLED and not AI_PROVIDER_NAME:
        problems.append("AI review is on but AI_PROVIDER_NAME is empty; your Privacy Policy should name the "
                        "provider that receives customer code.")
    return problems
