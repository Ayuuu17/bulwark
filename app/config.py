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
