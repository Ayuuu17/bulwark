"""Proof of domain ownership, required before we scan a site.

The owner puts a token we give them in a DNS TXT record or in a file on the site.
Only someone who controls the domain can do either, so we know they agreed to the scan.
Tokens are per account: verifying a domain on one account doesn't unlock it for another.
"""

import hashlib
import hmac

import dns.asyncresolver
import dns.exception

from . import config, db
from .http_client import FetchError, fetch
from .safety import is_local_dev_target

DNS_LABEL = f"_{config.APP_SLUG}-challenge"
FILE_PATH = f"/.well-known/{config.APP_SLUG}-verify.txt"


def token_for(user_id: int, host: str) -> str:
    message = f"{user_id}:{host}".encode()
    digest = hmac.new(config.SECRET_KEY.encode(), message, hashlib.sha256).hexdigest()[:32]
    return f"{config.APP_SLUG}-verify={digest}"


def instructions(user_id: int, host: str) -> dict:
    token = token_for(user_id, host)
    return {
        "host": host,
        "token": token,
        "dns": {"name": f"{DNS_LABEL}.{host}", "type": "TXT", "value": token},
        "file": {"url": f"https://{host}{FILE_PATH}", "content": token},
    }


async def _dns_has_token(host: str, token: str) -> bool:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6
    try:
        answer = await resolver.resolve(f"{DNS_LABEL}.{host}", "TXT")
    except dns.exception.DNSException:
        return False
    return any(b"".join(r.strings).decode(errors="replace").strip() == token for r in answer)


async def _file_has_token(host: str, token: str) -> bool:
    # One file can hold several lines, so several accounts (e.g. agency + client) can verify the same site.
    for scheme in ("https", "http"):
        try:
            result = await fetch(f"{scheme}://{host}{FILE_PATH}", same_host_only=True)
        except FetchError:
            continue
        if result.status == 200 and token in result.body.split():
            return True
    return False


async def is_authorized(user_id: int, host: str) -> bool:
    return db.is_verified(user_id, host) or await is_local_dev_target(host)


async def verify(user_id: int, host: str) -> tuple[bool, str | None]:
    """Check both methods; remember the domain for this account if either works."""
    if await is_local_dev_target(host):
        return True, "local"
    token = token_for(user_id, host)
    for method, checker in (("dns", _dns_has_token), ("file", _file_has_token)):
        if await checker(host, token):
            db.mark_verified(user_id, host, method)
            return True, method
    return False, None
