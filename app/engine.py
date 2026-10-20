"""Runs all website checks against one target and builds the report."""

import asyncio
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from .checks import ALL_CHECKS
from .checks.context import ScanContext
from .http_client import FetchError, fetch
from .models import Finding, Report, Severity, summarize
from .safety import assert_safe_host, normalize_url

log = logging.getLogger(__name__)


class ScanError(Exception):
    pass


def with_scheme(url: str, scheme: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((scheme, parts.netloc, parts.path, parts.query, ""))


async def _try_fetch(url: str, **kwargs):
    try:
        return await fetch(url, **kwargs), None
    except FetchError as exc:
        return None, str(exc)


async def run_site_scan(raw_url: str) -> dict:
    started = time.monotonic()
    target = normalize_url(raw_url)
    parts = urlsplit(target)
    host, port, scheme = parts.hostname, parts.port, parts.scheme
    ips = await assert_safe_host(host)

    https_res = http_res = https_err = None
    if port is None or scheme == "https":
        https_res, https_err = await _try_fetch(with_scheme(target, "https"))
    if port is None or scheme == "http":
        http_res, _ = await _try_fetch(with_scheme(target, "http"))

    primary = https_res or http_res
    if primary is None and https_err:
        # Probably a bad certificate. Load the page anyway so we can still check
        # everything else; the transport check reports the certificate problem.
        primary, _ = await _try_fetch(with_scheme(target, "https"), verify_tls=False)
    if primary is None:
        raise ScanError(f"Couldn't load {target}: {https_err or 'no response'}.")

    ctx = ScanContext(
        target=target, host=host, port=port, scheme=scheme, ips=ips,
        primary=primary, https=https_res, https_error=https_err, http=http_res,
    )
    report = Report()
    results = await asyncio.gather(*(check(ctx, report) for _, check in ALL_CHECKS), return_exceptions=True)
    for (name, _), result in zip(ALL_CHECKS, results):
        if isinstance(result, Exception):
            log.exception("check %s failed", name, exc_info=result)
            report.add(Finding(
                id=f"check-error-{name}",
                title=f"\"{name}\" check couldn't complete",
                severity=Severity.INFO,
                category="Scanner",
                description="Something unexpected happened during this check, so it was skipped.",
                evidence=f"{result.__class__.__name__}: {result}",
                impact="Results for this area are incomplete.",
                fix="Re-run the scan. If it keeps failing, let us know.",
            ))

    return summarize(
        report,
        kind="site",
        target=target,
        final_url=primary.url,
        status_code=primary.status,
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        duration_ms=int((time.monotonic() - started) * 1000),
        checks_run=[name for name, _ in ALL_CHECKS],
    )
