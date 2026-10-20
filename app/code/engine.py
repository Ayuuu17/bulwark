"""Runs a code or app scan on an uploaded archive and builds the report."""

import asyncio
import posixpath
import time
from collections import Counter
from datetime import datetime, timezone

import httpx

from .. import config, deps
from ..models import Finding, Report, Severity, summarize
from . import ai_review, mobile, rules, secrets
from .archive import Archive, ArchiveError, detect_kind

LANGUAGES = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".vue": "Vue", ".svelte": "Svelte", ".php": "PHP", ".java": "Java",
    ".kt": "Kotlin", ".kts": "Kotlin", ".go": "Go", ".rb": "Ruby", ".cs": "C#", ".swift": "Swift",
    ".m": "Objective-C", ".dart": "Dart", ".rs": "Rust", ".scala": "Scala",
}
LOCKFILE_SUFFIXES = (".lock", "-lock.json", ".lockfile")


def _spots(*hit_maps: dict[str, list[str]]) -> list[tuple[str, int, str]]:
    """(path, line, rule id) for every evidence line shaped like "path:line  code"."""
    spots = []
    for hit_map in hit_maps:
        for rule_id, lines in hit_map.items():
            for evidence in lines:
                path, _, line = evidence.split("  ", 1)[0].rpartition(":")
                if line.isdigit():
                    spots.append((path, int(line), rule_id))
    return spots


def _static_checks(files, report: Report) -> tuple[dict, dict, set, list[str]]:
    secret_hits: dict[str, list[str]] = {}
    for file in files:
        if not file.path.endswith(LOCKFILE_SUFFIXES):
            secrets.scan_text(file.path, file.text, secret_hits, skip_generic=rules.is_test_path(file.path))
    env_files = [f.path for f in files if secrets.is_env_file(f.path)]
    secrets.report_hits(secret_hits, report, env_files)
    if not secret_hits and not env_files:
        report.ok("No hardcoded secrets found")

    hits, hot = rules.scan(files)
    rules.report_hits(hits, report)
    if not hits:
        report.ok("No dangerous code patterns matched the built-in rules")
    platforms = mobile.scan_source(files, report)
    return hits, secret_hits, hot, platforms


async def _scan_source(archive: Archive, report: Report, notes: list[str], use_ai: bool) -> dict:
    files, skipped = await asyncio.to_thread(archive.text_files)
    if not files:
        raise ArchiveError("We didn't find any source files in that zip.")
    hits, secret_hits, hot, platforms = await asyncio.to_thread(_static_checks, files, report)

    packages, loose, manifests = deps.collect(files)
    if packages:
        try:
            await deps.report_vulnerable(packages, report)
        except httpx.HTTPError:
            report.add(Finding(
                id="osv-unavailable", title="Couldn't check dependencies for known vulnerabilities",
                severity=Severity.INFO, category="Vulnerable dependency",
                description="The vulnerability database didn't respond.", impact="Dependency results are missing.",
                fix="Re-run the scan in a few minutes.",
            ))
    deps.report_loose(loose, "PyPI" if any("requirements" in m for m in manifests) else "npm", report)
    if any(f.name == "Podfile.lock" for f in files):
        notes.append("CocoaPods dependencies (Podfile.lock) aren't covered by the vulnerability database we use; "
                     "check them by hand or move to Swift Package Manager.")

    ai_meta = {}
    if use_ai and config.AI_ENABLED:
        ai_meta = await ai_review.review(files, hot, _spots(hits, secret_hits), report)
        if ai_meta.get("ai_files_reviewed"):
            notes.append(f"AI review read the {ai_meta['ai_files_reviewed']} most security-relevant files. "
                         "AI findings can be wrong: double-check them before changing code.")
    elif use_ai:
        notes.append("AI deep review isn't set up on this server, so only the built-in rules ran.")

    if skipped:
        notes.append(f"{skipped} very large files were skipped.")
    counts = Counter(LANGUAGES[f.ext] for f in files if f.ext in LANGUAGES)
    return {
        "files_scanned": len(files),
        "languages": [name for name, _ in counts.most_common(5)],
        "platforms": platforms,
        "packages_scanned": len(packages),
        "manifests": manifests[:20],
        **ai_meta,
    }


async def run_code_scan(filename: str, data: bytes, use_ai: bool) -> dict:
    started = time.monotonic()
    kind = detect_kind(filename)
    archive = await asyncio.to_thread(Archive, data)
    report, notes = Report(), []

    if kind == "source":
        meta = await _scan_source(archive, report, notes, use_ai)
    else:
        secret_hits: dict[str, list[str]] = {}
        scanner = mobile.scan_apk if kind == "apk" else mobile.scan_ipa
        platforms = await asyncio.to_thread(scanner, archive, report, secret_hits)
        secrets.report_hits(secret_hits, report, [])
        if not secret_hits:
            report.ok("No embedded secrets found in the app binary")
        meta = {"platforms": platforms}
        notes.append("Built apps are checked for risky settings, embedded secrets and insecure URLs. "
                     "Upload the source code as well for a full code review.")
        if kind == "ipa":
            notes.append("IPAs downloaded from the App Store are encrypted, which hides most strings. "
                         "Upload a development or ad-hoc build for the best results.")

    notes.append("Your upload was analyzed in memory and not stored.")
    return summarize(
        report,
        kind="code" if kind == "source" else "app",
        target=posixpath.basename(filename),
        notes=notes,
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        duration_ms=int((time.monotonic() - started) * 1000),
        **meta,
    )
