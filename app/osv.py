"""Known-vulnerability lookups against the free OSV.dev database (no API key needed)."""

import asyncio
import re
from dataclasses import dataclass

import httpx

from . import config
from .models import Finding, Severity, max_severity

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
BATCH_SIZE = 500
MAX_DETAIL_LOOKUPS = 300

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str  # OSV ecosystem name: "npm", "PyPI", ...


@dataclass
class Vuln:
    id: str
    summary: str
    severity: Severity
    aliases: list[str]
    fixed: str | None  # lowest version that fixes it for the package's version, if known


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", version)[:4])


def _first_fix_after(vuln: dict, pkg: Package) -> str | None:
    current = version_key(pkg.version)
    candidates = []
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != pkg.name.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed and version_key(fixed) > current:
                    candidates.append(fixed)
    return min(candidates, key=version_key) if candidates else None


def _parse_vuln(data: dict, pkg: Package) -> Vuln:
    raw_severity = str((data.get("database_specific") or {}).get("severity", "")).upper()
    return Vuln(
        id=data["id"],
        summary=(data.get("summary") or data.get("details", "")[:160] or "No summary published").strip(),
        severity=SEVERITY_MAP.get(raw_severity, Severity.MEDIUM),
        aliases=[a for a in data.get("aliases", []) if a.startswith("CVE-")],
        fixed=_first_fix_after(data, pkg),
    )


async def lookup(packages: list[Package]) -> dict[Package, list[Vuln]]:
    """Return the known vulnerabilities for each affected package."""
    if not packages:
        return {}
    async with httpx.AsyncClient(timeout=30, headers={"User-Agent": config.USER_AGENT}) as client:
        hits: dict[Package, list[str]] = {}
        for start in range(0, len(packages), BATCH_SIZE):
            chunk = packages[start:start + BATCH_SIZE]
            resp = await client.post(OSV_BATCH_URL, json={"queries": [
                {"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version} for p in chunk
            ]})
            resp.raise_for_status()
            for pkg, result in zip(chunk, resp.json().get("results", [])):
                ids = [v["id"] for v in result.get("vulns", [])]
                if ids:
                    hits[pkg] = ids

        unique_ids = list(dict.fromkeys(i for ids in hits.values() for i in ids))[:MAX_DETAIL_LOOKUPS]
        semaphore = asyncio.Semaphore(10)

        async def fetch_detail(vuln_id: str) -> tuple[str, dict | None]:
            async with semaphore:
                try:
                    r = await client.get(OSV_VULN_URL.format(vuln_id))
                    r.raise_for_status()
                    return vuln_id, r.json()
                except httpx.HTTPError:
                    return vuln_id, None

        details = dict(await asyncio.gather(*(fetch_detail(i) for i in unique_ids)))

    results = {}
    for pkg, ids in hits.items():
        vulns = []
        for vuln_id in ids:
            data = details.get(vuln_id)
            vulns.append(_parse_vuln(data, pkg) if data else Vuln(vuln_id, "Details unavailable", Severity.MEDIUM, [], None))
        results[pkg] = vulns
    return results


def finding_for(pkg: Package, vulns: list[Vuln], *, category: str, snippets: dict[str, str]) -> Finding:
    fixes = [v.fixed for v in vulns if v.fixed]
    unfixed = [v for v in vulns if not v.fixed]
    target = max(fixes, key=version_key) if fixes else None
    if target:
        fix = f"Upgrade {pkg.name} to {target} or later — that version fixes "
        fix += "all of the issues below." if not unfixed else f"{len(vulns) - len(unfixed)} of {len(vulns)} issues."
        if unfixed:
            fix += " For the rest no fix is published yet: check the advisories for workarounds or replace the package."
    else:
        fix = (f"No fixed version of {pkg.name} has been published yet. Read the advisories for workarounds, "
               "or switch to a maintained alternative.")
    lines = []
    for v in sorted(vulns, key=lambda v: list(Severity).index(v.severity)):
        cve = f" ({', '.join(v.aliases)})" if v.aliases else ""
        lines.append(f"[{v.severity.value.upper()}] {v.id}{cve}: {v.summary}")
    count = len(vulns)
    return Finding(
        id=f"vuln-{pkg.ecosystem}-{pkg.name}".lower(),
        title=f"{pkg.name} {pkg.version} has {count} known vulnerabilit{'y' if count == 1 else 'ies'}",
        severity=max_severity([v.severity for v in vulns]),
        category=category,
        description=f"{pkg.name} version {pkg.version} matches published security advisories.",
        evidence="\n".join(lines),
        impact="Vulnerabilities in public libraries are well documented, and attackers routinely scan for "
               "sites and apps still running affected versions.",
        fix=fix,
        snippets={k: v.replace("{version}", target or "latest") for k, v in snippets.items()},
        references=[f"https://osv.dev/vulnerability/{v.id}" for v in vulns[:5]],
    )
