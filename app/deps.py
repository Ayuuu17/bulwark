"""Dependency scanning: parse lockfiles/manifests, look every package up in OSV."""

import json
import posixpath
import re
import time
import tomllib

import httpx

from . import osv
from .models import Finding, Report, Severity, summarize

MAX_PACKAGES = 5000
EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+[\w.+-]*")
SUPPORTED_FILES = (
    "package-lock.json", "yarn.lock", "package.json", "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock",
    "go.mod", "Gemfile.lock", "composer.lock", "Cargo.lock", "pubspec.lock", "gradle.lockfile",
    "libs.versions.toml", "build.gradle", "build.gradle.kts", "pom.xml",
)
INSTALL_HINTS = {
    "npm": ("npm", "npm install {name}@{version}"),
    "PyPI": ("pip", "pip install \"{name}>={version}\""),
    "Go": ("Go", "go get {name}@v{version}"),
    "RubyGems": ("Bundler", "# Gemfile\ngem '{name}', '>= {version}'\n\nbundle update {name}"),
    "Packagist": ("Composer", "composer require {name}:^{version}"),
    "crates.io": ("Cargo", "cargo update -p {name} --precise {version}"),
    "Pub": ("Flutter", "# pubspec.yaml\n  {name}: ^{version}\n\nflutter pub upgrade {name}"),
    "Maven": ("Gradle / Maven", "// build.gradle\nimplementation \"{name}:{version}\"\n\n"
                                "<!-- pom.xml -->\n<version>{version}</version>"),
}


class ManifestError(ValueError):
    pass


def pkg(name: str, version: str, ecosystem: str) -> osv.Package:
    return osv.Package(name.strip(), version.strip().lstrip("v="), ecosystem)


# --- JavaScript ---

def parse_package_lock(text: str) -> list[osv.Package]:
    data = json.loads(text)
    packages = []
    if "packages" in data:  # lockfile v2 / v3
        for path, info in data["packages"].items():
            if not path or "version" not in info or info.get("link"):
                continue
            name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
            packages.append(pkg(name, info["version"], "npm"))
    else:  # lockfile v1
        def walk(deps: dict):
            for name, info in deps.items():
                if "version" in info:
                    packages.append(pkg(name, info["version"], "npm"))
                walk(info.get("dependencies", {}))
        walk(data.get("dependencies", {}))
    return packages


def parse_yarn_lock(text: str) -> list[osv.Package]:
    packages, current = [], None
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")) and line.endswith(":"):
            spec = line[:-1].split(",")[0].strip().strip('"')
            current = spec.rsplit("@", 1)[0] if spec.count("@") > (1 if spec.startswith("@") else 0) else None
            if current == "__metadata":
                current = None
        elif current and (match := re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)):
            if EXACT_VERSION.match(match.group(1)):
                packages.append(pkg(current, match.group(1), "npm"))
            current = None
    return packages


def parse_package_json(text: str) -> tuple[list[osv.Package], list[str]]:
    data = json.loads(text)
    packages, skipped = [], []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            match = EXACT_VERSION.search(str(spec))
            if match and not str(spec).startswith(("git", "file:", "link:", "http", "workspace:")):
                packages.append(pkg(name, match.group(0), "npm"))
            else:
                skipped.append(name)
    return packages, skipped


# --- Python ---

def parse_requirements(text: str) -> tuple[list[osv.Package], list[str]]:
    packages, unpinned = [], []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([^\s,]+)$", line)
        if match:
            packages.append(pkg(match.group(1), match.group(3), "PyPI"))
        else:
            name = re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*", line)
            unpinned.append(name.group(0) if name else line)
    return packages, unpinned


def parse_toml_packages(text: str, ecosystem: str) -> list[osv.Package]:
    """poetry.lock, uv.lock and Cargo.lock all use [[package]] name/version."""
    data = tomllib.loads(text)
    return [pkg(p["name"], p["version"], ecosystem) for p in data.get("package", []) if "version" in p]


def parse_pipfile_lock(text: str) -> list[osv.Package]:
    data = json.loads(text)
    packages = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = str(info.get("version", "")).lstrip("=")
            if version:
                packages.append(pkg(name, version, "PyPI"))
    return packages


# --- Go, Ruby, PHP, Dart ---

def parse_go_mod(text: str) -> list[osv.Package]:
    packages, in_block = [], False
    for line in text.splitlines():
        stripped = line.split("//", 1)[0].strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if stripped.startswith("require "):
            stripped = stripped[len("require "):]
        elif not in_block:
            continue
        match = re.match(r"^(\S+)\s+v(\d[^\s+]*)", stripped)
        if match:
            packages.append(pkg(match.group(1), match.group(2), "Go"))
    return packages


def parse_gemfile_lock(text: str) -> list[osv.Package]:
    return [pkg(name, version, "RubyGems")
            for name, version in re.findall(r"^    ([\w.-]+) \((\d[\w.]*)", text, re.M)]


def parse_composer_lock(text: str) -> list[osv.Package]:
    data = json.loads(text)
    return [pkg(p["name"], p["version"], "Packagist") for section in ("packages", "packages-dev")
            for p in data.get(section) or [] if EXACT_VERSION.search(p.get("version", ""))]


def parse_pubspec_lock(text: str) -> list[osv.Package]:
    packages, name, source = [], None, None
    for line in text.splitlines():
        if match := re.match(r"^  ([\w-]+):\s*$", line):
            name, source = match.group(1), None
        elif name and (match := re.match(r"^    source:\s*\"?(\w+)", line)):
            source = match.group(1)
        elif name and (match := re.match(r"^    version:\s*\"?([^\"\s]+)", line)):
            if source == "hosted":
                packages.append(pkg(name, match.group(1), "Pub"))
            name = None
    return packages


# --- JVM / Android ---

GRADLE_DEP = re.compile(r"""(?:implementation|api|compileOnly|runtimeOnly|kapt|ksp|classpath)\s*\(?\s*["']([\w.-]+):([\w.-]+):(\d[\w.-]*)["']""")


def parse_gradle(text: str) -> list[osv.Package]:
    return [pkg(f"{g}:{a}", v, "Maven") for g, a, v in GRADLE_DEP.findall(text)]


def parse_gradle_lockfile(text: str) -> list[osv.Package]:
    return [pkg(f"{g}:{a}", v, "Maven") for g, a, v in re.findall(r"^([\w.-]+):([\w.-]+):([^=\s]+)=", text, re.M)]


def parse_version_catalog(text: str) -> list[osv.Package]:
    data = tomllib.loads(text)
    versions = data.get("versions", {})
    packages = []
    for lib in (data.get("libraries") or {}).values():
        if isinstance(lib, str):
            parts = lib.split(":")
            if len(parts) == 3:
                packages.append(pkg(f"{parts[0]}:{parts[1]}", parts[2], "Maven"))
            continue
        module = lib.get("module") or (f"{lib['group']}:{lib['name']}" if "group" in lib and "name" in lib else None)
        version = lib.get("version")
        if isinstance(version, dict):
            version = versions.get(version.get("ref")) if "ref" in version else version.get("strictly") or version.get("require")
        if module and isinstance(version, str) and EXACT_VERSION.match(version):
            packages.append(pkg(module, version, "Maven"))
    return packages


def parse_pom(text: str) -> list[osv.Package]:
    pattern = r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>(\d[^<$]*)</version>"
    return [pkg(f"{g}:{a}", v, "Maven") for g, a, v in re.findall(pattern, text)]


def parse_manifest(filename: str, text: str) -> tuple[list[osv.Package], list[str], str]:
    """Returns (packages, loosely-pinned package names, ecosystem label)."""
    base = posixpath.basename(filename)
    try:
        if base == "package-lock.json":
            return parse_package_lock(text), [], "npm"
        if base == "yarn.lock":
            return parse_yarn_lock(text), [], "npm"
        if base == "package.json":
            return *parse_package_json(text), "npm"
        if base.endswith(".txt") and "requirements" in base:
            return *parse_requirements(text), "PyPI"
        if base in ("poetry.lock", "uv.lock"):
            return parse_toml_packages(text, "PyPI"), [], "PyPI"
        if base == "Pipfile.lock":
            return parse_pipfile_lock(text), [], "PyPI"
        if base == "go.mod":
            return parse_go_mod(text), [], "Go"
        if base == "Gemfile.lock":
            return parse_gemfile_lock(text), [], "RubyGems"
        if base == "composer.lock":
            return parse_composer_lock(text), [], "Packagist"
        if base == "Cargo.lock":
            return parse_toml_packages(text, "crates.io"), [], "crates.io"
        if base == "pubspec.lock":
            return parse_pubspec_lock(text), [], "Pub"
        if base == "gradle.lockfile":
            return parse_gradle_lockfile(text), [], "Maven"
        if base == "libs.versions.toml":
            return parse_version_catalog(text), [], "Maven"
        if base in ("build.gradle", "build.gradle.kts"):
            return parse_gradle(text), [], "Maven"
        if base == "pom.xml":
            return parse_pom(text), [], "Maven"
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, AttributeError, KeyError, TypeError) as exc:
        raise ManifestError(f"Couldn't read {base}: {exc}")
    raise ManifestError(f"Unsupported file. Upload one of: {', '.join(SUPPORTED_FILES)}.")


def is_manifest(path: str) -> bool:
    base = posixpath.basename(path)
    return base in SUPPORTED_FILES or (base.endswith(".txt") and base.startswith("requirements"))


def collect(files) -> tuple[list[osv.Package], list[str], list[str]]:
    """Find every manifest in a source tree. Returns (packages, loose names, manifest paths).

    package.json only gives ranges, so it's skipped when a lockfile sits next to it.
    """
    paths = {f.path for f in files}
    packages, loose, used = [], [], []
    for file in files:
        if not is_manifest(file.path):
            continue
        folder = posixpath.dirname(file.path)
        if file.name == "package.json" and any(posixpath.join(folder, lock) in paths
                                               for lock in ("package-lock.json", "yarn.lock")):
            continue
        try:
            found, unpinned, _ = parse_manifest(file.path, file.text)
        except ManifestError:
            continue
        if found or unpinned:
            used.append(file.path)
        packages.extend(found)
        loose.extend(unpinned)
    return list(dict.fromkeys(packages))[:MAX_PACKAGES], loose, used


def report_loose(loose: list[str], ecosystem: str, report: Report) -> None:
    if not loose:
        return
    report.add(Finding(
        id="unpinned-dependencies",
        title=f"{len(loose)} dependencies aren't pinned to exact versions",
        severity=Severity.LOW,
        category="Dependency hygiene",
        description="Without exact versions we can't tell what you actually install, and neither can you.",
        evidence=", ".join(loose[:40]),
        impact="Each install can pull a different version, including a newly compromised or vulnerable one.",
        fix="Commit a lockfile and scan that instead.",
        snippets={"npm": "npm install   # creates package-lock.json — commit it"} if ecosystem == "npm" else {
            "pip-tools": "pip install pip-tools\npip-compile requirements.in   # writes pinned requirements.txt",
            "Poetry": "poetry lock",
        },
    ))


async def report_vulnerable(packages: list[osv.Package], report: Report) -> int:
    """Look packages up in OSV and add one finding per vulnerable package. Returns how many were vulnerable."""
    vulnerable = await osv.lookup(packages)
    for package, vulns in vulnerable.items():
        tool, template = INSTALL_HINTS.get(package.ecosystem, ("Upgrade", "Upgrade {name} to {version}"))
        report.add(osv.finding_for(package, vulns, category="Vulnerable dependency", snippets={
            tool: template.replace("{name}", package.name),
        }))
    clean = len(packages) - len(vulnerable)
    if clean:
        report.ok(f"{clean} of {len(packages)} packages have no known vulnerabilities")
    return len(vulnerable)


async def run_dependency_scan(filename: str, text: str) -> dict:
    started = time.monotonic()
    packages, loose, ecosystem = parse_manifest(filename, text)
    packages = list(dict.fromkeys(packages))[:MAX_PACKAGES]
    if not packages and not loose:
        raise ManifestError("No dependencies found in that file.")

    report = Report()
    notes = []
    if posixpath.basename(filename) in ("package.json", "build.gradle", "build.gradle.kts", "pom.xml"):
        notes.append("This file lists version ranges or only some versions, so results may be incomplete. "
                     "Upload your lockfile for exact results.")
    try:
        await report_vulnerable(packages, report)
    except httpx.HTTPError as exc:
        raise ManifestError(f"The vulnerability database didn't respond ({exc.__class__.__name__}). Try again.")
    report_loose(loose, ecosystem, report)

    return summarize(
        report,
        kind="deps",
        target=filename,
        ecosystem=ecosystem,
        packages_scanned=len(packages),
        notes=notes,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
