"""App configuration checks: Android manifest & network config, iOS Info.plist, Firebase rules, Dockerfile.

Works on source projects (text files) and on built apps (.apk / .ipa read from the archive).
"""

import plistlib
import re
import xml.etree.ElementTree as ET

from ..models import Finding, Report, Severity
from . import axml, secrets
from .archive import Archive, ArchiveError, SourceFile

SDK_PREFIXES = ("androidx.", "com.google.android.gms.", "com.google.firebase.", "com.android.")
IGNORED_HTTP_HOSTS = re.compile(
    r"^(?:localhost|127\.|10\.|192\.168\.|0\.0\.0\.0|schemas\.|www\.w3\.org|ns\.adobe\.com|purl\.org|"
    r"(?:www\.)?example\.(?:com|org)|www\.apache\.org|xml\.org|java\.sun\.com|xmlpull\.org|apple\.com|www\.apple\.com|"
    r"json-schema\.org|ocsp\.|crl\.|www\.slf4j\.org|.*\.(?:digicert|verisign|entrust|globalsign|thawte)\.(?:com|net))", re.I)
HTTP_URL = re.compile(r"http://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?")
STRINGS = re.compile(rb"[\x20-\x7e]{6,}")
MAX_BINARY_SCAN = 40_000_000

ANDROID_FIX = "In AndroidManifest.xml, inside <application ...>:"


def _a(element: ET.Element, name: str) -> str | None:
    return element.get("android:" + name)


def check_android_manifest(root: ET.Element, path: str, report: Report) -> None:
    app = root.find("application")
    if app is None:
        return
    if _a(app, "debuggable") == "true":
        report.add(Finding(
            id="android-debuggable", title="Android app is debuggable", severity=Severity.HIGH, category="App configuration",
            description="android:debuggable=\"true\" is set on the application.",
            evidence=f"{path}  <application android:debuggable=\"true\">",
            impact="Anyone with the device can attach a debugger, read the app's private data and change its behaviour "
                   "at runtime. Google Play rejects debuggable builds.",
            fix="Remove android:debuggable from the manifest; Gradle sets it correctly per build type.",
            snippets={"Manifest": ANDROID_FIX + "\n<!-- delete: android:debuggable=\"true\" -->"},
        ))
    if _a(app, "usesCleartextTraffic") == "true":
        report.add(Finding(
            id="android-cleartext", title="Android app allows unencrypted HTTP traffic", severity=Severity.MEDIUM,
            category="App configuration",
            description="android:usesCleartextTraffic=\"true\" lets the app send requests over plain HTTP.",
            evidence=f"{path}  <application android:usesCleartextTraffic=\"true\">",
            impact="Traffic on public Wi-Fi can be read and modified, including API tokens and user data.",
            fix="Set it to false (the default since Android 9) and use HTTPS for every endpoint.",
            snippets={"Manifest": ANDROID_FIX + "\nandroid:usesCleartextTraffic=\"false\""},
        ))
    if _a(app, "allowBackup") == "true":
        report.add(Finding(
            id="android-allow-backup", title="App data can be extracted via backups", severity=Severity.LOW,
            category="App configuration",
            description="android:allowBackup=\"true\" includes the app's private data in device backups.",
            evidence=f"{path}  <application android:allowBackup=\"true\">",
            impact="Tokens and local databases can be pulled off a device with adb backup or restored onto another device.",
            fix="Set allowBackup to false, or exclude sensitive files with dataExtractionRules / fullBackupContent.",
            snippets={"Manifest": ANDROID_FIX + "\nandroid:allowBackup=\"false\""},
        ))

    uses_sdk = root.find("uses-sdk")
    min_sdk = _a(uses_sdk, "minSdkVersion") if uses_sdk is not None else None
    if min_sdk and min_sdk.isdigit():
        report_min_sdk(int(min_sdk), path, report)

    exposed, providers = [], []
    for component in app:
        if component.tag not in ("activity", "activity-alias", "service", "receiver", "provider"):
            continue
        name = _a(component, "name") or "?"
        if name.startswith(SDK_PREFIXES):
            continue
        filters = component.findall("intent-filter")
        exported = _a(component, "exported")
        if exported == "false" or (exported is None and not filters):
            continue
        if _a(component, "permission") or _a(component, "readPermission") or _a(component, "writePermission"):
            continue
        is_launcher = any(
            any(_a(a, "name") == "android.intent.action.MAIN" for a in f.findall("action"))
            and any(_a(c, "name") == "android.intent.category.LAUNCHER" for c in f.findall("category"))
            for f in filters)
        if is_launcher:
            continue
        (providers if component.tag == "provider" else exposed).append(f"{path}  <{component.tag}> {name}")

    if providers:
        report.add(Finding(
            id="android-exported-provider", title="Content provider is open to other apps", severity=Severity.HIGH,
            category="App configuration",
            description="A content provider is exported without any permission.",
            evidence="\n".join(providers[:20]),
            impact="Any app on the device can query (and possibly modify) the data it exposes, which is often the "
                   "app's database.",
            fix="Set android:exported=\"false\", or protect it with a signature-level permission.",
            snippets={"Manifest": "<provider android:name=\".MyProvider\"\n    android:exported=\"false\" ... />"},
        ))
    if exposed:
        report.add(Finding(
            id="android-exported-components", title=f"{len(exposed)} app components can be started by other apps",
            severity=Severity.LOW, category="App configuration",
            description="These activities/services/receivers are exported without a permission.",
            evidence="\n".join(exposed[:25]),
            impact="Other apps (including malicious ones) can launch them with crafted data. That's fine for deep "
                   "links, but every input they accept must be validated.",
            fix="Set android:exported=\"false\" on anything that doesn't need to be reachable from outside, and validate "
                "all intent data in the ones that do.",
        ))


def report_min_sdk(min_sdk: int, path: str, report: Report) -> None:
    if min_sdk >= 23:
        return
    report.add(Finding(
        id="android-old-min-sdk", title=f"App supports very old Android versions (minSdk {min_sdk})",
        severity=Severity.LOW, category="App configuration",
        description="Android versions below 6.0 (API 23) no longer receive security updates.",
        evidence=f"{path}  minSdk {min_sdk}",
        impact="Users on these versions are exposed to known OS vulnerabilities, and you can't use modern "
               "protections like runtime permissions or the hardware-backed Keystore everywhere.",
        fix="Raise minSdk to at least 23 (most apps now target 24+).",
        snippets={"build.gradle": "android {\n    defaultConfig {\n        minSdk 24\n    }\n}"},
    ))


def check_network_config(root: ET.Element, path: str, report: Report) -> None:
    if root.tag != "network-security-config":
        return
    base = root.find("base-config")
    if base is not None and base.get("cleartextTrafficPermitted") == "true":
        report.add(Finding(
            id="android-nsc-cleartext", title="Network security config allows HTTP everywhere", severity=Severity.MEDIUM,
            category="App configuration",
            description="base-config sets cleartextTrafficPermitted=\"true\".",
            evidence=f"{path}  <base-config cleartextTrafficPermitted=\"true\">",
            impact="Every connection the app makes may fall back to unencrypted HTTP.",
            fix="Remove it, and if one legacy host truly needs HTTP, allow only that domain in a <domain-config>.",
        ))
    for anchors in root.iter("trust-anchors"):
        parent_is_debug = any(anchors in list(d.iter()) for d in root.findall("debug-overrides"))
        if not parent_is_debug and any(c.get("src") == "user" for c in anchors.findall("certificates")):
            report.add(Finding(
                id="android-nsc-user-ca", title="App trusts user-installed certificates", severity=Severity.MEDIUM,
                category="App configuration",
                description="The release network config trusts certificate authorities added by the user.",
                evidence=f"{path}  <certificates src=\"user\" />",
                impact="Anyone who gets a user to install a certificate (or controls a managed device) can intercept "
                       "and read the app's HTTPS traffic.",
                fix="Move <certificates src=\"user\"/> into <debug-overrides> so it only applies to debug builds.",
            ))
            break


def check_info_plist(plist: dict, path: str, report: Report) -> None:
    ats = plist.get("NSAppTransportSecurity") or {}
    if ats.get("NSAllowsArbitraryLoads") is True:
        report.add(Finding(
            id="ios-ats-disabled", title="iOS App Transport Security is turned off", severity=Severity.MEDIUM,
            category="App configuration",
            description="NSAllowsArbitraryLoads is true, so the app may load anything over plain HTTP.",
            evidence=f"{path}  NSAppTransportSecurity → NSAllowsArbitraryLoads = true",
            impact="Network traffic can be read and modified on untrusted networks. Apple also asks for a "
                   "justification during App Review.",
            fix="Remove NSAllowsArbitraryLoads and move every endpoint to HTTPS. If one legacy domain must use HTTP, "
                "add a narrow NSExceptionDomains entry for it.",
            snippets={"Info.plist": "<key>NSAppTransportSecurity</key>\n<dict>\n  <!-- remove NSAllowsArbitraryLoads -->\n</dict>"},
        ))
    insecure = [domain for domain, cfg in (ats.get("NSExceptionDomains") or {}).items()
                if isinstance(cfg, dict) and (cfg.get("NSExceptionAllowsInsecureHTTPLoads") or
                                              cfg.get("NSTemporaryExceptionAllowsInsecureHTTPLoads"))]
    if insecure:
        report.add(Finding(
            id="ios-ats-exceptions", title="iOS app allows HTTP for some domains", severity=Severity.LOW,
            category="App configuration",
            description="App Transport Security exceptions allow plain HTTP for these domains.",
            evidence="\n".join(f"{path}  {d}" for d in insecure[:20]),
            impact="Traffic to these domains is unencrypted.",
            fix="Enable HTTPS on these servers and remove the exceptions.",
        ))
    schemes = [s for t in plist.get("CFBundleURLTypes") or [] if isinstance(t, dict)
               for s in t.get("CFBundleURLSchemes") or []]
    if schemes:
        report.add(Finding(
            id="ios-url-schemes", title="Custom URL schemes accept links from any app", severity=Severity.INFO,
            category="App configuration",
            description="These schemes can be opened by any app or website: " + ", ".join(schemes[:10]) + ".",
            evidence=f"{path}  CFBundleURLSchemes",
            impact="Deep-link handlers that act on parameters without checking them can be abused (e.g. to trigger "
                   "actions or leak tokens). Other apps can also register the same scheme.",
            fix="Validate every deep-link parameter, never pass tokens through custom schemes, and prefer Universal "
                "Links for anything sensitive.",
        ))


FIREBASE_OPEN = re.compile(r"\"\.(?:read|write)\"\s*:\s*(?:true|\"true\")")
RULES_OPEN = re.compile(r"allow\s+[\w\s,]+(?::\s*if\s+true\s*;|;)|allow\s+[\w\s,]+:\s*if\s+request\.time\s*<")


def check_firebase_rules(file: SourceFile, report: Report) -> None:
    pattern = FIREBASE_OPEN if file.name.endswith(".json") else RULES_OPEN
    lines = [f"{file.path}:{n}  {line.strip()}" for n, line in enumerate(file.text.splitlines(), 1)
             if pattern.search(line)]
    if lines:
        report.add(Finding(
            id=f"firebase-open-{file.name}", title="Firebase database/storage is open to everyone",
            severity=Severity.CRITICAL, category="Backend configuration",
            description="Security rules allow reads or writes without any authentication check (or are still in "
                        "\"test mode\").",
            evidence="\n".join(lines[:15]),
            impact="Anyone who knows your project ID (it's inside your app) can read, change or delete all of this "
                   "data. Open Firebase databases are one of the most common causes of mobile app data leaks.",
            fix="Require authentication and limit each user to their own data.",
            snippets={
                "Firestore": "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n"
                             "    match /users/{userId}/{document=**} {\n"
                             "      allow read, write: if request.auth != null && request.auth.uid == userId;\n"
                             "    }\n  }\n}",
                "Realtime Database": "{\n  \"rules\": {\n    \"users\": {\n      \"$uid\": {\n"
                                     "        \".read\": \"auth != null && auth.uid === $uid\",\n"
                                     "        \".write\": \"auth != null && auth.uid === $uid\"\n      }\n    }\n  }\n}",
            },
        ))


def check_dockerfile(file: SourceFile, report: Report) -> None:
    instructions = [line.strip() for line in file.text.splitlines() if line.strip() and not line.strip().startswith("#")]
    users = [i for i in instructions if i.upper().startswith("USER ")]
    if not users or users[-1].split()[1] in ("root", "0"):
        report.add(Finding(
            id=f"docker-root-{file.path}", title="Container runs as root", severity=Severity.LOW,
            category="Infrastructure",
            description=f"{file.path} never switches to a non-root user.",
            evidence=file.path,
            impact="If the app is compromised, the attacker is root inside the container, which makes escaping to "
                   "the host far easier.",
            fix="Create an unprivileged user and switch to it before the CMD.",
            snippets={"Dockerfile": "RUN addgroup --system app && adduser --system --ingroup app app\nUSER app"},
        ))
    baked = [i for i in instructions if re.match(r"(?i)^(?:ENV|ARG)\s+\S*(?:PASSWORD|SECRET|TOKEN|API_?KEY)\S*[= ]\S+", i)]
    if baked:
        report.add(Finding(
            id=f"docker-secrets-{file.path}", title="Secrets baked into the Docker image", severity=Severity.MEDIUM,
            category="Infrastructure",
            description="ENV/ARG instructions set secret-looking values at build time.",
            evidence="\n".join(f"{file.path}  {re.sub(r'([=\s])(\S{4})\S+$', r'\1\2…', b)}" for b in baked[:10]),
            impact="Anyone who can pull the image can read them with docker history / inspect.",
            fix="Pass secrets at runtime (environment variables from your platform, Docker secrets, or a secrets "
                "manager), not in the Dockerfile.",
        ))


def scan_source(files: list[SourceFile], report: Report) -> list[str]:
    """Checks app/infra config files in a source tree. Returns detected platforms."""
    platforms = set()
    for file in files:
        try:
            if file.name == "AndroidManifest.xml":
                platforms.add("Android")
                check_android_manifest(axml.from_text(file.text), file.path, report)
            elif file.ext == ".xml" and "network-security-config" in file.text:
                check_network_config(axml.from_text(file.text), file.path, report)
            elif file.name == "Info.plist" and "/Pods/" not in file.path:
                platforms.add("iOS")
                if "<!DOCTYPE" in file.text and "<!ENTITY" in file.text:
                    continue
                check_info_plist(plistlib.loads(file.text.encode()), file.path, report)
            elif file.name in ("build.gradle", "build.gradle.kts"):
                match = re.search(r"minSdk(?:Version)?\s*(?:=|\s)\s*(\d+)", file.text)
                if match:
                    report_min_sdk(int(match.group(1)), file.path, report)
            elif file.name in ("database.rules.json", "firestore.rules", "storage.rules"):
                platforms.add("Firebase")
                check_firebase_rules(file, report)
            elif file.name == "Dockerfile" or file.name.startswith("Dockerfile."):
                check_dockerfile(file, report)
            elif file.name == "pubspec.yaml":
                platforms.add("Flutter")
            elif file.name == "package.json" and '"react-native"' in file.text:
                platforms.add("React Native")
        except (ET.ParseError, axml.AxmlError, plistlib.InvalidFileException, ValueError):
            continue
    return sorted(platforms)


def _scan_binary(path: str, data: bytes, secret_hits: dict, hosts: dict) -> None:
    text = "\n".join(s.decode("ascii") for s in STRINGS.findall(data[:MAX_BINARY_SCAN]))
    secrets.scan_text(path, text, secret_hits, binary=True, skip_generic=True)
    for host in HTTP_URL.findall(text):
        if not IGNORED_HTTP_HOSTS.match(host):
            hosts.setdefault(host.lower(), set()).add(path)


def report_cleartext_hosts(hosts: dict[str, set[str]], report: Report) -> None:
    if not hosts:
        return
    report.add(Finding(
        id="app-cleartext-hosts", severity=Severity.LOW,
        title=f"App contains plain-HTTP addresses ({len(hosts)} host{'' if len(hosts) == 1 else 's'})",
        category="Insecure transport",
        description="The built app contains http:// URLs for these hosts.",
        evidence="\n".join(f"http://{h}  (in {', '.join(sorted(p)[:2])})" for h, p in sorted(hosts.items())[:30]),
        impact="If the app actually calls these, the traffic can be read or tampered with on the network.",
        fix="Switch them to https://. Some may be harmless leftovers from libraries; check each one.",
    ))


def scan_apk(archive: Archive, report: Report, secret_hits: dict) -> list[str]:
    names = archive.names()
    if "AndroidManifest.xml" not in names:
        raise ArchiveError("This APK has no AndroidManifest.xml.")
    try:
        check_android_manifest(axml.decode(archive.read("AndroidManifest.xml")), "AndroidManifest.xml", report)
    except axml.AxmlError as exc:
        raise ArchiveError(f"Couldn't read the APK's manifest ({exc}).")
    for name in names:
        if name.startswith("res/") and name.endswith(".xml"):
            try:
                check_network_config(axml.decode(archive.read(name, limit=1_000_000)), name, report)
            except (axml.AxmlError, ArchiveError):
                continue

    platforms = ["Android"]
    if "assets/index.android.bundle" in names:
        platforms.append("React Native")
    if any(n.endswith("libflutter.so") for n in names):
        platforms.append("Flutter")
    if any(n.startswith(("assets/www/", "assets/public/")) for n in names):
        platforms.append("Cordova/Capacitor")

    hosts: dict[str, set[str]] = {}
    for name in names:
        if (name.startswith("classes") and name.endswith(".dex")) or name.startswith("assets/") \
                or name.endswith("libapp.so") or name == "res/raw" or name.startswith("res/raw/"):
            try:
                _scan_binary(name, archive.read(name), secret_hits, hosts)
            except ArchiveError:
                continue
    report_cleartext_hosts(hosts, report)
    return platforms


def scan_ipa(archive: Archive, report: Report, secret_hits: dict) -> list[str]:
    names = archive.names()
    info_paths = [n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)]
    if not info_paths:
        raise ArchiveError("This IPA has no Payload/<App>.app/Info.plist.")
    app_dir = info_paths[0].rsplit("/", 1)[0] + "/"
    try:
        plist = plistlib.loads(archive.read(info_paths[0], limit=5_000_000))
    except (plistlib.InvalidFileException, ValueError, ArchiveError) as exc:
        raise ArchiveError(f"Couldn't read Info.plist ({exc}).")
    check_info_plist(plist, info_paths[0], report)

    platforms = ["iOS"]
    executable = plist.get("CFBundleExecutable")
    hosts: dict[str, set[str]] = {}
    for name in names:
        if not name.startswith(app_dir) or "/Frameworks/" in name[len(app_dir):]:
            continue
        relative = name[len(app_dir):]
        if relative == "main.jsbundle":
            platforms.append("React Native")
        is_main_binary = executable and relative == executable
        if is_main_binary or relative.endswith((".plist", ".json", ".jsbundle", ".js", ".strings")) and relative != "Info.plist":
            try:
                _scan_binary(name, archive.read(name), secret_hits, hosts)
            except ArchiveError:
                continue
    report_cleartext_hosts(hosts, report)
    return platforms
