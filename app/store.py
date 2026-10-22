"""Scan a published app from its App Store or Google Play link.

We cannot download the app binary: neither store offers an API for that, and App Store downloads are
DRM-encrypted anyway. What a store link *does* give us, from sources meant to be read publicly:

  * Apple's iTunes Lookup API (official, documented, no key) for App Store listings.
  * The public Google Play listing page for Android.
  * The developer's App Links files (`assetlinks.json`, `apple-app-site-association`) — published
    specifically so phones can fetch them, and the place deep-link hijacking shows up.

That covers the app's published security posture and its link between app and backend. For issues
inside the binary, the customer uploads a build or scans their source.
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from . import config
from .http_client import FetchError, fetch
from .models import Finding, Report, Severity, summarize

ITUNES_LOOKUP = "https://itunes.apple.com/lookup"
PLAY_DETAILS = "https://play.google.com/store/apps/details"
BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
PLAY_MAX_BYTES = 4_000_000
STALE_DAYS = 365
VERY_STALE_DAYS = 730
# iOS versions still receiving security updates, roughly. Below this, users can't be patched.
MIN_SUPPORTED_IOS = 16

APPLE_ID = re.compile(r"(?:^|/)id(\d{6,})")
PLAY_PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+){1,}$")
COUNTRY = re.compile(r"^/([a-z]{2})/app/")


class StoreError(ValueError):
    pass


@dataclass
class AppListing:
    platform: str  # "ios" or "android"
    app_id: str  # bundle id or package name
    store_id: str  # Apple numeric id, or the package name again
    name: str
    developer: str
    version: str | None = None
    updated: datetime | None = None
    released: datetime | None = None
    min_os: str | None = None
    privacy_policy: str | None = None
    developer_site: str | None = None
    support_email: str | None = None
    store_url: str = ""
    rating: float | None = None
    ratings_count: int | None = None
    installs: str | None = None
    data_safety: list[str] = field(default_factory=list)
    collects_data: bool | None = None

    @property
    def platform_name(self) -> str:
        return "iOS" if self.platform == "ios" else "Android"

    def link_hosts(self) -> list[str]:
        """Hosts that should carry an App Links file: the sites the listing itself links to."""
        found = []
        for url in (self.developer_site, self.privacy_policy):
            host = urlsplit(url).hostname if url else None
            if host and host not in found:
                found.append(host)
        return found

    def domains(self) -> list[str]:
        """Every host the listing points at, as candidates for a full backend scan."""
        found = self.link_hosts()
        if self.support_email and "@" in self.support_email:
            domain = self.support_email.rsplit("@", 1)[1].lower()
            if domain not in found:
                found.append(domain)
        return found


# --- parsing the link the customer pastes ---

def parse_target(raw: str) -> tuple[str, str, str]:
    """Returns (platform, id, country) from a store URL, bundle id or package name."""
    text = (raw or "").strip()
    if not text:
        raise StoreError("Paste your app's App Store or Google Play link.")
    # People paste links with and without the scheme, so treat anything store-shaped as a URL.
    looks_like_url = "://" in text or text.startswith("www.") or "apple.com/" in text or "play.google.com/" in text
    if looks_like_url:
        url = text if "://" in text else "https://" + text
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if host.endswith("apple.com"):
            match = APPLE_ID.search(parts.path) or re.search(r"(?:^|&)id=(\d{6,})", parts.query)
            if not match:
                raise StoreError("That App Store link has no app id in it. It should look like "
                                 "https://apps.apple.com/us/app/name/id123456789")
            country = COUNTRY.match(parts.path)
            return "ios", match.group(1), (country.group(1) if country else "us")
        if host.endswith("play.google.com"):
            match = re.search(r"(?:^|&)id=([A-Za-z0-9_.]+)", parts.query)
            if not match:
                raise StoreError("That Google Play link has no package name in it. It should look like "
                                 "https://play.google.com/store/apps/details?id=com.example.app")
            return "android", match.group(1), "us"
        raise StoreError("Paste a link from apps.apple.com or play.google.com.")
    if text.isdigit() and len(text) >= 6:
        return "ios", text, "us"
    if PLAY_PACKAGE.match(text):
        return "android", text, "us"
    raise StoreError("Paste your app's App Store or Google Play link.")


# --- fetching listings ---

def _as_date(value) -> datetime | None:
    if isinstance(value, (int, float)) and 10**9 < value < 10**10:
        return datetime.fromtimestamp(value, timezone.utc)
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%b %d, %Y"):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


async def fetch_apple(app_id: str, country: str) -> AppListing:
    params = {"id": app_id, "country": country, "entity": "software"}
    try:
        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT, headers={"User-Agent": config.USER_AGENT}) as client:
            response = await client.get(ITUNES_LOOKUP, params=params)
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise StoreError(f"Couldn't reach the App Store ({exc.__class__.__name__}). Try again in a moment.")
    results = payload.get("results") or []
    if not results:
        raise StoreError(f"No app with id {app_id} in the {country.upper()} App Store. "
                         "Check the link, or try the store country the app is published in.")
    app = results[0]
    return AppListing(
        platform="ios",
        app_id=app.get("bundleId") or app_id,
        store_id=app_id,
        name=app.get("trackName") or "Unknown app",
        developer=app.get("sellerName") or app.get("artistName") or "Unknown developer",
        version=app.get("version"),
        updated=_as_date(app.get("currentVersionReleaseDate")),
        released=_as_date(app.get("releaseDate")),
        min_os=app.get("minimumOsVersion"),
        developer_site=app.get("sellerUrl"),
        store_url=app.get("trackViewUrl") or f"https://apps.apple.com/{country}/app/id{app_id}",
        rating=app.get("averageUserRating"),
        ratings_count=app.get("userRatingCount"),
    )


def dig(data, *path, default=None):
    """Index nested lists safely. Google's payload shape shifts, so every lookup has to tolerate misses."""
    node = data
    for key in path:
        try:
            node = node[key]
        except (IndexError, KeyError, TypeError):
            return default
    return node if node is not None else default


def _play_strings(node) -> list[str]:
    out = []
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, list):
        for item in node:
            out.extend(_play_strings(item))
    return out


def parse_play_html(html: str, package: str) -> AppListing:
    blobs = re.findall(r"AF_initDataCallback\((\{.*?\})\);</script>", html, re.S)
    info = None
    for blob in blobs:
        payload = re.search(r"data:(\[.*\])\s*,\s*sideChannel", blob, re.S)
        if not payload:
            continue
        try:
            data = json.loads(payload.group(1))
        except json.JSONDecodeError:
            continue
        candidate = dig(data, 1, 2)
        # The listing blob is a long list whose first entry holds the app title.
        if isinstance(candidate, list) and len(candidate) > 100 and isinstance(dig(candidate, 0, 0), str):
            info = candidate
            break
    if info is None:
        raise StoreError("Google Play didn't return a readable listing for that app. It may be unpublished, "
                         "region-locked, or Play changed its page format.")

    def url_at(index: int) -> str | None:
        value = dig(info, index, 0, 5, 2) or dig(info, index, 5, 2)
        return value if isinstance(value, str) and value.startswith("http") else None

    emails = [s for s in _play_strings(dig(info, 69, default=[]))
              if "@" in s and "." in s and " " not in s and not s.startswith("http")]
    safety = [s for s in _play_strings(dig(info, 136, default=[]))
              if 3 < len(s) < 120 and not s.startswith("http") and "<a href" not in s]

    return AppListing(
        platform="android",
        app_id=package,
        store_id=package,
        name=dig(info, 0, 0, default="Unknown app"),
        developer=dig(info, 68, 0, default=None) or dig(info, 37, 0, default="Unknown developer"),
        version=dig(info, 140, 0, 0, 0),
        updated=_as_date(dig(info, 145, 0, 1, 0)) or _as_date(dig(info, 145, 0, 0)),
        released=_as_date(dig(info, 10, 1, 0)) or _as_date(dig(info, 10, 0)),
        privacy_policy=url_at(99),
        developer_site=url_at(69),
        support_email=emails[0] if emails else None,
        store_url=f"{PLAY_DETAILS}?id={package}",
        rating=dig(info, 51, 0, 0),
        installs=dig(info, 13, 0),
        data_safety=safety,
        collects_data=any("collect" in s.lower() for s in safety),
    )


async def fetch_play(package: str) -> AppListing:
    try:
        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT, headers={"User-Agent": BROWSER_UA},
                                     follow_redirects=True) as client:
            async with client.stream("GET", PLAY_DETAILS, params={"id": package, "hl": "en", "gl": "us"}) as response:
                if response.status_code == 404:
                    raise StoreError(f"Google Play has no app with the package name {package}.")
                response.raise_for_status()
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > PLAY_MAX_BYTES:
                        break
                    chunks.append(chunk)
        html = b"".join(chunks).decode("utf-8", errors="replace")
    except httpx.HTTPError as exc:
        raise StoreError(f"Couldn't reach Google Play ({exc.__class__.__name__}). Try again in a moment.")
    return parse_play_html(html, package)


# --- App Links: the public files that tie an app to its domain ---

@dataclass
class LinkFile:
    url: str
    found: bool
    matches_app: bool = False
    detail: str = ""
    wide_open: bool = False


async def check_app_links(listing: AppListing, host: str) -> LinkFile:
    """Fetch the domain's App Links file. Phones fetch these too; they're published to be read."""
    path = ("/.well-known/assetlinks.json" if listing.platform == "android"
            else "/.well-known/apple-app-site-association")
    url = f"https://{host}{path}"
    try:
        result = await fetch(url, same_host_only=True)
    except FetchError as exc:
        return LinkFile(url, found=False, detail=str(exc))
    if result.status != 200 or not result.body.strip():
        return LinkFile(url, found=False, detail=f"HTTP {result.status}")
    try:
        data = json.loads(result.body)
    except json.JSONDecodeError:
        return LinkFile(url, found=True, detail="the file isn't valid JSON, so phones will ignore it")

    if listing.platform == "android":
        packages = [dig(entry, "target", "package_name") for entry in data] if isinstance(data, list) else []
        has_fingerprints = any(dig(entry, "target", "sha256_cert_fingerprints") for entry in data) \
            if isinstance(data, list) else False
        matches = listing.app_id in [p for p in packages if p]
        detail = "" if has_fingerprints else "no signing-certificate fingerprints are listed"
        return LinkFile(url, found=True, matches_app=matches, detail=detail)

    details = dig(data, "applinks", "details", default=[])
    app_ids = []
    paths = []
    for entry in details if isinstance(details, list) else []:
        app_ids += [a for a in (entry.get("appIDs") or []) if isinstance(a, str)]
        if isinstance(entry.get("appID"), str):
            app_ids.append(entry["appID"])
        paths += [p for p in (entry.get("paths") or []) if isinstance(p, str)]
        for component in entry.get("components") or []:
            if isinstance(component, dict) and isinstance(component.get("/"), str):
                paths.append(component["/"])
    matches = any(app_id.endswith("." + listing.app_id) or app_id == listing.app_id for app_id in app_ids)
    return LinkFile(url, found=True, matches_app=matches, wide_open=any(p.strip() in ("*", "/*") for p in paths))


# --- checks ---

PRIVACY_SNIPPETS = {
    "App Store Connect": "App Store Connect → your app → App Privacy → Privacy Policy URL.\n"
                         "Apple requires a reachable HTTPS privacy policy for every app.",
    "Play Console": "Play Console → Policy → App content → Privacy policy.\n"
                    "Google requires a reachable HTTPS privacy policy for every app.",
}


async def check_privacy_policy(listing: AppListing, report: Report) -> None:
    url = listing.privacy_policy
    if not url:
        if listing.platform == "ios":
            return  # Apple's public API doesn't expose it, so its absence here proves nothing
        report.add(Finding(
            id="store-no-privacy-policy",
            title="No privacy policy link on the store listing",
            severity=Severity.HIGH,
            category="App store listing",
            description="The Google Play listing doesn't link to a privacy policy.",
            impact="Both app stores require one for any app that handles user data, and privacy law in the "
                   "EU, UK, California and elsewhere requires it too. Apps get removed over this.",
            fix="Publish a privacy policy at a stable HTTPS address and add the link in Play Console.",
            snippets={"Play Console": PRIVACY_SNIPPETS["Play Console"]},
        ))
        return

    if url.startswith("http://"):
        report.add(Finding(
            id="store-privacy-policy-http",
            title="Privacy policy link uses plain HTTP",
            severity=Severity.MEDIUM,
            category="App store listing",
            description=f"The listing points at {url}, which isn't encrypted.",
            evidence=url,
            impact="Anyone on the user's network can alter what your privacy policy appears to say, and "
                   "browsers mark the page 'Not secure', which undermines trust at the moment users check it.",
            fix="Serve the policy over HTTPS and update the link in your store listing.",
        ))

    try:
        result = await fetch(url)
        reachable, status = result.status < 400, result.status
    except FetchError as exc:
        reachable, status = False, str(exc)
    if reachable:
        report.ok("Privacy policy link is reachable")
    else:
        report.add(Finding(
            id="store-privacy-policy-broken",
            title="Privacy policy link is broken",
            severity=Severity.HIGH,
            category="App store listing",
            description=f"The privacy policy URL on your listing didn't load ({status}).",
            evidence=url,
            impact="A dead privacy policy link is grounds for removal from both stores, and it breaks the "
                   "disclosure that data protection law requires.",
            fix="Fix or replace the URL in your store listing so it loads over HTTPS.",
            snippets=PRIVACY_SNIPPETS,
        ))


def check_freshness(listing: AppListing, report: Report) -> None:
    if listing.updated is None:
        return
    days = (datetime.now(timezone.utc) - listing.updated).days
    when = listing.updated.date().isoformat()
    if days < STALE_DAYS:
        report.ok(f"App was updated recently ({when})")
        return
    very = days >= VERY_STALE_DAYS
    report.add(Finding(
        id="store-stale-release",
        title=f"App hasn't been updated in {days // 30} months",
        severity=Severity.HIGH if very else Severity.MEDIUM,
        category="App maintenance",
        description=f"The published version ({listing.version or 'unknown'}) dates from {when}.",
        evidence=f"Last updated {when} · {days} days ago",
        impact="Every SDK compiled into that build is frozen at its state back then. Vulnerabilities found "
               "since are still shipping to every user, and neither store patches apps for you. Stores also "
               "remove apps that fall behind their target-API requirements.",
        fix="Rebuild with current dependencies and publish an update. Scan your source or a fresh build here "
            "to see which libraries are affected.",
        snippets={
            "Android": "./gradlew dependencyUpdates   # com.github.ben-manes.versions\n"
                       "# then rebuild and upload to Play Console",
            "iOS": "# Swift Package Manager\nswift package update\n# CocoaPods\npod update",
        },
    ))


def check_min_os(listing: AppListing, report: Report) -> None:
    if listing.platform != "ios" or not listing.min_os:
        return
    try:
        major = int(str(listing.min_os).split(".")[0])
    except ValueError:
        return
    if major >= MIN_SUPPORTED_IOS:
        report.ok(f"Requires iOS {listing.min_os} or later")
        return
    report.add(Finding(
        id="store-old-min-os",
        title=f"App still supports iOS {listing.min_os}",
        severity=Severity.LOW,
        category="App configuration",
        description=f"The listing says the app runs on iOS {listing.min_os} and up.",
        evidence=f"minimumOsVersion: {listing.min_os}",
        impact="Apple no longer ships security fixes for those versions, so some of your users are on an "
               "operating system with publicly known, unpatched vulnerabilities. It also stops you relying "
               "on newer platform protections.",
        fix=f"Raise the deployment target to iOS {MIN_SUPPORTED_IOS} or later once your analytics show few "
            "users left behind.",
        snippets={"Xcode": "Target → General → Minimum Deployments → iOS 16.0"},
    ))


def check_data_safety(listing: AppListing, report: Report) -> None:
    if listing.platform != "android":
        return
    if not listing.data_safety:
        report.add(Finding(
            id="store-no-data-safety",
            title="No Data safety information on the listing",
            severity=Severity.MEDIUM,
            category="App store listing",
            description="Google Play didn't show a completed Data safety section for this app.",
            impact="The Data safety form is mandatory. An incomplete or missing one blocks updates and can "
                   "get the app removed, and users see a warning instead of your disclosures.",
            fix="Complete Play Console → Policy → App content → Data safety.",
        ))
        return
    labels = " ".join(listing.data_safety).lower()
    report.ok("Data safety section is filled in")
    if "encrypted in transit" not in labels:
        report.add(Finding(
            id="store-no-transit-encryption",
            title="Listing doesn't declare that data is encrypted in transit",
            severity=Severity.HIGH,
            category="App store listing",
            description="The Data safety section doesn't include \"Data is encrypted in transit\".",
            evidence="\n".join(listing.data_safety),
            impact="Either the app really does send user data unencrypted, in which case anyone on the same "
                   "network can read it, or the declaration is wrong, which is a policy violation. Both are "
                   "worth fixing before a reviewer notices.",
            fix="Send everything over HTTPS/TLS, then tick \"Data is encrypted in transit\" in the Data "
                "safety form. Check for `http://` endpoints by scanning your source or a build here.",
        ))
    if "delet" not in labels:
        report.add(Finding(
            id="store-no-deletion-path",
            title="No way for users to request data deletion",
            severity=Severity.LOW,
            category="App store listing",
            description="The Data safety section doesn't mention users being able to request deletion.",
            impact="GDPR and similar laws give users a deletion right, and Google requires apps with accounts "
                   "to offer account deletion. Missing it risks both enforcement and removal.",
            fix="Add in-app account deletion and a web deletion request form, then declare it in Play Console.",
        ))


def check_app_links_result(listing: AppListing, host: str, link: LinkFile, report: Report) -> None:
    kind = "assetlinks.json" if listing.platform == "android" else "apple-app-site-association"
    if not link.found:
        report.add(Finding(
            id=f"store-applinks-missing-{host}",
            title=f"No App Links file on {host}",
            severity=Severity.MEDIUM,
            category="Deep links",
            description=f"We couldn't load {link.url} ({link.detail}).",
            evidence=link.url,
            impact="Without this file the operating system can't confirm that your app owns your links, so "
                   "your https:// links open in the browser instead of your app — and on Android another app "
                   "can register the same links and intercept them, including password-reset and "
                   "email-confirmation links.",
            fix=f"Publish {kind} over HTTPS at that exact path, served as application/json with no redirect.",
            snippets={
                "assetlinks.json (Android)": json.dumps([{
                    "relation": ["delegate_permission/common.handle_all_urls"],
                    "target": {"namespace": "android_app", "package_name": listing.app_id,
                               "sha256_cert_fingerprints": ["<your release signing SHA-256>"]},
                }], indent=2),
                "apple-app-site-association (iOS)": json.dumps({
                    "applinks": {"details": [{"appIDs": ["<TEAMID>." + listing.app_id],
                                              "components": [{"/": "/app/*"}]}]},
                }, indent=2),
                "Verify": f"# Android\nadb shell pm verify-app-links --re-verify {listing.app_id}\n"
                          f"# Both\ncurl -sI https://{host}/.well-known/{kind}",
            },
        ))
        return

    report.ok(f"App Links file published on {host}")
    if not link.matches_app:
        report.add(Finding(
            id=f"store-applinks-mismatch-{host}",
            title=f"App Links file on {host} doesn't list this app",
            severity=Severity.MEDIUM,
            category="Deep links",
            description=f"{link.url} exists but doesn't name {listing.app_id}.",
            evidence=link.url,
            impact="Link verification fails, so your links won't open your app — and on Android the "
                   "unverified namespace can be claimed by another app.",
            fix=f"Add {listing.app_id} to the file, with the release signing fingerprint on Android or the "
                "Team ID prefix on iOS.",
        ))
    if link.detail:
        report.add(Finding(
            id=f"store-applinks-weak-{host}",
            title=f"App Links file on {host} is incomplete",
            severity=Severity.LOW,
            category="Deep links",
            description=f"{link.url}: {link.detail}.",
            evidence=link.url,
            impact="Android can't verify the link without the signing fingerprint, so the app won't be "
                   "granted the domain.",
            fix="Add the SHA-256 fingerprint of your release signing certificate.",
            snippets={"Get the fingerprint": "keytool -list -v -keystore release.keystore -alias <alias> | grep SHA256"},
        ))
    if link.wide_open:
        report.add(Finding(
            id=f"store-applinks-wildcard-{host}",
            title=f"App claims every path on {host}",
            severity=Severity.LOW,
            category="Deep links",
            description="The apple-app-site-association file matches all paths with a bare wildcard.",
            evidence=link.url,
            impact="Every link on the domain is routed into the app, including admin, billing and "
                   "password-reset pages the app was never designed to handle. Any screen that acts on a "
                   "URL it didn't expect becomes reachable from any website.",
            fix="List the specific path prefixes the app handles instead of \"*\".",
            snippets={"apple-app-site-association": json.dumps(
                {"applinks": {"details": [{"appIDs": ["<TEAMID>." + listing.app_id],
                                           "components": [{"/": "/share/*"}, {"/": "/invite/*"}]}]}}, indent=2)},
        ))


def report_backend(listing: AppListing, hosts: list[str], report: Report) -> None:
    if not hosts:
        return
    report.add(Finding(
        id="store-backend-next-step",
        title="Scan the servers this app talks to",
        severity=Severity.INFO,
        category="Next step",
        description="Your listing points at these domains: " + ", ".join(hosts) + ".",
        evidence="\n".join(f"https://{host}" for host in hosts),
        impact="Most real-world damage in mobile apps happens on the server, not in the app: APIs that "
               "don't check who's calling, data belonging to other users, missing rate limits. A store "
               "listing can't show any of that.",
        fix="Run a website scan on each domain you own. You'll verify ownership once, then get the full "
            "set of transport, header, cookie and DNS checks.",
    ))


# --- runner ---

async def run_store_scan(raw_target: str) -> dict:
    started = time.monotonic()
    platform, identifier, country = parse_target(raw_target)
    listing = await (fetch_apple(identifier, country) if platform == "ios" else fetch_play(identifier))

    report = Report()
    link_hosts = listing.link_hosts()[:2]
    results = await asyncio.gather(
        check_privacy_policy(listing, report),
        *(check_app_links(listing, host) for host in link_hosts),
        return_exceptions=True,
    )
    for host, link in zip(link_hosts, results[1:]):
        if isinstance(link, LinkFile):
            check_app_links_result(listing, host, link, report)
    hosts = listing.domains()[:4]

    check_freshness(listing, report)
    check_min_os(listing, report)
    check_data_safety(listing, report)

    if listing.developer_site and listing.developer_site.startswith("http://"):
        report.add(Finding(
            id="store-developer-site-http",
            title="Developer website link uses plain HTTP",
            severity=Severity.LOW,
            category="App store listing",
            description=f"Your listing links to {listing.developer_site}.",
            evidence=listing.developer_site,
            impact="Users who tap it get an unencrypted page that can be modified in transit, and browsers "
                   "label it 'Not secure' right next to your app's name.",
            fix="Serve the site over HTTPS and update the link in your store listing.",
        ))

    report_backend(listing, hosts, report)

    notes = [
        f"This scan reads what {listing.platform_name} publishes about your app, plus the App Links files on "
        "your own domains. Neither store lets anyone download an app binary through an API"
        + (", and App Store downloads are encrypted." if platform == "ios" else ".")
        + " To check the code itself, upload a build or scan your source.",
    ]
    if platform == "android":
        notes.append("Google Play no longer publishes the minimum Android version on web listings, so that "
                     "check only runs on uploaded builds.")

    return summarize(
        report,
        kind="store",
        target=listing.store_url or raw_target,
        app_name=listing.name,
        app_id=listing.app_id,
        developer=listing.developer,
        app_version=listing.version,
        platforms=[listing.platform_name],
        last_updated=listing.updated.date().isoformat() if listing.updated else None,
        backend_domains=hosts,
        notes=notes,
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
