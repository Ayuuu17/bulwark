import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import store
from app.models import Report, Severity
from app.store import AppListing, LinkFile, StoreError, parse_target

NOW = datetime.now(timezone.utc)


def listing(**kwargs) -> AppListing:
    base = dict(platform="android", app_id="com.example.app", store_id="com.example.app",
                name="Example", developer="Example Ltd", version="1.0.0", updated=NOW,
                privacy_policy="https://example.com/privacy", developer_site="https://example.com")
    return AppListing(**{**base, **kwargs})


def ids(report: Report) -> set[str]:
    return {f.id for f in report.findings}


# --- link parsing ---

@pytest.mark.parametrize("raw,expected", [
    ("https://apps.apple.com/us/app/whatsapp-messenger/id310633997", ("ios", "310633997", "us")),
    ("https://apps.apple.com/gb/app/foo/id123456789?mt=8", ("ios", "123456789", "gb")),
    ("apps.apple.com/app/id999888777", ("ios", "999888777", "us")),
    ("https://play.google.com/store/apps/details?id=com.whatsapp", ("android", "com.whatsapp", "us")),
    ("https://play.google.com/store/apps/details?hl=en&id=com.a.b&gl=us", ("android", "com.a.b", "us")),
    ("com.spotify.music", ("android", "com.spotify.music", "us")),
    ("310633997", ("ios", "310633997", "us")),
])
def test_parse_store_links(raw, expected):
    assert parse_target(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "https://example.com/app", "not a link",
                                 "https://apps.apple.com/us/app/whatsapp-messenger",
                                 "https://play.google.com/store/apps/details?hl=en"])
def test_rejects_bad_links(raw):
    with pytest.raises(StoreError):
        parse_target(raw)


# --- listing parsers ---

def test_parse_play_html(monkeypatch):
    info = [None] * 150
    info[0] = ["Example App"]
    info[10] = ["Oct 18, 2020", [1602979200, 0]]
    info[13] = ["1,000,000+", 1000000]
    info[68] = ["Example Ltd"]
    info[69] = [[None, None, None, None, None, [None, None, "http://example.com/"]], ["help@example.com"]]
    info[99] = [[None, None, None, None, None, [None, None, "https://example.com/privacy"]]]
    info[136] = [[None, [1, 0]], [[None, None, "This app may collect these data types"],
                                  [None, None, "Data is encrypted in transit"]]]
    info[140] = [[["4.2.1"]]]
    info[145] = [["Jan 5, 2026", [1767571200, 0]]]
    blob = "AF_initDataCallback({key: 'ds:5', data:" + json.dumps([None, [None, None, info]]) + ", sideChannel: {}});</script>"
    result = store.parse_play_html(blob, "com.example.app")
    assert result.name == "Example App"
    assert result.developer == "Example Ltd"
    assert result.version == "4.2.1"
    assert result.privacy_policy == "https://example.com/privacy"
    assert result.developer_site == "http://example.com/"
    assert result.support_email == "help@example.com"
    assert result.updated.date().isoformat() == "2026-01-05"
    assert "Data is encrypted in transit" in result.data_safety
    assert result.collects_data is True


def test_parse_play_html_without_listing_blob():
    with pytest.raises(StoreError, match="readable listing"):
        store.parse_play_html("<html><body>nothing here</body></html>", "com.example.app")


# --- individual checks ---

def test_stale_app_is_flagged():
    report = Report()
    store.check_freshness(listing(updated=NOW - timedelta(days=800), version="1.0.0"), report)
    finding = report.findings[0]
    assert finding.id == "store-stale-release" and finding.severity == Severity.HIGH

    report = Report()
    store.check_freshness(listing(updated=NOW - timedelta(days=400)), report)
    assert report.findings[0].severity == Severity.MEDIUM

    report = Report()
    store.check_freshness(listing(updated=NOW - timedelta(days=30)), report)
    assert report.findings == [] and report.passed


def test_old_ios_version_flagged_android_ignored():
    report = Report()
    store.check_min_os(listing(platform="ios", min_os="13.0"), report)
    assert "store-old-min-os" in ids(report)

    report = Report()
    store.check_min_os(listing(platform="ios", min_os="17.2"), report)
    assert report.findings == [] and report.passed

    report = Report()
    store.check_min_os(listing(platform="android", min_os="13.0"), report)
    assert report.findings == []  # Play doesn't publish this on the web listing


def test_data_safety_checks():
    report = Report()
    store.check_data_safety(listing(data_safety=[]), report)
    assert "store-no-data-safety" in ids(report)

    report = Report()
    store.check_data_safety(listing(data_safety=["This app may collect these data types", "Location"]), report)
    assert {"store-no-transit-encryption", "store-no-deletion-path"} <= ids(report)

    report = Report()
    store.check_data_safety(listing(data_safety=["Data is encrypted in transit",
                                                 "You can request that data be deleted"]), report)
    assert report.findings == []

    report = Report()
    store.check_data_safety(listing(platform="ios", data_safety=[]), report)
    assert report.findings == []  # Apple's public API carries no equivalent


def test_privacy_policy_checks(monkeypatch):
    async def ok(url, **kwargs):
        return type("R", (), {"status": 200})()

    async def broken(url, **kwargs):
        raise store.FetchError("connection refused")

    monkeypatch.setattr(store, "fetch", ok)
    report = Report()
    asyncio.run(store.check_privacy_policy(listing(privacy_policy="http://example.com/privacy"), report))
    assert "store-privacy-policy-http" in ids(report) and report.passed

    monkeypatch.setattr(store, "fetch", broken)
    report = Report()
    asyncio.run(store.check_privacy_policy(listing(), report))
    assert "store-privacy-policy-broken" in ids(report)

    report = Report()
    asyncio.run(store.check_privacy_policy(listing(privacy_policy=None), report))
    assert "store-no-privacy-policy" in ids(report)

    report = Report()
    asyncio.run(store.check_privacy_policy(listing(platform="ios", privacy_policy=None), report))
    assert report.findings == []  # Apple's API doesn't expose it, so silence proves nothing


# --- App Links ---

def fake_fetch(body: str, status: int = 200):
    async def _fetch(url, **kwargs):
        return type("R", (), {"status": status, "body": body})()
    return _fetch


def test_android_assetlinks_match(monkeypatch):
    good = json.dumps([{"relation": ["delegate_permission/common.handle_all_urls"],
                        "target": {"namespace": "android_app", "package_name": "com.example.app",
                                   "sha256_cert_fingerprints": ["AB:CD"]}}])
    monkeypatch.setattr(store, "fetch", fake_fetch(good))
    link = asyncio.run(store.check_app_links(listing(), "example.com"))
    assert link.found and link.matches_app and not link.detail


def test_android_assetlinks_wrong_package_and_no_fingerprint(monkeypatch):
    bad = json.dumps([{"target": {"namespace": "android_app", "package_name": "com.other.app"}}])
    monkeypatch.setattr(store, "fetch", fake_fetch(bad))
    link = asyncio.run(store.check_app_links(listing(), "example.com"))
    report = Report()
    store.check_app_links_result(listing(), "example.com", link, report)
    assert {"store-applinks-mismatch-example.com", "store-applinks-weak-example.com"} <= ids(report)


def test_ios_aasa_wildcard_paths(monkeypatch):
    aasa = json.dumps({"applinks": {"details": [{"appIDs": ["TEAM123.com.example.app"], "paths": ["*"]}]}})
    monkeypatch.setattr(store, "fetch", fake_fetch(aasa))
    app = listing(platform="ios")
    link = asyncio.run(store.check_app_links(app, "example.com"))
    assert link.matches_app and link.wide_open
    report = Report()
    store.check_app_links_result(app, "example.com", link, report)
    assert "store-applinks-wildcard-example.com" in ids(report)


def test_ios_aasa_components_form(monkeypatch):
    aasa = json.dumps({"applinks": {"details": [
        {"appID": "TEAM123.com.example.app", "components": [{"/": "/invite/*"}]}]}})
    monkeypatch.setattr(store, "fetch", fake_fetch(aasa))
    link = asyncio.run(store.check_app_links(listing(platform="ios"), "example.com"))
    assert link.matches_app and not link.wide_open


def test_missing_app_links_file(monkeypatch):
    monkeypatch.setattr(store, "fetch", fake_fetch("", status=404))
    link = asyncio.run(store.check_app_links(listing(), "example.com"))
    report = Report()
    store.check_app_links_result(listing(), "example.com", link, report)
    finding = next(f for f in report.findings if f.id.startswith("store-applinks-missing"))
    assert finding.severity == Severity.MEDIUM
    assert "assetlinks.json (Android)" in finding.snippets


def test_malformed_app_links_json(monkeypatch):
    monkeypatch.setattr(store, "fetch", fake_fetch("not json at all"))
    link = asyncio.run(store.check_app_links(listing(), "example.com"))
    assert link.found and not link.matches_app and "isn't valid JSON" in link.detail


# --- full run ---

def test_full_store_scan(monkeypatch):
    async def fake_apple(app_id, country):
        return listing(platform="ios", app_id="com.example.app", store_id=app_id, name="Example",
                       min_os="12.0", updated=NOW - timedelta(days=900),
                       developer_site="http://example.com", privacy_policy=None,
                       store_url="https://apps.apple.com/us/app/example/id123456789")
    monkeypatch.setattr(store, "fetch_apple", fake_apple)
    monkeypatch.setattr(store, "fetch", fake_fetch("", status=404))

    result = asyncio.run(store.run_store_scan("https://apps.apple.com/us/app/example/id123456789"))
    found = {f["id"] for f in result["findings"]}
    assert {"store-stale-release", "store-old-min-os", "store-developer-site-http",
            "store-applinks-missing-example.com", "store-backend-next-step"} <= found
    assert result["kind"] == "store"
    assert result["app_name"] == "Example" and result["platforms"] == ["iOS"]
    assert result["backend_domains"] == ["example.com"]
    assert any("encrypted" in note for note in result["notes"])  # honest about the binary
    assert result["grade"] in {"C", "D", "F"}


def test_store_scan_surfaces_unknown_app(monkeypatch):
    async def missing(app_id, country):
        raise StoreError("No app with id 1 in the US App Store.")
    monkeypatch.setattr(store, "fetch_apple", missing)
    with pytest.raises(StoreError):
        asyncio.run(store.run_store_scan("https://apps.apple.com/us/app/x/id1234567"))
