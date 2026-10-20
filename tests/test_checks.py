import asyncio

import httpx
import pytest

from app import config
from app.checks import cookies, headers
from app.checks.content import detect_libraries
from app.checks.context import ScanContext
from app.checks.dns_email import org_domain
from app.deps import ManifestError, parse_manifest
from app.http_client import FetchResult
from app.models import Report, Severity
from app.osv import Package, version_key
from app.safety import UnsafeTargetError, assert_safe_host, is_private_address, normalize_url


def make_ctx(header_map: dict, cookies_raw=(), url="https://example.com/") -> ScanContext:
    result = FetchResult(url=url, status=200, headers=httpx.Headers(header_map), body="",
                         set_cookies=list(cookies_raw))
    return ScanContext(target=url, host="example.com", port=None, scheme="https", ips=["93.184.215.14"],
                       primary=result, https=result, https_error=None, http=None)


def run(check, ctx) -> Report:
    report = Report()
    asyncio.run(check(ctx, report))
    return report


def ids(report: Report) -> set[str]:
    return {f.id for f in report.findings}


# --- safety ---

def test_normalize_adds_scheme_and_strips_fragment():
    assert normalize_url("Example.com") == "https://example.com/"
    assert normalize_url("http://example.com:8080/a?b=1#frag") == "http://example.com:8080/a?b=1"


@pytest.mark.parametrize("bad", ["", "ftp://example.com", "javascript:alert(1)", "https://user:pw@example.com"])
def test_normalize_rejects_bad_urls(bad):
    with pytest.raises(UnsafeTargetError):
        normalize_url(bad)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "100.64.0.1",
                                "::ffff:127.0.0.1", "0.0.0.0"])
def test_private_addresses_detected(ip):
    assert is_private_address(ip)


def test_public_address_allowed():
    assert not is_private_address("8.8.8.8")


def test_localhost_blocked_outside_dev_mode(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_PRIVATE_TARGETS", False)
    with pytest.raises(UnsafeTargetError):
        asyncio.run(assert_safe_host("localhost"))


def test_metadata_address_blocked_even_in_dev_mode(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_PRIVATE_TARGETS", True)
    with pytest.raises(UnsafeTargetError):
        asyncio.run(assert_safe_host("169.254.169.254"))


# --- headers ---

def test_missing_headers_reported():
    report = run(headers.check, make_ctx({}))
    assert {"hsts-missing", "csp-missing", "clickjacking", "nosniff-missing", "referrer-policy"} <= ids(report)


def test_good_headers_pass():
    report = run(headers.check, make_ctx({
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
        "Server": "nginx",
    }))
    assert report.findings == []


def test_weak_csp_and_version_leak():
    report = run(headers.check, make_ctx({
        "Content-Security-Policy": "script-src 'self' 'unsafe-inline'",
        "Server": "Apache/2.4.29",
        "X-Powered-By": "PHP/7.2",
    }))
    assert {"csp-weak", "version-disclosure"} <= ids(report)


def test_csp_nonce_allows_unsafe_inline_fallback():
    report = run(headers.check, make_ctx({"Content-Security-Policy": "script-src 'nonce-abc' 'unsafe-inline'"}))
    assert "csp-weak" not in ids(report)


# --- cookies ---

def test_session_cookie_without_flags():
    report = run(cookies.check, make_ctx({}, ["PHPSESSID=abc; path=/"]))
    findings = {f.id: f for f in report.findings}
    assert findings["cookie-no-secure"].severity == Severity.HIGH
    assert "cookie-no-httponly" in findings
    assert "cookie-no-samesite" in findings


def test_safe_cookie_passes():
    report = run(cookies.check, make_ctx({}, ["sid=1; Secure; HttpOnly; SameSite=Lax"]))
    assert report.findings == []


# --- content / libraries ---

def test_detect_libraries_from_cdn_urls():
    found = detect_libraries([
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js",
        "https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js",
        "https://example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1",
        "https://example.com/static/bootstrap-4.1.3.min.js",
        "https://example.com/app.js",
    ])
    assert set(found) == {
        Package("jquery", "1.12.4", "npm"),
        Package("lodash", "4.17.15", "npm"),
        Package("jquery", "3.7.1", "npm"),
        Package("bootstrap", "4.1.3", "npm"),
    }


def test_version_key_ordering():
    assert version_key("4.17.21") > version_key("4.17.4")
    assert version_key("10.0.0") > version_key("9.9.9")


def test_org_domain():
    assert org_domain("www.example.com") == "example.com"
    assert org_domain("shop.example.co.uk") == "example.co.uk"


# --- manifests ---

def test_parse_requirements():
    packages, unpinned, eco = parse_manifest("requirements.txt", "django==3.2.0\nrequests[socks]==2.19.0 ; python_version>'3'\nflask>=2\n# comment\n-r other.txt\n")
    assert eco == "PyPI"
    assert [(p.name, p.version) for p in packages] == [("django", "3.2.0"), ("requests", "2.19.0")]
    assert unpinned == ["flask"]


def test_parse_package_lock_v3():
    text = '{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.15"},' \
           '"node_modules/a/node_modules/@scope/b":{"version":"1.0.0"}}}'
    packages, _, eco = parse_manifest("package-lock.json", text)
    assert eco == "npm"
    assert {(p.name, p.version) for p in packages} == {("lodash", "4.17.15"), ("@scope/b", "1.0.0")}


def test_parse_package_json_ranges():
    packages, skipped, _ = parse_manifest("package.json", '{"dependencies":{"express":"^4.16.0","x":"latest"}}')
    assert [(p.name, p.version) for p in packages] == [("express", "4.16.0")]
    assert skipped == ["x"]


def test_unsupported_manifest():
    with pytest.raises(ManifestError):
        parse_manifest("Gemfile", "gem 'rails'")
