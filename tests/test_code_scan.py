import asyncio
import io
import zipfile

import pytest

from app import config, deps, osv
from app.code import ai_review, axml
from app.code.archive import Archive, ArchiveError, SourceFile
from app.code.engine import run_code_scan
from app.models import Severity
from tests.demo_project import FAKE_AWS_KEY, build_apk, build_ipa, build_source_zip


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    async def no_vulns(packages):
        return {}
    monkeypatch.setattr(osv, "lookup", no_vulns)
    monkeypatch.setattr(config, "AI_ENABLED", False)


def scan(filename: str, data: bytes, ai: bool = False) -> dict:
    return asyncio.run(run_code_scan(filename, data, ai))


def ids(result: dict) -> set[str]:
    return {f["id"] for f in result["findings"]}


def test_source_scan_finds_the_planted_issues():
    result = scan("demo-shop.zip", build_source_zip())
    found = ids(result)
    expected = {
        "secret-aws-access-key", "env-file-committed", "secret-generic-secret",
        "code-sql-injection", "code-command-injection", "code-py-deserialization", "code-py-debug-mode",
        "code-py-tls-disabled", "code-py-weak-random", "code-code-injection", "code-open-redirect",
        "code-cors-credentials-wildcard", "code-jwt-weak", "code-xss-raw-html", "code-insecure-local-storage",
        "code-sensitive-logging", "code-cleartext-url",
        "android-debuggable", "android-cleartext", "android-allow-backup", "android-exported-provider",
        "android-old-min-sdk", "ios-ats-disabled", "ios-url-schemes",
        "firebase-open-firestore.rules", "docker-root-Dockerfile", "docker-secrets-Dockerfile",
    }
    assert expected <= found, expected - found
    assert result["kind"] == "code"
    assert {"Python", "JavaScript", "Java"} <= set(result["languages"])
    assert {"Android", "iOS", "Firebase"} <= set(result["platforms"])
    assert result["packages_scanned"] >= 6  # requirements + package-lock + pubspec + gradle


def test_report_never_contains_full_secrets():
    text = str(scan("demo.zip", build_source_zip()))
    assert FAKE_AWS_KEY not in text
    assert "sk_" + "live_" + "DemoFakeKey0000000000000" not in text


def test_test_files_are_skipped_by_code_rules():
    result = scan("demo.zip", build_source_zip())
    evidence = "\n".join(f["evidence"] for f in result["findings"])
    assert "tests/test_app.py" not in evidence
    assert "demo-shop-main/" not in evidence  # wrapper folder stripped from paths


def test_github_paths_and_line_numbers():
    result = scan("demo.zip", build_source_zip())
    sql = next(f for f in result["findings"] if f["id"] == "code-sql-injection")
    assert "app.py:13" in sql["evidence"] and "server.js:9" in sql["evidence"]


def test_apk_scan():
    result = scan("shop.apk", build_apk())
    assert result["kind"] == "app"
    assert {"android-debuggable", "android-cleartext", "android-exported-provider", "android-old-min-sdk",
            "secret-aws-access-key", "app-cleartext-hosts"} <= ids(result)
    assert "android-exported-components" not in ids(result)  # launcher activity isn't flagged


def test_ipa_scan():
    result = scan("shop.ipa", build_ipa())
    assert {"ios-ats-disabled", "secret-stripe-live"} <= ids(result)


def test_axml_roundtrip():
    from tests.demo_project import encode_axml
    root = axml.decode(encode_axml(("manifest", {}, [("application", {"android:debuggable": "true"}, [])])))
    assert root.find("application").get("android:debuggable") == "true"


@pytest.mark.parametrize("name", ["notes.txt", "app.aab"])
def test_unsupported_uploads(name):
    with pytest.raises(ArchiveError):
        scan(name, b"x")


def test_rejects_non_zip_and_zip_bombs():
    with pytest.raises(ArchiveError):
        Archive(b"not a zip")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.txt", b"\x00" * 50_000_000)
    with pytest.raises(ArchiveError, match="zip bomb"):
        Archive(buffer.getvalue())


def test_path_traversal_names_are_harmless():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("../../etc/evil.py", "eval(input())\n")
    files, _ = Archive(buffer.getvalue()).text_files()
    assert [f.path for f in files] == ["etc/evil.py"]


# --- dependency parsers for app ecosystems ---

def test_more_lockfile_formats():
    cases = {
        "yarn.lock": ('"lodash@^4.17.15", lodash@^4.17.4:\n  version "4.17.15"\n\n"@babel/core@^7.0.0":\n'
                      '  version "7.1.0"\n', {("lodash", "4.17.15"), ("@babel/core", "7.1.0")}),
        "go.mod": ("module x\n\nrequire (\n\tgolang.org/x/text v0.3.0 // indirect\n)\nrequire github.com/a/b v1.2.3\n",
                   {("golang.org/x/text", "0.3.0"), ("github.com/a/b", "1.2.3")}),
        "Gemfile.lock": ("GEM\n  specs:\n    rails (5.2.0)\n      actionpack (= 5.2.0)\n    nokogiri (1.13.10-arm64-darwin)\n",
                         {("rails", "5.2.0"), ("nokogiri", "1.13.10")}),
        "composer.lock": ('{"packages": [{"name": "guzzlehttp/guzzle", "version": "v6.5.0"}]}',
                          {("guzzlehttp/guzzle", "6.5.0")}),
        "Cargo.lock": ('[[package]]\nname = "time"\nversion = "0.1.43"\n', {("time", "0.1.43")}),
        "pubspec.lock": ('packages:\n  http:\n    dependency: "direct main"\n    source: hosted\n    version: "0.12.0"\n'
                         '  flutter:\n    source: sdk\n    version: "0.0.0"\n', {("http", "0.12.0")}),
        "build.gradle": ("implementation 'com.squareup.okhttp3:okhttp:3.12.0'\nimplementation(\"a:b:$ver\")\n",
                         {("com.squareup.okhttp3:okhttp", "3.12.0")}),
        "libs.versions.toml": ('[versions]\nokhttp = "4.9.0"\n[libraries]\n'
                               'okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }\n'
                               'gson = "com.google.code.gson:gson:2.8.5"\n',
                               {("com.squareup.okhttp3:okhttp", "4.9.0"), ("com.google.code.gson:gson", "2.8.5")}),
    }
    for filename, (text, expected) in cases.items():
        packages, _, _ = deps.parse_manifest(filename, text)
        assert {(p.name, p.version) for p in packages} == expected, filename


def test_collect_prefers_lockfile_over_package_json():
    files = [SourceFile("web/package.json", '{"dependencies": {"lodash": "^4.0.0"}}'),
             SourceFile("web/package-lock.json", '{"packages": {"node_modules/lodash": {"version": "4.17.15"}}}')]
    packages, _, used = deps.collect(files)
    assert [(p.name, p.version) for p in packages] == [("lodash", "4.17.15")]
    assert used == ["web/package-lock.json"]


# --- AI review (provider is mocked; parsing must be defensive) ---

def test_ai_findings_are_validated(monkeypatch):
    monkeypatch.setattr(config, "AI_ENABLED", True)
    monkeypatch.setattr(config, "AI_MODEL", "test-model")
    reply = '''Here you go:
```json
{"findings": [
  {"file": "app.py", "line": 33, "severity": "HIGH", "title": "Missing ownership check on invoices",
   "description": "Any user can read any invoice.", "impact": "Data leak.", "fix": "Check the owner.",
   "fixed_code": "if row.owner_id != current_user.id: abort(404)"},
  {"file": "../../etc/passwd", "line": 1, "severity": "high", "title": "Invented file"},
  {"file": "app.py", "line": 99999, "severity": "bogus", "title": "Line out of range"},
  {"file": "app.py", "line": 13, "severity": "high", "title": "SQL injection (duplicate of a rule hit)"},
  {"file": "app.py", "line": 22, "severity": "critical", "title": "Deserialization attack",
   "description": "pickle.loads on request data (rule already reports line 24)"},
  {"file": "app.py", "line": 6, "severity": "high", "title": "Hardcoded AWS credential"}
]}
```'''

    async def fake_chat(client, messages):
        assert "untrusted data" in messages[0]["content"]
        return reply
    monkeypatch.setattr(ai_review, "_chat", fake_chat)

    result = scan("demo.zip", build_source_zip(), ai=True)
    ai = [f for f in result["findings"] if f["category"] == "AI code review"]
    titles = {f["title"] for f in ai}
    assert "Missing ownership check on invoices" in titles
    assert "Invented file" not in titles
    assert "SQL injection (duplicate of a rule hit)" not in titles
    assert "Deserialization attack" not in titles  # same topic, 2 lines from the rule hit
    assert "Hardcoded AWS credential" not in titles  # already a secret finding
    out_of_range = next(f for f in ai if f["title"] == "Line out of range")
    assert out_of_range["severity"] == "medium" and out_of_range["evidence"].startswith("app.py")
    owner = next(f for f in ai if f["title"].startswith("Missing ownership"))
    assert owner["severity"] == Severity.HIGH.value and "abort(404)" in owner["snippets"]["Suggested fix"]


def test_ai_provider_failure_is_reported_not_fatal(monkeypatch):
    monkeypatch.setattr(config, "AI_ENABLED", True)

    async def broken(client, messages):
        raise ai_review.AIError("AI provider returned HTTP 401: invalid key")
    monkeypatch.setattr(ai_review, "_chat", broken)
    result = scan("demo.zip", build_source_zip(), ai=True)
    assert "ai-review-errors" in ids(result)
    assert "code-sql-injection" in ids(result)


def test_ai_off_adds_a_note():
    result = scan("demo.zip", build_source_zip(), ai=True)
    assert any("isn't set up" in note for note in result["notes"])
