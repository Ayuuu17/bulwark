import pytest
from fastapi.testclient import TestClient

from app import auth, config, db, main, verification

PASSWORD = "correct horse battery"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test.db")
    main.signup_limiter._hits.clear()
    main.login_limiter._hits.clear()
    with TestClient(main.app, base_url="https://testserver") as c:
        yield c


def signup(client, email="a@example.com", password=PASSWORD):
    return client.post("/api/auth/signup", json={"email": email, "password": password})


def test_password_hashing():
    stored = auth.hash_password("hunter2hunter2")
    assert stored.startswith("scrypt$") and "hunter2" not in stored
    assert auth.verify_password("hunter2hunter2", stored)
    assert not auth.verify_password("wrong", stored)
    assert not auth.verify_password("x", "garbage")


def test_signup_sets_secure_session_cookie(client):
    res = signup(client, "  A@Example.com ")
    assert res.status_code == 200
    assert res.json()["user"]["email"] == "a@example.com"
    cookie = res.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=lax" in cookie
    assert client.get("/api/auth/me").json()["user"]["email"] == "a@example.com"


def test_signup_validation(client):
    assert signup(client, "not-an-email").status_code == 400
    assert signup(client, password="short").status_code == 400
    assert signup(client).status_code == 200
    assert signup(client).status_code == 409


def test_login_logout(client):
    signup(client)
    client.post("/api/auth/logout")
    assert client.get("/api/auth/me").json()["user"] is None
    assert client.post("/api/auth/login", json={"email": "a@example.com", "password": "wrong password"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "nobody@example.com", "password": PASSWORD}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "A@example.com", "password": PASSWORD}).status_code == 200
    assert client.get("/api/auth/me").json()["user"]["email"] == "a@example.com"


def test_endpoints_require_login(client):
    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/domains").status_code == 401
    assert client.post("/api/scans", json={"url": "example.com"}).status_code == 401
    assert client.post("/api/deps", json={"filename": "requirements.txt", "content": "x==1"}).status_code == 401


def test_users_only_see_their_own_scans(client):
    signup(client, "alice@example.com")
    alice = db.get_user_by_email("alice@example.com")["id"]
    scan_id = db.create_scan(alice, "deps", "requirements.txt")
    db.update_scan(scan_id, "done", result={"grade": "B", "score": 85, "summary": {"high": 1}})
    listed = client.get("/api/scans").json()["scans"]
    assert [(s["id"], s["grade"], s["summary"]) for s in listed] == [(scan_id, "B", {"high": 1})]

    client.post("/api/auth/logout")
    signup(client, "bob@example.com")
    assert client.get("/api/scans").json()["scans"] == []
    assert client.get(f"/api/scans/{scan_id}").status_code == 404
    assert client.delete(f"/api/scans/{scan_id}").status_code == 404
    assert db.get_scan(scan_id, alice) is not None


def test_verification_is_per_account(client):
    signup(client, "alice@example.com")
    alice_token = client.post("/api/verify/instructions", json={"url": "example.com"}).json()["token"]
    alice = db.get_user_by_email("alice@example.com")["id"]
    db.mark_verified(alice, "example.com", "dns")
    assert [d["host"] for d in client.get("/api/domains").json()["domains"]] == ["example.com"]

    client.post("/api/auth/logout")
    signup(client, "bob@example.com")
    bob_info = client.post("/api/verify/instructions", json={"url": "example.com"}).json()
    assert bob_info["verified"] is False
    assert bob_info["token"] != alice_token
    assert client.post("/api/scans", json={"url": "example.com"}).status_code == 403
    assert client.get("/api/domains").json()["domains"] == []


def test_remove_domain(client):
    signup(client)
    user = db.get_user_by_email("a@example.com")["id"]
    db.mark_verified(user, "example.com", "file")
    assert client.delete("/api/domains/example.com").status_code == 200
    assert client.delete("/api/domains/example.com").status_code == 404
    assert not db.is_verified(user, "example.com")


def test_cross_site_post_blocked(client):
    signup(client)
    res = client.post("/api/scans", json={"url": "example.com"}, headers={"Origin": "https://evil.example"})
    assert res.status_code == 403 and res.json()["detail"] == "Cross-site request blocked."
    res = client.post("/api/auth/logout", headers={"Sec-Fetch-Site": "cross-site"})
    assert res.status_code == 403


def test_change_password_signs_out_other_sessions(client):
    signup(client)
    other = TestClient(main.app, base_url="https://testserver")
    assert other.post("/api/auth/login", json={"email": "a@example.com", "password": PASSWORD}).status_code == 200

    bad = client.post("/api/account/password", json={"current_password": "nope", "new_password": "new password 123"})
    assert bad.status_code == 400
    ok = client.post("/api/account/password", json={"current_password": PASSWORD, "new_password": "new password 123"})
    assert ok.status_code == 200
    assert client.get("/api/auth/me").json()["user"] is not None
    assert other.get("/api/auth/me").json()["user"] is None


def test_delete_account_removes_data(client):
    signup(client)
    user = db.get_user_by_email("a@example.com")["id"]
    scan_id = db.create_scan(user, "deps", "package.json")
    assert client.post("/api/account/delete", json={"password": "wrong"}).status_code == 400
    assert client.post("/api/account/delete", json={"password": PASSWORD}).status_code == 200
    assert db.get_user(user) is None
    assert db.get_scan(scan_id, user) is None
    assert client.get("/api/auth/me").json()["user"] is None


def test_tokens_differ_per_user_and_host():
    assert verification.token_for(1, "a.com") != verification.token_for(2, "a.com")
    assert verification.token_for(1, "a.com") != verification.token_for(1, "b.com")
