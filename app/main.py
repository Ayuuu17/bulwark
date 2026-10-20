import asyncio
import contextlib
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import auth, config, db, legal, mailer, verification
from .code.archive import ArchiveError, detect_kind
from .code.engine import run_code_scan
from .deps import SUPPORTED_FILES, ManifestError, run_dependency_scan
from .engine import ScanError, run_site_scan
from .ratelimit import SlidingWindow
from .safety import UnsafeTargetError, assert_safe_host, is_local_dev_target, normalize_url

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# Our own app should pass our own scan.
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
                               "frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

login_limiter = SlidingWindow(limit=20, seconds=900)
signup_limiter = SlidingWindow(limit=5, seconds=3600)
reset_limiter = SlidingWindow(limit=5, seconds=3600)


async def retention_loop() -> None:
    """Delete expired sessions, used reset links and reports past the retention period."""
    while True:
        try:
            removed = await asyncio.to_thread(db.purge_expired, config.RETENTION_DAYS)
            if removed:
                log.info("retention: deleted %d expired report(s)", removed)
        except Exception:
            log.exception("retention sweep failed")
        await asyncio.sleep(6 * 3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    for problem in config.startup_problems():
        log.warning("CONFIG: %s", problem)
    db.init()
    cleaner = asyncio.create_task(retention_loop())
    yield
    cleaner.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await cleaner


app = FastAPI(title=config.APP_NAME, lifespan=lifespan, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")


def is_same_origin(request: Request) -> bool:
    """CSRF guard for state-changing requests, on top of SameSite=Lax cookies."""
    site = request.headers.get("sec-fetch-site")
    if site is not None:
        return site in ("same-origin", "none")
    origin = request.headers.get("origin")
    return origin is None or urlsplit(origin).netloc == request.headers.get("host")


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if request.method in UNSAFE_METHODS and request.url.path.startswith("/api/") and not is_same_origin(request):
        response = JSONResponse({"detail": "Cross-site request blocked."}, status_code=403)
    else:
        response = await call_next(request)
    response.headers.update(SECURITY_HEADERS)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    elif request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"  # revalidate, so users get new CSS/JS after a deploy
    return response


_background_tasks: set[asyncio.Task] = set()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def enforce_scan_quota(user_id: int) -> None:
    if db.count_recent_scans(user_id, 3600) >= config.SCANS_PER_HOUR:
        raise HTTPException(429, "You've hit the hourly scan limit. Please try again later.")


def host_of(raw_url: str) -> tuple[str, str]:
    try:
        target = normalize_url(raw_url)
    except UnsafeTargetError as exc:
        raise HTTPException(400, str(exc))
    return target, urlsplit(target).hostname


def run_in_background(scan_id: str, coro) -> None:
    async def runner():
        db.update_scan(scan_id, "running")
        try:
            db.update_scan(scan_id, "done", result=await coro)
        except (ScanError, UnsafeTargetError, ManifestError, ArchiveError) as exc:
            db.update_scan(scan_id, "failed", error=str(exc))
        except Exception:
            log.exception("scan %s crashed", scan_id)
            db.update_scan(scan_id, "failed", error="Unexpected error while scanning.")

    task = asyncio.create_task(runner())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


def public_user(user: dict) -> dict:
    return {"email": user["email"], "created_at": user["created_at"]}


class UrlIn(BaseModel):
    url: str = Field(max_length=2048)


class ManifestIn(BaseModel):
    filename: str = Field(max_length=200)
    content: str = Field(max_length=config.MAX_UPLOAD_BYTES)


class Credentials(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=256)
    accept_terms: bool = False


class EmailIn(BaseModel):
    email: str = Field(max_length=254)


class ResetIn(BaseModel):
    token: str = Field(max_length=256)
    password: str = Field(max_length=256)


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class PasswordConfirm(BaseModel):
    password: str = Field(max_length=256)


# --- app info ---

@app.get("/api/config")
async def get_config():
    return {
        "app_name": config.APP_NAME,
        "supported_files": SUPPORTED_FILES,
        "dev_mode": config.ALLOW_PRIVATE_TARGETS,
        "ai_review": config.AI_ENABLED,
        "ai_provider": config.AI_PROVIDER_NAME,
        "max_upload_mb": config.MAX_CODE_UPLOAD_BYTES // 1_000_000,
        "retention_days": config.RETENTION_DAYS,
    }


@app.get("/healthz")
async def health():
    """Liveness/readiness probe for your host or load balancer."""
    try:
        await asyncio.to_thread(db.get_user, 0)
    except Exception:
        raise HTTPException(503, "database unavailable")
    return {"status": "ok", "app": config.APP_NAME}


# --- accounts ---

@app.post("/api/auth/signup")
async def signup(body: Credentials, request: Request, response: Response):
    if not signup_limiter.hit(client_ip(request)):
        raise HTTPException(429, "Too many sign-ups from this network. Please try again later.")
    if not body.accept_terms:
        raise HTTPException(400, "Please accept the Terms of Service and Acceptable Use Policy.")
    email = auth.normalize_email(body.email)
    auth.validate_email(email)
    auth.validate_password(body.password)
    user_id = db.create_user(email, await asyncio.to_thread(auth.hash_password, body.password),
                             config.TERMS_VERSION)
    if user_id is None:
        raise HTTPException(409, "There's already an account with this email. Log in instead.")
    auth.start_session(request, response, user_id)
    return {"user": public_user(db.get_user(user_id))}


@app.post("/api/auth/login")
async def login(body: Credentials, request: Request, response: Response):
    if not login_limiter.hit(client_ip(request)):
        raise HTTPException(429, "Too many log-in attempts. Please wait a few minutes.")
    user = await asyncio.to_thread(auth.check_login, auth.normalize_email(body.email), body.password)
    if user is None:
        raise HTTPException(401, "Wrong email or password.")
    auth.start_session(request, response, user["id"])
    return {"user": public_user(user)}


@app.post("/api/auth/forgot")
async def forgot_password(body: EmailIn, request: Request):
    """Always answers the same way, so this can't be used to discover which emails have accounts."""
    reply = {"message": "If that email has an account, we've sent a link to reset the password. "
                        "Check your inbox and spam folder."}
    if not reset_limiter.hit(client_ip(request)):
        return reply
    email = auth.normalize_email(body.email)
    user = db.get_user_by_email(email)
    if user is None:
        return reply
    token = auth.create_reset_token(user["id"])
    link = f"{config.PUBLIC_URL}/#reset={token}"
    await mailer.send(
        email,
        f"Reset your {config.APP_NAME} password",
        f"Someone asked to reset the password for your {config.APP_NAME} account.\n\n"
        f"Choose a new password here (the link works once and expires in 1 hour):\n{link}\n\n"
        "If this wasn't you, you can ignore this email: your password hasn't changed.\n",
    )
    return reply


@app.post("/api/auth/reset")
async def reset_password(body: ResetIn, request: Request, response: Response):
    # Check the password first: a rejected password must not burn the one-time link.
    auth.validate_password(body.password)
    user_id = auth.consume_reset_token(body.token)
    if user_id is None:
        raise HTTPException(400, "That reset link has expired or already been used. Request a new one.")
    db.set_password(user_id, await asyncio.to_thread(auth.hash_password, body.password))
    db.delete_user_sessions(user_id)  # a reset signs out every existing session
    auth.start_session(request, response, user_id)
    return {"user": public_user(db.get_user(user_id))}


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    auth.end_session(request, response)
    return {"ok": True}


@app.get("/api/auth/me")
async def me(request: Request):
    user = auth.optional_user(request)
    return {"user": public_user(user) if user else None}


@app.post("/api/account/password")
async def change_password(body: PasswordChange, request: Request, response: Response,
                          user: dict = Depends(auth.current_user)):
    stored = db.get_user(user["id"])["password_hash"]
    if not await asyncio.to_thread(auth.verify_password, body.current_password, stored):
        raise HTTPException(400, "Your current password is wrong.")
    auth.validate_password(body.new_password)
    db.set_password(user["id"], await asyncio.to_thread(auth.hash_password, body.new_password))
    db.delete_user_sessions(user["id"])  # sign out every other device
    auth.start_session(request, response, user["id"])
    return {"ok": True}


@app.get("/api/account/export")
async def export_account(user: dict = Depends(auth.current_user)):
    """Everything we hold about this account, as a JSON download (GDPR data portability)."""
    data = await asyncio.to_thread(db.export_user, user["id"])
    body = json.dumps({"exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), **data}, indent=2)
    return Response(body, media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="{config.APP_SLUG}-my-data.json"'})


@app.post("/api/account/delete")
async def delete_account(body: PasswordConfirm, request: Request, response: Response,
                         user: dict = Depends(auth.current_user)):
    stored = db.get_user(user["id"])["password_hash"]
    if not await asyncio.to_thread(auth.verify_password, body.password, stored):
        raise HTTPException(400, "That password is wrong.")
    db.delete_user(user["id"])
    auth.end_session(request, response)
    return {"ok": True}


# --- domain verification ---

@app.get("/api/domains")
async def list_domains(user: dict = Depends(auth.current_user)):
    return {"domains": db.list_domains(user["id"])}


@app.delete("/api/domains/{host}")
async def remove_domain(host: str, user: dict = Depends(auth.current_user)):
    if not db.delete_domain(user["id"], host.lower()):
        raise HTTPException(404, "Domain not found.")
    return {"ok": True}


@app.post("/api/verify/instructions")
async def verify_instructions(body: UrlIn, user: dict = Depends(auth.current_user)):
    _, host = host_of(body.url)
    if await is_local_dev_target(host):
        return {"host": host, "verified": True, "method": "local"}
    return {**verification.instructions(user["id"], host), "verified": db.is_verified(user["id"], host)}


@app.post("/api/verify/check")
async def verify_check(body: UrlIn, user: dict = Depends(auth.current_user)):
    _, host = host_of(body.url)
    verified, method = await verification.verify(user["id"], host)
    return {"host": host, "verified": verified, "method": method}


# --- scans ---

@app.post("/api/scans", status_code=202)
async def start_site_scan(body: UrlIn, user: dict = Depends(auth.current_user)):
    target, host = host_of(body.url)
    try:
        await assert_safe_host(host)
    except UnsafeTargetError as exc:
        raise HTTPException(400, str(exc))
    if not await verification.is_authorized(user["id"], host):
        raise HTTPException(403, f"Verify that you own {host} before scanning it.")
    enforce_scan_quota(user["id"])
    scan_id = db.create_scan(user["id"], "site", target)
    run_in_background(scan_id, run_site_scan(target))
    return {"id": scan_id}


@app.post("/api/deps", status_code=202)
async def start_dependency_scan(body: ManifestIn, user: dict = Depends(auth.current_user)):
    enforce_scan_quota(user["id"])
    scan_id = db.create_scan(user["id"], "deps", body.filename)
    run_in_background(scan_id, run_dependency_scan(body.filename, body.content))
    return {"id": scan_id}


@app.post("/api/code", status_code=202)
async def start_code_scan(request: Request, filename: str, ai: bool = False, attest: bool = False,
                          user: dict = Depends(auth.current_user)):
    """Raw-body upload of a .zip / .apk / .ipa (no multipart parser needed). The bytes stay in memory."""
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1][:200]
    if not attest:
        raise HTTPException(400, "Confirm that you own this code or app, or are authorized to scan it.")
    try:
        kind = detect_kind(filename)
    except ArchiveError as exc:
        raise HTTPException(400, str(exc))
    limit = config.MAX_CODE_UPLOAD_BYTES
    too_big = HTTPException(413, f"Uploads are limited to {limit // 1_000_000} MB.")
    if int(request.headers.get("content-length") or 0) > limit:
        raise too_big
    enforce_scan_quota(user["id"])
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > limit:
            raise too_big
    if not data:
        raise HTTPException(400, "The file is empty.")
    scan_id = db.create_scan(user["id"], "code" if kind == "source" else "app", filename, attested=True)
    run_in_background(scan_id, run_code_scan(filename, bytes(data), ai))
    return {"id": scan_id}


@app.get("/api/scans")
async def list_scans(user: dict = Depends(auth.current_user)):
    return {"scans": db.list_scans(user["id"])}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, user: dict = Depends(auth.current_user)):
    scan = db.get_scan(scan_id, user["id"])
    if scan is None:
        raise HTTPException(404, "Scan not found.")
    return scan


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str, user: dict = Depends(auth.current_user)):
    if not db.delete_scan(scan_id, user["id"]):
        raise HTTPException(404, "Scan not found.")
    return {"ok": True}


@app.get("/.well-known/security.txt", response_class=PlainTextResponse)
@app.get("/security.txt", response_class=PlainTextResponse)
async def security_txt():
    """RFC 9116: tells researchers how to report issues in our own service."""
    expires = datetime.now(timezone.utc).replace(microsecond=0).replace(year=datetime.now().year + 1)
    return (f"Contact: mailto:{config.SECURITY_EMAIL}\n"
            f"Expires: {expires.isoformat().replace('+00:00', 'Z')}\n"
            f"Policy: {config.PUBLIC_URL}/security-policy\n"
            "Preferred-Languages: en\n")


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt():
    return ("User-agent: *\n"
            "Allow: /$\n"
            "Allow: /terms\nAllow: /privacy\nAllow: /acceptable-use\nAllow: /security-policy\n"
            "Disallow: /api/\n"
            f"Sitemap: {config.PUBLIC_URL}/sitemap.xml\n")


@app.get("/sitemap.xml")
async def sitemap():
    paths = ["/", "/terms", "/privacy", "/acceptable-use", "/security-policy"]
    urls = "".join(f"<url><loc>{config.PUBLIC_URL}{p}</loc></url>" for p in paths)
    return Response(f'<?xml version="1.0" encoding="UTF-8"?>'
                    f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>',
                    media_type="application/xml")


@app.get("/{slug}", response_class=HTMLResponse)
async def legal_page(slug: str):
    page = legal.page_html(slug)
    if page is None:
        raise HTTPException(404, "Page not found.")
    return HTMLResponse(page)


@app.get("/")
async def index():
    return FileResponse(config.STATIC_DIR / "index.html")
