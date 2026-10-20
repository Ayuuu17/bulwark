"""HTTP fetching that re-checks every redirect hop against the SSRF guard."""

from dataclasses import dataclass, field

import httpx

from . import config
from .safety import UnsafeTargetError, assert_safe_host

MAX_REDIRECTS = 5


class FetchError(Exception):
    pass


@dataclass
class FetchResult:
    url: str  # final URL after redirects
    status: int
    headers: httpx.Headers
    body: str
    chain: list[str] = field(default_factory=list)  # every URL visited, in order
    set_cookies: list[str] = field(default_factory=list)  # from all hops


def _friendly_error(exc: Exception) -> str:
    text = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in text or isinstance(exc, httpx.ConnectError) and "SSL" in text:
        return "TLS certificate could not be verified"
    if isinstance(exc, httpx.TimeoutException):
        return "the server took too long to respond"
    if isinstance(exc, httpx.ConnectError):
        return "the connection was refused or failed"
    return text or exc.__class__.__name__


async def fetch(url: str, *, verify_tls: bool = True, same_host_only: bool = False) -> FetchResult:
    chain: list[str] = []
    cookies: list[str] = []
    current = httpx.URL(url)
    start_host = current.host
    async with httpx.AsyncClient(
        verify=verify_tls,
        timeout=config.HTTP_TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": config.USER_AGENT},
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            if current.scheme not in ("http", "https"):
                raise FetchError(f"redirected to an unsupported address ({current.scheme}:)")
            if same_host_only and current.host != start_host:
                raise FetchError("redirected to a different host")
            try:
                await assert_safe_host(current.host)
            except UnsafeTargetError as exc:
                raise FetchError(str(exc))
            chain.append(str(current))
            try:
                async with client.stream("GET", current) as resp:
                    cookies.extend(resp.headers.get_list("set-cookie"))
                    if resp.is_redirect and "location" in resp.headers:
                        current = current.join(resp.headers["location"])
                        continue
                    body = await _read_limited(resp)
                    return FetchResult(
                        url=str(current),
                        status=resp.status_code,
                        headers=resp.headers,
                        body=body.decode(resp.charset_encoding or "utf-8", errors="replace"),
                        chain=chain,
                        set_cookies=cookies,
                    )
            except httpx.HTTPError as exc:
                raise FetchError(_friendly_error(exc))
    raise FetchError("too many redirects")


async def _read_limited(resp: httpx.Response) -> bytes:
    chunks, size = [], 0
    async for chunk in resp.aiter_bytes():
        size += len(chunk)
        if size > config.MAX_BODY_BYTES:
            break
        chunks.append(chunk)
    return b"".join(chunks)
