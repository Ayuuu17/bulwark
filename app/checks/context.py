from dataclasses import dataclass

from ..http_client import FetchResult


@dataclass
class ScanContext:
    target: str
    host: str
    port: int | None  # only set when the user typed an explicit port
    scheme: str  # scheme the user typed
    ips: list[str]
    primary: FetchResult  # the page we analyze (HTTPS preferred)
    https: FetchResult | None
    https_error: str | None
    http: FetchResult | None  # result of loading the http:// version

    @property
    def is_https(self) -> bool:
        return self.primary.url.startswith("https://")
