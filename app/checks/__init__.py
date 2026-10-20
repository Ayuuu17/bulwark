from . import content, cookies, dns_email, headers, transport, wellknown

ALL_CHECKS = [
    ("Encryption (HTTPS/TLS)", transport.check),
    ("Security headers", headers.check),
    ("Cookies", cookies.check),
    ("Page content & libraries", content.check),
    ("Email spoofing protection (DNS)", dns_email.check),
    ("security.txt", wellknown.check),
]
