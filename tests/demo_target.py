"""A deliberately misconfigured local site to demo the scanner against.

    python tests/demo_target.py        # serves http://127.0.0.1:8899
"""

from http.server import BaseHTTPRequestHandler, HTTPServer

PAGE = b"""<!doctype html>
<html><head><title>Demo shop</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js"></script>
</head><body>
<h1>Demo shop</h1>
<form action="http://127.0.0.1:8899/login" method="post">
  <input name="user"><input name="pass" type="password"><button>Log in</button>
</form>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Powered-By", "PHP/7.2.24")
        self.send_header("Set-Cookie", "PHPSESSID=abc123; path=/")
        self.send_header("Set-Cookie", "theme=dark; path=/; SameSite=Lax")
        self.end_headers()
        self.wfile.write(PAGE)

    def version_string(self):
        return "Apache/2.4.29 (Ubuntu)"

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("Demo target on http://127.0.0.1:8899")
    HTTPServer(("127.0.0.1", 8899), Handler).serve_forever()
