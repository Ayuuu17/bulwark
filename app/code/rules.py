"""Static analysis rules: dangerous patterns in source code, with plain-language fixes.

Python files are parsed with `ast` for precise matches; other languages use line-based patterns.
Findings are grouped per rule, so one issue type is one report entry listing every location.
"""

import ast
import re
from dataclasses import dataclass, field

from ..models import Finding, Report, Severity
from .archive import SourceFile
from .secrets import redact

JS = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"})
PY = frozenset({".py"})
PHP = frozenset({".php"})
JVM = frozenset({".java", ".kt", ".kts"})
GO = frozenset({".go"})
RB = frozenset({".rb", ".erb"})
CS = frozenset({".cs"})
APPLE = frozenset({".swift", ".m"})
DART = frozenset({".dart"})
CODE = JS | PY | PHP | JVM | GO | RB | CS | APPLE | DART

H, M, L = Severity.HIGH, Severity.MEDIUM, Severity.LOW
USER_INPUT_JS = r"req\.(?:query|body|params|headers|cookies)"
USER_INPUT_PHP = r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER\[['\"](?:HTTP_|QUERY|REQUEST_URI))"
SENSITIVE = r"(?:password|passwd|token|secret|otp|pin\b|api_?key|credit|card|ssn)"

SQL_SNIPPETS = {
    "Node (pg/mysql2)": "// Placeholders: the driver sends values separately from the SQL\n"
                        "const { rows } = await db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);",
    "Python": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n"
              "# SQLAlchemy: session.execute(text(\"... WHERE id = :id\"), {\"id\": user_id})",
    "PHP (PDO)": "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n$stmt->execute([$_GET['id']]);",
    "Java/Kotlin": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n"
                   "ps.setString(1, userId);",
    "Go": "row := db.QueryRow(\"SELECT * FROM users WHERE id = $1\", id)",
    "Ruby (Rails)": "User.where(\"email = ?\", params[:email])\n# or: User.where(email: params[:email])",
    "C#": "var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Id = @id\", conn);\n"
          "cmd.Parameters.AddWithValue(\"@id\", id);",
}
COMMAND_SNIPPETS = {
    "Node": "// Pass arguments as an array, never through a shell string\n"
            "const { execFile } = require('child_process');\nexecFile('convert', [inputPath, outputPath], callback);",
    "Python": "subprocess.run([\"convert\", input_path, output_path], check=True)  # no shell=True",
    "Go": "exec.Command(\"convert\", inputPath, outputPath)  // no \"sh -c\"",
    "Java": "new ProcessBuilder(\"convert\", inputPath, outputPath).start();",
}
TLS_SNIPPET = {"Fix": "Remove the override and let the platform verify certificates.\n"
                      "For self-signed dev servers, trust your dev CA on the device/machine instead,\n"
                      "and never ship the bypass in a release build."}
XSS_SNIPPETS = {
    "React": "import DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />\n"
             "// better: render text normally: <div>{text}</div>",
    "Vanilla JS": "el.textContent = userText;           // safe: treated as text\n"
                  "el.innerHTML = DOMPurify.sanitize(html); // if you truly need HTML",
    "PHP": "echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');",
}


@dataclass(frozen=True)
class CodeRule:
    id: str
    title: str
    severity: Severity
    description: str
    impact: str
    fix: str
    languages: frozenset = CODE
    pattern: re.Pattern | None = None  # None: implemented by the Python AST checker
    requires: re.Pattern | None = None  # the file must also contain this
    unless: re.Pattern | None = None  # skip lines that also match this (e.g. a sanitizer)
    category: str = "Code vulnerability"
    snippets: dict = field(default_factory=dict)
    redact_strings: bool = False


def rx(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


RULES: list[CodeRule] = [
    # --- injection ---
    CodeRule("sql-injection", "SQL built by joining strings (SQL injection)", H,
             "SQL queries are assembled from variables with string concatenation, f-strings or templates.",
             "If any part comes from a user, they can rewrite the query: read every table, bypass login, "
             "or delete data. SQL injection is one of the most exploited bugs on the web.",
             "Use parameterized queries (placeholders) everywhere. Never put variables inside the SQL text.",
             languages=JS | PHP | JVM | GO | RB | CS,
             pattern=rx(r"(?:\.(?:query|execute|raw|whereRaw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*(?:`[^`]*\$\{"
                        r"|[\"'][^\"']*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^\"']*[\"']\s*\+)"
                        r"|(?:mysqli?_query|pg_query|->query|->exec)\s*\([^;]*(?:" + USER_INPUT_PHP +
                        r"|\"[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"]*\$\w|[\"'][^\"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*[\"']\s*\.\s*\$)"
                        r"|\b(?:executeQuery|executeUpdate|createQuery|createNativeQuery|rawQuery|execSQL)\s*\(\s*"
                        r"(?:\"[^\"]*\"\s*\+|\w+\s*\+\s*\"|\"[^\"]*\$\{?[A-Za-z_])"
                        r"|\.(?:Query|QueryRow|Exec|QueryContext|ExecContext|QueryRowContext)\s*\(\s*(?:ctx\s*,\s*)?"
                        r"(?:fmt\.Sprintf|\"[^\"]*\"\s*\+)"
                        r"|\.(?:where|find_by_sql|order|having|joins|pluck|execute)\s*\(\s*\"[^\"]*#\{"
                        r"|new\s+(?:Sql|MySql|Npgsql|Sqlite|OleDb)Command\s*\(\s*(?:\"[^\"]*\"\s*\+|\$\"[^\"]*\{)"
                        r"|\.(?:FromSqlRaw|ExecuteSqlRaw)\s*\(\s*(?:\$\"|\"[^\"]*\"\s*\+))", re.I),
             snippets=SQL_SNIPPETS),
    CodeRule("command-injection", "Shell command built from variables (command injection)", H,
             "A shell command is assembled from variables, so user input may reach the shell.",
             "An attacker who controls part of the command can run any program on your server, which "
             "usually means full takeover.",
             "Don't go through a shell. Call the program directly with an argument list, and validate inputs "
             "against an allow-list.",
             languages=JS | PHP | JVM | GO | RB,
             pattern=rx(r"(?:\bexec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+|[A-Za-z_$][\w$.]*\s*[,)])"
                        r"|\b(?:system|shell_exec|passthru|popen|proc_open)\s*\([^;]*" + USER_INPUT_PHP +
                        r"|Runtime\.getRuntime\(\)\.exec\s*\((?!\s*\"[^\"+]*\"\s*\))"
                        r"|exec\.Command\s*\(\s*\"(?:sh|bash|/bin/sh|/bin/bash|cmd)\"\s*,\s*\"(?:-c|/c)\"\s*,\s*(?!\")"
                        r"|\b(?:system|exec|spawn)\s*\(?\s*\"[^\"]*#\{|`[^`]*#\{|%x[({\[][^)}\]]*#\{)"),
             requires=rx(r"child_process|execa|shelljs|\$_(?:GET|POST|REQUEST)|Runtime\.getRuntime|os/exec|"
                         r"#\{|\bsystem\b"),
             snippets=COMMAND_SNIPPETS),
    CodeRule("code-injection", "Dynamic code execution (eval)", H,
             "Code strings are executed at runtime with eval / new Function / equivalents.",
             "If user input ever reaches these, attackers can run arbitrary code inside your app or server.",
             "Remove eval. Use JSON.parse for data, a lookup table for dynamic behaviour, or a proper parser.",
             languages=JS | PHP | RB,
             pattern=rx(r"(?<![.\w])eval\s*\(\s*(?![\"'`][^\"'`]*[\"'`]\s*\))|\bnew\s+Function\s*\(|"
                        r"\b(?:assert|create_function)\s*\(\s*\$|"
                        r"\b(?:instance_eval|class_eval|send|public_send)\s*\(\s*params|params\[[^\]]+\]\.constantize")),
    CodeRule("file-inclusion", "File included or read from a user-controlled path", H,
             "File paths are built from request data.",
             "Attackers can use ../ sequences to read files like .env, config or /etc/passwd, or in PHP even "
             "execute code via include.",
             "Never use raw request data as a path. Map IDs to known files, or resolve the path and check it "
             "stays inside the allowed folder.",
             languages=JS | PHP,
             pattern=rx(r"\b(?:include|require)(?:_once)?\s*\(?[^;]*" + USER_INPUT_PHP +
                        r"|\b(?:sendFile|readFile(?:Sync)?|createReadStream|download)\s*\([^)]*" + USER_INPUT_JS),
             snippets={"Node": "const safe = path.resolve(UPLOAD_DIR, path.basename(req.params.name));\n"
                               "if (!safe.startsWith(UPLOAD_DIR + path.sep)) return res.sendStatus(400);\n"
                               "res.sendFile(safe);"}),
    CodeRule("insecure-deserialization", "Untrusted data deserialized into objects", H,
             "Data is deserialized with a format that can create arbitrary objects.",
             "Feeding attacker-controlled bytes to these deserializers commonly leads to remote code execution.",
             "Use JSON for data exchange. If you must deserialize, only do it on data you signed yourself.",
             languages=JS | PHP | JVM | RB | CS,
             pattern=rx(r"require\([\"']node-serialize[\"']\)|\bunserialize\s*\(\s*\$_|\bnew\s+XMLDecoder\s*\(|"
                        r"\bnew\s+ObjectInputStream\s*\(|\bBinaryFormatter\b|"
                        r"TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects)|\bMarshal\.load\b|\bYAML\.unsafe_load\b")),
    # --- XSS & web ---
    CodeRule("xss-raw-html", "Raw HTML inserted into the page (XSS risk)", M,
             "HTML is written into the page without sanitizing it.",
             "If the HTML includes anything a user typed, attackers can inject scripts that steal sessions or "
             "act as the victim (cross-site scripting).",
             "Render user data as text, or sanitize HTML with a vetted library like DOMPurify first.",
             languages=JS | PHP | RB,
             pattern=rx(r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:|\.(?:innerHTML|outerHTML)\s*\+?=\s*(?![\"'][^\"'$]*[\"']\s*;?\s*$)|"
                        r"\bdocument\.write(?:ln)?\s*\(|\bv-html\s*=|\b(?:echo|print)\b[^;]*" + USER_INPUT_PHP +
                        r"|\.html_safe\b|<%==|\braw\s*\(\s*(?:params|@)"),
             unless=rx(r"DOMPurify|sanitize|htmlspecialchars|htmlentities|escape", re.I),
             snippets=XSS_SNIPPETS),
    CodeRule("open-redirect", "Redirect to a user-supplied URL (open redirect)", M,
             "The app redirects to a URL taken straight from the request.",
             "Attackers send links on your domain that bounce victims to phishing sites, which makes the "
             "phishing far more convincing (and can leak OAuth tokens).",
             "Only redirect to relative paths or an allow-list of your own domains.",
             languages=JS, pattern=rx(r"\.redirect\s*\(\s*(?:\d+\s*,\s*)?" + USER_INPUT_JS),
             snippets={"Node": "const next = req.query.next;\n"
                               "res.redirect(next && next.startsWith('/') && !next.startsWith('//') ? next : '/');"}),
    CodeRule("cors-credentials-wildcard", "CORS allows any website with credentials", M,
             "CORS is configured to accept any origin while also allowing cookies/credentials.",
             "Any website a logged-in user visits can call your API as that user and read the responses.",
             "List the exact origins that may call your API.",
             languages=JS, pattern=rx(r"origin\s*:\s*(?:true|[\"']\*[\"'])"), requires=rx(r"credentials\s*:\s*true"),
             snippets={"Express (cors)": "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));"}),
    CodeRule("csrf-disabled", "CSRF protection turned off", M,
             "Cross-site request forgery protection is skipped.",
             "Other sites can submit forms or requests that act on behalf of logged-in users.",
             "Keep CSRF protection on for cookie-authenticated routes; only skip it for token-authenticated APIs.",
             languages=RB | PY, pattern=rx(r"skip_before_action\s+:verify_authenticity_token|@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False")),
    # --- auth & crypto ---
    CodeRule("jwt-weak", "JWT verification can be bypassed", H,
             "JWTs are accepted with the 'none' algorithm or a hardcoded signing secret.",
             "Attackers can forge tokens and log in as any user, including admins.",
             "Verify every token with jwt.verify and a strong secret loaded from the environment; pin the "
             "algorithm (e.g. HS256 or RS256) and never allow 'none'.",
             languages=JS,
             pattern=rx(r"algorithms\s*:\s*\[[^\]]*[\"']none[\"']|jwt\.sign\s*\([^)]*,\s*[\"'][^\"']{3,}[\"']"),
             redact_strings=True,
             snippets={"Node": "const token = jwt.sign(payload, process.env.JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h' });\n"
                               "const data = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });"}),
    CodeRule("tls-verification-disabled", "TLS certificate checks are turned off", H,
             "The code disables HTTPS certificate verification.",
             "Anyone on the network path (public Wi-Fi, a malicious proxy) can impersonate your server and read "
             "or change all traffic, including passwords and tokens.",
             "Remove the bypass. Fix the certificate problem itself instead.",
             languages=JS | JVM | GO | CS | APPLE | DART,
             pattern=rx(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|InsecureSkipVerify\s*:\s*true|"
                        r"ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|setHostnameVerifier\s*\(\s*\{?[^)]*->\s*true|"
                        r"fun verify\([^)]*\)\s*(?::\s*Boolean)?\s*=\s*true|boolean verify\([^)]*\)\s*\{\s*return true|"
                        r"checkServerTrusted\([^)]*\)\s*(?:throws[^{]+)?\{\s*\}|handler\??\.proceed\(\)|"
                        r"ServerCertificate(?:Custom)?ValidationCallback\s*=\s*(?:HttpClientHandler\.DangerousAcceptAnyServerCertificateValidator|\([^)]*\)\s*=>\s*true|delegate\s*\{\s*return true)|"
                        r"allowsAnyHTTPSCertificate|badCertificateCallback\s*=\s*\([^)]*\)\s*(?:=>\s*true|\{\s*return\s+true)"),
             snippets=TLS_SNIPPET),
    CodeRule("weak-random-secret", "Predictable random numbers used for secrets", M,
             "Math.random()/rand is used near tokens, passwords, OTPs or session IDs.",
             "These generators are predictable; attackers can guess reset tokens or codes.",
             "Use a cryptographically secure generator.",
             languages=JS,
             pattern=rx(r"(?:token|secret|passw|otp|nonce|salt|session|reset|code).*Math\.random\(\)|Math\.random\(\).*(?:token|secret|passw|otp|nonce|salt|session)", re.I),
             snippets={"Node": "const token = require('crypto').randomBytes(32).toString('hex');",
                       "Browser": "const bytes = crypto.getRandomValues(new Uint8Array(32));"}),
    CodeRule("weak-crypto", "Weak or broken cryptography", M,
             "The code uses an outdated cipher or mode (DES, RC4, ECB, or AES without an explicit mode).",
             "ECB mode leaks patterns in the data; DES and RC4 can be broken. Encrypted data may be readable.",
             "Use AES-GCM (or ChaCha20-Poly1305) through a high-level library with random IVs.",
             languages=JS | JVM | CS,
             pattern=rx(r"createCipher\s*\(|-ecb[\"']|Cipher\.getInstance\(\s*\"(?:DES|DESede|RC4|AES|AES/ECB[^\"]*)\"|\bDESCryptoServiceProvider\b")),
    CodeRule("weak-hash", "MD5/SHA-1 hashing", L,
             "MD5 or SHA-1 is used. That's fine for checksums or cache keys, but not for passwords or signatures.",
             "If these hash passwords, leaked hashes can be cracked in seconds.",
             "For passwords use bcrypt, scrypt or Argon2. For integrity use SHA-256 or better.",
             languages=JS | JVM | GO | CS | PHP,
             pattern=rx(r"createHash\(\s*[\"'](?:md5|sha1)[\"']|MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"|"
                        r"\b(?:md5|sha1)\.(?:New|Sum)\s*\(|\b(?:MD5|SHA1)\.Create\s*\(|\b(?:md5|sha1)\s*\(\s*\$\w*pass", re.I),
             snippets={"Node": "const bcrypt = require('bcrypt');\nconst hash = await bcrypt.hash(password, 12);",
                       "PHP": "$hash = password_hash($password, PASSWORD_DEFAULT);\npassword_verify($input, $hash);"}),
    # --- data storage & logging (mobile-heavy) ---
    CodeRule("insecure-local-storage", "Sensitive data stored in plain local storage", M,
             "Tokens or passwords are saved in storage that isn't encrypted (localStorage, SharedPreferences, "
             "UserDefaults).",
             "Any XSS (web) or a rooted/jailbroken or backed-up device (mobile) exposes these values.",
             "Web: keep session tokens in HttpOnly cookies. Android: EncryptedSharedPreferences / Keystore. "
             "iOS: Keychain. Flutter: flutter_secure_storage.",
             languages=JS | JVM | APPLE | DART,
             pattern=rx(r"localStorage\.setItem\(\s*[\"'`][^\"'`]*(?:token|jwt|auth|session|password)|"
                        r"putString\s*\(\s*\"[^\"]*" + SENSITIVE + r"|UserDefaults\.standard\.set\([^)]*forKey:\s*\"[^\"]*" + SENSITIVE +
                        r"|\.setString\s*\(\s*['\"][^'\"]*" + SENSITIVE, re.I)),
    CodeRule("sensitive-logging", "Sensitive values written to logs", L,
             "Passwords, tokens or similar values appear in log statements.",
             "Logs are copied to many places (crash reporters, device logs, log services) and read by many people.",
             "Remove these log lines or mask the values.",
             languages=JVM | APPLE | JS | DART,
             pattern=rx(r"(?:\bLog\.[dviwe]|\bprint|\bNSLog|\bos_log|console\.log|debugPrint)\s*\([^)]*" + SENSITIVE, re.I)),
    CodeRule("android-world-readable", "Files created world-readable/writable", H,
             "Files are created with MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE.",
             "Any other app on the device can read or modify them.",
             "Use MODE_PRIVATE (the default) and Android's encrypted storage APIs.",
             languages=JVM, pattern=rx(r"MODE_WORLD_(?:READABLE|WRITEABLE)")),
    CodeRule("webview-risky", "WebView exposes app internals", M,
             "A WebView exposes a JavaScript bridge or allows file-URL access.",
             "If the WebView ever loads attacker-controlled content, that script can call your app's native code "
             "or read local files.",
             "Only load your own HTTPS content in WebViews with bridges, and keep file access off.",
             languages=JVM | APPLE,
             pattern=rx(r"addJavascriptInterface\s*\(|setAllowUniversalAccessFromFileURLs\(\s*true|setAllowFileAccessFromFileURLs\(\s*true|"
                        r"allow(?:Universal|File)AccessFromFileURLs[\"']?\s*(?:=|\)|,)\s*true|setValue\(\s*true\s*,\s*forKey:\s*\"allow(?:Universal|File)AccessFromFileURLs\"")),
    CodeRule("keychain-always", "Keychain items readable while the device is locked", M,
             "Keychain items use kSecAttrAccessibleAlways.",
             "Secrets stay accessible even when the phone is locked, which weakens protection on stolen devices.",
             "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly (or AfterFirstUnlockThisDeviceOnly for background use).",
             languages=APPLE, pattern=rx(r"kSecAttrAccessibleAlways")),
    CodeRule("cleartext-url", "App or server talks to other servers over plain HTTP", L,
             "Hardcoded http:// URLs point at non-local servers.",
             "Requests over HTTP can be read and modified on the network, including API responses your app trusts.",
             "Switch these endpoints to https://.",
             category="Insecure transport", languages=CODE,
             pattern=rx(r"[\"'`]http://(?!localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|\[::1\]|"
                        r"schemas\.|www\.w3\.org|ns\.adobe|purl\.org|json-schema\.org|(?:www\.)?example\.(?:com|org)|"
                        r"www\.apache\.org|xmlpull|java\.sun\.com|www\.opengis)")),
]

_R = {r.id: r for r in RULES}

# Python checks are implemented with ast below; these entries hold their report text.
PY_RULES = {r.id: r for r in [
    CodeRule("py-sql-injection", "SQL built by joining strings (SQL injection)", H,
             "Python code passes f-strings, % formatting, .format() or + concatenation into execute().",
             _R["sql-injection"].impact, _R["sql-injection"].fix, languages=PY, snippets=SQL_SNIPPETS),
    CodeRule("py-command-injection", "Shell command built from variables (command injection)", H,
             "subprocess runs with shell=True (or os.system/os.popen) on a non-constant command.",
             _R["command-injection"].impact, _R["command-injection"].fix, languages=PY, snippets=COMMAND_SNIPPETS),
    CodeRule("py-eval", "Dynamic code execution (eval/exec)", H,
             "eval() or exec() runs a non-constant string.", _R["code-injection"].impact,
             "Remove eval/exec. Use json.loads or ast.literal_eval for data.", languages=PY),
    CodeRule("py-deserialization", "Unsafe deserialization (pickle / yaml.load)", H,
             "pickle/marshal/dill loads data, or yaml.load runs without a safe loader.",
             "Loading attacker-controlled bytes this way runs arbitrary code on your server.",
             "Use json for untrusted data, and yaml.safe_load for YAML.", languages=PY,
             snippets={"Python": "data = yaml.safe_load(text)\ndata = json.loads(body)"}),
    CodeRule("py-tls-disabled", "TLS certificate checks are turned off", H,
             "HTTP calls pass verify=False (or create an unverified SSL context).", _R["tls-verification-disabled"].impact, _R["tls-verification-disabled"].fix,
             languages=PY, snippets=TLS_SNIPPET),
    CodeRule("py-debug-mode", "Debug mode enabled", H,
             "Flask's debug server or Django DEBUG=True is enabled in code.",
             "Flask's debugger lets anyone who can reach it run Python code; Django debug pages leak settings, "
             "SQL and source code.",
             "Turn debug off in production and drive it from an environment variable.", languages=PY,
             snippets={"Flask": "app.run(debug=os.environ.get(\"FLASK_DEBUG\") == \"1\")",
                       "Django": "DEBUG = os.environ.get(\"DJANGO_DEBUG\") == \"1\""}),
    CodeRule("py-jwt-weak", "JWT verification can be bypassed", H,
             "jwt.decode is called with signature verification off or with the 'none' algorithm.", _R["jwt-weak"].impact,
             "Always verify: jwt.decode(token, SECRET, algorithms=[\"HS256\"]).", languages=PY),
    CodeRule("py-weak-random", "Predictable random numbers used for secrets", M,
             "The random module generates something named like a token, password or code.", _R["weak-random-secret"].impact,
             "Use the secrets module.", languages=PY,
             snippets={"Python": "import secrets\ntoken = secrets.token_urlsafe(32)\ncode = secrets.randbelow(10**6)"}),
    CodeRule("py-weak-hash", "MD5/SHA-1 hashing", L, _R["weak-hash"].description, _R["weak-hash"].impact, _R["weak-hash"].fix,
             languages=PY, snippets={"Python": "from argon2 import PasswordHasher  # pip install argon2-cffi\n"
                                               "hash = PasswordHasher().hash(password)"}),
    CodeRule("py-xss-mark-safe", "Unescaped HTML marked as safe (XSS risk)", M,
             "mark_safe()/Markup() wraps a non-constant value, turning off template escaping.", _R["xss-raw-html"].impact,
             "Let the template engine escape values; use format_html() in Django.", languages=PY),
    CodeRule("py-allowed-hosts", "Django accepts any Host header", L,
             "ALLOWED_HOSTS contains '*'.",
             "Attackers can poison password-reset links and caches with their own domain.",
             "List your real domains in ALLOWED_HOSTS.", languages=PY),
]}

COMMENT = re.compile(r"^\s*(?://|#(?!\{)|\*|/\*|<!--|--)")
TEST_PATH = re.compile(r"(?:^|/)(?:tests?|__tests__|specs?|testdata|fixtures|e2e|cypress|__mocks__)/|"
                       r"(?:^|/)test_[^/]*\.py$|_test\.(?:py|go)$|\.(?:test|spec)\.[jt]sx?$|Tests?\.(?:java|kt|swift)$")


def is_test_path(path: str) -> bool:
    return bool(TEST_PATH.search(path))


def _evidence(path: str, number: int, line: str, redact_strings: bool = False) -> str:
    text = line.strip()
    if redact_strings:
        text = re.sub(r"([\"'])([^\"']{6,})\1", lambda m: m.group(1) + redact(m.group(2)) + m.group(1), text)
    return f"{path}:{number}  {text[:180]}"


# --- Python AST checks ---

SQL_WORDS = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b", re.I)
HTTP_CALLS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "Client",
              "AsyncClient", "Session", "urlopen"}
SECRET_NAME = re.compile(r"token|secret|passw|otp|nonce|salt|key|code|pin", re.I)


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _is_const_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _builds_sql(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        literal = "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
        return bool(SQL_WORDS.search(literal)) and any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        strings = [n.value for n in ast.walk(node) if _is_const_str(n)]
        return any(SQL_WORDS.search(s) for s in strings) and not all(
            _is_const_str(n) for n in (node.left, node.right))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return _is_const_str(node.func.value) and bool(SQL_WORDS.search(node.func.value.value))
    return False


def _kw(call: ast.Call, name: str):
    return next((k.value for k in call.keywords if k.arg == name), None)


def _is_false(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def python_hits(file: SourceFile, add) -> None:
    try:
        tree = ast.parse(file.text)
    except (SyntaxError, ValueError):
        return
    lines = file.text.splitlines()

    def hit(rule_id: str, node: ast.AST) -> None:
        number = getattr(node, "lineno", 0)
        add(rule_id, _evidence(file.path, number, lines[number - 1] if 0 < number <= len(lines) else ""))

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            names = [_dotted(t) for t in node.targets]
            if file.name.startswith("settings") and "DEBUG" in names and getattr(node.value, "value", None) is True:
                hit("py-debug-mode", node)
            if "ALLOWED_HOSTS" in names and any(_is_const_str(e) and e.value == "*"
                                                for e in getattr(node.value, "elts", [])):
                hit("py-allowed-hosts", node)
            if isinstance(node.value, ast.Call) and _dotted(node.value.func).startswith("random.") \
                    and any(SECRET_NAME.search(n) for n in names):
                hit("py-weak-random", node)
            continue
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        short = name.rsplit(".", 1)[-1]
        first = node.args[0] if node.args else None

        if short in ("execute", "executemany", "executescript", "raw", "text") and first is not None and _builds_sql(first):
            hit("py-sql-injection", node)
        elif name.startswith("subprocess.") and getattr(_kw(node, "shell"), "value", None) is True \
                and first is not None and not _is_const_str(first):
            hit("py-command-injection", node)
        elif name in ("os.system", "os.popen") and first is not None and not _is_const_str(first):
            hit("py-command-injection", node)
        elif name in ("eval", "exec") and first is not None and not _is_const_str(first):
            hit("py-eval", node)
        elif name in ("pickle.loads", "pickle.load", "cPickle.loads", "dill.loads", "marshal.loads",
                      "jsonpickle.decode", "yaml.unsafe_load", "shelve.open"):
            hit("py-deserialization", node)
        elif name == "yaml.load":
            loader = _kw(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
            if loader is None or "Safe" not in _dotted(loader):
                hit("py-deserialization", node)
        elif _is_false(_kw(node, "verify")) and short in HTTP_CALLS:
            hit("py-tls-disabled", node)
        elif name == "ssl._create_unverified_context":
            hit("py-tls-disabled", node)
        elif short == "run" and getattr(_kw(node, "debug"), "value", None) is True:
            hit("py-debug-mode", node)
        elif name == "jwt.decode":
            options = _kw(node, "options")
            no_verify = _is_false(_kw(node, "verify")) or (isinstance(options, ast.Dict) and any(
                _is_const_str(k) and k.value == "verify_signature" and _is_false(v)
                for k, v in zip(options.keys, options.values)))
            algorithms = _kw(node, "algorithms")
            allows_none = any(_is_const_str(e) and e.value.lower() == "none" for e in getattr(algorithms, "elts", []))
            if no_verify or allows_none:
                hit("py-jwt-weak", node)
        elif name in ("hashlib.md5", "hashlib.sha1") or (name == "hashlib.new" and first is not None and
                                                         _is_const_str(first) and first.value.lower() in ("md5", "sha1")):
            hit("py-weak-hash", node)
        elif short in ("mark_safe", "Markup") and first is not None and not _is_const_str(first):
            hit("py-xss-mark-safe", node)


# --- runner ---

def scan(files: list[SourceFile]) -> tuple[dict[str, list[str]], set[str]]:
    """Returns (rule id -> evidence lines, paths with findings)."""
    hits: dict[str, list[str]] = {}
    hot: set[str] = set()

    def add(rule_id: str, evidence: str) -> None:
        hits.setdefault(rule_id, []).append(evidence)
        hot.add(evidence.split(":", 1)[0])

    for file in files:
        if file.ext not in CODE or is_test_path(file.path) or file.path.endswith((".min.js", ".bundle.js")):
            continue
        if file.ext in PY:
            python_hits(file, add)
        rules = [r for r in RULES if r.pattern is not None and file.ext in r.languages
                 and (r.requires is None or r.requires.search(file.text))]
        if not rules:
            continue
        for number, line in enumerate(file.text.splitlines(), 1):
            if len(line) > 1000 or COMMENT.match(line):
                continue
            for rule in rules:
                if rule.pattern.search(line) and not (rule.unless and rule.unless.search(line)):
                    add(rule.id, _evidence(file.path, number, line, rule.redact_strings))
    return hits, hot


def report_hits(hits: dict[str, list[str]], report: Report) -> None:
    registry = {r.id: r for r in RULES} | PY_RULES
    merged: dict[str, list[str]] = {}
    for rule_id, locations in hits.items():
        # Python and pattern versions of the same issue share one report entry.
        key = rule_id.removeprefix("py-") if rule_id.removeprefix("py-") in registry else rule_id
        merged.setdefault(key, []).extend(locations)
    for rule_id, locations in merged.items():
        rule = registry[rule_id]
        count = len(locations)
        report.add(Finding(
            id=f"code-{rule_id}",
            title=rule.title + (f" ({count} places)" if count > 1 else ""),
            severity=rule.severity,
            category=rule.category,
            description=rule.description,
            evidence="\n".join(locations[:30]) + (f"\n… and {count - 30} more" if count > 30 else ""),
            impact=rule.impact,
            fix=rule.fix,
            snippets=rule.snippets,
        ))
