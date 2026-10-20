# Bulwark

A security scanner for **websites, source code and mobile apps**. Customers get a graded report where
every issue explains **what's wrong**, **why it matters**, and **how to fix it**, with copy-paste fixes for
their stack.

To rename the product, set `APP_NAME=YourName`. The UI, verification tokens and file names all follow it.

## Run it

```bash
./run.sh            # http://127.0.0.1:8000
PORT=8765 ./run.sh  # if port 8000 is busy
```

Try it on deliberately vulnerable demo targets:

```bash
.venv/bin/python tests/demo_target.py                   # broken website on http://127.0.0.1:8899
.venv/bin/python tests/demo_project.py ~/Desktop/demo   # demo-project.zip, demo-app.apk, demo-app.ipa
PORT=8765 ./run.sh --dev                                # --dev allows scanning localhost
```

Tests: `.venv/bin/python -m pytest -q`

## Three kinds of scan

### 1. Website (live site)

| Area | Checks |
|---|---|
| Encryption | HTTPS available, trusted certificate, expiry, outdated TLS, HTTP→HTTPS redirect |
| Security headers | CSP (missing/weak), HSTS, clickjacking, nosniff, Referrer-Policy, Permissions-Policy |
| Info disclosure | Server / X-Powered-By version banners |
| Cookies | Secure, HttpOnly, SameSite on cookies set on first visit |
| Page content | Mixed content, forms posting over HTTP, CDN files without SRI |
| Libraries | jQuery, Bootstrap, lodash, Angular… detected on the page and checked against [OSV.dev](https://osv.dev) |
| Email / DNS | SPF, DMARC, CAA, security.txt |

These checks are **non-intrusive**: they only look at what the site already serves to every visitor, plus
public DNS. Nothing tries to exploit, log in, fuzz, or guess hidden paths. Scanning requires proof of
domain ownership (below).

### 2. Code & apps (upload a `.zip`, `.apk` or `.ipa`)

**Source code (.zip of the project, e.g. GitHub's "Download ZIP")**

- **Leaked secrets:** AWS, Stripe, GitHub, Slack, OpenAI, Anthropic, SendGrid, Twilio and Google keys,
  private keys, database URLs with passwords, hardcoded passwords, committed `.env` files. Reports always
  show secrets redacted.
- **Code vulnerabilities:** SQL and command injection, eval, path traversal/file inclusion, insecure
  deserialization, XSS sinks, open redirects, CORS with credentials, disabled CSRF, broken JWT verification,
  disabled TLS checks, weak crypto/hashing/randomness, debug mode, insecure local storage, sensitive logging,
  hardcoded `http://` endpoints. Python is analyzed with its real parser (`ast`); JS/TS, PHP, Java, Kotlin,
  Go, Ruby, C#, Swift/Obj-C and Dart use pattern rules. Test files are excluded from these rules.
- **App and infrastructure config:** AndroidManifest (debuggable, cleartext traffic, backups, exported
  providers/components, old minSdk), Android network security config, iOS Info.plist (App Transport
  Security, URL schemes), **open Firebase/Firestore rules**, Dockerfiles (running as root, baked-in secrets).
- **Dependencies:** every lockfile in the project, across npm, yarn, Python (requirements, poetry, Pipfile,
  uv), Go, Ruby, PHP, Rust, Flutter (pubspec.lock) and Gradle/Maven (including `libs.versions.toml`).
- **AI deep review (optional):** an AI model reads the most security-relevant files (the ones the rules
  flagged, plus routes, auth, payments, data access…) to find logic flaws rules can't see, such as missing
  login or ownership checks. Its findings are labelled "AI code review" and come with suggested fixed code.

**Android `.apk`:** decodes the compiled manifest and network config, then searches the DEX code, assets
(React Native / Cordova bundles) and Flutter's compiled code for secrets and `http://` endpoints.

**iOS `.ipa`:** reads Info.plist (ATS, URL schemes) and searches the app binary and bundled files for
secrets and `http://` endpoints. App Store downloads are encrypted, so upload a development or ad-hoc build.

Uploads are processed **in memory and never written to disk or stored**. Zip bombs and `../` paths are
handled safely. The size limit is `MAX_CODE_UPLOAD_MB` (default 100).

### 3. Dependencies (single lockfile)

The same dependency check as above, for one uploaded lockfile or manifest.

## AI deep review setup

Bulwark works with **any OpenAI-compatible API**. Pick a provider by setting three variables. Leave
`AI_MODEL` empty to turn AI review off; the rest of the scanner works without it.

| Provider | `AI_BASE_URL` | `AI_API_KEY` |
|---|---|---|
| OpenAI | `https://api.openai.com/v1` | your OpenAI key |
| Google Gemini | `https://generativelanguage.googleapis.com/v1beta/openai` | your Gemini key |
| OpenRouter (many models) | `https://openrouter.ai/api/v1` | your OpenRouter key |
| DeepSeek | `https://api.deepseek.com/v1` | your DeepSeek key |
| Groq | `https://api.groq.com/openai/v1` | your Groq key |
| Ollama (local, free, private) | `http://localhost:11434/v1` | leave empty |

```bash
export AI_BASE_URL=https://api.openai.com/v1
export AI_API_KEY=...            # never commit this
export AI_MODEL=<a model name from your provider>
./run.sh
```

Tuning:

- `AI_MAX_FILES` (default 20): files reviewed per scan. This is your main cost control.
- `AI_BATCH_CHARS` (default 24000): code per request. Lower it for small local models. Ollama's default
  context is small, so either use `AI_BATCH_CHARS=6000` or start Ollama with `OLLAMA_CONTEXT_LENGTH=32768`.
- `AI_CONCURRENCY` (default 2) and `AI_TIMEOUT` (default 300 seconds).

Privacy: with a cloud provider, the selected files are sent to that provider. With Ollama, code never
leaves your server, which is a strong selling point for security-conscious customers. Customers can untick
"Include AI deep review" per scan.

How the AI review is kept safe: the prompt tells the model to treat code as untrusted data and ignore
instructions inside it, and to describe fixes rather than write exploits. Every finding must point at a
file that was actually sent (invented paths are dropped), line numbers are range-checked, text is
length-limited, findings that duplicate a rule hit are merged, and the UI renders everything as plain text.

## Accounts

Scanning requires a free account (email + password). Each account has its own:

- **Verified domains.** Verification tokens are tied to the account, so verifying a site on one account
  doesn't unlock it for anyone else.
- **Scan history.** Every report is saved and only visible to its owner, who can delete them.
- **Settings.** Change password (signs out other devices) or delete the account along with all its data.

How it's protected:

- Passwords are hashed with scrypt (Python standard library). Login takes the same time whether or not the
  email exists.
- Sessions are random tokens in an `HttpOnly`, `SameSite=Lax` cookie (`Secure` everywhere except
  localhost). Only a SHA-256 hash of each token is stored, so a leaked database can't be used to log in.
- State-changing API calls from other websites are rejected (Sec-Fetch-Site / Origin check), on top of
  SameSite cookies.
- Rate limits: 20 log-in attempts per 15 min and 5 sign-ups per hour per IP, plus `SCANS_PER_HOUR` per account.

Not built yet: password reset by email (needs an email provider such as Postmark, Resend or SES) and
email verification at sign-up.

## Website ownership verification

Before a website scan runs, the customer proves they control the domain in one of two ways:

- **DNS:** a TXT record at `_bulwark-challenge.<host>` holding their token.
- **File:** `https://<host>/.well-known/bulwark-verify.txt` containing the token.

Several accounts can verify the same site (for example an agency and its client): the DNS name can hold
several TXT values, and the file can hold one token per line.

A verification is remembered for 30 days (`VERIFICATION_TTL_DAYS`). It protects the people being scanned,
and it protects you legally: scanning sites without the owner's permission can break computer-misuse laws.

## Protecting the scanner itself

- **SSRF guard** (`app/safety.py`): every host, including each redirect hop, is resolved and refused if it
  points to a private, loopback or reserved address. Link-local addresses (cloud metadata) are refused even
  in dev mode.
- Scan limit per account (`SCANS_PER_HOUR`, default 20).
- The app sends its own strict security headers, and the UI never renders scan data as HTML.

## Going to production

1. Set `SECRET_KEY` to a long random value. Verification tokens are derived from it, so if it changes,
   every customer has to verify again.
2. Run behind HTTPS (Caddy/Nginx/a PaaS) with several workers: `uvicorn app.main:app --workers 4`.
3. **Never** set `ALLOW_PRIVATE_TARGETS=1` in production.
4. Publish terms of service saying customers may only scan assets they own or are authorized to test, and a
   privacy policy that says which AI provider (if any) sees uploaded code.

## Ideas for next steps

- GitHub/GitLab integration: connect a repo (OAuth proves access) and re-scan on every push / pull request.
- Password reset and email verification (needs an email provider).
- Scheduled re-scans with email alerts when the grade drops or a certificate is about to expire.
- Stripe billing (free single scan, paid monitoring, AI review on paid plans).
- A job queue (Redis + RQ/Celery) instead of in-process tasks, so scans survive restarts and scale.
- Pin the resolved IP for the whole request to close the DNS-rebinding gap in the SSRF guard.
