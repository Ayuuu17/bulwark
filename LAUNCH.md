# Launch checklist

Work top to bottom. Nothing here is optional if you're charging money or taking real customers.

## 1. Legal and business setup (do this first)

- [ ] **Have a lawyer review the legal pages.** `app/legal.py` holds a Terms of Service, Privacy Policy,
      Acceptable Use Policy and Security Policy written in plain language. They're a solid starting point,
      **not legal advice**, and they haven't been reviewed by a lawyer in your jurisdiction.
- [ ] **Decide what entity you're trading as.** A sole proprietorship is simplest to start, but it means
      personal liability. Most people selling a security service form an LLC (US) or Ltd (UK) before taking
      payment. Talk to an accountant.
- [ ] **Get insurance.** Professional indemnity / errors & omissions, and cyber liability. This is the normal
      cover for "we told you that you were secure and you weren't." Insurers will ask whether you do manual
      testing: say no, this is automated scanning.
- [ ] **Fill in every placeholder** in `.env` (`LEGAL_ENTITY`, `CONTACT_EMAIL`, `GOVERNING_LAW`, ...). Any
      placeholder still in square brackets shows up on your public legal pages. The app warns about these
      on startup.
- [ ] **Register the email addresses** in your legal pages: at minimum `security@` and `privacy@`, and make
      sure someone reads them. Your Security Policy promises a response.
- [ ] **Check the name.** Search your national trademark register and the EUIPO/USPTO databases for
      "Bulwark" in software/security classes before you print anything. It's a common word, and there may
      be existing marks. Change `APP_NAME` if needed, but note that changing it changes the domain
      verification record name, so do it before you have customers.
- [ ] **GDPR**: if you have UK/EU users, you're a data controller. Keep a record of processing activities,
      and sign a Data Processing Agreement with every sub-processor (your host, your email provider, your AI
      provider). If you're outside the UK/EU and target users there, you may need a representative.

## 2. Before the first deploy

- [ ] `cp .env.example .env` and fill it in.
- [ ] Generate a real secret: `python3 -c "import secrets; print(secrets.token_hex(32))"` → `SECRET_KEY`.
      **Never change it afterwards**: every customer's domain verification is derived from it.
- [ ] Set `PUBLIC_URL` to your real `https://` address.
- [ ] Confirm `ALLOW_PRIVATE_TARGETS` is **not** set. With it on, anyone could use your scanner to reach
      your internal network.
- [ ] Set up email (`SMTP_HOST`, `MAIL_FROM`) so password resets work. Postmark, Resend, SES and Mailgun all
      have free tiers.
- [ ] Choose your AI provider, or leave `AI_MODEL` empty to ship without AI review. If you use a cloud
      provider, set `AI_PROVIDER_NAME` so your Privacy Policy names who receives customer code — and check
      that provider's terms allow it and that they don't train on your data.
- [ ] Add SPF, DKIM and DMARC records for your sending domain, or your reset emails will land in spam.
      (Your own scanner checks these: scan your domain once it's live.)

## 3. Deploy

```bash
docker compose up -d --build        # or: docker build -t bulwark . && docker run --env-file .env -p 8000:8000 bulwark
```

- [ ] Put HTTPS in front. Caddy does it automatically; Cloudflare, Fly.io, Railway and Render include it.
      The app sets HSTS, so **don't** enable HTTPS before your certificate works.
- [ ] Point your proxy at `127.0.0.1:8000`, forwarding `X-Forwarded-For` and `X-Forwarded-Proto`.
- [ ] Mount a persistent volume at `/data`. That's your database; without it you lose every account on
      redeploy.
- [ ] Point your uptime monitor at `/healthz`.
- [ ] **Back up `/data`.** Nightly, off the server. Test a restore once.

## 4. Verify the live site

- [ ] Visit `/terms`, `/privacy`, `/acceptable-use`, `/security-policy`: no `[placeholders]` left.
- [ ] `/.well-known/security.txt` shows your real security email.
- [ ] Create an account, confirm the Terms checkbox is required.
- [ ] Request a password reset and confirm the email arrives.
- [ ] Run a scan of your own site and confirm the report loads.
- [ ] Export your data (Dashboard → Account & privacy) and confirm the file is complete.
- [ ] Delete that test account and confirm it's gone.
- [ ] **Scan your own site with Bulwark.** You should score an A. Fix anything it finds before customers do.
- [ ] Check the server logs for `CONFIG:` warnings on startup.

## 5. Things to fix before you scale

These are fine for launch but will bite you later:

- **SQLite** handles a few hundred users comfortably on one machine. Move to PostgreSQL before you run
  multiple servers.
- **Scans run in the web process.** A long AI review ties up a worker. Move to a job queue (Redis + RQ or
  Celery) when scans get slow or frequent.
- **Rate limits are per-process and in memory.** With several workers, each gets its own counter. Move them
  to Redis when you run more than one.
- **No admin view.** You can't see signups or usage without opening the database.
- **DNS rebinding.** The SSRF guard resolves a host, then fetches it. A determined attacker could change
  DNS in between. Pin the resolved IP for the whole request to close this.

## 6. After launch

- [ ] Re-read the AI findings your customers get for a week. If the model is producing noise, lower
      `AI_MAX_FILES` or switch models.
- [ ] Keep dependencies patched: `pip list --outdated`, and scan your own `requirements.txt` with Bulwark.
- [ ] Review the `RETENTION_DAYS` setting against what your Privacy Policy promises (they must match).
- [ ] Watch for abuse: repeated failed verifications on domains someone doesn't own.
