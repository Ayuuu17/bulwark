"use strict";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SECTIONS = ["start", "auth", "dashboard", "verify", "progress", "report"];
const METHOD_LABEL = { dns: "DNS record", file: "file upload", local: "local dev" };
const KIND_LABEL = { site: "Website report", deps: "Dependency report", code: "Code report",
  app: "App build report", store: "Published app report" };
const KIND_SUFFIX = { site: "", deps: " · dependencies", code: " · code", app: " · build", store: " · store listing" };
const RING_LENGTH = 326.73; // circumference of the grade ring (r = 52)
const REDUCED_MOTION = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const $ = (id) => document.getElementById(id);

let appName = "Bulwark";
let me = null; // logged-in user, or null
let afterAuth = null; // what to resume once the visitor has logged in
let authMessage = null;
let pendingUrl = null;
let currentResult = null;
let pollTimer = null;
let progressTimer = null;
let selectedFile = null;
let selectedCode = null;
let maxUploadMb = 100;
let resetToken = null;

class AuthRequired extends Error {}

// Build DOM nodes without innerHTML. Report text comes from scanned sites, so it is never parsed as HTML.
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") el.className = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

// Render `backtick` spans as <code>, everything else as plain text.
function richText(text) {
  return String(text).split("`").map((part, i) => (i % 2 ? h("code", {}, part) : part));
}

function show(section) {
  for (const id of SECTIONS) $(id).hidden = id !== section;
  window.scrollTo({ top: 0 });
}

function showError(message) {
  show("start");
  $("form-error").textContent = message;
  $("form-error").hidden = false;
}

function fail(err) {
  if (!(err instanceof AuthRequired)) showError(err.message);
}

// Navigate to a hash, re-running the router even if we're already there.
function go(hash) {
  if (location.hash === hash || (!hash && !location.hash)) route();
  else location.hash = hash;
}

async function api(path, { body, method, raw } = {}) {
  const options = { method: method || (body === undefined && raw === undefined ? "GET" : "POST"), headers: {} };
  if (raw !== undefined) {
    options.headers["Content-Type"] = "application/octet-stream";
    options.body = raw; // a File: streamed as-is
  } else if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const res = await fetch(path, options);
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON error page */ }
  if (res.status === 401 && !path.startsWith("/api/auth/")) {
    setUser(null);
    authMessage = "Your session ended. Please log in again.";
    go("#login");
    throw new AuthRequired();
  }
  if (!res.ok) {
    const detail = data && data.detail;
    throw new Error(typeof detail === "string" ? detail : `Request failed (${res.status})`);
  }
  return data;
}

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const original = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = original; }, 1200);
  } catch {
    button.textContent = "Select & copy";
  }
}

function formatDate(seconds) {
  return new Date(seconds * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function setStatus(el, message, ok) {
  el.textContent = message;
  el.className = `form-status ${ok ? "good" : "bad"}`;
}

/* ---------- hero: a sample report, drawn line by line ---------- */

// An abbreviated version of a real website report, so the landing page shows the actual output.
const SAMPLE_REPORT = [
  ["cmd", "scan example.com"],
  ["dim", "ownership verified · non-intrusive checks"],
  ["ok", "TLS 1.3 · certificate valid 74 more days"],
  ["ok", "HTTP redirects to HTTPS"],
  ["warn", "Content-Security-Policy header missing"],
  ["bad", "Session cookie missing the Secure flag"],
  ["warn", "jquery 3.4.1 · 2 known vulnerabilities"],
  ["ok", "SPF and DMARC published"],
  ["dim", "8 checks · 2 warnings · 1 failure"],
  ["grade", "B"],
];

function drawSampleReport() {
  const list = $("scanlines");
  if (!list) return;
  const node = ([kind, text]) => kind === "grade"
    ? h("li", { class: "line grade-line" }, "grade ", h("b", { class: "grade-B" }, text),
      h("span", { class: "dim" }, "  → fix 2 issues to reach A"))
    : h("li", { class: `line ${kind}` }, text);

  if (REDUCED_MOTION) {
    list.replaceChildren(...SAMPLE_REPORT.map(node));
    return;
  }
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  (async function loop() {
    for (;;) {
      list.replaceChildren();
      for (const line of SAMPLE_REPORT) {
        list.append(node(line));
        await sleep(line[0] === "cmd" ? 700 : 320);
      }
      await sleep(6000);
    }
  })();
}

/* ---------- accounts ---------- */

function setUser(user) {
  me = user;
  $("nav").replaceChildren(...(user
    ? [
      h("a", { href: "#dashboard", class: "btn ghost small" }, "Dashboard"),
      h("span", { class: "nav-email muted" }, user.email),
      h("button", { type: "button", class: "btn ghost small", onclick: logout }, "Log out"),
    ]
    : [
      h("a", { href: "#login", class: "btn ghost small" }, "Log in"),
      h("a", { href: "#signup", class: "btn primary small" }, "Sign up"),
    ]));
}

function requireLogin(message, next, mode = "#signup") {
  authMessage = message;
  afterAuth = next;
  go(mode);
}

const AUTH_MODES = {
  signup: { title: "Create your account", sub: "Free. Keep your verified domains and every report in one place.",
    submit: "Create account", switchText: "Already have an account?", switchLabel: "Log in", switchHref: "#login" },
  login: { title: "Log in", sub: "Welcome back.", submit: "Log in",
    switchText: "New here?", switchLabel: "Create an account", switchHref: "#signup" },
  forgot: { title: "Reset your password", sub: "Enter your email and we'll send you a link to choose a new password.",
    submit: "Send reset link", switchText: "Remembered it?", switchLabel: "Log in", switchHref: "#login" },
  reset: { title: "Choose a new password", sub: "This signs you out everywhere else.", submit: "Set new password",
    switchText: "Changed your mind?", switchLabel: "Log in", switchHref: "#login" },
};

function showAuth(mode) {
  const config = AUTH_MODES[mode];
  $("auth-form").dataset.mode = mode;
  $("auth-title").textContent = config.title;
  $("auth-sub").textContent = authMessage || config.sub;
  $("auth-email-group").hidden = mode === "reset";
  $("auth-password-group").hidden = mode === "forgot";
  $("auth-password").setAttribute("autocomplete", mode === "login" ? "current-password" : "new-password");
  $("auth-hint").hidden = mode === "login";
  $("auth-terms").hidden = mode !== "signup";
  $("auth-forgot").hidden = mode !== "login";
  $("auth-submit").textContent = config.submit;
  $("auth-switch-text").textContent = config.switchText;
  $("auth-switch-link").textContent = config.switchLabel;
  $("auth-switch-link").href = config.switchHref;
  $("auth-error").hidden = true;
  $("auth-info").hidden = true;
  show("auth");
  (mode === "reset" ? $("auth-password") : $("auth-email")).focus();
}

async function onAuthSubmit(event) {
  event.preventDefault();
  const button = $("auth-submit");
  const mode = $("auth-form").dataset.mode;
  const email = $("auth-email").value;
  const password = $("auth-password").value;
  $("auth-error").hidden = true;
  if (mode === "signup" && !$("auth-accept").checked) {
    $("auth-error").textContent = "Please accept the Terms of Service and Acceptable Use Policy to continue.";
    $("auth-error").hidden = false;
    return;
  }
  button.disabled = true;
  try {
    if (mode === "forgot") {
      const { message } = await api("/api/auth/forgot", { body: { email } });
      $("auth-info").textContent = message;
      $("auth-info").hidden = false;
      return;
    }
    const { user } = mode === "reset"
      ? await api("/api/auth/reset", { body: { token: resetToken, password } })
      : await api(`/api/auth/${mode}`, { body: { email, password, accept_terms: mode === "signup" } });
    resetToken = null;
    $("auth-password").value = "";
    setUser(user);
    authMessage = null;
    const next = afterAuth;
    afterAuth = null;
    if (next) {
      history.replaceState(null, "", location.pathname);
      next();
    } else {
      go("#dashboard");
    }
  } catch (err) {
    $("auth-error").textContent = err.message;
    $("auth-error").hidden = false;
  } finally {
    button.disabled = false;
  }
}

async function logout() {
  try { await api("/api/auth/logout", { body: {} }); } catch { /* signed out locally anyway */ }
  setUser(null);
  go("");
}

/* ---------- start screen ---------- */

function selectTab(name) {
  document.querySelectorAll(".tab").forEach((tab) => tab.setAttribute("aria-selected", String(tab.dataset.tab === name)));
  document.querySelectorAll(".panel").forEach((panel) => { panel.hidden = panel.dataset.panel !== name; });
  $("form-error").hidden = true;
}

function onSiteSubmit(event) {
  event.preventDefault();
  $("form-error").hidden = true;
  const url = $("url").value.trim();
  if (!url) return showError("Enter your website address.");
  if (!me) return requireLogin("Create a free account to scan your site. It takes ten seconds.", () => beginSiteScan(url));
  beginSiteScan(url, event.submitter);
}

async function beginSiteScan(url, button) {
  if (button) button.disabled = true;
  try {
    const info = await api("/api/verify/instructions", { body: { url } });
    pendingUrl = url;
    if (info.verified) return await startSiteScan(url);
    $("verify-host").textContent = info.host;
    $("dns-name").textContent = info.dns.name;
    $("dns-value").textContent = info.dns.value;
    $("file-url").textContent = info.file.url;
    $("file-content").textContent = info.file.content;
    $("verify-status").textContent = "";
    $("verify-status").className = "verify-status";
    show("verify");
  } catch (err) {
    fail(err);
  } finally {
    if (button) button.disabled = false;
  }
}

async function onVerify() {
  const status = $("verify-status");
  const button = $("verify-btn");
  button.disabled = true;
  status.className = "verify-status";
  status.textContent = "Checking…";
  try {
    const res = await api("/api/verify/check", { body: { url: pendingUrl } });
    if (res.verified) {
      status.className = "verify-status good";
      status.textContent = "Verified. Starting scan…";
      await startSiteScan(pendingUrl);
    } else {
      status.className = "verify-status bad";
      status.textContent = "We couldn't find the token yet. DNS can take a few minutes to update; try again shortly.";
    }
  } catch (err) {
    if (err instanceof AuthRequired) return;
    status.className = "verify-status bad";
    status.textContent = err.message;
  } finally {
    button.disabled = false;
  }
}

async function startSiteScan(url) {
  try {
    const { id } = await api("/api/scans", { body: { url } });
    go(`#scan=${id}`);
  } catch (err) {
    fail(err);
  }
}

function wireDropzone(input, onFile) {
  const zone = input.closest(".dropzone");
  input.addEventListener("change", () => onFile(input.files[0]));
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("drag"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("drag"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("drag");
    onFile(e.dataTransfer.files[0]);
  });
}

function onStoreSubmit(event) {
  event.preventDefault();
  $("form-error").hidden = true;
  const url = $("store-url").value.trim();
  if (!url) return showError("Paste your app's App Store or Google Play link.");
  if (!me) return requireLogin("Create a free account to scan your published app.", () => submitStore(url));
  submitStore(url, event.submitter);
}

async function submitStore(url, button) {
  if (button) button.disabled = true;
  try {
    const { id } = await api("/api/store", { body: { url } });
    go(`#scan=${id}`);
  } catch (err) {
    fail(err);
  } finally {
    if (button) button.disabled = false;
  }
}

function setFile(file) {
  selectedFile = file || null;
  $("dropzone-title").textContent = file ? file.name : "Choose a file or drop it here";
}

function setCodeFile(file) {
  selectedCode = file || null;
  $("code-drop-title").textContent = file ? `${file.name} (${(file.size / 1e6).toFixed(1)} MB)` : "Choose a file or drop it here";
}

function onCodeSubmit(event) {
  event.preventDefault();
  $("form-error").hidden = true;
  if (!selectedCode) return showError("Choose a .zip, .apk or .ipa file first.");
  if (!/\.(zip|apk|ipa)$/i.test(selectedCode.name)) return showError("Upload a .zip of your project, an .apk or an .ipa.");
  if (selectedCode.size > maxUploadMb * 1e6) return showError(`That file is over ${maxUploadMb} MB.`);
  if (!$("code-attest").checked) return showError("Please confirm you own this code or are authorized to scan it.");
  if (!me) return requireLogin("Create a free account to scan your code.", submitCode);
  submitCode();
}

async function submitCode() {
  const ai = !$("ai-option").hidden && $("code-ai").checked;
  const params = new URLSearchParams({ filename: selectedCode.name, ai: String(ai), attest: "true" });
  try {
    const { id } = await api(`/api/code?${params}`, { raw: selectedCode });
    go(`#scan=${id}`);
  } catch (err) {
    fail(err);
  }
}

function onDepsSubmit(event) {
  event.preventDefault();
  $("form-error").hidden = true;
  if (!selectedFile) return showError("Choose a dependency file first.");
  if (selectedFile.size > 5_000_000) return showError("That file is over 5 MB.");
  if (!me) return requireLogin("Create a free account to check your dependencies.", submitDeps);
  submitDeps();
}

async function submitDeps() {
  try {
    const content = await selectedFile.text();
    const { id } = await api("/api/deps", { body: { filename: selectedFile.name, content } });
    go(`#scan=${id}`);
  } catch (err) {
    fail(err);
  }
}

/* ---------- routing & progress ---------- */

function route() {
  clearTimeout(pollTimer);
  clearInterval(progressTimer);
  $("progress-steps").dataset.kind = "";
  const hash = location.hash;
  const scan = hash.match(/^#scan=([a-f0-9]{32})$/);
  const reset = hash.match(/^#reset=([A-Za-z0-9_-]{20,})$/);
  if (reset) {
    resetToken = reset[1];
    history.replaceState(null, "", location.pathname); // keep the token out of history
    authMessage = null;
    return showAuth("reset");
  }
  if (["#login", "#signup", "#forgot"].includes(hash)) return showAuth(hash.slice(1));
  if (hash === "#scanner" || hash === "#how") {
    show("start");
    return requestAnimationFrame(() => $(hash.slice(1)).scrollIntoView({ behavior: "smooth" }));
  }
  if ((scan || hash === "#dashboard") && !me) {
    return requireLogin("Log in to see your reports.", () => go(hash), "#login");
  }
  if (scan) {
    $("progress-title").textContent = "Loading report…";
    $("progress-sub").textContent = "";
    show("progress");
    return poll(scan[1]);
  }
  if (hash === "#dashboard") return loadDashboard();
  show("start");
}

async function poll(id) {
  let scan;
  try {
    scan = await api(`/api/scans/${id}`);
  } catch (err) {
    history.replaceState(null, "", location.pathname);
    return fail(err);
  }
  if (location.hash !== `#scan=${id}`) return; // navigated away meanwhile
  if (scan.status === "done") return renderReport(scan.result);
  if (scan.status === "failed") {
    history.replaceState(null, "", location.pathname);
    return showError(scan.error || "The scan failed.");
  }
  $("progress-title").textContent = `Scanning ${scan.target}…`;
  $("progress-sub").textContent = scan.kind === "code"
    ? "Code scans take a few seconds, or a few minutes with AI review. You can leave this page; the report will be in your dashboard."
    : "This usually takes 5–20 seconds.";
  startProgressSteps(scan.kind);
  pollTimer = setTimeout(() => poll(id), 1500);
}

// Shows which part of the scan is likely running. The backend does them concurrently, so these are
// paced estimates for feedback, not reported progress.
const PROGRESS_STEPS = {
  site: ["Resolving host", "Checking HTTPS and certificate", "Reading security headers",
    "Inspecting cookies and page content", "Looking up JavaScript libraries", "Checking DNS email records"],
  code: ["Unpacking archive in memory", "Searching for leaked secrets", "Running code security rules",
    "Checking app and cloud configuration", "Looking up dependencies", "Finishing up"],
  app: ["Unpacking app in memory", "Decoding app configuration", "Searching for embedded secrets",
    "Checking for insecure endpoints"],
  store: ["Reading the store listing", "Checking the privacy policy link", "Reading data-safety disclosures",
    "Fetching App Links files", "Finding backend domains"],
  deps: ["Reading dependency file", "Querying the vulnerability database", "Matching fixed versions"],
};

function startProgressSteps(kind) {
  const steps = PROGRESS_STEPS[kind] || PROGRESS_STEPS.site;
  const list = $("progress-steps");
  if (list.dataset.kind === kind) return; // already running for this scan
  list.dataset.kind = kind;
  clearInterval(progressTimer);
  const items = steps.map((text) => h("li", {}, text));
  list.replaceChildren(...items);
  let index = 0;
  const advance = () => {
    items.forEach((li, i) => { li.className = i < index ? "done" : i === index ? "active" : ""; });
    index += 1;
    if (index > items.length) clearInterval(progressTimer);
  };
  advance();
  progressTimer = setInterval(advance, 1800);
}

/* ---------- dashboard ---------- */

function renderDashStats(scans, domains) {
  const done = scans.filter((s) => s.status === "done");
  const open = done.reduce((total, s) => total + SEVERITIES
    .filter((sev) => sev !== "info" && sev !== "low")
    .reduce((n, sev) => n + ((s.summary && s.summary[sev]) || 0), 0), 0);
  const critical = done.reduce((n, s) => n + ((s.summary && s.summary.critical) || 0), 0);
  const stats = [
    [String(done.length), "reports"],
    [String(domains.length), domains.length === 1 ? "verified domain" : "verified domains"],
    [String(open), "high-priority issues"],
    [String(critical), "critical issues"],
  ];
  $("dash-stats").replaceChildren(...stats.map(([value, label], i) =>
    h("div", { class: "dash-stat" },
      h("strong", { class: i >= 2 && Number(value) > 0 ? "sev-high" : "" }, value),
      h("span", {}, label))));
}

function loadDashboard() {
  $("dash-email").textContent = me.email;
  const loading = () => h("p", { class: "empty-line" }, "Loading…");
  $("dash-stats").replaceChildren();
  $("domains").replaceChildren(loading());
  $("history").replaceChildren(loading());
  for (const id of ["password-status", "delete-status"]) $(id).textContent = "";
  show("dashboard");
  refreshDashboard();
}

async function refreshDashboard() {
  try {
    const [{ domains }, { scans }] = await Promise.all([api("/api/domains"), api("/api/scans")]);
    if (location.hash !== "#dashboard") return;
    renderDashStats(scans, domains);
    renderDomains(domains);
    renderHistory(scans);
    if (scans.some((s) => s.status === "queued" || s.status === "running")) {
      pollTimer = setTimeout(refreshDashboard, 2500);
    }
  } catch (err) {
    fail(err);
  }
}

function renderDomains(domains) {
  if (!domains.length) {
    return $("domains").replaceChildren(h("p", { class: "empty-line" },
      "No verified domains yet. Start a website scan and we'll walk you through verifying it."));
  }
  $("domains").replaceChildren(...domains.map((d) => {
    const daysLeft = Math.max(0, Math.ceil((d.expires_at * 1000 - Date.now()) / 86_400_000));
    return h("div", { class: "item no-badge" },
      h("div", {},
        h("div", { class: "item-title" }, d.host),
        h("div", { class: "item-meta" }, d.expired
          ? "Verification expired. Re-verify to scan again."
          : `Verified by ${METHOD_LABEL[d.method] || d.method} · valid for ${daysLeft} more day${daysLeft === 1 ? "" : "s"}`)),
      h("div", { class: "item-actions" },
        h("button", { type: "button", class: "btn small primary", onclick: () => beginSiteScan(`https://${d.host}`) },
          d.expired ? "Re-verify" : "Scan"),
        h("button", { type: "button", class: "btn small ghost", onclick: () => removeDomain(d.host) }, "Remove")));
  }));
}

function issueSummary(summary) {
  const parts = SEVERITIES.filter((sev) => sev !== "info" && summary && summary[sev]).map((sev) => `${summary[sev]} ${sev}`);
  return parts.length ? parts.join(", ") : "No issues";
}

function renderHistory(scans) {
  if (!scans.length) {
    return $("history").replaceChildren(h("p", { class: "empty-line" }, "No scans yet. Your reports will show up here."));
  }
  $("history").replaceChildren(...scans.map((s) => {
    const done = s.status === "done";
    const badge = done
      ? h("span", { class: `mini-grade grade-${s.grade}` }, s.grade)
      : s.status === "failed"
        ? h("span", { class: "mini-grade failed", title: "Failed" }, "!")
        : h("span", { class: "mini-grade pending", title: "Scanning" }, "…");
    const label = s.target + (KIND_SUFFIX[s.kind] || "");
    const status = done ? issueSummary(s.summary) : s.status === "failed" ? s.error || "Scan failed" : "Scanning…";
    return h("div", { class: "item" },
      badge,
      h("div", {},
        done ? h("a", { href: `#scan=${s.id}`, class: "item-title" }, label) : h("div", { class: "item-title" }, label),
        h("div", { class: "item-meta" }, `${formatDate(s.created_at)} · ${status}`)),
      h("div", { class: "item-actions" },
        done && h("a", { href: `#scan=${s.id}`, class: "btn small ghost" }, "View"),
        h("button", { type: "button", class: "btn small ghost", onclick: () => deleteScan(s.id) }, "Delete")));
  }));
}

async function removeDomain(host) {
  if (!confirm(`Remove ${host}? You'll need to verify it again before scanning it.`)) return;
  try {
    await api(`/api/domains/${encodeURIComponent(host)}`, { method: "DELETE" });
    refreshDashboard();
  } catch (err) {
    fail(err);
  }
}

async function deleteScan(id) {
  if (!confirm("Delete this report? This can't be undone.")) return;
  try {
    await api(`/api/scans/${id}`, { method: "DELETE" });
    refreshDashboard();
  } catch (err) {
    fail(err);
  }
}

async function onPasswordSubmit(event) {
  event.preventDefault();
  const status = $("password-status");
  try {
    await api("/api/account/password", {
      body: { current_password: $("pw-current").value, new_password: $("pw-new").value },
    });
    event.target.reset();
    setStatus(status, "Password updated. Any other devices were signed out.", true);
  } catch (err) {
    if (!(err instanceof AuthRequired)) setStatus(status, err.message, false);
  }
}

async function onDeleteSubmit(event) {
  event.preventDefault();
  if (!confirm("Permanently delete your account and all your reports?")) return;
  try {
    await api("/api/account/delete", { body: { password: $("delete-password").value } });
    event.target.reset();
    setUser(null);
    go("");
  } catch (err) {
    if (!(err instanceof AuthRequired)) setStatus($("delete-status"), err.message, false);
  }
}

/* ---------- report ---------- */

function renderReport(result) {
  currentResult = result;
  $("grade").textContent = result.grade;
  $("grade-score").textContent = `${result.score}/100`;
  const ringBox = document.querySelector(".grade-ring");
  ringBox.className = `grade-ring grade-${result.grade}`;
  const ring = $("ring-value");
  ring.style.setProperty("stroke-dashoffset", String(RING_LENGTH));
  requestAnimationFrame(() => requestAnimationFrame(() =>
    ring.style.setProperty("stroke-dashoffset", String(RING_LENGTH * (1 - result.score / 100)))));

  $("report-kind").textContent = KIND_LABEL[result.kind] || "Report";
  $("report-target").textContent = result.kind === "site" ? result.final_url || result.target
    : result.kind === "store" ? `${result.app_name} (${result.app_id})`
      : result.target;
  const meta = [`Score ${result.score}/100`];
  if (result.kind === "deps") meta.push(`${result.packages_scanned} packages checked (${result.ecosystem})`);
  if (result.kind === "code") {
    meta.push(`${result.files_scanned} files`);
    if (result.languages.length) meta.push(result.languages.join(", "));
    if (result.packages_scanned) meta.push(`${result.packages_scanned} dependencies`);
  }
  if (result.kind === "store") {
    if (result.app_version) meta.push(`v${result.app_version}`);
    if (result.developer) meta.push(result.developer);
    if (result.last_updated) meta.push(`updated ${result.last_updated}`);
  }
  if (result.platforms && result.platforms.length) meta.push(result.platforms.join(" + "));
  if (result.scanned_at) meta.push(new Date(result.scanned_at).toLocaleString());
  meta.push(`${(result.duration_ms / 1000).toFixed(1)}s`);
  $("report-meta").textContent = meta.join(" · ");

  $("counts").replaceChildren(...SEVERITIES.map((sev) =>
    h("span", { class: `pill sev-${sev}${result.summary[sev] ? "" : " zero"}` }, `${result.summary[sev]} ${sev}`)));

  $("notes").replaceChildren(...(result.notes || []).map((note) => h("p", { class: "note" }, note)));

  const filters = ["all", ...SEVERITIES.filter((sev) => result.summary[sev])];
  $("filters").replaceChildren(...filters.map((sev) => h("button", {
    type: "button",
    class: "filter",
    "aria-pressed": String(sev === "all"),
    "data-sev": sev,
    onclick: () => applyFilter(sev),
  }, sev === "all" ? `All (${result.findings.length})` : `${sev[0].toUpperCase()}${sev.slice(1)} (${result.summary[sev]})`)));

  $("findings").replaceChildren(...(result.findings.length
    ? result.findings.map((finding, i) => renderFinding(finding, i, result))
    : [h("div", { class: "card empty" }, "No issues found. Nice work!")]));

  $("passed-summary").textContent = `Passed checks (${result.passed.length})`;
  $("passed").replaceChildren(...result.passed.map((item) => h("li", {}, item)));
  $("passed-box").hidden = result.passed.length === 0;

  document.title = `${result.grade} · ${$("report-target").textContent} · ${appName}`;
  show("report");
}

function applyFilter(sev) {
  document.querySelectorAll(".filter").forEach((btn) => btn.setAttribute("aria-pressed", String(btn.dataset.sev === sev)));
  document.querySelectorAll(".finding").forEach((card) => { card.hidden = sev !== "all" && card.dataset.sev !== sev; });
}

// A store report lists the app's backend domains; turn them into one-click website scans.
function backendActions(result) {
  return h("div", { class: "row inline-actions" }, ...result.backend_domains.map((host) =>
    h("button", {
      type: "button",
      class: "btn small primary",
      onclick: () => beginSiteScan(`https://${host}`),
    }, `Scan ${host}`)));
}

function renderFinding(finding, index, result) {
  const extra = finding.id === "store-backend-next-step" && result && result.backend_domains
    && result.backend_domains.length ? backendActions(result) : null;
  const body = h("div", { class: "finding-body" },
    h("h4", {}, "What we found"), h("p", {}, richText(finding.description)),
    finding.evidence && [h("h4", {}, "Evidence"), h("pre", { class: "evidence" }, finding.evidence)],
    h("h4", {}, "Why it matters"), h("p", {}, richText(finding.impact)),
    h("h4", {}, "How to fix it"), h("p", {}, richText(finding.fix)),
    extra,
    Object.keys(finding.snippets).length > 0 && renderSnippets(finding.snippets),
    finding.references.length > 0 && [
      h("h4", {}, "Learn more"),
      h("ul", { class: "refs" }, finding.references
        .filter((url) => url.startsWith("https://"))
        .map((url) => h("li", {}, h("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, url)))),
    ],
  );
  return h("details", { class: `card finding sev-${finding.severity}`, "data-sev": finding.severity, open: index < 3 },
    h("summary", {},
      h("span", { class: `pill sev-${finding.severity}` }, finding.severity),
      h("span", { class: "finding-title" }, finding.title, h("span", { class: "finding-cat" }, finding.category))),
    body);
}

function renderSnippets(snippets) {
  const names = Object.keys(snippets);
  const pre = h("pre", {}, snippets[names[0]]);
  let active = names[0];
  const tabs = names.map((name, i) => h("button", {
    type: "button",
    class: "snippet-tab",
    role: "tab",
    "aria-selected": String(i === 0),
    onclick: (event) => {
      active = name;
      pre.textContent = snippets[name];
      tabs.forEach((tab) => tab.setAttribute("aria-selected", String(tab === event.currentTarget)));
    },
  }, name));
  const copy = h("button", { type: "button", class: "snippet-copy", onclick: (e) => copyText(snippets[active], e.currentTarget) }, "Copy");
  return h("div", { class: "snippets" }, h("div", { class: "snippet-tabs", role: "tablist" }, tabs, copy), pre);
}

function downloadJson() {
  if (!currentResult) return;
  const blob = new Blob([JSON.stringify(currentResult, null, 2)], { type: "application/json" });
  const link = h("a", { href: URL.createObjectURL(blob), download: `security-report-${Date.now()}.json` });
  link.click();
  URL.revokeObjectURL(link.href);
}

// Closed <details> don't print, so open everything for the PDF and restore afterwards.
let closedBeforePrint = [];
window.addEventListener("beforeprint", () => {
  closedBeforePrint = [...document.querySelectorAll("#report details:not([open])")];
  closedBeforePrint.forEach((d) => { d.open = true; });
});
window.addEventListener("afterprint", () => closedBeforePrint.forEach((d) => { d.open = false; }));

/* ---------- wiring ---------- */

document.addEventListener("DOMContentLoaded", async () => {
  document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => selectTab(tab.dataset.tab)));
  $("site-form").addEventListener("submit", onSiteSubmit);
  $("deps-form").addEventListener("submit", onDepsSubmit);
  $("auth-form").addEventListener("submit", onAuthSubmit);
  $("password-form").addEventListener("submit", onPasswordSubmit);
  $("delete-form").addEventListener("submit", onDeleteSubmit);
  $("verify-btn").addEventListener("click", onVerify);
  $("verify-cancel").addEventListener("click", () => go(""));
  $("new-scan").addEventListener("click", () => go(""));
  $("dl-json").addEventListener("click", downloadJson);
  $("print").addEventListener("click", () => window.print());
  document.querySelectorAll("[data-copy]").forEach((btn) =>
    btn.addEventListener("click", () => copyText($(btn.dataset.copy).textContent, btn)));

  $("code-form").addEventListener("submit", onCodeSubmit);
  $("store-form").addEventListener("submit", onStoreSubmit);
  document.querySelectorAll("[data-goto-tab]").forEach((btn) =>
    btn.addEventListener("click", () => selectTab(btn.dataset.gotoTab)));
  wireDropzone($("manifest"), setFile);
  wireDropzone($("code-file"), setCodeFile);

  try {
    setUser((await api("/api/auth/me")).user);
  } catch {
    setUser(null);
  }
  window.addEventListener("hashchange", route);
  route();
  drawSampleReport();

  try {
    const cfg = await api("/api/config");
    appName = cfg.app_name;
    document.querySelectorAll("[data-app-name]").forEach((el) => { el.textContent = appName; });
    if (!location.hash) document.title = `${appName}: security scanner`;
    $("dev-badge").hidden = !cfg.dev_mode;
    $("ai-option").hidden = !cfg.ai_review;
    maxUploadMb = cfg.max_upload_mb;
    if (cfg.ai_review && cfg.ai_provider) {
      $("ai-provider").textContent = ` Files are reviewed by ${cfg.ai_provider}.`;
    }
  } catch { /* keep defaults */ }
});
