# HEXWARD ⬢ — Web Vulnerability Scanner for Chrome

Hexward watches every page you load, flags security weaknesses, and maps each one to
**MITRE ATT&CK** (how attackers abuse it), **NIST SP 800-53 Rev.5** + **NIST CSF 2.0**
(the control that fixes it), and **CWE** (the weakness class). Every finding comes with a
plain-English explanation and two fixes: one for the site owner (with copy-paste config),
one for you as a visitor.

## Install (2 minutes, desktop Chrome / Edge / Brave)
1. Unzip `hexward.zip`.
2. Go to `chrome://extensions` and switch on **Developer mode** (top right).
3. Click **Load unpacked** → select the `hexward` folder.
4. Pin it: puzzle-piece icon → pin Hexward. Reload any open tabs.

The toolbar badge shows the count of Critical + High + Medium issues, colored by the worst one.
A green ✓ means the page passed. Click the icon for the full breakdown.

## What it checks (31 rules + live CVE intelligence)
| Area | Checks |
|---|---|
| Transport | Plain HTTP, password field on HTTP, mixed active/passive content, missing or short HSTS |
| Forms | Credentials over GET, forms posting to HTTP, passwords sent to a different domain (skimmer/phishing pattern) |
| Headers | CSP missing / weak (`unsafe-inline`, `unsafe-eval`, wildcards) / report-only, clickjacking (frame-ancestors / XFO), nosniff, Referrer-Policy, CORS `*`, server version banners |
| Cookies | Missing Secure, HttpOnly (session cookies), SameSite, SameSite=None without Secure |
| Components | Known-CVE versions of jQuery, Lodash, Underscore, Bootstrap, Moment, Handlebars; EOL AngularJS 1.x, Vue 2, Bootstrap 3/4 |
| Supply chain | Third-party scripts without Subresource Integrity |
| **Live CVEs** | Every detected library version is looked up on **OSV.dev**; server software announced in headers (Apache, nginx, PHP, IIS, OpenSSL, Tomcat, Jetty, lighttpd) is looked up on **NIST NVD**. Results are cross-checked against **CISA KEV**, so CVEs being exploited in real attacks are flagged **EXPLOITED IN THE WILD** and force a Critical rating. |
| Data exposure | Hard-coded secrets in inline JS (AWS, Stripe live, GitHub, Slack, OpenAI/Anthropic-style keys, private keys, Google API keys), JWTs embedded in HTML, tokens in the URL, auth tokens in localStorage, sensitive HTML comments |

## CVE lookup
- **Automatic:** after each scan, Hexward checks every detected component live and shows each CVE with its CVSS score, severity, KEV status, fixed version, and a link to NVD/OSV. Results are cached for 24 hours.
- **Manual:** tap the 🔍 button in the popup and enter any CVE ID (e.g. `CVE-2021-44228`) to pull its NVD record: score, description, CWE, and CISA's required action if it's actively exploited.
- **Offline fallback:** if the lookup fails or is turned off, a built-in database of verified CVEs for the most common libraries still runs.
- NVD allows 5 requests per 30 seconds without an API key, so server-software lookups are paced automatically.

## Scoring
Starts at 100. Critical −30, High −15, Medium −7, Low −2. Any Critical caps the grade at **D**;
any High caps it at **C**. A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F below.

## Privacy & safety
- **Page analysis is 100% local.** No analytics, no telemetry, no accounts.
- **Live CVE lookup sends only a software name + version** (e.g. `jquery 1.12.4` or a CPE string) to OSV.dev / NVD, plus a daily download of the CISA KEV list. Never the page URL, cookies, or anything you type. Turn it off in Settings to go fully offline.
- **Passive only.** It reads what your browser already received. It never sends payloads,
  probes endpoints, or fuzzes anything — so it is legal to run on any site you visit.
- Secrets are masked in the UI and in reports (`AKIA••••LE`).
- Permissions: `webRequest` (read response headers + Set-Cookie), `scripting` (run the read-only
  scanner), `storage` (keep results per tab), host access to http/https sites (required to scan them).

## Limits — know them
Hexward catches what the page exposes. It cannot see server-side flaws (SQL injection, broken
auth/IDOR, SSRF, misconfigured buckets). A clean grade means "no passive red flags," not
"secure." Real assurance needs an authorized penetration test.

## Files
`manifest.json` · `background.js` (header capture, library CVE matching, scoring, badge) ·
`content.js` (read-only DOM scanner) · `kb.js` (rules + NIST/ATT&CK/CWE mappings — edit here to add rules) ·
`popup.*` (UI) · `icons/`

---
**Credits:** Made by your friendly neighborhood bear **Brizzly** 🐻
