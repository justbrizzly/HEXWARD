// HEXWARD service worker: captures response headers, orchestrates scans, scores, badges.
import { RULES, SEVERITY } from './kb.js';
import { lookupNpm, lookupCpe, getKev, serverSoftware, cveFinding, NPM_PACKAGES } from './cve.js';

const hKey = (tabId) => `h:${tabId}`;
const rKey = (tabId) => `r:${tabId}`;
const stripHash = (u) => { try { const x = new URL(u); x.hash = ''; return x.href; } catch { return u; } };
const scannable = (u) => /^https?:\/\//i.test(u || '') && !/^https:\/\/(chrome\.google\.com\/webstore|chromewebstore\.google\.com)/i.test(u);

// ───────── 1. Capture main-document response headers (passive, read-only) ─────────
chrome.webRequest.onHeadersReceived.addListener(
  (d) => {
    if (d.tabId < 0) return;
    chrome.storage.session.set({
      [hKey(d.tabId)]: { url: stripHash(d.url), status: d.statusCode, headers: d.responseHeaders || [], ts: Date.now() },
    });
  },
  { urls: ['http://*/*', 'https://*/*'], types: ['main_frame'] },
  ['responseHeaders', 'extraHeaders'],
);

// ───────── 2. Header analysis ─────────
function parseCsp(str) {
  const map = {};
  for (const part of str.split(';')) {
    const [name, ...vals] = part.trim().split(/\s+/);
    if (name && !(name.toLowerCase() in map)) map[name.toLowerCase()] = vals;
  }
  return map;
}

function analyzeHeaders(rec, pageUrl, metaCsp) {
  const out = [];
  const isHttps = pageUrl.startsWith('https:');
  const all = rec.headers.map((h) => ({ name: h.name.toLowerCase(), value: h.value || '' }));
  const get = (n) => all.filter((h) => h.name === n).map((h) => h.value);
  const one = (n) => get(n)[0];

  // HSTS
  if (isHttps) {
    const hsts = one('strict-transport-security');
    if (!hsts) out.push({ rule: 'hsts-missing', evidence: ['Strict-Transport-Security: (absent)'] });
    else {
      const age = +(hsts.match(/max-age\s*=\s*"?(\d+)/i) || [])[1] || 0;
      if (age < 15552000) out.push({ rule: 'hsts-weak', evidence: [`max-age=${age} (${Math.round(age / 86400)} days; want ≥ 365)`] });
    }
  }

  // CSP
  const cspHeaders = get('content-security-policy');
  const cspRO = get('content-security-policy-report-only');
  const policies = [...cspHeaders, ...(metaCsp || [])];
  if (!policies.length) {
    if (cspRO.length) out.push({ rule: 'csp-report-only', evidence: ['Content-Security-Policy-Report-Only: ' + cspRO[0].slice(0, 140)] });
    else out.push({ rule: 'csp-missing', evidence: ['Content-Security-Policy: (absent)'] });
  } else {
    // A script is allowed only if every policy allows it, so the page is protected if ANY policy is strong.
    const problemsPer = policies.map((p) => {
      const d = parseCsp(p);
      const src = d['script-src'] || d['default-src'];
      const issues = [];
      if (!src) { issues.push('No script-src or default-src — scripts unrestricted'); return issues; }
      const s = src.map((x) => x.toLowerCase());
      const hasNonceHash = s.some((x) => /^'(nonce-|sha(256|384|512)-)/.test(x));
      const strictDyn = s.includes("'strict-dynamic'");
      if (s.includes("'unsafe-inline'") && !hasNonceHash) issues.push("script-src allows 'unsafe-inline'");
      if (s.includes("'unsafe-eval'")) issues.push("script-src allows 'unsafe-eval'");
      if (!strictDyn) {
        const wild = s.filter((x) => x === '*' || x === 'http:' || x === 'https:' || x === 'data:' || /^https?:\/\/\*$/.test(x));
        if (wild.length) issues.push('script-src allows any host: ' + wild.join(' '));
      }
      return issues;
    });
    const strong = problemsPer.some((p) => p.length === 0);
    if (!strong) out.push({ rule: 'csp-weak', evidence: [...new Set(problemsPer.flat())] });
  }

  // Clickjacking
  const xfo = (one('x-frame-options') || '').toLowerCase();
  const fa = cspHeaders.some((p) => /frame-ancestors/i.test(p));
  if (!fa && !/deny|sameorigin/.test(xfo)) out.push({ rule: 'clickjacking', evidence: ['No CSP frame-ancestors', 'X-Frame-Options: ' + (xfo || '(absent)')] });

  // nosniff
  if ((one('x-content-type-options') || '').toLowerCase().trim() !== 'nosniff') out.push({ rule: 'nosniff-missing', evidence: ['X-Content-Type-Options: ' + (one('x-content-type-options') || '(absent)')] });

  // Referrer-Policy (header or meta handled by browser default — Chrome default is safe)
  if (!one('referrer-policy')) out.push({ rule: 'referrer-policy-missing', evidence: ['Referrer-Policy: (absent)'] });

  // Server banners
  const banners = [];
  const server = one('server');
  if (server && /\d/.test(server)) banners.push('Server: ' + server);
  for (const n of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator']) {
    const v = one(n);
    if (v) banners.push(n.replace(/(^|-)([a-z])/g, (m, a, b) => a + b.toUpperCase()) + ': ' + v);
  }
  if (banners.length) out.push({ rule: 'server-banner', evidence: banners });

  // CORS on the document
  const acao = one('access-control-allow-origin');
  const acac = (one('access-control-allow-credentials') || '').toLowerCase() === 'true';
  if (acao === '*' && acac) out.push({ rule: 'cors-credentials', evidence: ['Access-Control-Allow-Origin: *', 'Access-Control-Allow-Credentials: true'] });
  else if (acao === '*') out.push({ rule: 'cors-wildcard', evidence: ['Access-Control-Allow-Origin: *'] });

  // Cookies
  const SESSIONY = /(sess|sid|token|auth|jwt|login|connect\.sid|remember|csrf|xsrf)/i;
  const noSecure = [], noHttpOnly = [], noSameSite = [], noneInsecure = [];
  for (const raw of get('set-cookie').flatMap((v) => v.split('\n'))) {
    const parts = raw.split(';').map((p) => p.trim());
    const name = (parts[0] || '').split('=')[0];
    if (!name) continue;
    const attrs = parts.slice(1).map((p) => p.toLowerCase());
    const secure = attrs.includes('secure') || /^__(secure|host)-/i.test(name);
    const httpOnly = attrs.includes('httponly');
    const ss = (attrs.find((a) => a.startsWith('samesite')) || '').split('=')[1];
    const expired = attrs.some((a) => a === 'max-age=0' || /^expires=.*19[67]\d/.test(a));
    if (expired) continue;
    if (isHttps && !secure) noSecure.push(name);
    if (!httpOnly && SESSIONY.test(name) && !/csrf|xsrf/i.test(name)) noHttpOnly.push(name);
    if (!ss) noSameSite.push(name);
    if (ss === 'none' && !secure) noneInsecure.push(name);
  }
  if (noSecure.length) out.push({ rule: 'cookie-no-secure', evidence: noSecure });
  if (noHttpOnly.length) out.push({ rule: 'cookie-no-httponly', evidence: noHttpOnly });
  if (noneInsecure.length) out.push({ rule: 'cookie-samesite-none-insecure', evidence: noneInsecure });
  if (noSameSite.length) out.push({ rule: 'cookie-no-samesite', evidence: noSameSite });

  return out;
}

// ───────── 3. Library version detection (runs in the PAGE's JS world, read-only) ─────────
function detectLibsInPage() {
  const o = {};
  const g = window;
  try { if (g.jQuery?.fn?.jquery) o.jquery = g.jQuery.fn.jquery; } catch {}
  try { if (g.angular?.version?.full) o.angular = g.angular.version.full; } catch {}
  try {
    const bs = g.bootstrap?.Tooltip?.VERSION || g.jQuery?.fn?.tooltip?.Constructor?.VERSION;
    if (bs) o.bootstrap = bs;
  } catch {}
  try {
    if (g._?.VERSION) {
      if (typeof g._.flatMapDeep === 'function') o.lodash = g._.VERSION; else o.underscore = g._.VERSION;
    }
  } catch {}
  try { if (g.moment?.version) o.moment = g.moment.version; } catch {}
  try { if (g.Handlebars?.VERSION) o.handlebars = g.Handlebars.VERSION; } catch {}
  try { if (g.Vue?.version) o.vue = g.Vue.version; } catch {}
  try { if (g.jQuery?.ui?.version) o.jqueryui = g.jQuery.ui.version; } catch {}
  try { if (g.React?.version) o.react = g.React.version; } catch {}
  try { if (g.DOMPurify?.version) o.dompurify = g.DOMPurify.version; } catch {}
  try { if (g.ko?.version) o.knockout = g.ko.version; } catch {}
  try { if (g.axios?.VERSION) o.axios = g.axios.VERSION; } catch {}
  try { if (g.d3?.version) o.d3 = g.d3.version; } catch {}
  try { if (g.Ember?.VERSION) o.ember = g.Ember.VERSION; } catch {}
  try { if (g.Chart?.version) o.chartjs = g.Chart.version; } catch {}
  try { if (g.videojs?.VERSION) o.videojs = g.videojs.VERSION; } catch {}
  try { if (g.tinymce?.majorVersion) o.tinymce = g.tinymce.majorVersion + '.' + g.tinymce.minorVersion; } catch {}
  return o;
}

const cmp = (a, b) => {
  const pa = String(a).split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  return 0;
};

// Known-vulnerable thresholds (each CVE verified against the vendor advisory / NVD).
function assessLib(lib, v) {
  const lt = (x) => cmp(v, x) < 0;
  switch (lib) {
    case 'jquery': {
      const c = [];
      if (lt('1.9.0')) c.push('CVE-2012-6708');
      if (lt('3.0.0')) c.push('CVE-2015-9251');
      if (lt('3.4.0')) c.push('CVE-2019-11358');
      if (lt('3.5.0')) c.push('CVE-2020-11022', 'CVE-2020-11023');
      return c.length ? { rule: 'vuln-library', severity: 'high', fixed: '3.5.0', cves: c } : null;
    }
    case 'angular':
      if (v.startsWith('1.')) return { rule: 'eol-library', severity: 'high', note: 'AngularJS 1.x — support ended Dec 31, 2021; unpatched ReDoS/XSS CVEs incl. CVE-2023-26116/26117/26118' };
      return null;
    case 'bootstrap': {
      const c = [];
      if (cmp(v, '3.4.0') < 0 || (cmp(v, '4.0.0') >= 0 && cmp(v, '4.1.2') < 0)) c.push('CVE-2018-14040', 'CVE-2018-14042');
      if (cmp(v, '3.4.1') < 0 || (cmp(v, '4.0.0') >= 0 && cmp(v, '4.3.1') < 0)) c.push('CVE-2019-8331');
      if (c.length) return { rule: 'vuln-library', severity: 'medium', fixed: v.startsWith('3') ? '3.4.1' : '4.3.1', cves: [...new Set(c)] };
      if (v.startsWith('3.') || v.startsWith('4.')) return { rule: 'eol-library', severity: 'low', note: `Bootstrap ${v.split('.')[0]} is end-of-life` };
      return null;
    }
    case 'lodash': {
      const c = [];
      if (lt('4.17.19')) c.push('CVE-2020-8203');
      if (lt('4.17.21')) c.push('CVE-2021-23337');
      return c.length ? { rule: 'vuln-library', severity: 'high', fixed: '4.17.21', cves: c } : null;
    }
    case 'underscore':
      return lt('1.12.1') ? { rule: 'vuln-library', severity: 'medium', fixed: '1.12.1', cves: ['CVE-2021-23358'] } : null;
    case 'moment':
      return lt('2.29.4') ? { rule: 'vuln-library', severity: 'medium', fixed: '2.29.4', cves: ['CVE-2022-31129'] } : null;
    case 'handlebars':
      return lt('4.7.7') ? { rule: 'vuln-library', severity: 'high', fixed: '4.7.7', cves: ['CVE-2021-23369', 'CVE-2021-23383'] } : null;
    case 'vue':
      return v.startsWith('2.') ? { rule: 'eol-library', severity: 'medium', note: 'Vue 2 reached end-of-life Dec 31, 2023' } : null;
  }
  return null;
}

const LIB_NAMES = { jquery: 'jQuery', jqueryui: 'jQuery UI', angular: 'AngularJS', bootstrap: 'Bootstrap', lodash: 'Lodash', underscore: 'Underscore', moment: 'Moment.js', handlebars: 'Handlebars', vue: 'Vue', react: 'React', dompurify: 'DOMPurify', knockout: 'Knockout', axios: 'Axios', d3: 'D3', ember: 'Ember', chartjs: 'Chart.js', videojs: 'Video.js', tinymce: 'TinyMCE' };

// Offline fallback: one finding per vulnerable library (replaced by live CVE data when available).
function libFindings(libs) {
  const out = [];
  const eol = [];
  let eSev = 'info';
  for (const [lib, ver] of Object.entries(libs)) {
    if (!/^\d+\.\d+/.test(ver)) continue;
    const a = assessLib(lib, ver);
    if (!a) continue;
    if (a.rule === 'vuln-library') {
      out.push({ rule: 'vuln-library', lib, severity: a.severity, evidence: [`${LIB_NAMES[lib]} ${ver} → upgrade to ≥ ${a.fixed} (${a.cves.join(', ')})`] });
    } else {
      eol.push(`${LIB_NAMES[lib]} ${ver} — ${a.note}`);
      if (SEVERITY[a.severity].rank > SEVERITY[eSev].rank) eSev = a.severity;
    }
  }
  if (eol.length) out.push({ rule: 'eol-library', severity: eSev, evidence: eol });
  return out;
}

// ───────── 4. Scoring ─────────
function score(findings) {
  let s = 100;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) { counts[f.severity]++; s -= SEVERITY[f.severity].weight; }
  s = Math.max(0, s);
  // Hard caps: a critical finding can never earn better than D, high never better than C.
  if (counts.critical) s = Math.min(s, 59);
  else if (counts.high) s = Math.min(s, 79);
  const grade = s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 70 ? 'C' : s >= 60 ? 'D' : 'F';
  return { score: s, grade, counts };
}

const BADGE = { critical: '#FF2E63', high: '#FF7A1A', medium: '#E0A800', low: '#2BB3E0', info: '#3A4256' };

async function setBadge(tabId, result) {
  try {
    if (!result) { await chrome.action.setBadgeText({ tabId, text: '' }); return; }
    const { counts } = result;
    const worst = ['critical', 'high', 'medium', 'low'].find((k) => counts[k]) || 'info';
    const n = counts.critical + counts.high + counts.medium;
    await chrome.action.setBadgeText({ tabId, text: n ? String(n) : '✓' });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: n ? BADGE[worst] : '#10B981' });
    if (chrome.action.setBadgeTextColor) await chrome.action.setBadgeTextColor({ tabId, color: '#FFFFFF' });
  } catch { /* tab closed */ }
}

// ───────── 5. Orchestration ─────────
const inflight = new Map();

async function scan(tabId) {
  if (inflight.has(tabId)) return inflight.get(tabId);
  const p = (async () => {
    const tab = await chrome.tabs.get(tabId);
    if (!scannable(tab.url)) return { unsupported: true, url: tab.url };

    const [dom] = await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
    const domRes = dom?.result;
    if (!domRes) throw new Error('DOM scan returned nothing');

    let pageLibs = {};
    try {
      const [libs] = await chrome.scripting.executeScript({ target: { tabId }, world: 'MAIN', func: detectLibsInPage });
      pageLibs = libs?.result || {};
    } catch { /* page blocked MAIN world */ }

    const store = await chrome.storage.session.get(hKey(tabId));
    const rec = store[hKey(tabId)];
    const headersAvailable = !!rec && stripHash(rec.url) === stripHash(domRes.url);
    const headerFindings = headersAvailable ? analyzeHeaders(rec, domRes.url, domRes.metaCsp) : [];

    const libs = { ...domRes.libsFromSrc, ...pageLibs };
    const raw = [...domRes.findings, ...headerFindings, ...libFindings(libs)];
    const findings = finalize(raw);

    const banners = headersAvailable
      ? rec.headers.filter((x) => /^(server|x-powered-by)$/i.test(x.name)).map((x) => x.value || '')
      : [];
    const software = serverSoftware(banners);
    const live = await liveCveEnabled();
    const hasTargets = Object.keys(libs).some((l) => NPM_PACKAGES[l]) || software.length;

    const result = {
      url: domRes.url, title: domRes.title, ts: Date.now(),
      headersAvailable, httpStatus: headersAvailable ? rec.status : null,
      libs, software, stats: domRes.stats, findings, ...score(findings),
      cve: { status: !live ? 'off' : hasTargets ? 'pending' : 'none' },
    };
    await chrome.storage.session.set({ [rKey(tabId)]: result });
    await setBadge(tabId, result);
    if (live && hasTargets) enrich(tabId, result).catch(() => {});
    return result;
  })().finally(() => inflight.delete(tabId));
  inflight.set(tabId, p);
  return p;
}

function finalize(raw) {
  return raw
    .filter((f) => RULES[f.rule])
    .map((f) => ({ ...f, severity: f.severity || RULES[f.rule].severity }))
    .sort((a, b) => SEVERITY[b.severity].rank - SEVERITY[a.severity].rank);
}

async function liveCveEnabled() {
  const { liveCve = true } = await chrome.storage.sync.get('liveCve');
  return liveCve;
}

// ───────── 6. Live CVE enrichment (async, after the instant local scan) ─────────
async function enrich(tabId, base) {
  const kevP = getKev();
  const jobs = [];
  for (const [lib, ver] of Object.entries(base.libs)) {
    const pkg = NPM_PACKAGES[lib];
    if (!pkg || !/^\d+\.\d+/.test(ver)) continue;
    jobs.push(lookupNpm(pkg, ver).then((cves) => ({ ok: true, lib, name: LIB_NAMES[lib] || lib, ver, kind: 'library', cves }))
      .catch((e) => ({ ok: false, lib, name: LIB_NAMES[lib] || lib, ver, error: String(e.message || e) })));
  }
  for (const sw of base.software) {
    jobs.push(lookupCpe(sw.cpes).then((cves) => ({ ok: true, name: sw.name, ver: sw.version, kind: 'server', cves }))
      .catch((e) => ({ ok: false, name: sw.name, ver: sw.version, error: String(e.message || e) })));
  }
  const results = await Promise.all(jobs);
  const kev = await kevP;

  // Tab moved on? Drop the stale enrichment.
  const cur = (await chrome.storage.session.get(rKey(tabId)))[rKey(tabId)];
  if (!cur || cur.url !== base.url || cur.ts !== base.ts) return;

  const replaced = new Set(results.filter((r) => r.ok && r.lib).map((r) => r.lib));
  const kept = cur.findings.filter((f) => !(f.rule === 'vuln-library' && replaced.has(f.lib)) && f.rule !== 'known-cves');
  const live = results.filter((r) => r.ok && r.cves.length).map((r) => cveFinding(r.name, r.ver, r.kind, r.cves, kev));
  const findings = finalize([...kept, ...live]);

  const checked = results.map((r) => ({ name: r.name, version: r.ver, ok: r.ok, count: r.ok ? r.cves.length : null, error: r.error || null }));
  const failed = results.filter((r) => !r.ok).length;
  const result = {
    ...cur, findings, ...score(findings),
    cve: { status: failed === results.length ? 'error' : 'done', checked, total: live.reduce((n, f) => n + f.count, 0), kev: live.reduce((n, f) => n + f.cves.filter((c) => c.kev).length, 0), ts: Date.now() },
  };
  await chrome.storage.session.set({ [rKey(tabId)]: result });
  await setBadge(tabId, result);
}

// Manual CVE lookup from the popup search box
async function lookupCveId(id) {
  const { devEndpoints } = await chrome.storage.local.get('devEndpoints');
  const base = devEndpoints?.nvd || 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  const r = await fetch(`${base}?cveId=${encodeURIComponent(id)}`, { credentials: 'omit', referrerPolicy: 'no-referrer' });
  if (!r.ok) throw new Error(r.status === 403 || r.status === 429 ? 'NVD rate limit hit — wait 30 seconds and try again' : `NVD returned HTTP ${r.status}`);
  const j = await r.json();
  const c = j.vulnerabilities?.[0]?.cve;
  if (!c) return null;
  const m = c.metrics || {};
  const metric = (m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV40 || m.cvssMetricV2 || [])[0];
  const kev = await getKev();
  return {
    id: c.id, published: c.published, status: c.vulnStatus,
    score: metric?.cvssData?.baseScore ?? null, vector: metric?.cvssData?.vectorString || null,
    summary: (c.descriptions || []).find((d) => d.lang === 'en')?.value || '',
    cwes: [...new Set((c.weaknesses || []).flatMap((w) => w.description || []).map((d) => d.value).filter((v) => /^CWE-\d+$/.test(v)))],
    kev: kev.has(c.id) || !!c.cisaExploitAdd,
    kevAction: c.cisaRequiredAction || null,
  };
}

async function autoScanEnabled() {
  const { autoScan = true } = await chrome.storage.sync.get('autoScan');
  return autoScan;
}

chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status === 'loading' && info.url) {
    await chrome.storage.session.remove(rKey(tabId));
    setBadge(tabId, null);
  }
  if (info.status === 'complete' && scannable(tab.url) && (await autoScanEnabled())) {
    scan(tabId).catch(() => {});
  }
});

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove([hKey(tabId), rKey(tabId)]));

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  (async () => {
    try {
      if (msg.type === 'get') {
        const s = await chrome.storage.session.get(rKey(msg.tabId));
        const tab = await chrome.tabs.get(msg.tabId);
        const cached = s[rKey(msg.tabId)];
        if (cached && stripHash(cached.url) === stripHash(tab.url)) return reply({ ok: true, result: cached });
        return reply({ ok: true, result: await scan(msg.tabId) });
      }
      if (msg.type === 'scan') return reply({ ok: true, result: await scan(msg.tabId) });
      if (msg.type === 'cveLookup') return reply({ ok: true, cve: await lookupCveId(msg.id) });
      if (msg.type === 'highlight') {
        await chrome.scripting.executeScript({
          target: { tabId: msg.tabId },
          args: [msg.ids],
          func: (ids) => {
            const els = (window.__hexwardEls || []);
            const targets = ids.map((i) => els[i]).filter((e) => e && e.isConnected);
            targets.forEach((el, i) => {
              const prev = el.style.cssText;
              el.style.outline = '3px solid #FF2BD6';
              el.style.outlineOffset = '3px';
              el.style.boxShadow = '0 0 0 6px rgba(34,230,255,.35), 0 0 28px rgba(255,43,214,.6)';
              el.style.transition = 'box-shadow .3s';
              if (i === 0) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
              setTimeout(() => { el.style.cssText = prev; }, 4000);
            });
            return targets.length;
          },
        });
        return reply({ ok: true });
      }
      reply({ ok: false, error: 'unknown message' });
    } catch (e) {
      reply({ ok: false, error: String(e?.message || e) });
    }
  })();
  return true;
});
