// HEXWARD live CVE intelligence.
// Sources (all free, no API key):
//   • OSV.dev   — CVEs/GHSAs for JavaScript libraries detected on the page (npm ecosystem)
//   • NVD 2.0   — CVEs for server software announced in response headers (Apache, nginx, PHP…)
//   • CISA KEV  — "Known Exploited Vulnerabilities": CVEs attackers are actively using right now
// Privacy: only "<package> <version>" or a CPE string is ever sent. Never the page URL.

const DEFAULT_ENDPOINTS = {
  osv: 'https://api.osv.dev/v1/query',
  nvd: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
  kev: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
};
const TTL = 24 * 60 * 60 * 1000; // cache each lookup for 24h
const NVD_GAP = 6500;             // keyless NVD limit is 5 requests / 30s

async function endpoints() {
  // Test hook: allows pointing at a mock server. Never set in normal use.
  const { devEndpoints } = await chrome.storage.local.get('devEndpoints');
  return { ...DEFAULT_ENDPOINTS, ...(devEndpoints || {}) };
}

const inflight = new Map(); // dedupe concurrent identical lookups (e.g. rapid rescans)
async function cached(key, fn) {
  const k = 'cve:' + key;
  const hit = (await chrome.storage.local.get(k))[k];
  if (hit && Date.now() - hit.ts < TTL) return hit.data;
  if (inflight.has(k)) return inflight.get(k);
  const p = (async () => {
    const data = await fn();
    await chrome.storage.local.set({ [k]: { ts: Date.now(), data } });
    return data;
  })().finally(() => inflight.delete(k));
  inflight.set(k, p);
  return p;
}

async function fetchJson(url, opts = {}, timeout = 20000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(url, { ...opts, signal: ctl.signal, credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (!r.ok) { const e = new Error(`HTTP ${r.status}`); e.status = r.status; throw e; }
    return await r.json();
  } finally { clearTimeout(t); }
}

// ───────── Severity helpers ─────────
export const sevFromScore = (s) => (s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'medium' : s > 0 ? 'low' : 'info');
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// CVSS v3.x base score (FIRST specification formula)
export function cvss3Score(vector) {
  const m = Object.fromEntries(String(vector).split('/').slice(1).map((p) => p.split(':')));
  const W = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }, AC: { L: 0.77, H: 0.44 }, UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 },
  };
  const changed = m.S === 'C';
  const PR = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  if ([W.AV[m.AV], W.AC[m.AC], PR, W.UI[m.UI], W.CIA[m.C], W.CIA[m.I], W.CIA[m.A]].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const expl = 8.22 * W.AV[m.AV] * W.AC[m.AC] * PR * W.UI[m.UI];
  if (impact <= 0) return 0;
  const roundUp = (x) => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };
  return roundUp(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}

// ───────── CISA KEV ─────────
let kevMem = null;
export async function getKev() {
  if (kevMem) return kevMem;
  const ep = await endpoints();
  try {
    const ids = await cached('kev', async () => {
      const j = await fetchJson(ep.kev, {}, 30000);
      return (j.vulnerabilities || []).map((v) => v.cveID);
    });
    kevMem = new Set(ids);
  } catch { kevMem = new Set(); }
  return kevMem;
}

// ───────── OSV (npm libraries) ─────────
const cmp = (a, b) => {
  const pa = String(a).split(/[.+-]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(/[.+-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length, 3); i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  return 0;
};

function osvToCve(v, pkg, version) {
  const cveId = (v.aliases || []).find((a) => /^CVE-\d{4}-\d+$/.test(a)) || (/^CVE-/.test(v.id) ? v.id : null);
  let score = null;
  for (const s of v.severity || []) {
    if (s.type === 'CVSS_V3' && s.score) { score = cvss3Score(s.score); if (score !== null) break; }
  }
  const dbSev = String(v.database_specific?.severity || '').toUpperCase();
  const severity = score !== null ? sevFromScore(score)
    : { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' }[dbSev] || 'medium';
  // Lowest fixed version above the installed one
  const fixes = [];
  for (const a of v.affected || []) {
    if (a.package?.name !== pkg) continue;
    for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed && cmp(e.fixed, version) > 0) fixes.push(e.fixed);
  }
  fixes.sort(cmp);
  return {
    id: cveId || v.id, advisory: v.id, score, severity,
    summary: (v.summary || v.details || '').replace(/\s+/g, ' ').trim().slice(0, 220),
    fixed: fixes[0] || null, published: v.published || null,
  };
}

export async function lookupNpm(pkg, version) {
  const ep = await endpoints();
  return cached(`osv:${pkg}@${version}`, async () => {
    const vulns = [];
    let page_token;
    for (let i = 0; i < 5; i++) {
      const body = { package: { name: pkg, ecosystem: 'npm' }, version };
      if (page_token) body.page_token = page_token;
      const j = await fetchJson(ep.osv, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      vulns.push(...(j.vulns || []));
      page_token = j.next_page_token;
      if (!page_token) break;
    }
    // Dedupe by CVE id (OSV can return both the GHSA and the CVE record)
    const byId = new Map();
    for (const v of vulns) {
      if (v.withdrawn) continue;
      const c = osvToCve(v, pkg, version);
      const prev = byId.get(c.id);
      if (!prev || (c.score ?? 0) > (prev.score ?? 0)) byId.set(c.id, prev ? { ...c, fixed: c.fixed || prev.fixed } : c);
    }
    return [...byId.values()];
  });
}

// ───────── NVD (server software) ─────────
let nvdChain = Promise.resolve();
let nvdLast = 0;
function nvdThrottle(fn) {
  const run = nvdChain.then(async () => {
    const wait = nvdLast + NVD_GAP - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    nvdLast = Date.now();
    return fn();
  });
  nvdChain = run.catch(() => {});
  return run;
}

function nvdToCve(item) {
  const c = item.cve;
  const m = c.metrics || {};
  const metric = (m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV40 || m.cvssMetricV2 || [])[0];
  const score = metric?.cvssData?.baseScore ?? null;
  return {
    id: c.id, score, severity: score !== null ? sevFromScore(score) : 'medium',
    summary: ((c.descriptions || []).find((d) => d.lang === 'en')?.value || '').replace(/\s+/g, ' ').slice(0, 220),
    fixed: null, published: c.published || null, nvdKev: !!c.cisaExploitAdd,
  };
}

export async function lookupCpe(cpes) {
  const ep = await endpoints();
  return cached(`nvd:${cpes[0]}`, async () => {
    let lastErr;
    for (const cpe of cpes) {
      for (const param of ['cpeName', 'virtualMatchString']) {
        try {
          const out = [];
          for (let start = 0; start < 600; start += 200) {
            const url = `${ep.nvd}?${param}=${encodeURIComponent(cpe)}&resultsPerPage=200&startIndex=${start}`;
            const j = await nvdThrottle(() => fetchJson(url, {}, 45000));
            out.push(...(j.vulnerabilities || []).map(nvdToCve));
            if (start + 200 >= (j.totalResults || 0)) break;
          }
          return out;
        } catch (e) { lastErr = e; if (e.status && e.status !== 404 && e.status !== 400) throw e; }
      }
    }
    throw lastErr || new Error('NVD lookup failed');
  });
}

// ───────── Detection → lookup targets ─────────
export const NPM_PACKAGES = {
  jquery: 'jquery', jqueryui: 'jquery-ui', angular: 'angular', bootstrap: 'bootstrap', lodash: 'lodash',
  underscore: 'underscore', moment: 'moment', handlebars: 'handlebars', vue: 'vue', react: 'react',
  dompurify: 'dompurify', knockout: 'knockout', axios: 'axios', d3: 'd3', ember: 'ember-source',
  chartjs: 'chart.js', videojs: 'video.js', tinymce: 'tinymce', prototype: 'prototypejs',
};

const SERVER_SOFTWARE = [
  { re: /\bApache\/(\d+\.\d+\.\d+)/i, name: 'Apache HTTP Server', cpe: (v) => [`cpe:2.3:a:apache:http_server:${v}:*:*:*:*:*:*:*`] },
  { re: /\bnginx\/(\d+\.\d+\.\d+)/i, name: 'nginx', cpe: (v) => [`cpe:2.3:a:f5:nginx:${v}:*:*:*:*:*:*:*`, `cpe:2.3:a:nginx:nginx:${v}:*:*:*:*:*:*:*`] },
  { re: /\bPHP\/(\d+\.\d+\.\d+)/i, name: 'PHP', cpe: (v) => [`cpe:2.3:a:php:php:${v}:*:*:*:*:*:*:*`] },
  { re: /\bMicrosoft-IIS\/(\d+\.\d+)/i, name: 'Microsoft IIS', cpe: (v) => [`cpe:2.3:a:microsoft:internet_information_services:${v}:*:*:*:*:*:*:*`] },
  { re: /\bOpenSSL\/(\d+\.\d+\.\d+[a-z]?)/i, name: 'OpenSSL', cpe: (v) => [`cpe:2.3:a:openssl:openssl:${v}:*:*:*:*:*:*:*`] },
  { re: /\blighttpd\/(\d+\.\d+\.\d+)/i, name: 'lighttpd', cpe: (v) => [`cpe:2.3:a:lighttpd:lighttpd:${v}:*:*:*:*:*:*:*`] },
  { re: /\bTomcat\/?(\d+\.\d+\.\d+)/i, name: 'Apache Tomcat', cpe: (v) => [`cpe:2.3:a:apache:tomcat:${v}:*:*:*:*:*:*:*`] },
  { re: /\bJetty\(?(\d+\.\d+\.\d+)/i, name: 'Eclipse Jetty', cpe: (v) => [`cpe:2.3:a:eclipse:jetty:${v}:*:*:*:*:*:*:*`] },
];

export function serverSoftware(banners) {
  const out = [];
  const seen = new Set();
  for (const b of banners) for (const s of SERVER_SOFTWARE) {
    const m = b.match(s.re);
    if (m && !seen.has(s.name)) { seen.add(s.name); out.push({ name: s.name, version: m[1], cpes: s.cpe(m[1]) }); }
  }
  return out;
}

// ───────── Build findings ─────────
export function cveFinding(component, version, kind, cves, kev) {
  for (const c of cves) c.kev = kev.has(c.id) || !!c.nvdKev;
  cves.sort((a, b) => (b.kev - a.kev) || (SEV_RANK[b.severity] - SEV_RANK[a.severity]) || ((b.score ?? 0) - (a.score ?? 0)));
  const worst = cves.reduce((w, c) => (SEV_RANK[c.severity] > SEV_RANK[w] ? c.severity : w), 'info');
  const kevCount = cves.filter((c) => c.kev).length;
  const fixes = cves.map((c) => c.fixed).filter(Boolean).sort(cmp);
  return {
    rule: 'known-cves',
    severity: kevCount ? 'critical' : worst,
    title: `${component} ${version}: ${cves.length} known CVE${cves.length > 1 ? 's' : ''}${kevCount ? ` (${kevCount} actively exploited)` : ''}`,
    component, version, kind,
    upgradeTo: fixes.length ? fixes[fixes.length - 1] : null,
    cves: cves.slice(0, 40),
    count: cves.length,
    evidence: [`${component} ${version}`, kevCount ? `${kevCount} listed in CISA Known Exploited Vulnerabilities` : null, fixes.length ? `Upgrade to ≥ ${fixes[fixes.length - 1]} to clear every listed CVE` : null].filter(Boolean),
  };
}
