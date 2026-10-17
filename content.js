// HEXWARD DOM scanner — injected on demand via chrome.scripting.executeScript.
// Read-only: never modifies the page (except temporary highlight outlines on request).
// The IIFE's return value is handed back to the service worker.
(() => {
  const findings = [];
  const els = [];
  const reg = (el) => { els.push(el); return els.length - 1; };
  const loc = new URL(location.href);
  const isHttps = loc.protocol === 'https:';
  const MAX_EVIDENCE = 8;

  const mask = (s) => (s.length <= 8 ? '••••' : s.slice(0, 4) + '••••' + s.slice(-2));
  const short = (u) => { try { const x = new URL(u); return x.host + x.pathname; } catch { return String(u).slice(0, 120); } };

  // eTLD+1 approximation (good enough to separate "same company" from "other company")
  const MULTI = /\.(co|com|org|net|gov|edu|ac|ne|or)\.[a-z]{2}$/i;
  const site = (host) => {
    const p = host.split('.');
    return p.slice(MULTI.test(host) ? -3 : -2).join('.');
  };
  const pageSite = site(loc.hostname);
  const resolve = (u) => { try { return new URL(u, location.href); } catch { return null; } };

  // ── Transport ──
  const pwInputs = [...document.querySelectorAll('input[type="password"]')];
  if (loc.protocol === 'http:') {
    findings.push({ rule: 'no-https', evidence: [loc.origin] });
    if (pwInputs.length) {
      findings.push({ rule: 'password-over-http', evidence: [`${pwInputs.length} password field(s)`], highlight: pwInputs.map(reg) });
    }
  }

  // ── Forms ──
  const insecureAction = [], pwGet = [], pwCross = [];
  for (const form of document.forms) {
    const action = resolve(form.getAttribute('action') || location.href);
    if (!action) continue;
    const hasPw = !!form.querySelector('input[type="password"]');
    const method = (form.getAttribute('method') || 'get').toLowerCase();
    if (isHttps && action.protocol === 'http:') insecureAction.push([form, action.href]);
    if (hasPw && method === 'get') pwGet.push([form, action.href]);
    if (hasPw && /^https?:$/.test(action.protocol) && site(action.hostname) !== pageSite) pwCross.push([form, action.origin]);
  }
  if (insecureAction.length) findings.push({ rule: 'form-insecure-action', evidence: insecureAction.slice(0, MAX_EVIDENCE).map((x) => '→ ' + x[1]), highlight: insecureAction.map((x) => reg(x[0])) });
  if (pwGet.length) findings.push({ rule: 'form-password-get', evidence: pwGet.map((x) => 'GET → ' + short(x[1])), highlight: pwGet.map((x) => reg(x[0])) });
  if (pwCross.length) findings.push({ rule: 'form-cross-origin-password', evidence: pwCross.map((x) => `${loc.hostname} → ${x[1]}`), highlight: pwCross.map((x) => reg(x[0])) });

  // ── Mixed content ──
  if (isHttps) {
    const active = [], passive = [];
    const activeSel = 'script[src],link[rel~="stylesheet"][href],iframe[src],frame[src],object[data],embed[src]';
    for (const el of document.querySelectorAll(activeSel)) {
      const u = el.src || el.href || el.data;
      if (typeof u === 'string' && u.startsWith('http:')) active.push([el, u]);
    }
    for (const el of document.querySelectorAll('img[src],audio[src],video[src],source[src],img[srcset],source[srcset]')) {
      const u = el.getAttribute('src') || '';
      const set = el.getAttribute('srcset') || '';
      if (/^http:/i.test(u) || /(^|,\s*)http:/i.test(set)) passive.push([el, u || set.split(/\s/)[0]]);
    }
    if (active.length) findings.push({ rule: 'mixed-active', evidence: active.slice(0, MAX_EVIDENCE).map((x) => x[0].tagName.toLowerCase() + ': ' + x[1]), count: active.length, highlight: active.filter((x) => x[0].tagName === 'IFRAME').map((x) => reg(x[0])) });
    if (passive.length) findings.push({ rule: 'mixed-passive', evidence: passive.slice(0, MAX_EVIDENCE).map((x) => x[0].tagName.toLowerCase() + ': ' + x[1]), count: passive.length, highlight: passive.map((x) => reg(x[0])) });
  }

  // ── Third-party scripts without SRI + library versions from URLs ──
  const noSri = [];
  const libsFromSrc = {};
  const LIBS = ['jquery', 'angular', 'bootstrap', 'lodash', 'underscore', 'moment', 'handlebars', 'vue'];
  for (const s of document.querySelectorAll('script[src]')) {
    const u = resolve(s.getAttribute('src'));
    if (!u || !/^https?:$/.test(u.protocol)) continue;
    if (site(u.hostname) !== pageSite && !s.hasAttribute('integrity')) noSri.push(u.host + u.pathname);
    const href = u.href.toLowerCase();
    for (const lib of LIBS) {
      const re = new RegExp(`(?:^|[/_.@-])${lib}(?:js)?(?:\\.js)?[@/_.-]v?(\\d+\\.\\d+\\.\\d+)`);
      const wp = new RegExp(`/${lib}(?:\\.min)?\\.js\\?ver=(\\d+\\.\\d+\\.\\d+)`);
      const m = href.match(re) || href.match(wp);
      if (m && !libsFromSrc[lib]) libsFromSrc[lib] = m[1];
    }
  }
  if (noSri.length) findings.push({ rule: 'sri-missing', evidence: [...new Set(noSri)].slice(0, MAX_EVIDENCE), count: new Set(noSri).size });

  // ── Secrets in inline scripts ──
  let inline = '';
  for (const s of document.querySelectorAll('script:not([src])')) {
    if (inline.length > 1_500_000) break;
    inline += '\n' + s.textContent;
  }
  const SECRETS = [
    { name: 'Private key block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, sev: 'critical' },
    { name: 'AWS access key ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, sev: 'critical' },
    { name: 'Stripe secret key', re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/g, sev: 'critical' },
    { name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, sev: 'critical' },
    { name: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, sev: 'high' },
    { name: 'OpenAI/Anthropic-style API key', re: /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}\b/g, sev: 'critical' },
    { name: 'Google API key (verify it is restricted)', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, sev: 'low' },
  ];
  const secretHits = [];
  let worst = null;
  const order = ['info', 'low', 'medium', 'high', 'critical'];
  for (const s of SECRETS) {
    const hits = [...new Set(inline.match(s.re) || [])];
    if (hits.length) {
      hits.slice(0, 3).forEach((h) => secretHits.push(`${s.name}: ${mask(h)}`));
      if (!worst || order.indexOf(s.sev) > order.indexOf(worst)) worst = s.sev;
    }
  }
  if (secretHits.length) findings.push({ rule: 'secret-exposed', severity: worst, evidence: secretHits });

  const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
  const jwts = [...new Set(inline.match(JWT) || [])];
  if (jwts.length) findings.push({ rule: 'jwt-in-page', evidence: jwts.slice(0, 3).map((j) => 'JWT ' + mask(j)) });

  // ── Sensitive URL params ──
  const SENS = /^(password|passwd|pwd|pass|secret|client_secret|api_?key|access_token|id_token|refresh_token|token|auth|session|sessionid|sid|jsessionid|phpsessid)$/i;
  const urlHits = [];
  const params = new URLSearchParams(loc.search);
  const hashParams = new URLSearchParams(loc.hash.replace(/^#/, '').includes('=') ? loc.hash.slice(1) : '');
  for (const [k, v] of [...params, ...hashParams]) {
    if (SENS.test(k) && v && v.length >= 4) urlHits.push(`${k}=${mask(v)}`);
  }
  if (urlHits.length) {
    const pw = urlHits.some((h) => /^(password|passwd|pwd|pass|secret|client_secret)=/i.test(h));
    findings.push({ rule: 'sensitive-url-param', severity: pw ? 'high' : 'medium', evidence: urlHits });
  }

  // ── Tokens in localStorage ──
  try {
    const ls = [];
    for (let i = 0; i < Math.min(localStorage.length, 500); i++) {
      const k = localStorage.key(i);
      const v = localStorage.getItem(k) || '';
      if (/eyJ[A-Za-z0-9_-]{10,}\.eyJ/.test(v) || (/(token|jwt|auth|session)/i.test(k) && v.length >= 20 && !/^\{?\s*"?(expires|consent)/i.test(v))) ls.push(k);
    }
    if (ls.length) findings.push({ rule: 'token-localstorage', evidence: ls.slice(0, MAX_EVIDENCE).map((k) => 'localStorage["' + k + '"]') });
  } catch { /* storage blocked */ }

  // ── Sensitive HTML comments ──
  const COMMENT_RE = /\b(password|passwd|secret|api[ _-]?key|access[ _-]?key|private[ _-]?key|credentials?|db[ _-]?pass|connection ?string)\b|\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?:\.\d{1,3})?\b|\b(?:staging|internal|dev)\.[a-z0-9-]+\.[a-z]{2,}\b/i;
  const cHits = [];
  const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
  let n = 0;
  while (walker.nextNode() && n++ < 3000) {
    const t = walker.currentNode.nodeValue.trim();
    if (t.length > 3 && t.length < 2000 && COMMENT_RE.test(t)) cHits.push('<!-- ' + t.replace(/\s+/g, ' ').slice(0, 90) + (t.length > 90 ? '…' : '') + ' -->');
  }
  if (cHits.length) findings.push({ rule: 'sensitive-comment', evidence: cHits.slice(0, MAX_EVIDENCE), count: cHits.length });

  // ── Meta CSP (header analysis happens in the service worker) ──
  const metaCsp = [...document.querySelectorAll('meta[http-equiv="Content-Security-Policy" i]')].map((m) => m.content).filter(Boolean);

  window.__hexwardEls = els;
  return {
    url: location.href,
    title: document.title,
    findings,
    libsFromSrc,
    metaCsp,
    stats: { scripts: document.scripts.length, forms: document.forms.length, passwordFields: pwInputs.length },
  };
})();
