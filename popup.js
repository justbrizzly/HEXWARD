import { RULES, SEVERITY, ATTACK, NIST, CSF, CWE, links } from './kb.js';

const $ = (s) => document.querySelector(s);
const main = $('#main');
let tabId = null;
let current = null;
let filter = 'all';
const openKeys = new Set();
const cardKey = (f) => f.rule + '|' + (f.component || f.lib || '');

// Tiny DOM builder — all page-derived strings go through textContent (no innerHTML injection).
function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') el.className = v;
    else if (k === 'style') el.style.cssText = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) el.append(kid instanceof Node ? kid : String(kid));
  return el;
}

const send = (msg) => new Promise((res) => chrome.runtime.sendMessage(msg, (r) => res(r || { ok: false, error: chrome.runtime.lastError?.message })));

function toast(text) {
  let t = $('.toast');
  if (!t) { t = h('div', { class: 'toast' }); document.body.append(t); }
  t.textContent = text; t.classList.add('on');
  clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove('on'), 1600);
}

function showLoading(text = 'Scanning page…') {
  $('#bar').hidden = true;
  main.replaceChildren(h('div', { class: 'state' }, h('div', { class: 'scanner' }, h('span')), h('p', {}, text)));
}

function showMessage(title, body) {
  $('#bar').hidden = true;
  main.replaceChildren(h('div', { class: 'state' },
    h('div', { class: 'scanner', style: 'background:linear-gradient(135deg,#1b2336,#262f45)' }),
    h('h3', {}, title), h('p', {}, body)));
}

// ───────── Hero ─────────
const GRADE_COLOR = { A: '#10e0a0', B: '#4cc9f0', C: '#ffc531', D: '#ff7a1a', F: '#ff2e63' };

function verdict(r) {
  const c = r.counts;
  if (c.critical) return `Exposed — ${c.critical} critical issue${c.critical > 1 ? 's' : ''}`;
  if (c.high) return `At risk — ${c.high} high-severity issue${c.high > 1 ? 's' : ''}`;
  if (c.medium) return `Hardening needed — ${c.medium} medium`;
  if (c.low) return 'Solid, with minor gaps';
  return 'Clean on every passive check';
}

function hero(r) {
  const color = GRADE_COLOR[r.grade];
  const C = 2 * Math.PI * 40;
  const ring = h('div', { class: 'ring', style: `--gc:${color};--glow:${color}88` });
  ring.innerHTML = `<svg viewBox="0 0 92 92"><circle class="track" cx="46" cy="46" r="40" fill="none" stroke-width="7"/><circle class="val" cx="46" cy="46" r="40" fill="none" stroke="${color}" stroke-width="7" stroke-linecap="round" stroke-dasharray="${C}" stroke-dashoffset="${C}"/></svg>`;
  ring.append(h('div', { class: 'grade' }, h('div', {}, h('b', {}, r.grade), h('small', {}, `${r.score}/100`))));
  requestAnimationFrame(() => requestAnimationFrame(() => { ring.querySelector('.val').style.strokeDashoffset = C * (1 - r.score / 100); }));

  const chips = h('div', { class: 'chips' }, ['critical', 'high', 'medium', 'low', 'info'].map((s) =>
    h('span', { class: 'chip' + (r.counts[s] ? '' : ' zero'), style: `--c:var(--${s})`, title: SEVERITY[s].label }, h('i'), `${r.counts[s]} ${{critical:'CRIT',high:'HIGH',medium:'MED',low:'LOW',info:'INFO'}[s]}`)));

  return h('section', { class: 'hero' }, ring,
    h('div', { class: 'hero-text' }, h('div', { class: 'eyebrow' }, 'Security posture'), h('div', { class: 'verdict' }, verdict(r)), chips));
}

// ───────── Cards ─────────
function codeBlock(text) {
  const btn = h('button', { class: 'copy', onclick: async (e) => { e.stopPropagation(); await navigator.clipboard.writeText(text); toast('Copied fix'); } }, 'COPY');
  return h('pre', {}, text, btn);
}

function card(f) {
  const rule = RULES[f.rule];
  const tpl = $('#cardTpl').content.firstElementChild.cloneNode(true);
  tpl.style.setProperty('--c', `var(--${f.severity})`);
  tpl.querySelector('.sev-label').textContent = SEVERITY[f.severity].label;
  tpl.querySelector('.cat').textContent = rule.category;
  const n = f.count || (f.evidence?.length > 1 ? f.evidence.length : 0);
  tpl.querySelector('.count').textContent = n > 1 ? `×${n}` : '';
  tpl.querySelector('.title').textContent = f.title || rule.title;
  tpl.querySelector('.tags').append(...[
    f.cves?.[0] ? h('span', { class: 'tag cwe', style: 'color:#fff;border-color:rgba(255,255,255,.25)' }, f.cves[0].id) : null,
    h('span', { class: 'tag attack', title: ATTACK[rule.attack[0]] }, rule.attack[0]),
    h('span', { class: 'tag nist', title: NIST[rule.nist[0]] }, 'NIST ' + rule.nist[0]),
    h('span', { class: 'tag cwe', title: CWE[rule.cwe[0]] }, 'CWE-' + rule.cwe[0]),
  ].filter(Boolean));

  const body = tpl.querySelector('.card-body');
  const head = tpl.querySelector('.card-head');
  let built = false;
  const toggle = (open) => {
    if (open && !built) { buildBody(body, f, rule); built = true; }
    body.hidden = !open;
    tpl.classList.toggle('open', open);
    head.setAttribute('aria-expanded', String(open));
    open ? openKeys.add(cardKey(f)) : openKeys.delete(cardKey(f));
  };
  head.addEventListener('click', () => toggle(body.hidden));
  if (openKeys.has(cardKey(f))) toggle(true);
  return tpl;
}

function buildBody(body, f, rule) {
  const sec = (label, ...kids) => h('div', { class: 'sec' }, h('h4', {}, label), ...kids);

  body.append(
    sec("What's wrong", h('p', {}, rule.what)),
    sec('How attackers use it', h('p', {}, rule.risk),
      h('ul', { class: 'attack-list', style: 'margin-top:8px' }, rule.attack.map((id) =>
        h('li', {}, h('a', { href: links.attack(id), target: '_blank' }, h('code', {}, id), ATTACK[id]))))),
    sec('The fix',
      h('div', { class: 'fix owner' }, h('b', {}, 'If you run this site'), h('p', {}, rule.fixOwner), rule.snippet ? codeBlock(rule.snippet) : null),
      h('div', { class: 'fix user' }, h('b', {}, 'If you’re just visiting'), h('p', {}, rule.fixUser))),
  );

  if (f.cves?.length) body.append(sec(`Known CVEs · ${f.count}`, cveList(f.cves, f.count)));

  if (f.evidence?.length) body.append(sec('Evidence', h('ul', { class: 'ev' }, f.evidence.map((e) => h('li', {}, e)), f.count > f.evidence.length ? h('li', {}, `…and ${f.count - f.evidence.length} more`) : null)));

  const dl = h('dl', { class: 'map-grid' });
  const row = (label, items) => dl.append(h('dt', {}, label), h('dd', {}, ...items.flatMap((x, i) => [i ? h('br') : null, x])));
  row('NIST 800-53', rule.nist.map((id) => h('a', { href: links.nist(), target: '_blank' }, h('code', {}, id), NIST[id])));
  row('NIST CSF 2.0', rule.csf.map((id) => h('a', { href: links.csf(), target: '_blank' }, h('code', {}, id), CSF[id])));
  row('CWE', rule.cwe.map((id) => h('a', { href: links.cwe(id), target: '_blank' }, h('code', {}, 'CWE-' + id), CWE[id])));
  body.append(sec('Framework mapping', dl));

  if (f.highlight?.length) {
    body.append(h('button', { class: 'btn sm show-btn', onclick: async () => {
      await send({ type: 'highlight', tabId, ids: f.highlight });
      window.close();
    } }, '◎  Show me on the page'));
  }
}

// ───────── CVE rendering ─────────
const nvdLink = (id) => /^CVE-/.test(id) ? `https://nvd.nist.gov/vuln/detail/${id}` : `https://osv.dev/vulnerability/${id}`;

function cveRow(c) {
  return h('li', { class: 'cve' },
    h('div', { class: 'cve-top' },
      h('a', { href: nvdLink(c.id), target: '_blank' }, c.id),
      h('span', { class: 'score', style: `--c:var(--${c.severity})` }, c.score != null ? `${c.score.toFixed(1)} ${SEVERITY[c.severity].label.toUpperCase()}` : SEVERITY[c.severity].label.toUpperCase()),
      c.kev ? h('span', { class: 'kev', title: 'Listed in CISA Known Exploited Vulnerabilities' }, 'EXPLOITED IN THE WILD') : null,
      c.fixed ? h('span', { class: 'fixed' }, 'fixed ' + c.fixed) : null),
    c.summary ? h('p', {}, c.summary) : null);
}

function cveList(cves, total) {
  const ul = h('ul', { class: 'cve-list' });
  const SHOW = 6;
  cves.slice(0, SHOW).forEach((c) => ul.append(cveRow(c)));
  const wrap = h('div', {}, ul);
  if (cves.length > SHOW) {
    const btn = h('button', { class: 'btn sm more', onclick: () => { cves.slice(SHOW).forEach((c) => ul.append(cveRow(c))); btn.remove(); } }, `Show all ${cves.length}`);
    wrap.append(btn);
  }
  if (total > cves.length) wrap.append(h('p', { class: 'caveat', style: 'text-align:left;margin-top:6px' }, `Top ${cves.length} of ${total} shown, sorted by exploitation and severity.`));
  return wrap;
}

function cveStatus(r) {
  const c = r.cve || { status: 'off' };
  if (c.status === 'none') return null;
  if (c.status === 'off') return h('div', { class: 'cve-status' }, h('i', { class: 'dot' }), h('span', {}, 'Live CVE lookup is off — using the built-in database.'));
  if (c.status === 'pending') return h('div', { class: 'cve-status pending' }, h('i', { class: 'dot' }), h('span', {}, h('b', {}, 'Looking up CVEs'), ` for ${Object.keys(r.libs).length + (r.software?.length || 0)} component(s) on OSV, NVD & CISA KEV…`));
  if (c.status === 'error') return h('div', { class: 'cve-status error', title: (c.checked || []).map((x) => `${x.name}: ${x.error}`).join('\n') }, h('i', { class: 'dot' }), h('span', {}, 'Live CVE lookup failed (offline or rate-limited). Showing the built-in database. Hit Rescan to retry.'));
  const failed = (c.checked || []).filter((x) => !x.ok).length;
  return h('div', { class: 'cve-status ' + (c.kev ? 'hot' : 'done'), title: (c.checked || []).map((x) => `${x.name} ${x.version}: ${x.ok ? x.count + ' CVEs' : 'lookup failed'}`).join('\n') },
    h('i', { class: 'dot' }),
    h('span', {}, h('b', {}, `${c.checked.length} component${c.checked.length > 1 ? 's' : ''} checked live`),
      ` · ${c.total} CVE${c.total === 1 ? '' : 's'}`, c.kev ? h('b', { style: 'color:var(--critical)' }, ` · ${c.kev} exploited in the wild`) : null,
      failed ? ` · ${failed} lookup${failed > 1 ? 's' : ''} failed` : null));
}

// ───────── Render ─────────
function render(r) {
  current = r;
  $('#bar').hidden = false;
  try { $('#host').textContent = new URL(r.url).host + ' · ' + new Date(r.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); } catch {}

  const frag = [hero(r), cveStatus(r)].filter(Boolean);

  if (!r.headersAvailable) {
    frag.push(h('div', { class: 'notice' }, h('span', {}, '⚠'),
      h('span', {}, 'Header & cookie checks need a fresh load of this page.'),
      h('button', { class: 'btn sm', onclick: reload }, 'Reload')));
  }

  if (!r.findings.length) {
    frag.push(h('div', { class: 'state', style: 'padding:30px 10px' },
      h('div', { class: 'clean-hex' }, '⬢'), h('h3', {}, 'Nothing flagged'),
      h('p', {}, 'Every passive check passed. That’s a strong signal — not a guarantee.')));
  } else {
    const present = ['critical', 'high', 'medium', 'low', 'info'].filter((s) => r.counts[s]);
    const filters = h('div', { class: 'filters', role: 'tablist' },
      ['all', ...present].map((s) => h('button', {
        class: 'filter' + (filter === s ? ' on' : ''), role: 'tab',
        onclick: () => { filter = s; render(current); },
      }, s === 'all' ? `All ${r.findings.length}` : `${SEVERITY[s].label} ${r.counts[s]}`)));
    if (filter !== 'all' && !present.includes(filter)) filter = 'all';
    const list = h('div', { class: 'list' }, r.findings.filter((f) => filter === 'all' || f.severity === filter).map(card));
    frag.push(filters, list);
  }

  frag.push(h('p', { class: 'caveat' }, 'Passive checks only: what the page itself reveals. Server-side flaws (SQLi, auth logic) need an authorized pentest.'));
  main.replaceChildren(...frag);
}

// ───────── Actions ─────────
async function load(type = 'get') {
  showLoading(type === 'scan' ? 'Rescanning…' : 'Scanning page…');
  const r = await send({ type, tabId });
  if (!r.ok) return showMessage('Can’t scan this page', r.error?.includes('Cannot access') || r.error?.includes('cannot be scripted') ? 'Chrome blocks extensions on this page.' : (r.error || 'Unknown error'));
  if (r.result?.unsupported) return showMessage('Nothing to scan here', 'Hexward scans regular http:// and https:// websites. Browser pages and the Web Store are off-limits to extensions.');
  render(r.result);
}

async function reload() {
  showLoading('Reloading for a full scan…');
  const key = `r:${tabId}`;
  const onChange = (changes, area) => {
    if (area === 'session' && changes[key]?.newValue) {
      chrome.storage.onChanged.removeListener(onChange);
      render(changes[key].newValue);
    }
  };
  chrome.storage.onChanged.addListener(onChange);
  await chrome.tabs.reload(tabId, { bypassCache: true });
  // If auto-scan is off, trigger manually once the tab finishes.
  const { autoScan = true } = await chrome.storage.sync.get('autoScan');
  if (!autoScan) {
    const done = (id, info) => {
      if (id === tabId && info.status === 'complete') { chrome.tabs.onUpdated.removeListener(done); send({ type: 'scan', tabId }); }
    };
    chrome.tabs.onUpdated.addListener(done);
  }
}

function report(r) {
  const lines = [`# Hexward report — ${r.url}`, `Grade **${r.grade}** (${r.score}/100) · ${new Date(r.ts).toISOString()}`, ''];
  for (const f of r.findings) {
    const rule = RULES[f.rule];
    lines.push(`## [${SEVERITY[f.severity].label.toUpperCase()}] ${f.title || rule.title}`,
      `- **What:** ${rule.what}`, `- **Risk:** ${rule.risk}`, `- **Fix (owner):** ${rule.fixOwner}`, `- **Fix (visitor):** ${rule.fixUser}`,
      `- **ATT&CK:** ${rule.attack.map((id) => `${id} ${ATTACK[id]}`).join('; ')}`,
      `- **NIST 800-53:** ${rule.nist.map((id) => `${id} ${NIST[id]}`).join('; ')}`,
      `- **NIST CSF 2.0:** ${rule.csf.join(', ')}`,
      `- **CWE:** ${rule.cwe.map((id) => `CWE-${id}`).join(', ')}`);
    if (rule.snippet) lines.push('```', rule.snippet, '```');
    if (f.evidence?.length) lines.push('- **Evidence:**', ...f.evidence.map((e) => `  - \`${e}\``));
    if (f.cves?.length) lines.push('- **CVEs:**', ...f.cves.map((c) => `  - [${c.id}](${nvdLink(c.id)}) ${c.score ?? ''} ${c.severity.toUpperCase()}${c.kev ? ' **EXPLOITED IN THE WILD**' : ''}${c.fixed ? ` (fixed ${c.fixed})` : ''} — ${c.summary}`));
    lines.push('');
  }
  if (!r.headersAvailable) lines.push('_Header/cookie checks were not run (reload the page and rescan)._');
  lines.push('', '---', '_Hexward · Made by your friendly neighborhood bear Brizzly 🐻_');
  return lines.join('\n');
}

$('#rescanBtn').addEventListener('click', () => load('scan'));
$('#reloadBtn').addEventListener('click', reload);
$('#copyBtn').addEventListener('click', async () => { if (current) { await navigator.clipboard.writeText(report(current)); toast('Report copied as Markdown'); } });
$('#settingsBtn').addEventListener('click', (e) => {
  const s = $('#settings'); s.hidden = !s.hidden; e.currentTarget.setAttribute('aria-pressed', String(!s.hidden));
});
$('#liveCve').addEventListener('change', (e) => chrome.storage.sync.set({ liveCve: e.target.checked }));

$('#lookupBtn').addEventListener('click', (e) => {
  const p = $('#lookup'); p.hidden = !p.hidden; e.currentTarget.setAttribute('aria-pressed', String(!p.hidden));
  if (!p.hidden) $('#lookupInput').focus();
});
$('#lookupForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = $('#lookupOut');
  const id = $('#lookupInput').value.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) { out.replaceChildren(h('p', { class: 'err' }, 'Format: CVE-YYYY-NNNN (e.g. CVE-2021-44228)')); return; }
  out.replaceChildren(h('p', { class: 'fine' }, 'Querying NIST NVD…'));
  const r = await send({ type: 'cveLookup', id });
  if (!r.ok) return out.replaceChildren(h('p', { class: 'err' }, r.error));
  if (!r.cve) return out.replaceChildren(h('p', { class: 'err' }, `${id} not found in NVD.`));
  const c = r.cve;
  const sev = c.score != null ? (c.score >= 9 ? 'critical' : c.score >= 7 ? 'high' : c.score >= 4 ? 'medium' : 'low') : 'info';
  out.replaceChildren(h('div', { class: 'cve' },
    h('div', { class: 'cve-top' },
      h('a', { href: nvdLink(c.id), target: '_blank' }, c.id),
      h('span', { class: 'score', style: `--c:var(--${sev})` }, c.score != null ? `${c.score.toFixed(1)} ${SEVERITY[sev].label.toUpperCase()}` : 'NOT SCORED'),
      c.kev ? h('span', { class: 'kev' }, 'EXPLOITED IN THE WILD') : null),
    h('p', {}, c.summary),
    c.kevAction ? h('p', { style: 'color:#ffb3c4' }, 'CISA required action: ' + c.kevAction) : null,
    h('div', { class: 'meta-line' }, [c.cwes.join(', '), c.published ? 'Published ' + c.published.slice(0, 10) : null, c.status].filter(Boolean).join(' · '))));
});

// Re-render when live CVE results land (or another scan finishes) for this tab.
chrome.storage.onChanged.addListener((changes, area) => {
  const nv = area === 'session' && tabId != null && changes[`r:${tabId}`]?.newValue;
  if (nv && current && nv.url === current.url && nv.ts === current.ts) {
    const y = main.scrollTop; render(nv); main.scrollTop = y;
  }
});

$('#autoScan').addEventListener('change', (e) => chrome.storage.sync.set({ autoScan: e.target.checked }));

(async () => {
  const { autoScan = true, liveCve = true } = await chrome.storage.sync.get(['autoScan', 'liveCve']);
  $('#autoScan').checked = autoScan;
  $('#liveCve').checked = liveCve;
  // ?tabId= lets the popup be opened as a full page for a specific tab (used for testing/screenshots).
  const forced = Number(new URLSearchParams(location.search).get('tabId'));
  const [tab] = forced ? [await chrome.tabs.get(forced)] : await chrome.tabs.query({ active: true, currentWindow: true });
  tabId = tab?.id;
  try { $('#host').textContent = new URL(tab.url).host || tab.url; } catch {}
  load('get');
})();
