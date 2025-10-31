export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/generate" && request.method === "POST") {
        return handleGenerate(request);
      }
      if (url.pathname === "/api/proxies") {
        const key = url.searchParams.get("source") || "all";
        const proxies = await getProxies(key);
        return json({ count: proxies.length, items: proxies });
      }
      return htmlPage();
    } catch (e) {
      return new Response("Internal Error: " + (e?.message || e), { status: 500 });
    }
  }
};

// ========= Konfigurasi Sumber =========
const PROXY_SOURCES = [
  {
    key: "all",
    name: "Semua (gabungan)",
    type: "multi",
    includes: ["txt", "json"]
  },
  {
    key: "txt",
    name: "proxyList.txt (raw)",
    type: "text",
    url: "https://raw.githubusercontent.com/mrzero0nol/My-v2ray/refs/heads/main/proxyList.txt"
  },
  {
    key: "json",
    name: "KvProxyList.json",
    type: "json",
    url: "https://raw.githubusercontent.com/mrzero0nol/My-v2ray/refs/heads/main/KvProxyList.json"
  }
];

// Default UI
const DEFAULTS = {
  frontDomain: "df.game.naver.com",
  sni: "df.game.naver.com.ukonskypea.dpdns.org",
  hostHeader: "",
  cfTlsPort: 443,
  genTrojan: true,
  genVless: true,
  sourceKey: "all"
};

// Cache sederhana
const cacheStore = {
  data: new Map(), // key -> { ts, items }
  ttlMs: 10 * 60 * 1000 // 10 menit
};

// ========= Handlers =========
async function handleGenerate(request) {
  const body = await request.json().catch(() => ({}));
  const {
    sourceKey = DEFAULTS.sourceKey,
    frontDomain = DEFAULTS.frontDomain,
    sni = DEFAULTS.sni,
    hostHeader = DEFAULTS.hostHeader || DEFAULTS.sni,
    cfTlsPort = DEFAULTS.cfTlsPort,
    genTrojan = DEFAULTS.genTrojan,
    genVless = DEFAULTS.genVless,
    selected = [] // [{ip,port,label}]
  } = body || {};

  let items = [];
  if (Array.isArray(selected) && selected.length) {
    items = dedupeAndValidate(selected);
    if (!items.length) return json({ ok: false, error: "Pilihan proxy tidak valid." }, 400);
  } else {
    // fallback: jika tidak ada pilihan, ambil semua dari source
    items = await getProxies(sourceKey);
    if (!items.length) return json({ ok: false, error: "List proxy kosong atau gagal diambil." }, 400);
  }

  const trojanList = [];
  const vlessList = [];

  for (const p of items) {
    const { trojan, vless } = buildURIs(p, {
      frontDomain,
      sni,
      hostHeader: hostHeader || sni,
      cfTlsPort,
      includeTrojan: !!genTrojan,
      includeVless: !!genVless
    });
    if (trojan) trojanList.push(trojan);
    if (vless) vlessList.push(vless);
  }

  const combined = [...trojanList, ...vlessList].join("\n");
  return json({
    ok: true,
    counts: { trojan: trojanList.length, vless: vlessList.length },
    trojan: trojanList,
    vless: vlessList,
    combined
  });
}

// ========= Fetch & Parse =========
async function getProxies(sourceKey) {
  const src = PROXY_SOURCES.find(s => s.key === sourceKey) || PROXY_SOURCES[0];
  const now = Date.now();
  const hit = cacheStore.data.get(src.key);
  if (hit && now - hit.ts < cacheStore.ttlMs) return hit.items;

  let items = [];
  if (src.type === "multi") {
    const parts = await Promise.all(
      src.includes.map(k => getProxies(k))
    );
    items = dedupeAndValidate(parts.flat());
  } else {
    const res = await fetch(src.url, { cf: { cacheTtl: 600, cacheEverything: true } });
    if (!res.ok) throw new Error(`Gagal fetch ${src.name}: ${res.status}`);
    const raw = src.type === "json" ? await res.json() : await res.text();
    items = src.type === "json" ? parseJSONProxies(raw) : parseTextProxies(raw);
    items = dedupeAndValidate(items);
  }

  cacheStore.data.set(src.key, { ts: now, items });
  return items;
}

function parseTextProxies(text) {
  const lines = String(text).split(/\r?\n/);
  const items = [];
  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith("#") || line.length < 4) continue;

    let ip, port, label = "";

    // Tangkap IP + Port
    const m = line.match(/((\d{1,3}\.){3}\d{1,3})\s*[-:\s]\s*(\d{2,5})/);
    if (m) {
      ip = m[1];
      port = parseInt(m[3], 10);
      label = sanitizeLabel(line.replace(m[0], "").replace(/[|,;]+/g, " ").trim());
    } else {
      const m2 = line.match(/((\d{1,3}\.){3}\d{1,3})/);
      if (m2) {
        ip = m2[1];
        port = 443;
        label = sanitizeLabel(line.replace(m2[0], "").replace(/[|,;]+/g, " ").trim());
      }
    }

    if (ip && port) items.push({ ip, port, label });
  }
  return items;
}

function parseJSONProxies(json) {
  let arr = [];
  if (Array.isArray(json)) arr = json;
  else if (json && typeof json === "object") {
    if (Array.isArray(json.list)) arr = json.list;
    else if (Array.isArray(json.items)) arr = json.items;
    else if (Array.isArray(json.proxies)) arr = json.proxies;
    else arr = Object.values(json);
  }

  const out = [];
  for (const item of arr) {
    if (!item) continue;

    if (typeof item === "string") {
      const parsed = parseTextProxies(item);
      out.push(...parsed);
      continue;
    }

    if (typeof item === "object") {
      let ip = item.ip || item.address || item.server || item.host || item.hostname || item.domain;
      let port = item.port || item.server_port || item.p || item.srv_port || item.dstPort || item.destinationPort;
      if (typeof port === "string") port = parseInt(port, 10);
      if (!port) port = 443;

      let label = item.label || item.name || item.remark || item.tag || item.loc || item.location || item.country || item.note || "";

      if (ip && port) out.push({ ip, port, label: sanitizeLabel(label) });
    }
  }
  return out;
}

function dedupeAndValidate(items) {
  const seen = new Set();
  const out = [];
  for (const it of items) {
    const ip = String(it.ip || "").trim();
    const port = Number(it.port || 0);
    if (!isIPv4(ip)) continue;
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
    const key = `${ip}:${port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ip, port, label: sanitizeLabel(it.label || "") });
  }
  // Sort ringan: label -> ip -> port
  out.sort((a, b) => {
    const la = a.label.toLowerCase(), lb = b.label.toLowerCase();
    if (la !== lb) return la < lb ? -1 : 1;
    if (a.ip !== b.ip) return a.ip < b.ip ? -1 : 1;
    return a.port - b.port;
  });
  return out;
}

function isIPv4(s) {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) return false;
  return s.split(".").every(n => {
    const v = Number(n);
    return v >= 0 && v <= 255;
  });
}
function sanitizeLabel(label) {
  label = String(label || "").replace(/[\[\]]/g, "").replace(/\s+/g, " ").trim();
  return label;
}

// ========= Builders =========
function buildURIs(proxy, opts) {
  const { frontDomain, sni, hostHeader, cfTlsPort = 443, includeTrojan = true, includeVless = true } = opts;
  const ip = proxy.ip;
  const backendPort = proxy.port || 443;
  const tagLabel = (proxy.label ? `${proxy.label} [${ip}]` : `[${ip}]`);
  const path = `/${ip}-${backendPort}`;
  const qpath = encodeURIComponent(path);
  const host = hostHeader || sni;

  let trojan = null, vless = null;

  if (includeTrojan) {
    const pass = crypto.randomUUID();
    trojan = `trojan://${pass}@${frontDomain}:${cfTlsPort}/?type=ws&host=${host}&path=${qpath}&security=tls&sni=${sni}#${encodeURIComponent(tagLabel)}`;
  }
  if (includeVless) {
    const uuid = crypto.randomUUID();
    vless = `vless://${uuid}@${frontDomain}:${cfTlsPort}/?type=ws&encryption=none&flow=&host=${host}&path=${qpath}&security=tls&sni=${sni}#${encodeURIComponent(tagLabel)}`;
  }
  return { trojan, vless, tag: tagLabel };
}

// ========= Helpers =========
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
}

function htmlPage() {
  const page = `<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Red Bunny</title>
<style>
  :root{
    --bg: #000;
    --panel: #110808;
    --muted: #a0a0a0;
    --accent: #dc143c; /* Crimson */
    --accent-2: #ff4040;
    --card-border: rgba(220, 20, 60, 0.25);
    color-scheme: dark;
  }
  html,body{
    height:100%; margin:0; background: var(--bg);
    font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
    color: var(--muted);
  }
  .container{max-width:1200px; margin:0 auto; padding:16px;}
  header{
    text-align:center;
    padding: 20px 0;
  }
  .logo{
    font-size: 48px;
    font-weight: bold;
    color: var(--accent);
    text-shadow: 0 0 10px var(--accent-2), 0 0 20px var(--accent);
  }
  header h1{font-size: 24px; margin: 0; color:#fff; letter-spacing: 0.5px;}
  header p{margin:4px 0 0; color:var(--muted); font-size:14px;}

  .panel{
    background: var(--panel);
    border:1px solid var(--card-border);
    border-radius:12px;
    padding:16px;
    margin-bottom: 20px;
  }

  .controls{display:grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap:16px;}
  label{display:block; font-weight:600; font-size:14px; color:#fff; margin-bottom:8px;}
  input, select, textarea{
    width: 100%;
    box-sizing: border-box;
    background: #000;
    border:1px solid #333;
    color:#fff;
    padding:12px 14px;
    border-radius:8px;
    outline:none;
    font-size:14px;
    transition: border-color 0.2s;
  }
  input:focus, select:focus, textarea:focus {
    border-color: var(--accent);
  }
  input::placeholder{color: #555;}

  .toolbar{display:flex; gap:10px; flex-wrap:wrap; margin-top:16px; align-items: center;}
  button{
    background: var(--accent);
    color:#fff; border:0; padding:12px 18px; border-radius:8px;
    cursor:pointer; font-weight:600; font-size: 14px;
    transition: background-color 0.2s, transform 0.1s;
    box-shadow: 0 4px 15px rgba(220, 20, 60, 0.3);
  }
  button:hover{ background: var(--accent-2); }
  button:active{ transform: scale(0.98); }

  button.secondary{
    background:transparent;
    border:1px solid #444;
    color: var(--muted);
    box-shadow:none;
  }
  button.secondary:hover{ background: #222; color: #fff; }

  .table-wrap{
    margin-top:16px; border-radius:10px; overflow-x:auto;
    border:1px solid var(--card-border);
    background: var(--panel);
  }
  table{width:100%; border-collapse:collapse; color:#fff; font-size:14px;}
  thead th{
    background: #1a0a0a;
    color: var(--muted); padding:12px 15px; text-align:left;
    font-weight:700; font-size:13px;
    position: sticky; top: 0;
  }
  tbody td{padding:12px 15px; border-top:1px solid #2a1a1a; vertical-align:middle;}
  tbody tr:hover td{background: rgba(220, 20, 60, 0.1);}

  .counts{margin-top:12px; color:var(--muted); font-size:14px; text-align:center;}
  .paging-controls button { padding: 8px 12px; font-size: 13px; }

  .badges{display:flex; gap:10px; flex-wrap:wrap; justify-content: center; margin-top:10px;}
  .pill{
    background: #333; color:#fff; padding:6px 12px;
    border-radius:16px; font-size:13px;
  }
  .pill#pillSelected { background: var(--accent); }

  .output-card h2{margin:0 0 12px 0; color:#fff; font-size:16px;}
  textarea{min-height:120px; resize:vertical; font-family: 'Courier New', Courier, monospace; background: #000;}
  .output-row{display:flex; flex-direction: column; gap:16px; margin-bottom: 16px;}
  @media (min-width: 600px) {
    .output-row{flex-direction: row;}
  }

  .modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,0.7);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }
  .modal-overlay.active {
    display: flex;
  }
  .modal-content {
    background: var(--panel);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 24px;
    width: 90%;
    max-width: 500px;
    position: relative;
  }
  .modal-close {
    position: absolute;
    top: 10px;
    right: 15px;
    font-size: 24px;
    color: var(--muted);
    cursor: pointer;
    line-height: 1;
  }
</style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">RB</div>
      <h1>Red Bunny</h1>
      <p>VLESS & Trojan Generator</p>
    </header>

    <div class="panel">
      <div class="controls">
        <div>
          <label for="countryFilter">Filter by Country</label>
          <select id="countryFilter">
            <option value="all">All Countries</option>
          </select>
        </div>
        <div>
          <label for="search">Search (Name/IP/Port)</label>
          <input id="search" placeholder="e.g. Singapore, 43.218, :443" />
        </div>
      </div>
      <div class="toolbar" style="margin-top:20px;">
        <button id="btnReload" class="secondary">Reload List</button>
        <div style="flex-grow: 1;"></div>
        <button id="btnShowGenerateModal" title="Generate for selected proxies">Generate for Selected Proxies</button>
      </div>
    </div>

    <div class="panel">
      <div class="toolbar">
        <button id="btnSelectFiltered" class="secondary">Select All Visible</button>
        <button id="btnClearSelection" class="secondary">Clear Selection</button>
      </div>
      <div class="badges">
        <span class="pill" id="pillTotal">Total: 0</span>
        <span class="pill" id="pillFiltered">Visible: 0</span>
        <span class="pill" id="pillSelected">Selected: 0</span>
      </div>
      <div class="table-wrap">
        <table id="tbl">
          <thead>
            <tr>
              <th style="width:40px"><input type="checkbox" id="chkAllPage" title="Select all visible" /></th>
              <th>Proxy Name</th>
              <th>IP Address</th>
              <th>Port</th>
            </tr>
          </thead>
          <tbody id="tbody"></tbody>
        </table>
      </div>
      <div class="counts" id="counts"></div>
    </div>

    <div class="panel output-card">
        <h2>Results</h2>
        <div class="output-row">
          <div>
            <label for="outTrojan">Trojan</label>
            <textarea id="outTrojan" readonly></textarea>
            <button class="secondary" data-copy="#outTrojan" style="margin-top:8px;">Copy</button>
          </div>
          <div>
            <label for="outVless">VLESS</label>
            <textarea id="outVless" readonly></textarea>
            <button class="secondary" data-copy="#outVless" style="margin-top:8px;">Copy</button>
          </div>
        </div>

        <label for="outCombined">Combined</label>
        <textarea id="outCombined" readonly style="min-height:80px"></textarea>
        <button class="secondary" data-copy="#outCombined" style="margin-top:8px;">Copy All</button>
    </div>
  </div>

  <div class="modal-overlay" id="generateModal">
    <div class="modal-content">
      <span class="modal-close" id="modalCloseBtn">&times;</span>
      <h2>Generation Settings</h2>
      <div class="controls" style="margin-top: 20px;">
        <div>
          <label for="frontDomain">Front Domain</label>
          <input id="frontDomain" value="%%FRONT_DOMAIN%%" />
        </div>
        <div>
          <label for="sni">SNI</label>
          <input id="sni" value="%%SNI%%" />
        </div>
        <div>
          <label for="hostHeader">Host Header (optional)</label>
          <input id="hostHeader" placeholder="Defaults to SNI" value="%%HOST_HEADER%%" />
        </div>
        <div>
          <label for="cfTlsPort">TLS Port</label>
          <input id="cfTlsPort" type="number" min="1" max="65535" value="%%CF_TLS_PORT%%" />
        </div>
      </div>
      <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--card-border);">
        <label>Account Types</label>
        <div style="display:flex; gap:16px; align-items:center;">
          <label style="display:flex; align-items:center; gap:8px; font-weight:normal; color:#fff"><input id="genTrojan" type="checkbox" checked> Trojan</label>
          <label style="display:flex; align-items:center; gap:8px; font-weight:normal; color:#fff"><input id="genVless" type="checkbox" checked> VLESS</label>
        </div>
      </div>
      <button id="btnConfirmGenerate" style="width:100%; margin-top: 24px;">Confirm & Generate</button>
    </div>
  </div>

<script>
const $ = s => document.querySelector(s);
const PAGE_SIZE = 200;

let ALL_ITEMS = [];
let FILTERED_ITEMS = [];
let SELECTED = new Map(); // key => {ip, port, label}
let currentPage = 1;

// Element Refs
const elSearch = $("#search");
const elCountryFilter = $("#countryFilter");
const elTBody = $("#tbody");
const elChkAllPage = $("#chkAllPage");
const elCounts = $("#counts");
const elPillTotal = $("#pillTotal");
const elPillFiltered = $("#pillFiltered");
const elPillSelected = $("#pillSelected");
const modal = $("#generateModal");
const showModalBtn = $("#btnShowGenerateModal");
const closeModalBtn = $("#modalCloseBtn");
const confirmGenerateBtn = $("#btnConfirmGenerate");

// --- Helper Functions ---
function getCountryFromLabel(label) {
    if (!label) return 'Unknown';
    const parts = label.replace(/[^a-zA-Z\s]/g, '').trim().split(/\s+/);
    const commonWords = new Set(['the', 'and', 'proxy', 'v2ray', 'vmess', 'vless', 'trojan', 'server', 'node', 'cdn']);
    for (const part of parts) {
        if (part.length > 2 && !commonWords.has(part.toLowerCase())) {
            return part.charAt(0).toUpperCase() + part.slice(1).toLowerCase();
        }
    }
    return 'Unknown';
}

function populateCountryFilter() {
    const countries = new Set(ALL_ITEMS.map(item => item.country));
    const sortedCountries = [...countries].sort();

    elCountryFilter.innerHTML = '<option value="all">All Countries</option>';
    for (const country of sortedCountries) {
        if (country && country !== 'Unknown') {
            const option = document.createElement('option');
            option.value = country;
            option.textContent = country;
            elCountryFilter.appendChild(option);
        }
    }
}

// --- Core Functions ---
async function loadData() {
  const src = 'txt'; // Hardcoded to use proxyList.txt
  showModalBtn.disabled = true;
  showModalBtn.textContent = 'Loading...';
  try {
    const res = await fetch(\`/api/proxies?source=\${encodeURIComponent(src)}\`);
    if (!res.ok) throw new Error('Network response was not ok');
    const j = await res.json();
    ALL_ITEMS = (j.items || []).map(item => ({...item, country: getCountryFromLabel(item.label)}));
    populateCountryFilter();
    filterData();
  } catch (err) {
    console.error("Failed to load data:", err);
    elTBody.innerHTML = '<tr><td colspan="4" style="padding:16px;color:var(--accent);">Failed to load proxy list.</td></tr>';
  } finally {
    showModalBtn.disabled = false;
    showModalBtn.textContent = 'Generate for Selected Proxies';
  }
}

function filterData() {
  const q = elSearch.value.trim().toLowerCase();
  const selectedCountry = elCountryFilter.value;

  let items = ALL_ITEMS;

  if (selectedCountry !== 'all') {
    items = items.filter(x => x.country === selectedCountry);
  }

  if (q) {
    items = items.filter(x =>
      (x.label || "").toLowerCase().includes(q) ||
      (x.ip || "").toLowerCase().includes(q) ||
      String(x.port || "").toLowerCase().includes(q)
    );
  }

  FILTERED_ITEMS = items;
  currentPage = 1;
  render();
}

function keyOf(x) { return \`\${x.ip}:\${x.port}\`; }

function render() {
  const total = FILTERED_ITEMS.length;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (currentPage > pages) currentPage = pages;
  const start = (currentPage - 1) * PAGE_SIZE;
  const slice = FILTERED_ITEMS.slice(start, start + PAGE_SIZE);

  elTBody.innerHTML = slice.map(it => {
    const k = keyOf(it);
    const checked = SELECTED.has(k) ? "checked" : "";
    const name = it.label ? escapeHtml(it.label) : "(No Name)";
    return \`<tr>
      <td><input type="checkbox" class="rowchk" data-key="\${k}" \${checked} /></td>
      <td>\${name}</td>
      <td>\${it.ip}</td>
      <td>\${it.port}</td>
    </tr>\`;
  }).join('') || '<tr><td colspan="4" style="padding:16px;text-align:center;">No data found.</td></tr>';

  bindRowChecks();

  elChkAllPage.checked = slice.length > 0 && slice.every(it => SELECTED.has(keyOf(it)));
  elCounts.innerHTML = renderPaging(total, pages);
  bindPaging();
  updatePills();
}

function bindRowChecks() {
  elTBody.querySelectorAll(".rowchk").forEach(chk => {
    chk.addEventListener("change", () => {
      const key = chk.getAttribute("data-key");
      const item = ALL_ITEMS.find(x => keyOf(x) === key);
      if (!item) return;
      if (chk.checked) SELECTED.set(key, item);
      else SELECTED.delete(key);
      updatePills();
    });
  });
}

function bindPaging() {
  elCounts.querySelectorAll("[data-page]").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const p = btn.getAttribute("data-page");
      if (p === "prev") currentPage = Math.max(1, currentPage - 1);
      else if (p === "next") currentPage = Math.min(pages, currentPage + 1);
      else currentPage = parseInt(p, 10);
      render();
    });
  });
}

function renderPaging(total, pages) {
  if (total <= PAGE_SIZE) return \`\${total} results\`;
  let pageLinks = "";
  const maxShow = 5;
  let start = Math.max(1, currentPage - 2);
  let end = Math.min(pages, start + maxShow - 1);
  if (end - start + 1 < maxShow) start = Math.max(1, end - maxShow + 1);

  pageLinks += \`<button class="secondary paging-controls" data-page="prev" \${currentPage === 1 ? 'disabled' : ''}>◀</button>\`;
  for (let p = start; p <= end; p++) {
    const act = p === currentPage ? "style='background:var(--accent); color:#fff; border-color:var(--accent)'" : "";
    pageLinks += \`<button class="secondary paging-controls" data-page="\${p}" \${act}>\${p}</button>\`;
  }
  pageLinks += \`<button class="secondary paging-controls" data-page="next" \${currentPage === pages ? 'disabled' : ''}>▶</button>\`;

  return \`Page \${currentPage}/\${pages} (\${total} results) <div style="margin-top:8px;">\${pageLinks}</div>\`;
}

function updatePills() {
  elPillTotal.textContent = "Total: " + ALL_ITEMS.length;
  elPillFiltered.textContent = "Visible: " + FILTERED_ITEMS.length;
  elPillSelected.textContent = "Selected: " + SELECTED.size;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

async function handleGenerate() {
  const selected = Array.from(SELECTED.values());
  if (!selected.length) {
    alert("Please select at least one proxy.");
    return;
  }
  confirmGenerateBtn.textContent = 'Generating...';
  confirmGenerateBtn.disabled = true;

  try {
    const payload = {
      selected,
      frontDomain: $("#frontDomain").value.trim(),
      sni: $("#sni").value.trim(),
      hostHeader: $("#hostHeader").value.trim(),
      cfTlsPort: +$("#cfTlsPort").value || 443,
      genTrojan: $("#genTrojan").checked,
      genVless: $("#genVless").checked
    };
    const res = await fetch("/generate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload)
    });
    const j = await res.json();
    if (!j.ok) throw new Error(j.error || "Unknown error");

    $("#outTrojan").value = (j.trojan || []).join("\\n");
    $("#outVless").value = (j.vless || []).join("\\n");
    $("#outCombined").value = j.combined || "";
    modal.classList.remove("active");
  } catch (err) {
    alert("Failed to generate: " + err.message);
  } finally {
    confirmGenerateBtn.textContent = 'Confirm & Generate';
    confirmGenerateBtn.disabled = false;
  }
}

// --- Event Listeners ---
$("#btnReload").addEventListener("click", loadData);
$("#search").addEventListener("input", () => {
  clearTimeout(window.__deb);
  window.__deb = setTimeout(filterData, 200);
});
elCountryFilter.addEventListener("change", filterData);
$("#btnSelectFiltered").addEventListener("click", () => {
  const slice = FILTERED_ITEMS.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);
  slice.forEach(it => SELECTED.set(keyOf(it), it));
  render();
});
$("#btnClearSelection").addEventListener("click", () => {
  SELECTED.clear();
  render();
});

showModalBtn.addEventListener("click", () => {
  if (SELECTED.size === 0) {
    alert("Please select at least one proxy before generating.");
    return;
  }
  modal.classList.add("active");
});

closeModalBtn.addEventListener("click", () => modal.classList.remove("active"));
modal.addEventListener("click", (e) => {
  if (e.target === modal) modal.classList.remove("active");
});

confirmGenerateBtn.addEventListener("click", handleGenerate);

document.querySelectorAll("button[data-copy]").forEach(b => {
  b.addEventListener("click", async () => {
    const t = document.querySelector(b.getAttribute("data-copy"));
    if (!t || !t.value) return;
    try {
      await navigator.clipboard.writeText(t.value);
      b.textContent = "Copied!";
    } catch {
      t.select();
      document.execCommand("copy");
      b.textContent = "Copied!";
    }
    setTimeout(() => (b.textContent = "Copy"), 1500);
  });
});

elChkAllPage.addEventListener("change", () => {
  const slice = FILTERED_ITEMS.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);
  if (elChkAllPage.checked) {
    slice.forEach(it => SELECTED.set(keyOf(it), it));
  } else {
    slice.forEach(it => SELECTED.delete(keyOf(it)));
  }
  render();
});

// Initial Load
loadData();
</script>
</body>
</html>`;

  const renderedPage = page
    .replace('%%FRONT_DOMAIN%%', DEFAULTS.frontDomain)
    .replace('%%SNI%%', DEFAULTS.sni)
    .replace('%%HOST_HEADER%%', DEFAULTS.hostHeader)
    .replace('%%CF_TLS_PORT%%', String(DEFAULTS.cfTlsPort));

  return new Response(renderedPage, { headers: { "content-type": "text/html; charset=utf-8" } });
}
