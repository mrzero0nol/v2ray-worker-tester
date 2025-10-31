export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/generate" && request.method === "POST") {
        return handleGenerate(request);
      }
      if (url.pathname === "/api/proxies") {
        const key = 'txt'; // Always use the txt source
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
  genVless: true
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
    items = await getProxies('txt');
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

  const res = await fetch(src.url, { cf: { cacheTtl: 600, cacheEverything: true } });
  if (!res.ok) throw new Error(`Gagal fetch ${src.name}: ${res.status}`);
  const raw = await res.text();
  let items = parseTextProxies(raw);
  items = dedupeAndValidate(items);

  cacheStore.data.set(src.key, { ts: now, items });
  return items;
}

function parseTextProxies(text) {
  const lines = String(text).split(/\r?\n/);
  const items = [];
  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith("#")) continue;

    const parts = line.split(',');
    if (parts.length >= 4) {
      const ip = parts[0].trim();
      const port = parseInt(parts[1].trim(), 10);
      const country = parts[2].trim().toUpperCase();
      const label = sanitizeLabel(parts.slice(3).join(',').trim()); // Join the rest for provider name

      if (ip && port && country) {
        items.push({ ip, port, country, label });
      }
    }
  }
  return items;
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
    out.push({ ip, port, label: sanitizeLabel(it.label || ""), country: it.country || 'Unknown' });
  }
  out.sort((a, b) => {
    if (a.country !== b.country) return a.country < b.country ? -1 : 1;
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
<title>Redbunny</title>
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
    padding: 4px 0 20px;
    position: sticky;
    top: 0;
    background: var(--bg);
    z-index: 999;
  }
  .logo{
    /* Adjusted for image logo */
    margin-bottom: 8px; /* Add some space below the logo */
  }
  header h1{font-size: 18px; margin: 0; color:#fff; letter-spacing: 0.5px;}
  header p{margin:2px 0 0; color:var(--muted); font-size:11px;}

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

  .proxy-grid-container {
    margin-top: 16px;
  }
  .proxy-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 12px;
  }
  .proxy-card {
    background: #1a0a0a;
    border: 1px solid var(--card-border);
    border-radius: 10px;
    padding: 12px;
    cursor: pointer;
    transition: all 0.2s ease;
    position: relative;
    overflow: hidden;
  }
  .proxy-card:hover {
    transform: translateY(-2px);
    border-color: var(--accent);
  }
  .proxy-card.selected {
    border-color: var(--accent-2);
    box-shadow: 0 0 15px rgba(220, 20, 60, 0.5);
    background: var(--accent);
  }
  .proxy-card-country {
    font-size: 12px;
    font-weight: 600;
    color: var(--muted);
    margin-bottom: 8px;
    text-transform: uppercase;
  }
  .proxy-card.selected .proxy-card-country {
      color: rgba(255,255,255,0.8);
  }
  .proxy-card-label {
    font-size: 14px;
    color: #fff;
    font-weight: 600;
    margin-bottom: 4px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .proxy-card-ip {
    font-size: 13px;
    color: var(--muted);
    font-family: 'Courier New', Courier, monospace;
  }
  .proxy-card.selected .proxy-card-ip {
      color: rgba(255,255,255,0.9);
  }

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
    left: 15px;
    font-size: 24px;
    color: var(--muted);
    cursor: pointer;
    line-height: 1;
  }
  .fab-search {
    position: fixed;
    bottom: 20px;
    left: 20px;
    width: 48px;
    height: 48px;
    border-radius: 50%;
    background: transparent;
    color: var(--muted);
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 4px 20px rgba(0,0,0,0.4);
    cursor: pointer;
    z-index: 1001;
    border: 1px solid #444;
    font-size: 24px;
  }
  .fab-generate {
    position: fixed;
    bottom: 20px;
    right: 20px;
    width: auto;
    height: 48px;
    padding: 0 24px;
    border-radius: 24px;
    background: var(--accent);
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 4px 20px rgba(0,0,0,0.4);
    cursor: pointer;
    z-index: 1001;
    border: none;
    font-size: 16px;
    font-weight: 600;
  }
  #splash-screen {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: #000;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 9999;
    transition: opacity 0.5s ease-out;
  }
  #splash-screen.hidden {
    opacity: 0;
    pointer-events: none;
  }
  .splash-logo {
    width: 100px;
    margin-bottom: 16px;
  }
  .splash-text {
    /* Match header h1 style */
    font-size: 18px;
    margin: 0;
    color: #fff;
    letter-spacing: 0.5px;
    font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
  }
  .custom-select {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #000;
    border: 1px solid #333;
    color: #fff;
    padding: 12px 14px;
    border-radius: 8px;
    cursor: pointer;
    transition: border-color 0.2s;
  }
  .custom-select:hover {
    border-color: var(--accent);
  }
  .country-list {
    max-height: 400px;
    overflow-y: auto;
    margin-top: 16px;
  }
  .country-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 10px;
    border-bottom: 1px solid #2a1a1a;
    cursor: pointer;
    transition: background-color 0.2s;
  }
  .country-item:hover {
    background: rgba(220, 20, 60, 0.1);
  }
  .country-item:last-child {
    border-bottom: none;
  }
  .country-item span {
    font-size: 16px;
    color: #fff;
  }
  .radio-icon {
    width: 22px;
    height: 22px;
    border-radius: 50%;
    border: 2px solid #555;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .country-item.selected .radio-icon {
    border-color: var(--accent);
    background: var(--accent);
  }
  .radio-icon::after {
    content: '';
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #fff;
    opacity: 0;
    transform: scale(0.5);
    transition: all 0.2s;
  }
  .country-item.selected .radio-icon::after {
    opacity: 1;
    transform: scale(1);
  }
</style>
</head>
<body>
  <div id="splash-screen">
    <img src="https://i.postimg.cc/J04TF2Rm/20251031-150628.png" alt="Redbunny Logo" class="splash-logo">
    <h1 class="splash-text">Redbunny</h1>
  </div>
  <div class="container">
    <header>
      <div class="logo"><img src="https://i.postimg.cc/HstGpzdk/redbunny1.png" alt="Redbunny Logo" style="height: 40px; vertical-align: middle;"></div>
      <h1>Redbunny</h1>
      <p>VLESS & Trojan Generator</p>
    </header>

    <button class="fab-search" id="btnShowSearchModal" aria-label="Search and Filter">
      <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
    </button>

    <button class="fab-generate" id="btnShowGenerateModal" aria-label="Generate">
      Generate
    </button>

    <div class="panel">
      <div class="badges" style="justify-content: space-between; align-items:center; margin-bottom: 16px;">
        <div>
          <span class="pill" id="pillTotal">Total: 0</span>
          <span class="pill" id="pillSelected">Selected: 0</span>
        </div>
        <button id="selectAllBtn" class="secondary" style="padding: 6px 12px; font-size: 13px;">Select All Visible</button>
      </div>
       <div class="proxy-grid-container">
        <div id="proxyGrid" class="proxy-grid"></div>
      </div>
      <div class="counts" id="counts"></div>
    </div>
    <div class="modal-overlay" id="resultsModal">
    <div class="modal-content">
      <span class="modal-close" id="resultsModalCloseBtn">&times;</span>
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
  <div class="modal-overlay" id="searchModal">
    <div class="modal-content">
      <span class="modal-close" id="searchModalCloseBtn">&times;</span>
      <h2>Search & Filter</h2>
      <div class="controls" style="margin-top:20px;">
        <div>
            <label>Filter by Country</label>
            <div class="custom-select" id="countrySelector">
                <span id="selectedCountry">All Countries</span>
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
            </div>
        </div>
        <div>
          <label for="search">Search (Name/IP/Port)</label>
          <input id="search" placeholder="e.g. Singapore, 43.218, :443" />
        </div>
      </div>
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
      <button id="btnConfirmGenerate" style="width:100%; margin-top: 24px;">Generate</button>
    </div>
  </div>

  <div class="modal-overlay" id="countryModal">
    <div class="modal-content">
      <span class="modal-close" id="countryModalCloseBtn">&times;</span>
      <h2>Select a Country</h2>
      <div class="country-list" id="countryList">
        <!-- Countries will be populated by JS -->
      </div>
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
const proxyGrid = $("#proxyGrid");
const selectAllBtn = $("#selectAllBtn");
const elCounts = $("#counts");
const elPillTotal = $("#pillTotal");
const elPillSelected = $("#pillSelected");

// Modal Refs
const generateModal = $("#generateModal");
const showModalBtn = $("#btnShowGenerateModal");
const closeModalBtn = $("#modalCloseBtn");
const confirmGenerateBtn = $("#btnConfirmGenerate");
const searchModal = $("#searchModal");
const showSearchModalBtn = $("#btnShowSearchModal");
const closeSearchModalBtn = $("#searchModalCloseBtn");
const resultsModal = $("#resultsModal");
const closeResultsModalBtn = $("#resultsModalCloseBtn");
const countryModal = $("#countryModal");
const countrySelector = $("#countrySelector");
const countryList = $("#countryList");
const selectedCountryEl = $("#selectedCountry");
const closeCountryModalBtn = $("#countryModalCloseBtn");


// --- Helper Functions ---
let selectedCountry = 'all';

function populateCountryFilter() {
    const countries = new Set(ALL_ITEMS.map(item => item.country));
    const sortedCountries = ['All Countries', ...[...countries].sort()];

    countryList.innerHTML = ''; // Clear previous list
    for (const country of sortedCountries) {
        if (!country || country === 'Unknown') continue;

        const countryCode = country === 'All Countries' ? 'all' : country;
        const item = document.createElement('div');
        item.className = 'country-item';
        item.dataset.value = countryCode;
        item.innerHTML =
            '<span>' + country + '</span>' +
            '<div class="radio-icon"></div>';
        item.addEventListener('click', () => {
            selectedCountry = countryCode;
            selectedCountryEl.textContent = country;

            // Update selected class
            countryList.querySelectorAll('.country-item').forEach(it => it.classList.remove('selected'));
            item.classList.add('selected');

            setTimeout(() => {
              countryModal.classList.remove('active');
              searchModal.classList.remove('active');
            }, 150);
            filterData();
        });
        countryList.appendChild(item);
    }
}

// --- Core Functions ---
async function loadData() {
  const src = 'txt';
  showModalBtn.disabled = true;
  showModalBtn.textContent = 'Loading...';
  try {
    const res = await fetch('/api/proxies?source=' + encodeURIComponent(src));
    if (!res.ok) throw new Error('Network response was not ok');
    const j = await res.json();
    ALL_ITEMS = j.items || [];
    populateCountryFilter();
    filterData();
  } catch (err) {
    console.error("Failed to load data:", err);
    proxyGrid.innerHTML = '<p style="grid-column: 1 / -1; text-align: center; color:var(--accent);">Failed to load proxy list.</p>';
  } finally {
    showModalBtn.disabled = false;
    showModalBtn.textContent = 'Generate';
  }
}

function filterData() {
  const q = elSearch.value.trim().toLowerCase();

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

function keyOf(x) { return x.ip + ':' + x.port; }

function render() {
  const total = FILTERED_ITEMS.length;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (currentPage > pages) currentPage = pages;
  const start = (currentPage - 1) * PAGE_SIZE;
  const slice = FILTERED_ITEMS.slice(start, start + PAGE_SIZE);

  proxyGrid.innerHTML = ''; // Clear grid

  if (slice.length === 0) {
    proxyGrid.innerHTML = '<p style="grid-column: 1 / -1; text-align: center;">No data found.</p>';
  } else {
    slice.forEach(it => {
      const k = keyOf(it);
      const card = document.createElement('div');
      card.className = 'proxy-card';
      if (SELECTED.has(k)) {
        card.classList.add('selected');
      }
      card.dataset.key = k;
      card.innerHTML =
        '<div class="proxy-card-country">' + escapeHtml(it.country) + '</div>' +
        '<div class="proxy-card-label" title="' + escapeHtml(it.label) + '">' + (it.label ? escapeHtml(it.label) : '(No Name)') + '</div>' +
        '<div class="proxy-card-ip">' + it.ip + ':' + it.port + '</div>';

      card.addEventListener('click', () => {
        toggleSelection(card, it);
      });
      proxyGrid.appendChild(card);
    });
  }

  elCounts.innerHTML = renderPaging(total, pages);
  bindPaging();
  updatePills();
}

function toggleSelection(cardElement, item) {
    const key = keyOf(item);
    if (SELECTED.has(key)) {
        SELECTED.delete(key);
        cardElement.classList.remove('selected');
    } else {
        SELECTED.set(key, item);
        cardElement.classList.add('selected');
    }
    updatePills();
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
  if (total <= PAGE_SIZE) return total + ' results';
  let pageLinks = "";
  const maxShow = 5;
  let start = Math.max(1, currentPage - 2);
  let end = Math.min(pages, start + maxShow - 1);
  if (end - start + 1 < maxShow) start = Math.max(1, end - maxShow + 1);

  pageLinks += '<button class="secondary paging-controls" data-page="prev" ' + (currentPage === 1 ? 'disabled' : '') + '>◀</button>';
  for (let p = start; p <= end; p++) {
    const act = p === currentPage ? "style='background:var(--accent); color:#fff; border-color:var(--accent)'" : "";
    pageLinks += '<button class="secondary paging-controls" data-page="' + p + '" ' + act + '>' + p + '</button>';
  }
  pageLinks += '<button class="secondary paging-controls" data-page="next" ' + (currentPage === pages ? 'disabled' : '') + '>▶</button>';

  return 'Page ' + currentPage + '/' + pages + ' (' + total + ' results) <div style="margin-top:8px;">' + pageLinks + '</div>';
}

function updatePills() {
  elPillTotal.textContent = "Total: " + ALL_ITEMS.length;
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
    generateModal.classList.remove("active");
    resultsModal.classList.add("active");
  } catch (err) {
    alert("Failed to generate: " + err.message);
  } finally {
    confirmGenerateBtn.textContent = 'Confirm & Generate';
    confirmGenerateBtn.disabled = false;
  }
}

// --- Event Listeners ---
elSearch.addEventListener("input", () => {
  clearTimeout(window.__deb);
  window.__deb = setTimeout(filterData, 200);
});

showModalBtn.addEventListener("click", () => {
  if (SELECTED.size === 0) {
    alert("Please select at least one proxy before generating.");
    return;
  }
  generateModal.classList.add("active");
});

closeModalBtn.addEventListener("click", () => generateModal.classList.remove("active"));
generateModal.addEventListener("click", (e) => {
  if (e.target === generateModal) generateModal.classList.remove("active");
});

showSearchModalBtn.addEventListener("click", () => searchModal.classList.add("active"));
closeSearchModalBtn.addEventListener("click", () => searchModal.classList.remove("active"));
searchModal.addEventListener("click", (e) => {
    if (e.target === searchModal) searchModal.classList.remove("active");
});

closeResultsModalBtn.addEventListener("click", () => resultsModal.classList.remove("active"));
resultsModal.addEventListener("click", (e) => {
    if (e.target === resultsModal) resultsModal.classList.remove("active");
});

countrySelector.addEventListener("click", () => countryModal.classList.add("active"));
closeCountryModalBtn.addEventListener("click", () => countryModal.classList.remove("active"));
countryModal.addEventListener("click", (e) => {
    if (e.target === countryModal) countryModal.classList.remove("active");
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

selectAllBtn.addEventListener("click", () => {
    const slice = FILTERED_ITEMS.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);
    // Cek apakah semua kartu yang terlihat sudah dipilih. Jika ya, batalkan pilihan semua. Jika tidak, pilih semua.
    const allVisibleSelected = slice.every(it => SELECTED.has(keyOf(it)));

    slice.forEach(it => {
        if (allVisibleSelected) {
            SELECTED.delete(keyOf(it));
        } else {
            SELECTED.set(keyOf(it), it);
        }
    });
    render();
});

// Initial Load
loadData();

window.addEventListener('DOMContentLoaded', () => {
  const splash = document.getElementById('splash-screen');
  setTimeout(() => {
    splash.classList.add('hidden');
    setTimeout(() => {
      splash.style.display = 'none';
    }, 500); // Match CSS transition duration
  }, 3000);
});
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
