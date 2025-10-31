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
<title>Red Bunny</title>
<style>
  :root{
    --bg: #000;
    --panel: #110808;
    --muted: #a0a0a0;
    --accent: #dc143c; /* Crimson */
    --accent-2: #ff4040;
    --card-border: rgba(220, 20, 60, 0.5);
     --glow-shadow: 0 0 8px var(--accent), 0 0 16px var(--accent-2);
    color-scheme: dark;
  }
  html,body{
    height:100%; margin:0; background: var(--bg);
    font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
    color: var(--muted);
  }
  .container{max-width:1200px; margin:0 auto; padding: 16px 16px 100px 16px;}
  header{
    text-align:center;
    padding: 10px 0 20px 0;
  }
  .logo{
    font-size: 48px;
    font-weight: bold;
    color: var(--accent);
    text-shadow: var(--glow-shadow);
  }
  header h1{font-size: 24px; margin: 0; color:#fff; letter-spacing: 0.5px;}

  /* Pills */
  .pills-container {
    display:flex; gap:10px; flex-wrap:wrap; justify-content: center;
    margin-bottom: 24px;
  }
  .pill{
    background: #222; color:#fff; padding:6px 12px;
    border-radius:16px; font-size:13px; border: 1px solid #444;
  }
  .pill#pillSelected { background: var(--accent); border-color: var(--accent-2); }


  /* Proxy Grid */
  .proxy-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 16px;
  }
  .proxy-card {
    background: var(--panel);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 12px;
    cursor: pointer;
    transition: all 0.2s ease-in-out;
    box-shadow: 0 0 0 rgba(0,0,0,0);
  }
  .proxy-card:hover {
    transform: translateY(-2px);
    border-color: var(--accent-2);
    box-shadow: 0 4px 15px rgba(220, 20, 60, 0.2);
  }
  .proxy-card.selected {
    background: rgba(220, 20, 60, 0.2);
    border-color: var(--accent);
    box-shadow: var(--glow-shadow);
  }
  .proxy-card .country { font-weight: bold; font-size: 16px; color: #fff; }
  .proxy-card .label { font-size: 14px; color: var(--muted); margin: 4px 0; min-height: 1.2em; }
  .proxy-card .ip-port { font-size: 13px; color: var(--accent-2); font-family: 'Courier New', monospace;}


  /* Floating Buttons */
  .fab {
    position: fixed;
    width: 60px;
    height: 60px;
    border-radius: 50%;
    border: none;
    color: white;
    font-size: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    box-shadow: 0 4px 20px rgba(0,0,0,0.4);
    transition: all 0.3s ease;
    z-index: 999;
  }
  .fab:hover { transform: scale(1.1); }
  .fab-search {
    top: 20px;
    right: 20px;
    background-color: #333;
    border: 1px solid var(--card-border);
  }
  .fab-generate {
    bottom: 20px;
    right: 20px;
    background-color: var(--accent);
    box-shadow: var(--glow-shadow);
  }

  /* Filter Panel */
  .filter-panel {
    position: fixed;
    top: 0;
    right: -100%;
    width: 100%;
    max-width: 350px;
    height: 100%;
    background: #0a0404;
    border-left: 1px solid var(--card-border);
    z-index: 1001;
    transition: right 0.3s ease-in-out;
    display: flex;
    flex-direction: column;
  }
  .filter-panel.open { right: 0; }
  .filter-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px;
    border-bottom: 1px solid var(--card-border);
  }
  .filter-header h2 { margin: 0; color: #fff; }
  .close-btn { font-size: 28px; cursor: pointer; color: var(--muted); line-height: 1;}
  .panel-content { padding: 16px; }


  /* General controls */
  .controls{display:grid; grid-template-columns: 1fr; gap:16px;}
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
  input:focus, select:focus, textarea:focus { border-color: var(--accent); }
  input::placeholder{color: #555;}

  .toolbar{display:flex; flex-direction:column; gap:10px; margin-top:20px;}
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

  /* Modal & Paging */
   .counts{margin-top:16px; color:var(--muted); font-size:14px; text-align:center;}
  .paging-controls button { padding: 8px 12px; font-size: 13px; }
  .output-row{display:flex; flex-direction: column; gap:16px; margin-bottom: 16px;}
  @media (min-width: 600px) { .output-row{flex-direction: row;} }
  textarea{min-height:120px; resize:vertical; font-family: 'Courier New', Courier, monospace; background: #000;}

  .modal-overlay {
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(0,0,0,0.7); display: none; align-items: center;
    justify-content: center; z-index: 1000;
  }
  .modal-overlay.active { display: flex; }
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
    position: absolute; top: 10px; right: 15px; font-size: 24px;
    color: var(--muted); cursor: pointer; line-height: 1;
  }
</style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">RB</div>
      <h1>Red Bunny</h1>
    </header>

    <div class="pills-container">
        <span class="pill" id="pillTotal">Total: 0</span>
        <span class="pill" id="pillFiltered">Visible: 0</span>
        <span class="pill" id="pillSelected">Selected: 0</span>
    </div>

    <div id="proxyGrid" class="proxy-grid">
      <!-- Proxy cards will be injected here by JS -->
    </div>
     <div class="counts" id="counts"></div>
  </div>

  <!-- Floating Buttons -->
  <button id="fabSearch" class="fab fab-search" title="Search & Filter">🔍</button>
  <button id="fabGenerate" class="fab fab-generate" title="Generate for Selected Proxies">Generate</button>

  <!-- Filter Panel (hidden by default) -->
  <div id="filterPanel" class="filter-panel">
    <div class="filter-header">
      <h2>Filter Options</h2>
      <span id="closeFilterPanel" class="close-btn">&times;</span>
    </div>
    <div class="panel-content">
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
      <div class="toolbar">
        <button id="btnSelectFiltered" class="secondary">Select All Visible</button>
        <button id="btnClearSelection" class="secondary">Clear Selection</button>
        <button id="btnReload" class="secondary">Reload List</button>
      </div>
    </div>
  </div>

  <!-- Output Modal -->
    <div class="modal-overlay" id="outputModal">
        <div class="modal-content">
            <span class="modal-close" data-close-modal="outputModal">&times;</span>
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
const PAGE_SIZE = 100;

let ALL_ITEMS = [];
let FILTERED_ITEMS = [];
let SELECTED = new Map(); // key => {ip, port, label, country}
let currentPage = 1;

// --- Element Refs ---
const el = {
    search: $("#search"),
    countryFilter: $("#countryFilter"),
    proxyGrid: $("#proxyGrid"),
    counts: $("#counts"),
    pillTotal: $("#pillTotal"),
    pillFiltered: $("#pillFiltered"),
    pillSelected: $("#pillSelected"),

    // Modals & Panels
    generateModal: $("#generateModal"),
    outputModal: $("#outputModal"),
    filterPanel: $("#filterPanel"),

    // Buttons
    fabSearch: $("#fabSearch"),
    fabGenerate: $("#fabGenerate"),
    closeFilterPanel: $("#closeFilterPanel"),
    btnReload: $("#btnReload"),
    btnSelectFiltered: $("#btnSelectFiltered"),
    btnClearSelection: $("#btnClearSelection"),
    btnConfirmGenerate: $("#btnConfirmGenerate"),
};

// --- Helper Functions ---
function populateCountryFilter() {
    const countries = new Set(ALL_ITEMS.map(item => item.country));
    const sortedCountries = [...countries].sort();
    el.countryFilter.innerHTML = '<option value="all">All Countries</option>';
    for (const country of sortedCountries) {
        if (country && country !== 'Unknown') {
            const option = document.createElement('option');
            option.value = country;
            option.textContent = country;
            el.countryFilter.appendChild(option);
        }
    }
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
}

function keyOf(x) { return `${x.ip}:${x.port}`; }

// --- Core Functions ---
async function loadData() {
    el.fabGenerate.disabled = true;
    el.fabGenerate.textContent = '...';
    try {
        const res = await fetch(`/api/proxies?source=txt`);
        if (!res.ok) throw new Error('Network response was not ok');
        const j = await res.json();
        ALL_ITEMS = j.items || [];
        populateCountryFilter();
        filterData();
    } catch (err) {
        console.error("Failed to load data:", err);
        el.proxyGrid.innerHTML = `<p style="color:var(--accent);grid-column: 1 / -1;">Failed to load proxy list.</p>`;
    } finally {
        el.fabGenerate.disabled = false;
        el.fabGenerate.textContent = 'Generate';
    }
}

function filterData() {
    const q = el.search.value.trim().toLowerCase();
    const selectedCountry = el.countryFilter.value;

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

function render() {
    const total = FILTERED_ITEMS.length;
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    if (currentPage > totalPages) currentPage = totalPages;
    const start = (currentPage - 1) * PAGE_SIZE;
    const end = start + PAGE_SIZE;
    const slice = FILTERED_ITEMS.slice(start, end);

    el.proxyGrid.innerHTML = slice.map(it => {
        const k = keyOf(it);
        const selectedClass = SELECTED.has(k) ? "selected" : "";
        const name = it.label ? escapeHtml(it.label) : "(No Name)";
        const country = it.country ? escapeHtml(it.country) : "Unknown";
        return `<div class="proxy-card ${selectedClass}" data-key="${k}">
            <div class="country">${country}</div>
            <div class="label">${name}</div>
            <div class="ip-port">${it.ip}:${it.port}</div>
        </div>`;
    }).join('') || `<p style="color:var(--muted);grid-column: 1 / -1;text-align:center;">No proxies found.</p>`;

    el.counts.innerHTML = renderPaging(total, totalPages);
    bindPaging();
    updatePills();
}

function renderPaging(total, pages) {
    if (total <= PAGE_SIZE) return `${total} results`;
    let pageLinks = "";
    const maxShow = 5;
    let start = Math.max(1, currentPage - 2);
    let end = Math.min(pages, start + maxShow - 1);
    if (end - start + 1 < maxShow) start = Math.max(1, end - maxShow + 1);

    pageLinks += `<button class="secondary paging-controls" data-page="prev" ${currentPage === 1 ? 'disabled' : ''}>◀</button>`;
    for (let p = start; p <= end; p++) {
        const act = p === currentPage ? "style='background:var(--accent); color:#fff; border-color:var(--accent)'" : "";
        pageLinks += `<button class="secondary paging-controls" data-page="${p}" ${act}>${p}</button>`;
    }
    pageLinks += `<button class="secondary paging-controls" data-page="next" ${currentPage === pages ? 'disabled' : ''}>▶</button>`;
    return `Page ${currentPage}/${pages} (${total} results) <div style="margin-top:8px;">${pageLinks}</div>`;
}

function bindPaging() {
    el.counts.querySelectorAll("[data-page]").forEach(btn => {
        btn.addEventListener("click", (e) => {
            e.preventDefault();
            const p = btn.getAttribute("data-page");
            if (p === "prev") currentPage = Math.max(1, currentPage - 1);
            else if (p === "next") currentPage = Math.min(Math.ceil(FILTERED_ITEMS.length / PAGE_SIZE), currentPage + 1);
            else currentPage = parseInt(p, 10);
            render();
        });
    });
}

function updatePills() {
    el.pillTotal.textContent = "Total: " + ALL_ITEMS.length;
    el.pillFiltered.textContent = "Visible: " + FILTERED_ITEMS.length;
    el.pillSelected.textContent = "Selected: " + SELECTED.size;
}

async function handleGenerate() {
    const selected = Array.from(SELECTED.values());
    if (selected.length === 0) {
        alert("Please select at least one proxy.");
        return;
    }
    el.btnConfirmGenerate.textContent = 'Generating...';
    el.btnConfirmGenerate.disabled = true;

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

        $("#outTrojan").value = (j.trojan || []).join("\n");
        $("#outVless").value = (j.vless || []).join("\n");
        $("#outCombined").value = j.combined || "";

        el.generateModal.classList.remove("active");
        el.outputModal.classList.add("active");

    } catch (err) {
        alert("Failed to generate: " + err.message);
    } finally {
        el.btnConfirmGenerate.textContent = 'Confirm & Generate';
        el.btnConfirmGenerate.disabled = false;
    }
}

// --- Event Listeners ---
el.btnReload.addEventListener("click", loadData);
el.search.addEventListener("input", () => {
    clearTimeout(window.__deb);
    window.__deb = setTimeout(filterData, 200);
});
el.countryFilter.addEventListener("change", filterData);

el.btnSelectFiltered.addEventListener("click", () => {
    const start = (currentPage - 1) * PAGE_SIZE;
    const slice = FILTERED_ITEMS.slice(start, start + PAGE_SIZE);
    slice.forEach(it => SELECTED.set(keyOf(it), it));
    render();
});
el.btnClearSelection.addEventListener("click", () => {
    SELECTED.clear();
    render();
});

// Proxy Card Selection
el.proxyGrid.addEventListener("click", (e) => {
    const card = e.target.closest(".proxy-card");
    if (!card) return;
    const key = card.getAttribute("data-key");
    const item = ALL_ITEMS.find(x => keyOf(x) === key);
    if (!item) return;

    if (SELECTED.has(key)) {
        SELECTED.delete(key);
        card.classList.remove("selected");
    } else {
        SELECTED.set(key, item);
        card.classList.add("selected");
    }
    updatePills();
});

// Panel & Modal Controls
el.fabSearch.addEventListener("click", () => el.filterPanel.classList.add("open"));
el.closeFilterPanel.addEventListener("click", () => el.filterPanel.classList.remove("open"));

el.fabGenerate.addEventListener("click", () => {
    if (SELECTED.size === 0) {
        alert("Please select at least one proxy before generating.");
        return;
    }
    el.generateModal.classList.add("active");
});
el.btnConfirmGenerate.addEventListener("click", handleGenerate);

// Generic modal close logic
document.querySelectorAll(".modal-overlay").forEach(modal => {
    modal.addEventListener("click", (e) => {
        if (e.target === modal) modal.classList.remove("active");
    });
});
document.querySelectorAll(".modal-close").forEach(btn => {
    btn.addEventListener("click", () => {
        btn.closest(".modal-overlay").classList.remove("active");
    });
});

// Clipboard copy
document.querySelectorAll("button[data-copy]").forEach(b => {
    b.addEventListener("click", async () => {
        const t = $(b.getAttribute("data-copy"));
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

// --- Initial Load ---
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
