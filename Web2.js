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
<title>Generator VLESS & Trojan + Picker Proxy (Cloudflare Worker)</title>
<style>
  :root{
    --bg:#0b0b0b;
    --panel:#0f0f10;
    --muted:#a8a8a8;
    --accent:#d32f2f; /* red */
    --accent-2:#ff5252;
    --card-border: rgba(255,82,82,0.08);
    --glass: rgba(255,255,255,0.03);
    --glass-2: rgba(255,82,82,0.06);
    color-scheme: dark;
  }
  html,body{height:100%; margin:0; background:linear-gradient(180deg,#070707 0%, #0b0b0b 100%); font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial}
  .container{max-width:1200px; margin:28px auto; padding:20px; display:grid; grid-template-columns: 1fr 440px; gap:20px;}
  header{grid-column:1/-1; display:flex; align-items:center; gap:16px; margin-bottom:6px;}
  .logo{
    width:56px; height:56px; border-radius:12px; background:linear-gradient(135deg,var(--accent),var(--accent-2)); display:flex; align-items:center; justify-content:center; color:#111; font-weight:700; box-shadow:0 6px 18px rgba(211,47,47,0.18);
  }
  header h1{font-size:18px; margin:0; color:#fff; letter-spacing:0.2px}
  header p{margin:0; color:var(--muted); font-size:13px}

  /* Left column */
  .panel{
    background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));
    border:1px solid var(--card-border);
    border-radius:12px;
    padding:14px;
    box-shadow: 0 6px 30px rgba(0,0,0,0.6);
  }

  .controls{display:grid; grid-template-columns: repeat(2,1fr); gap:10px; align-items:start;}
  .controls .full{grid-column: 1 / -1;}
  label{display:block; font-weight:600; font-size:13px; color:#fff; margin-bottom:6px;}
  input, select, textarea{background:transparent; border:1px solid rgba(255,255,255,0.06); color:#fff; padding:10px 12px; border-radius:8px; outline:none; box-shadow: inset 0 -1px 0 rgba(255,255,255,0.02); font-size:14px}
  input::placeholder{color:rgba(255,255,255,0.25)}
  .muted{color:var(--muted)}
  .toolbar{display:flex; gap:10px; flex-wrap:wrap; margin-top:12px;}
  button{background:linear-gradient(180deg,var(--accent),#b71c1c); color:#fff; border:0; padding:10px 14px; border-radius:9px; cursor:pointer; font-weight:600; box-shadow: 0 8px 18px rgba(211,47,47,0.12);}
  button.secondary{background:transparent; border:1px solid rgba(255,255,255,0.06); color:var(--muted); box-shadow:none;}
  .small-btn{padding:8px 10px; border-radius:8px; font-size:13px}

  .table-wrap{margin-top:12px; border-radius:10px; overflow:hidden; border:1px solid rgba(255,255,255,0.04); background: linear-gradient(180deg, rgba(255,255,255,0.01), rgba(255,255,255,0.005));}
  table{width:100%; border-collapse:collapse; color:#fff; font-size:13px}
  thead th{position:sticky; top:0; background:linear-gradient(180deg, rgba(0,0,0,0.4), rgba(0,0,0,0.2)); color:var(--muted); padding:10px; text-align:left; font-weight:700; font-size:12px}
  tbody td{padding:10px; border-top:1px solid rgba(255,255,255,0.02); vertical-align:middle}
  tr:hover td{background: linear-gradient(90deg, rgba(255,82,82,0.02), rgba(0,0,0,0));}
  .table-actions{display:flex; gap:8px; align-items:center}

  .counts{margin-top:8px; color:var(--muted); font-size:13px}
  .badges{display:flex; gap:8px; margin-top:10px}
  .pill{background:linear-gradient(90deg, rgba(255,255,255,0.02), rgba(255,82,82,0.03)); color:#fff; padding:6px 10px; border-radius:999px; font-size:13px; border:1px solid rgba(255,255,255,0.03)}

  /* Right column (outputs) */
  .right-col{display:flex; flex-direction:column; gap:12px;}
  .output-card{padding:12px; border-radius:12px; border:1px solid var(--card-border); background: linear-gradient(180deg, rgba(0,0,0,0.12), rgba(0,0,0,0.06));}
  .output-card h2{margin:0 0 10px 0; color:#fff; font-size:15px}
  textarea{min-height:110px; resize:vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: linear-gradient(180deg, rgba(0,0,0,0.18), rgba(0,0,0,0.12));}
  .output-row{display:flex; gap:10px}
  .output-row > div{flex:1}

  /* responsive */
  @media (max-width:1100px){
    .container{grid-template-columns:1fr; padding:14px}
    header{flex-direction:column; align-items:flex-start; gap:6px}
  }
</style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">V2</div>
      <div>
        <h1>Generator VLESS & Trojan — Picker Proxy</h1>
        <p class="muted">Cloudflare Worker • Pilih proxy, lalu generate akun (Trojan/VLESS)</p>
      </div>
    </header>

    <div class="panel" id="leftPanel">
      <div class="controls">
        <div>
          <label>Source Daftar Proxy</label>
          <select id="sourceKey">
            <option value="all">Semua (gabungan)</option>
            <option value="txt">proxyList.txt (raw)</option>
            <option value="json">KvProxyList.json</option>
          </select>
        </div>

        <div>
          <label>Cari (nama/IP/port)</label>
          <input id="search" placeholder="mis. Singapore, 43.218, :443" />
        </div>

        <div>
          <label>Front Domain</label>
          <input id="frontDomain" value="${DEFAULTS.frontDomain}" />
        </div>

        <div>
          <label>SNI</label>
          <input id="sni" value="${DEFAULTS.sni}" />
        </div>

        <div class="full">
          <label>Host Header (opsional)</label>
          <input id="hostHeader" placeholder="kosongkan untuk pakai SNI" value="${DEFAULTS.hostHeader}" />
        </div>

        <div>
          <label>TLS Port</label>
          <input id="cfTlsPort" type="number" min="1" max="65535" value="${DEFAULTS.cfTlsPort}" />
        </div>

        <div>
          <label>Jenis Akun</label>
          <div style="display:flex; gap:12px; align-items:center; margin-top:6px">
            <label style="font-weight:600; color:#fff"><input id="genTrojan" type="checkbox" checked style="margin-right:8px"> Trojan</label>
            <label style="font-weight:600; color:#fff"><input id="genVless" type="checkbox" checked style="margin-right:8px"> VLESS</label>
          </div>
        </div>
      </div>

      <div class="toolbar" style="margin-top:12px">
        <button id="btnReload" class="secondary small-btn">Muat / Refresh</button>
        <button id="btnSelectFiltered" class="secondary small-btn">Pilih Semua (Filter Aktif)</button>
        <button id="btnClearSelection" class="secondary small-btn">Bersihkan Pilihan</button>
        <div style="flex:1"></div>
        <div class="badges" style="margin-left:auto">
          <span class="pill" id="pillTotal">Total: 0</span>
          <span class="pill" id="pillFiltered">Filtered: 0</span>
          <span class="pill" id="pillSelected">Dipilih: 0</span>
        </div>
      </div>

      <div class="table-wrap" id="tableWrap">
        <table id="tbl" aria-describedby="counts">
          <thead>
            <tr>
              <th style="width:40px"><input type="checkbox" id="chkAllPage" title="Centang semua yang tampil" /></th>
              <th>Nama Proxy</th>
              <th>IP</th>
              <th>Port</th>
            </tr>
          </thead>
          <tbody id="tbody"></tbody>
        </table>
      </div>

      <div class="counts" id="counts"></div>
    </div>

    <div class="right-col">
      <div class="panel output-card">
        <div style="display:flex; align-items:center; justify-content:space-between; gap:12px">
          <h2 style="margin:0">Generate</h2>
          <div style="display:flex; gap:8px; align-items:center">
            <button id="btnGenerate" title="Generate untuk proxy terpilih">Generate untuk Proxy Terpilih</button>
          </div>
        </div>

        <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap">
          <div class="muted" style="flex:1">Format: trojan/vless (WS + TLS). Gunakan tombol Copy untuk menyalin.</div>
        </div>
      </div>

      <div class="panel output-card">
        <h2>Hasil</h2>
        <div class="output-row" style="margin-bottom:8px">
          <div>
            <label>Trojan</label>
            <textarea id="outTrojan" readonly></textarea>
            <div style="display:flex; gap:8px; margin-top:8px">
              <button class="secondary" data-copy="#outTrojan">Copy Trojan</button>
            </div>
          </div>
          <div>
            <label>VLESS</label>
            <textarea id="outVless" readonly></textarea>
            <div style="display:flex; gap:8px; margin-top:8px">
              <button class="secondary" data-copy="#outVless">Copy VLESS</button>
            </div>
          </div>
        </div>

        <label>Gabungan</label>
        <textarea id="outCombined" readonly style="min-height:80px"></textarea>
        <div style="display:flex; justify-content:flex-end; margin-top:8px">
          <button class="secondary" data-copy="#outCombined">Copy Semua</button>
        </div>
        <div style="margin-top:8px">
          <small class="muted">
            Format: trojan://UUID@front:443/?type=ws&host=SNI/Host&path=%2FIP-PORT&security=tls&sni=SNI#Label%20[IP]<br/>
            Format: vless://UUID@front:443/?type=ws&encryption=none&flow=&host=SNI/Host&path=%2FIP-PORT&security=tls&sni=SNI#Label%20[IP]
          </small>
        </div>
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

const elSource = $("#sourceKey");
const elSearch = $("#search");
const elTBody = $("#tbody");
const elChkAllPage = $("#chkAllPage");
const elCounts = $("#counts");
const elPillTotal = $("#pillTotal");
const elPillFiltered = $("#pillFiltered");
const elPillSelected = $("#pillSelected");

async function loadData() {
  const src = elSource.value;
  const res = await fetch(\`/api/proxies?source=\${encodeURIComponent(src)}\`);
  const j = await res.json();
  ALL_ITEMS = (j.items || []);
  FILTERED_ITEMS = [...ALL_ITEMS];
  currentPage = 1;
  render();
}

function filterData() {
  const q = elSearch.value.trim().toLowerCase();
  if (!q) {
    FILTERED_ITEMS = [...ALL_ITEMS];
  } else {
    FILTERED_ITEMS = ALL_ITEMS.filter(x => {
      const name = (x.label || "").toLowerCase();
      const ip = (x.ip || "").toLowerCase();
      const port = String(x.port || "").toLowerCase();
      return name.includes(q) || ip.includes(q) || port.includes(q);
    });
  }
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

  // Tabel
  let rows = "";
  for (const it of slice) {
    const k = keyOf(it);
    const checked = SELECTED.has(k) ? "checked" : "";
    const name = it.label ? it.label : "(Tanpa Nama)";
    rows += \`<tr>
      <td><input type="checkbox" class="rowchk" data-key="\${k}" \${checked} /></td>
      <td>\${escapeHtml(name)}</td>
      <td>\${it.ip}</td>
      <td>\${it.port}</td>
    </tr>\`;
  }
  elTBody.innerHTML = rows || '<tr><td colspan="4" style="padding:12px;color:#888">Tidak ada data</td></tr>';
  bindRowChecks();

  // Header checkbox: centang jika semua di halaman terpilih
  const allOnPageSelected = slice.length && slice.every(it => SELECTED.has(keyOf(it)));
  elChkAllPage.checked = allOnPageSelected;

  // Counts + Paging
  elCounts.innerHTML = renderCountsAndPaging(total, pages);
  bindPaging();

  elPillTotal.textContent = "Total: " + (ALL_ITEMS.length || 0);
  elPillFiltered.textContent = "Filtered: " + total;
  elPillSelected.textContent = "Dipilih: " + SELECTED.size;
}

function bindRowChecks() {
  document.querySelectorAll(".rowchk").forEach(chk => {
    chk.addEventListener("change", e => {
      const key = chk.getAttribute("data-key");
      const [ip, port] = key.split(":");
      const item = FILTERED_ITEMS.find(x => x.ip === ip && String(x.port) === port);
      if (!item) return;
      if (chk.checked) SELECTED.set(key, item);
      else SELECTED.delete(key);
      updatePills();
    });
  });
}

function bindPaging() {
  document.querySelectorAll("[data-page]").forEach(btn => {
    btn.addEventListener("click", () => {
      const p = btn.getAttribute("data-page");
      if (p === "prev") currentPage = Math.max(1, currentPage - 1);
      else if (p === "next") currentPage = Math.min(Math.ceil(FILTERED_ITEMS.length / PAGE_SIZE), currentPage + 1);
      else currentPage = parseInt(p, 10) || 1;
      render();
    });
  });
}

function renderCountsAndPaging(total, pages) {
  if (!total) return \`0 hasil | Halaman 0/0\`;
  let pageLinks = "";
  const maxShow = 7;
  let start = Math.max(1, currentPage - 3);
  let end = Math.min(pages, start + maxShow - 1);
  if (end - start + 1 < maxShow) start = Math.max(1, end - maxShow + 1);

  pageLinks += \`<button class="secondary" data-page="prev">◀</button>\`;
  for (let p = start; p <= end; p++) {
    const act = p === currentPage ? "style='background:#3a0f0f; color:#fff; border-color:rgba(255,82,82,0.12)'" : "";
    pageLinks += \`<button class="secondary" data-page="\${p}" \${act}>\${p}</button>\`;
  }
  pageLinks += \`<button class="secondary" data-page="next">▶</button>\`;

  return \`\${total} hasil | Halaman \${currentPage}/\${pages} | \${pageLinks}\`;
}

function updatePills() {
  elPillTotal.textContent = "Total: " + (ALL_ITEMS.length || 0);
  elPillFiltered.textContent = "Filtered: " + (FILTERED_ITEMS.length || 0);
  elPillSelected.textContent = "Dipilih: " + SELECTED.size;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// Events
$("#btnReload").addEventListener("click", loadData);
$("#search").addEventListener("input", () => {
  // Debounce ringan
  clearTimeout(window.__deb);
  window.__deb = setTimeout(filterData, 150);
});
$("#sourceKey").addEventListener("change", loadData);
$("#btnSelectFiltered").addEventListener("click", () => {
  for (const it of FILTERED_ITEMS) SELECTED.set(keyOf(it), it);
  render();
});
$("#btnClearSelection").addEventListener("click", () => {
  SELECTED.clear();
  render();
});
$("#btnGenerate").addEventListener("click", async () => {
  const selected = Array.from(SELECTED.values());
  if (!selected.length) {
    alert("Pilih minimal satu proxy terlebih dahulu.");
    return;
  }
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
  if (!j.ok) {
    alert("Gagal: " + (j.error || "unknown"));
    return;
  }
  $("#outTrojan").value = (j.trojan || []).join("\\n");
  $("#outVless").value = (j.vless || []).join("\\n");
  $("#outCombined").value = j.combined || "";
});

document.querySelectorAll("button[data-copy]").forEach(b => {
  b.addEventListener("click", async () => {
    const t = document.querySelector(b.getAttribute("data-copy"));
    if (!t) return;
    t.select();
    t.setSelectionRange(0, 99999);
    try {
      await navigator.clipboard.writeText(t.value);
      b.textContent = "Copied!";
      setTimeout(() => (b.textContent = "Copy"), 1200);
    } catch {
      document.execCommand("copy");
    }
  });
});

elChkAllPage.addEventListener("change", () => {
  // Centang semua baris yang sedang terlihat
  const total = FILTERED_ITEMS.length;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const start = (currentPage - 1) * PAGE_SIZE;
  const slice = FILTERED_ITEMS.slice(start, start + PAGE_SIZE);
  if (elChkAllPage.checked) {
    for (const it of slice) SELECTED.set(keyOf(it), it);
  } else {
    for (const it of slice) SELECTED.delete(keyOf(it));
  }
  render();
});

// Load awal
loadData();
</script>
</body>
</html>`;
  return new Response(page, { headers: { "content-type": "text/html; charset=utf-8" } });
}
