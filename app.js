"use strict";

// ── State ──────────────────────────────────────────────────────────────────────
let countriesIndex = {};   // iso2 → countries.json entry
let scanData       = {};   // iso2 → data.json country result
let worldGeoJSON   = null; // FeatureCollection from world.geojson
let polyLayers     = [];   // [{layer, iso2, entry, result}]
let activeLayer    = null;

// ── Map init ───────────────────────────────────────────────────────────────────
const map = L.map("map", {
  center: [20, 10],
  zoom: 2,
  zoomControl: true,
  preferCanvas: true,
  worldCopyJump: true,
});

L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
  attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
  maxZoom: 19,
  referrerPolicy: "no-referrer-when-downgrade",
}).addTo(map);

// ── Color helpers ──────────────────────────────────────────────────────────────
function scoreColor(score) {
  if (score == null) return "#111827";
  const hue = (score / 100) * 120;
  return `hsl(${hue}, 75%, 38%)`;
}

// ── DOM helpers ────────────────────────────────────────────────────────────────
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls)  e.className   = cls;
  if (text != null) e.textContent = text;
  return e;
}

function span(cls, text) { return el("span", cls, text); }
function div(cls, text)  { return el("div",  cls, text); }

// ── Status helpers ─────────────────────────────────────────────────────────────
function setStatus(msg, cls = "") {
  const e = document.getElementById("status-msg");
  e.textContent = msg;
  e.className   = cls;
}

// ── Load data ──────────────────────────────────────────────────────────────────
async function loadCountries() {
  const r = await fetch("countries.json");
  if (!r.ok) throw new Error(`countries.json: HTTP ${r.status}`);
  const d = await r.json();
  for (const e of d.entries) countriesIndex[e.iso2] = e;
}

async function loadScanData() {
  try {
    const r = await fetch("data.json");
    if (!r.ok) return null;
    const d = await r.json();
    scanData = d.countries || {};
    return d;
  } catch (_) { return null; }
}

async function loadWorldGeoJSON() {
  const r = await fetch("world.geojson");
  if (!r.ok) throw new Error(`world.geojson: HTTP ${r.status}`);
  worldGeoJSON = await r.json();
}

// ── Find GeoJSON feature by ISO_A2 ────────────────────────────────────────────
function findFeature(iso2) {
  if (!worldGeoJSON) return null;
  return worldGeoJSON.features.find(
    f => (f.properties?.ISO_A2 || "").toUpperCase() === iso2.toUpperCase()
  ) || null;
}

// ── Tooltip (uses Leaflet's tooltip — built from DOM node) ────────────────────
function buildTooltipNode(iso2) {
  const entry  = countriesIndex[iso2] || {};
  const result = scanData[iso2];
  const wrapper = div("gov-tooltip-inner");

  const header = div(null);
  if (entry.flag) header.appendChild(span("tt-flag", entry.flag));
  header.appendChild(span("tt-name", entry.name || iso2));
  wrapper.appendChild(header);

  if (result?.score != null) {
    const gr = div("tt-score");
    gr.textContent = `Grade ${result.grade} · ${Math.round(result.score)}/100`;
    gr.style.color = scoreColor(result.score);
    wrapper.appendChild(gr);
    wrapper.appendChild(div("tt-domain", result.gov_domain || entry.gov_domain || ""));
  } else {
    wrapper.appendChild(div("tt-domain", entry.gov_domain || ""));
    wrapper.appendChild(div("tt-score", "Not yet scanned"));
  }

  return wrapper;
}

// ── Render polygons ────────────────────────────────────────────────────────────
function renderPolygons() {
  for (const item of polyLayers) item.layer.remove();
  polyLayers = [];
  activeLayer = null;

  let rendered = 0;

  for (const [iso2, entry] of Object.entries(countriesIndex)) {
    if (entry.no_polygon) continue;
    const feat = findFeature(iso2);
    if (!feat) continue;

    const result  = scanData[iso2];
    const score   = result?.score ?? null;
    const color   = scoreColor(score);
    const opacity = score != null ? 0.72 : 0.35;

    const layer = L.geoJSON(feat, {
      style: {
        fillColor:   color,
        fillOpacity: opacity,
        weight:      0.8,
        color:       "#2a3040",
        opacity:     0.9,
      },
    });

    layer.bindTooltip(
      () => buildTooltipNode(iso2),
      { sticky: true, className: "gov-tooltip", opacity: 1.0 }
    );

    layer.on("click", (e) => {
      L.DomEvent.stopPropagation(e);
      showInfo(iso2, layer);
    });

    layer.addTo(map);
    polyLayers.push({ layer, iso2, entry, result });
    rendered++;
  }

  setStatus(`${rendered} countries`, "ok");
  return rendered;
}

// ── Check card ─────────────────────────────────────────────────────────────────
const CHECK_META = [
  { key: "dkim",   label: "DKIM",    weight: "20%" },
  { key: "spf",    label: "SPF",     weight: "15%" },
  { key: "dmarc",  label: "DMARC",   weight: "15%" },
  { key: "mtasts", label: "MTA-STS", weight: "15%" },
  { key: "dnssec", label: "DNSSEC",  weight: "10%" },
  { key: "mx",     label: "MX",      weight: "10%" },
  { key: "dane",   label: "DANE",    weight: "10%" },
  { key: "tlsrpt", label: "TLS-RPT", weight:  "3%" },
  { key: "caa",    label: "CAA",     weight:  "2%" },
];

function buildCheckCard(meta, checkData) {
  const rating = (checkData?.skipped ? "warning" : (checkData?.rating || "unknown"));
  const detail = checkData?.detail || "";
  const record = Array.isArray(checkData?.records)
    ? checkData.records.join("\n")
    : (checkData?.record || "");

  const card = div("check-card");

  // Header
  const hdr = div("check-card-hdr");
  hdr.appendChild(span("check-name", meta.label));
  hdr.appendChild(span("check-weight", meta.weight));

  const badgeText = checkData?.skipped
    ? rating.charAt(0).toUpperCase() + rating.slice(1) + " (skipped)"
    : rating.charAt(0).toUpperCase() + rating.slice(1);
  const badge = span(`rating-badge rating-${rating}`, badgeText);
  hdr.appendChild(badge);
  card.appendChild(hdr);

  // Detail
  if (detail) card.appendChild(div("check-detail", detail));

  // Raw record expandable
  if (record) {
    const toggle = el("button", "check-record-toggle");
    const arrow  = span("toggle-arrow", "▶");
    toggle.appendChild(arrow);
    toggle.appendChild(document.createTextNode(" Raw record"));

    const body = div("check-record-body", record);

    toggle.addEventListener("click", () => {
      const open = body.classList.toggle("open");
      toggle.classList.toggle("open", open);
    });

    card.appendChild(toggle);
    card.appendChild(body);
  }

  return card;
}

// ── Info sidebar ───────────────────────────────────────────────────────────────
// layer may be null for countries without a map polygon (small nations, disputed)
function showInfo(iso2, layer) {
  const panel  = document.getElementById("info-panel");
  const entry  = countriesIndex[iso2] || {};
  const result = scanData[iso2];
  const score  = result?.score ?? null;
  const grade  = result?.grade ?? null;

  // Restore previous highlight
  if (activeLayer && activeLayer !== layer) {
    const prev = polyLayers.find(i => i.layer === activeLayer);
    if (prev) {
      const s = scanData[prev.iso2]?.score ?? null;
      prev.layer.setStyle({ weight: 0.8, color: "#2a3040",
        fillOpacity: s != null ? 0.72 : 0.35 });
    }
  }
  // Highlight new polygon (if one exists)
  if (layer) {
    layer.setStyle({ weight: 2.5, color: "#58a6ff", fillOpacity: 0.85 });
    layer.bringToFront();
  }
  activeLayer = layer;

  // Swatch
  document.getElementById("info-swatch").style.background = scoreColor(score);

  // Flag
  document.getElementById("info-flag").textContent = entry.flag || "🏳";

  // Name
  document.getElementById("info-name").textContent = entry.name || iso2;

  // Meta
  const meta = document.getElementById("info-meta");
  meta.textContent = "";

  const statusLabels = { un_member: "UN Member", observer: "Observer",
                         disputed: "Disputed",   territory: "Territory" };
  const sbadge = span(`status-badge status-${entry.status || "un_member"}`,
                      statusLabels[entry.status] || entry.status || "");
  meta.appendChild(sbadge);

  const gradeEl = span(`grade-display ${grade || "none"}`, grade || "—");
  meta.appendChild(gradeEl);

  if (score != null) {
    meta.appendChild(span("score-text", `${Math.round(score)}/100`));
  }

  // Gov link — result.gov_url is authoritative (may be Wikidata P856 or countries.json)
  const link     = document.getElementById("info-gov-link");
  const govUrl   = result?.gov_url || entry.gov_url || (entry.gov_domain ? `https://${entry.gov_domain}` : "#");
  link.href      = govUrl;
  link.textContent = result?.gov_domain || entry.gov_domain || govUrl;

  // Provenance note
  const wikiNote = document.getElementById("info-wiki-note");
  wikiNote.textContent = "";
  wikiNote.className   = "";
  const govSrc = result?.gov_domain_source;
  if (govSrc === "wikidata") {
    wikiNote.className   = "wiki-note";
    wikiNote.textContent = "ℹ URL sourced from Wikidata (Wikipedia P856 — official website).";
  }

  // Body
  const body = document.getElementById("info-body");
  body.textContent = "";

  if (!result || (result.score == null && !Object.keys(result.checks || {}).length)) {
    const ns = div("not-scanned");
    ns.appendChild(div(null, "This country has not been scanned yet."));

    const hint = div(null, "Run: ");
    const code = el("code", null, `python scanner.py --country ${iso2}`);
    hint.appendChild(code);
    ns.appendChild(hint);

    if (entry.gov_domain) {
      ns.appendChild(div("domain-hint", entry.gov_domain));
    }

    if (result?.error) {
      const err = div(null, `Error: ${result.error}`);
      err.style.cssText = "color:var(--danger);margin-top:8px;font-family:monospace;font-size:10px;";
      ns.appendChild(err);
    }
    body.appendChild(ns);

  } else {
    body.appendChild(div("checks-divider", "Security Checks"));

    for (const m of CHECK_META) {
      body.appendChild(buildCheckCard(m, (result.checks || {})[m.key]));
    }

    if (result.scanned_at) {
      const ts = div(null, `Scanned ${result.scanned_at.slice(0, 10)}`);
      ts.style.cssText = "font-size:10px;color:var(--text-dim);margin-top:8px;text-align:right;";
      body.appendChild(ts);
    }
  }

  // Domain notes (blocking / unreachable) — shown above checks
  if (result?.domain_notes || result?.blocked_by) {
    const note = div("domain-note");
    const icon = result?.blocked_by ? "⚠️ " : "ℹ️ ";
    note.appendChild(document.createTextNode(
      icon + (result.domain_notes || `${result.blocked_by} WAF detected`)
    ));
    note.style.cssText =
      "font-size:11px;padding:6px 8px;border-radius:4px;margin-bottom:8px;" +
      "background:rgba(210,153,34,.12);border:1px solid rgba(210,153,34,.3);color:#d29922;line-height:1.5;";
    body.insertBefore(note, body.firstChild);
  }

  // Close burger, open info panel
  document.getElementById("burger-panel").classList.remove("visible");
  document.getElementById("btn-burger").classList.remove("active");
  panel.classList.add("visible");

  // Zoom to country polygon if one exists
  if (layer) {
    try {
      map.fitBounds(layer.getBounds(), { padding: [60, 60], maxZoom: 7 });
    } catch (_) {}
  }
}

// ── Burger panel ───────────────────────────────────────────────────────────────
function populateBurger(dataJson) {
  if (!dataJson) return;
  const stats = dataJson.stats || {};

  // Stats grid
  const grid = document.getElementById("stats-grid");
  grid.textContent = "";

  const cells = [
    { val: stats.total_countries ?? "—", lbl: "Countries" },
    { val: stats.scanned ?? "—",         lbl: "Scanned" },
    { val: stats.avg_score != null ? Math.round(stats.avg_score) : "—", lbl: "Avg score" },
    { val: stats.errors ?? "—",          lbl: "Errors" },
  ];
  for (const { val, lbl } of cells) {
    const cell = div("stat-cell");
    cell.appendChild(span("stat-val", String(val)));
    cell.appendChild(span("stat-lbl", lbl));
    grid.appendChild(cell);
  }

  // Grade distribution
  const gd      = stats.grade_distribution || {};
  const gradeEl = document.getElementById("grade-dist");
  gradeEl.textContent = "";
  for (const g of ["A", "B", "C", "F"]) {
    const wrap   = div("grade-badge");
    const letter = span(`grade-letter ${g}`, g);
    wrap.appendChild(letter);
    wrap.appendChild(document.createTextNode(` ${gd[g] ?? 0}`));
    gradeEl.appendChild(wrap);
  }

  // Rankings
  populateRankList("top10",    stats.top10    || []);
  populateRankList("bottom10", stats.bottom10 || []);

  // Stats note
  const noteEl = document.getElementById("stats-note");
  if (noteEl) {
    noteEl.textContent =
      "Both countries and disputed territories have been checked. " +
      "This is for statistics, not politics.";
  }
}

function populateRankList(listId, codes) {
  const ol = document.getElementById(listId);
  ol.textContent = "";
  let rank = 1;
  for (const iso2 of codes) {
    const entry  = countriesIndex[iso2] || {};
    const result = scanData[iso2];
    const score  = result?.score;
    const grade  = result?.grade;

    const li = el("li", "rank-item");

    li.appendChild(span("rank-num",  String(rank)));
    li.appendChild(span("rank-flag", entry.flag || ""));

    const nameWrap = span("rank-name", entry.name || iso2);
    nameWrap.appendChild(span("rank-iso", ` ${iso2}`));
    li.appendChild(nameWrap);

    if (score != null) {
      const chip = span("score-chip", `${grade} ${Math.round(score)}`);
      chip.style.background = scoreColor(score);
      li.appendChild(chip);
    }

    li.addEventListener("click", () => {
      // For countries without a polygon, layer will be null — showInfo handles that
      const item = polyLayers.find(p => p.iso2 === iso2);
      showInfo(iso2, item?.layer || null);
    });

    ol.appendChild(li);
    rank++;
  }
}

// ── Toolbar summary ────────────────────────────────────────────────────────────
function updateSummary(dataJson) {
  const el   = document.getElementById("status-summary");
  const total = Object.keys(countriesIndex).length;
  if (!dataJson) {
    el.textContent = `${total} countries · no scan data yet`;
    document.getElementById("status-scan-time").textContent = "";
    return;
  }
  const s  = dataJson.stats;
  const ts = (dataJson.generated || "").slice(0, 10);
  el.textContent =
    `${s.scanned}/${s.total_countries} scanned · avg ${Math.round(s.avg_score || 0)}/100 · ${ts}`;

  // Footer scan time
  const scanEl = document.getElementById("status-scan-time");
  if (dataJson.generated) {
    // Format ISO timestamp → "Last scan: 2026-04-15 14:32 UTC"
    const d = new Date(dataJson.generated);
    const pad = n => String(n).padStart(2, "0");
    const formatted =
      `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ` +
      `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
    scanEl.textContent = `Last scan: ${formatted}`;
  } else {
    scanEl.textContent = "";
  }
}

// ── Boot ───────────────────────────────────────────────────────────────────────
async function init() {
  setStatus("Loading …", "loading");
  try {
    const [dataJson] = await Promise.all([
      (async () => {
        await loadCountries();
        return loadScanData();
      })(),
      loadWorldGeoJSON(),
    ]);

    renderPolygons();
    updateSummary(dataJson);
    if (dataJson) populateBurger(dataJson);

  } catch (e) {
    setStatus(`Error: ${e.message}`, "error");
    console.error(e);
  }
}

// ── Event listeners ────────────────────────────────────────────────────────────
function toggleBurger() {
  const panel   = document.getElementById("burger-panel");
  const btn     = document.getElementById("btn-burger");
  const info    = document.getElementById("info-panel");
  const opening = !panel.classList.contains("visible");
  panel.classList.toggle("visible", opening);
  btn.classList.toggle("active",    opening);
  if (opening) info.classList.remove("visible");
}

document.getElementById("btn-burger").addEventListener("click", toggleBurger);
document.getElementById("burger-prompt").addEventListener("click", toggleBurger);

document.getElementById("burger-close").addEventListener("click", () => {
  document.getElementById("burger-panel").classList.remove("visible");
  document.getElementById("btn-burger").classList.remove("active");
});

document.getElementById("info-close").addEventListener("click", () => {
  document.getElementById("info-panel").classList.remove("visible");
  if (activeLayer) {
    const prev = polyLayers.find(i => i.layer === activeLayer);
    if (prev) {
      const s = scanData[prev.iso2]?.score ?? null;
      prev.layer.setStyle({ weight: 0.8, color: "#2a3040",
        fillOpacity: s != null ? 0.72 : 0.35 });
    }
    activeLayer = null;
  }
});

map.on("click", () => {
  document.getElementById("info-panel").classList.remove("visible");
  document.getElementById("burger-panel").classList.remove("visible");
  document.getElementById("btn-burger").classList.remove("active");
  if (activeLayer) {
    const prev = polyLayers.find(i => i.layer === activeLayer);
    if (prev) {
      const s = scanData[prev.iso2]?.score ?? null;
      prev.layer.setStyle({ weight: 0.8, color: "#2a3040",
        fillOpacity: s != null ? 0.72 : 0.35 });
    }
    activeLayer = null;
  }
});

init();
