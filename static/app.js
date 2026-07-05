/* fast-secrets — vanilla JS front-end (no build step). */
"use strict";

const LS = {
  get(k, d) { try { const v = localStorage.getItem("fs:" + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("fs:" + k, JSON.stringify(v)); } catch {} },
};

const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };

const state = {
  specs: [],          // generator metadata
  byId: {},
  current: null,      // selected generator id (single view)
  liveTimer: null,
};

/* ── boot ───────────────────────────────────────────── */
async function boot() {
  initTheme();
  initTabs();
  const res = await fetch("/api/generators");
  const data = await res.json();
  state.specs = data.generators;
  state.specs.forEach(s => (state.byId[s.id] = s));

  buildSidebar();
  buildDashboard();
  wireControls();
  initDiff();
  initShortcuts();

  const last = LS.get("lastGen");
  selectGenerator(state.byId[last] ? last : state.specs[0].id);

  const lastView = LS.get("lastView", "single");
  if (lastView !== "single") activateView(lastView);
}

/* ── theme ──────────────────────────────────────────── */
function initTheme() {
  // data-theme is already resolved by the inline <head> script (no FOUC).
  $("#theme-toggle").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    LS.set("theme", next);
  });
}

/* ── tabs / views ───────────────────────────────────── */
function initTabs() {
  const tabs = $("#tabs");
  tabs.addEventListener("click", e => {
    const btn = e.target.closest(".tab");
    if (btn) activateView(btn.dataset.view);
  });
  // Roving tablist keyboard nav (Arrow/Home/End), per the tablist ARIA pattern.
  tabs.addEventListener("keydown", e => {
    if (!e.target.closest(".tab")) return;
    const list = [...tabs.querySelectorAll(".tab")];
    const i = list.indexOf(e.target.closest(".tab"));
    let j = null;
    if (e.key === "ArrowRight") j = (i + 1) % list.length;
    else if (e.key === "ArrowLeft") j = (i - 1 + list.length) % list.length;
    else if (e.key === "Home") j = 0;
    else if (e.key === "End") j = list.length - 1;
    else return;
    e.preventDefault();
    activateView(list[j].dataset.view);
    list[j].focus();
  });
}

function activateView(view) {
  document.querySelectorAll(".tab").forEach(t => {
    const on = t.dataset.view === view;
    t.classList.toggle("is-active", on);
    t.setAttribute("aria-selected", on ? "true" : "false");
    t.tabIndex = on ? 0 : -1;
  });
  document.querySelectorAll(".view").forEach(v => v.classList.toggle("is-active", v.id === "view-" + view));
  LS.set("lastView", view);
}

function activeViewName() {
  const v = document.querySelector(".view.is-active");
  return v ? v.id.replace("view-", "") : "single";
}

/* ── sidebar ────────────────────────────────────────── */
function buildSidebar() {
  const list = $("#gen-list");
  list.innerHTML = "";
  for (const [cat, specs] of groupByCategory()) {
    const group = el("div", "gen-group");
    group.appendChild(el("div", "gen-group-label", cat));
    specs.forEach(s => {
      const btn = el("button", "gen-item");
      btn.type = "button";
      btn.dataset.id = s.id;
      btn.setAttribute("role", "option");
      btn.setAttribute("aria-selected", "false");
      btn.tabIndex = -1;
      btn.appendChild(el("span", "gi-label", s.label));
      btn.appendChild(el("span", "gi-cat", s.category));
      btn.addEventListener("click", () => selectGenerator(s.id));
      group.appendChild(btn);
    });
    list.appendChild(group);
  }
  const emptyEl = el("div", "gen-empty", "No generators match.");
  emptyEl.style.display = "none";
  list.appendChild(emptyEl);

  const filter = $("#gen-filter");
  filter.addEventListener("input", applyGenFilter);
  filter.addEventListener("keydown", onFilterKeydown);
  list.addEventListener("keydown", onGenListKeydown);
  applyGenFilter();
}

function visibleGenItems() {
  return [...document.querySelectorAll(".gen-item")].filter(i => i.style.display !== "none");
}

function applyGenFilter() {
  const q = $("#gen-filter").value.trim().toLowerCase();
  document.querySelectorAll(".gen-item").forEach(it => {
    const s = state.byId[it.dataset.id];
    const hit = !q || s.label.toLowerCase().includes(q) || s.id.includes(q) || s.description.toLowerCase().includes(q);
    it.style.display = hit ? "" : "none";
  });
  document.querySelectorAll(".gen-group").forEach(g => {
    const any = [...g.querySelectorAll(".gen-item")].some(i => i.style.display !== "none");
    g.style.display = any ? "" : "none";
  });
  const vis = visibleGenItems();
  $(".gen-empty").style.display = vis.length ? "none" : "";
  const total = state.specs.length;
  $("#gen-count").textContent = q ? `${vis.length} of ${total}` : `${total} generators`;
}

// ArrowDown into the list; Enter commits the first match.
function onFilterKeydown(e) {
  const vis = visibleGenItems();
  if (e.key === "ArrowDown" && vis.length) { e.preventDefault(); vis[0].focus(); }
  else if (e.key === "Enter" && vis.length) { e.preventDefault(); selectGenerator(vis[0].dataset.id); vis[0].focus(); }
}

// Roving listbox nav over the currently-visible items.
function onGenListKeydown(e) {
  const item = e.target.closest(".gen-item");
  if (!item) return;
  const vis = visibleGenItems();
  const i = vis.indexOf(item);
  if (i < 0) return;
  let next = null;
  if (e.key === "ArrowDown") next = vis[Math.min(vis.length - 1, i + 1)];
  else if (e.key === "ArrowUp") {
    if (i === 0) { e.preventDefault(); $("#gen-filter").focus(); return; }
    next = vis[i - 1];
  } else if (e.key === "Home") next = vis[0];
  else if (e.key === "End") next = vis[vis.length - 1];
  else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectGenerator(item.dataset.id); return; }
  else return;
  if (next) { e.preventDefault(); next.focus(); }
}

function groupByCategory() {
  const order = [];
  const map = new Map();
  state.specs.forEach(s => {
    if (!map.has(s.category)) { map.set(s.category, []); order.push(s.category); }
    map.get(s.category).push(s);
  });
  return order.map(c => [c, map.get(c)]);
}

/* ── generator selection + options form ─────────────── */
function selectGenerator(id) {
  state.current = id;
  LS.set("lastGen", id);
  const spec = state.byId[id];
  document.querySelectorAll(".gen-item").forEach(i => {
    const on = i.dataset.id === id;
    i.classList.toggle("is-active", on);
    i.setAttribute("aria-selected", on ? "true" : "false");
    i.tabIndex = on ? 0 : -1;
    if (on) i.setAttribute("aria-current", "true"); else i.removeAttribute("aria-current");
  });
  $("#gen-title").textContent = spec.label;
  $("#gen-desc").textContent = spec.description;

  renderOptions(spec);
  renderStrength(spec, readOptions());
  // Count only makes sense for random generators.
  $("#count-wrap").style.display = spec.random === false ? "none" : "";

  $("#output-count").textContent = "Output";
  if (spec.random === false) showOutputEmpty("Enter input above, then press Generate.");
  else generate();   // auto-generate so the panel is never empty
}

function setOutputCols(show) {
  const cols = $("#output-cols");
  if (cols) cols.hidden = !show;
}

function showOutputEmpty(msg) {
  const out = $("#output");
  out.innerHTML = "";
  setOutputCols(false);
  const box = el("div", "output-empty");
  box.appendChild(el("div", "glyph", "🔑"));
  box.appendChild(el("div", "msg", msg));
  box.appendChild(el("div", "hint", "Ctrl/Cmd + Enter also generates"));
  out.appendChild(box);
  $("#output-count").textContent = "Output";
}

function renderOptions(spec) {
  const form = $("#options-form");
  form.innerHTML = "";
  const saved = LS.get("opts:" + spec.id, {});
  // Group by type: full-width text inputs first, then sized inputs, then compact toggles.
  const grid = el("div", "opt-grid");
  const toggles = el("div", "opt-toggles");
  spec.options.forEach(opt => {
    const value = saved[opt.key] !== undefined ? saved[opt.key] : opt.default;
    const field = buildField(opt, value);
    if (opt.type === "text") form.appendChild(field);
    else if (opt.type === "bool") toggles.appendChild(field);
    else grid.appendChild(field);
  });
  if (grid.children.length) form.appendChild(grid);
  if (toggles.children.length) form.appendChild(toggles);
  updateConditionals();
}

function buildField(opt, value) {
  if (opt.type === "bool") {
    const label = el("label", "field check");
    const input = el("input");
    input.type = "checkbox";
    input.checked = !!value;
    input.dataset.key = opt.key;
    input.dataset.type = opt.type;
    label.appendChild(input);
    label.appendChild(el("span", null, opt.label));
    return label;
  }
  const label = el("label", "field");
  if (opt.type === "text") label.classList.add("full");
  label.appendChild(el("span", null, opt.label));
  let input;
  if (opt.type === "select") {
    input = el("select");
    opt.choices.forEach(c => {
      const o = el("option", null, c.label);
      o.value = String(c.value);
      if (String(c.value) === String(value)) o.selected = true;
      input.appendChild(o);
    });
  } else if (opt.type === "text") {
    input = el("textarea");
    input.value = value ?? "";
    input.placeholder = opt.placeholder || "Text input…";
  } else {
    input = el("input");
    input.type = opt.type === "int" ? "number" : "text";
    if (opt.type === "int") { if (opt.min != null) input.min = opt.min; if (opt.max != null) input.max = opt.max; }
    input.value = value ?? "";
    if (opt.placeholder) input.placeholder = opt.placeholder;
  }
  input.dataset.key = opt.key;
  input.dataset.type = opt.type;
  label.appendChild(input);
  return label;
}

function readOptions() {
  const out = {};
  $("#options-form").querySelectorAll("[data-key]").forEach(inp => {
    const key = inp.dataset.key, type = inp.dataset.type;
    if (type === "bool") out[key] = inp.checked;
    else if (type === "int") out[key] = inp.value === "" ? null : Number(inp.value);
    else if (type === "select") { const n = Number(inp.value); out[key] = inp.value !== "" && !Number.isNaN(n) && /^-?\d+$/.test(inp.value) ? n : inp.value; }
    else out[key] = inp.value;
  });
  return out;
}

/* custom_charset is only meaningful when charset === "custom" */
function updateConditionals() {
  const form = $("#options-form");
  const charset = form.querySelector('[data-key="charset"]');
  const custom = form.querySelector('[data-key="custom_charset"]');
  if (charset && custom) {
    const on = charset.value === "custom";
    custom.disabled = !on;
    custom.setAttribute("aria-disabled", String(!on));
    custom.title = on ? "" : "Set Charset to “Custom…” to edit";
    custom.closest(".field").classList.toggle("is-disabled", !on);
  }
}

/* ── strength / entropy meter ───────────────────────── */
/* Constants mirror generators.py — keep in sync if charsets change there. */
const ENT = { lower: 26, upper: 26, digits: 10, symbols: 25, wordlist: 1296 };
const AMBIG = { lower: 2, upper: 2, digits: 2, symbols: 0 };  // chars from "Il1O0o" per class
const PRESET_SIZE = { alphanumeric: 62, alpha: 52, lower: 26, upper: 26, numeric: 10, hex: 16, hex_upper: 16 };
const log2 = n => Math.log(n) / Math.LN2;
const clampNum = (v, lo, hi) => { const n = Math.floor(Number(v)); return Number.isFinite(n) ? Math.max(lo, Math.min(hi, n)) : lo; };

function entropyBits(spec, o) {
  switch (spec && spec.id) {
    case "password": {
      const ex = !!o.exclude_ambiguous;
      let pool = 0;
      if (o.lowercase) pool += ENT.lower - (ex ? AMBIG.lower : 0);
      if (o.uppercase) pool += ENT.upper - (ex ? AMBIG.upper : 0);
      if (o.digits) pool += ENT.digits - (ex ? AMBIG.digits : 0);
      if (o.symbols) pool += ENT.symbols - (ex ? AMBIG.symbols : 0);
      return pool <= 1 ? 0 : clampNum(o.length, 4, 256) * log2(pool);
    }
    case "passphrase":
      return clampNum(o.words, 2, 16) * log2(ENT.wordlist) + (o.add_number ? log2(10) : 0);
    case "pin":
      return clampNum(o.length, 3, 12) * log2(10);
    case "string": {
      let size;
      if (o.charset === "custom") size = new Set((o.custom_charset || "").split("")).size || 62;
      else size = PRESET_SIZE[o.charset] || 62;
      return size <= 1 ? 0 : clampNum(o.length, 1, 1024) * log2(size);
    }
    case "hex": case "urlsafe": case "base64":
      return clampNum(o.nbytes, 1, 512) * 8;
    case "apikey":
      return clampNum(o.nbytes, 8, 256) * 8;
    case "nanoid":
      return clampNum(o.size, 2, 256) * log2((o.alphabet || "").length || 64);
    case "ulid":
      return 80;                       // 80 random bits (timestamp not secret)
    default:
      return null;                     // uuid / hash / hmac — not meaningful
  }
}

function renderStrength(spec, opts) {
  const box = $("#strength");
  const bits = entropyBits(spec, opts);
  if (bits == null) { box.hidden = true; return; }
  box.hidden = false;
  const level = bits < 60 ? "weak" : bits < 90 ? "fair" : "strong";
  box.className = "strength " + level;
  $(".strength-fill", box).style.width = Math.max(4, Math.min(100, (bits / 128) * 100)) + "%";
  $(".strength-label", box).textContent = `≈ ${Math.round(bits)} bits · ${level}`;
}

/* ── controls / generation ──────────────────────────── */
function clampCount(v, max) { return Math.min(max, Math.max(1, Math.floor(Number(v) || 1))); }

function setBusy(btn, on, busyLabel) {
  if (on) {
    if (btn.dataset.busy) return false;
    btn.dataset.busy = "1";
    btn.dataset.label = btn.textContent;
    btn.disabled = true;
    btn.textContent = busyLabel;
    return true;
  }
  delete btn.dataset.busy;
  btn.disabled = false;
  if (btn.dataset.label != null) { btn.textContent = btn.dataset.label; delete btn.dataset.label; }
  return true;
}

function wireControls() {
  $("#generate").addEventListener("click", generate);
  $("#copy-all").addEventListener("click", copyAll);
  $("#download").addEventListener("click", download);
  $("#clear").addEventListener("click", () => showOutputEmpty("Cleared. Press Generate to create values."));

  const count = $("#count");
  count.value = clampCount(LS.get("count", 1), 1000);
  count.addEventListener("change", () => { const c = clampCount(count.value, 1000); count.value = c; LS.set("count", c); if ($("#live").checked) generate(); });

  const live = $("#live");
  live.checked = LS.get("live", false);
  live.addEventListener("change", () => { LS.set("live", live.checked); if (live.checked) generate(); });

  $("#options-form").addEventListener("input", () => {
    updateConditionals();
    const opts = readOptions();
    if (state.current) LS.set("opts:" + state.current, opts);
    renderStrength(state.byId[state.current], opts);
    if (live.checked) { clearTimeout(state.liveTimer); state.liveTimer = setTimeout(generate, 160); }
  });

  // Dashboard
  $("#dash-generate").addEventListener("click", generateDashboard);
  $("#dash-all").addEventListener("click", () => toggleAllDash(true));
  $("#dash-none").addEventListener("click", () => toggleAllDash(false));
  const dc = $("#dash-count");
  dc.value = clampCount(LS.get("dashCount", 1), 100);
  dc.addEventListener("change", () => { const c = clampCount(dc.value, 100); dc.value = c; LS.set("dashCount", c); });
}

async function generate() {
  const btn = $("#generate");
  if (btn.dataset.busy) return;
  const spec = state.byId[state.current];
  const count = spec.random === false ? 1 : clampCount($("#count").value, 1000);
  const body = { type: state.current, options: readOptions(), count };
  setBusy(btn, true, "Generating…");
  try {
    const res = await fetch("/api/generate", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) { renderError(data.detail || "Generation failed"); return; }
    renderOutput(data.values);
  } catch (e) { renderError(String(e)); }
  finally { setBusy(btn, false); }
}

/* Value byte length (UTF-8) for the metadata column. */
const byteLen = v => new TextEncoder().encode(v).length;
const bitsLevel = bits => (bits == null ? null : bits < 60 ? "weak" : bits < 90 ? "fair" : "strong");

function renderOutput(values) {
  const out = $("#output");
  out.innerHTML = "";
  const spec = state.byId[state.current];
  if (!values.length) {
    setOutputCols(false);
    out.appendChild(el("li", "empty", "No output."));
    $("#output-count").textContent = "";
    return;
  }
  const canReroll = !!spec && spec.random !== false;
  // Entropy is a property of the options, not the value — compute once per render.
  const bits = entropyBits(spec, readOptions());
  const meta = { bits, level: bitsLevel(bits) };
  setOutputCols(true);
  values.forEach((v, i) => out.appendChild(outRow(v, canReroll ? { reroll: rerollRow } : null, i, meta)));
  const n = values.length;
  $("#output-count").textContent =
    `${n} ${n === 1 ? "value" : "values"} · ${values[0].length} chars` +
    (bits != null ? ` · ≈${Math.round(bits)} bits` : "");
}

function renderError(msg) {
  const out = $("#output");
  out.innerHTML = "";
  setOutputCols(false);
  out.appendChild(el("li", "empty is-error", "⚠ " + msg));
  $("#output-count").textContent = "";
}

/* One cell holding the entropy badge, or an em-dash when entropy isn't meaningful. */
function bitsCell(bits, level) {
  if (bits == null) return el("span", "cell-bits empty-bits", "—");
  const c = el("span", "cell-bits");
  c.appendChild(el("span", "badge " + level, "≈" + Math.round(bits)));
  return c;
}

/* A table row: # · value (in <code>, so copy-all/download still find it) · chars · bytes · bits · actions. */
function outRow(value, opts, index, meta) {
  opts = opts || {};
  meta = meta || {};
  const row = el("li", "out-row");
  row.appendChild(el("span", "cell-idx", index != null ? String(index + 1) : ""));
  row.appendChild(el("code", "cell-val", value));
  row.appendChild(el("span", "cell-num", String(value.length)));
  row.appendChild(el("span", "cell-num", String(byteLen(value))));
  row.appendChild(bitsCell(meta.bits, meta.level));
  const actions = el("div", "row-actions");
  if (opts.reroll) {
    const rr = el("button", "reroll-btn", "↻");
    rr.type = "button";
    rr.title = "Regenerate this value";
    rr.setAttribute("aria-label", "Regenerate this value");
    rr.addEventListener("click", () => opts.reroll(row, index, meta));
    actions.appendChild(rr);
  }
  const btn = el("button", "copy-btn", "Copy");
  btn.type = "button";
  btn.setAttribute("aria-label", "Copy value");
  btn.addEventListener("click", () => copy(value, btn));
  actions.appendChild(btn);
  row.appendChild(actions);
  return row;
}

async function rerollRow(row, index, meta) {
  const spec = state.byId[state.current];
  if (!spec || spec.random === false) return;
  try {
    const res = await fetch("/api/generate", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: state.current, options: readOptions(), count: 1 }),
    });
    const data = await res.json();
    if (!res.ok || !data.values || !data.values.length) return;
    // Preserve the row's column position + entropy metadata on replacement.
    row.replaceWith(outRow(data.values[0], { reroll: rerollRow }, index, meta));
  } catch { /* ignore */ }
}

function currentValues() {
  return [...$("#output").querySelectorAll(".out-row code")].map(c => c.textContent);
}

function copyAll() {
  const vals = currentValues();
  if (!vals.length) { toast("Nothing to copy"); return; }
  copy(vals.join("\n"));
}

function csvCell(v) {
  return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
}

function download() {
  const vals = currentValues();
  if (!vals.length) { toast("Nothing to download"); return; }
  const fmt = $("#export-format").value;
  let content, ext, mime;
  if (fmt === "json") {
    content = JSON.stringify({ type: state.current, options: readOptions(), values: vals }, null, 2);
    ext = "json"; mime = "application/json";
  } else if (fmt === "csv") {
    content = "value\n" + vals.map(csvCell).join("\n") + "\n";
    ext = "csv"; mime = "text/csv";
  } else {
    content = vals.join("\n") + "\n";
    ext = "txt"; mime = "text/plain";
  }
  const blob = new Blob([content], { type: mime });
  const a = el("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${state.current}-secrets.${ext}`;
  a.click();
  URL.revokeObjectURL(a.href);
  toast("Downloaded " + a.download);
}

/* ── dashboard ──────────────────────────────────────── */
function buildDashboard() {
  const grid = $("#dash-grid");
  grid.innerHTML = "";
  const selected = new Set(LS.get("dashSelected", state.specs.map(s => s.id)));
  state.specs.forEach(spec => {
    const card = el("div", "dash-card");
    card.dataset.id = spec.id;
    card.dataset.state = "idle";
    // A <label> so clicking anywhere on the head toggles selection (no JS needed for that).
    const head = el("label", "dash-card-head");
    const cb = el("input");
    cb.type = "checkbox";
    cb.checked = selected.has(spec.id);
    cb.setAttribute("aria-label", "Include " + spec.label);
    cb.addEventListener("change", () => { card.classList.toggle("is-selected", cb.checked); persistDash(); });
    head.appendChild(cb);
    head.appendChild(el("span", "name", spec.label));
    head.appendChild(el("span", "badge badge-muted", spec.category));
    card.appendChild(head);
    const vals = el("div", "dash-values");
    vals.appendChild(el("div", "dash-empty", "Not generated"));
    card.appendChild(vals);
    card.classList.toggle("is-selected", cb.checked);
    grid.appendChild(card);
  });
  updateDashGenerateState();
  updateDashSelected();
}

function toggleAllDash(on) {
  $("#dash-grid").querySelectorAll(".dash-card").forEach(card => {
    card.querySelector('input[type="checkbox"]').checked = on;
    card.classList.toggle("is-selected", on);
  });
  persistDash();
}

function persistDash() {
  const ids = [...$("#dash-grid").querySelectorAll(".dash-card")]
    .filter(c => c.querySelector('input[type="checkbox"]').checked)
    .map(c => c.dataset.id);
  LS.set("dashSelected", ids);
  updateDashGenerateState();
  updateDashSelected();
}

function updateDashGenerateState() {
  const any = [...$("#dash-grid").querySelectorAll('input[type="checkbox"]')].some(c => c.checked);
  $("#dash-generate").disabled = !any;
}

function updateDashSelected() {
  const n = [...$("#dash-grid").querySelectorAll('input[type="checkbox"]')].filter(c => c.checked).length;
  const badge = $("#dash-selected");
  badge.textContent = `${n} of ${state.specs.length} selected`;
  badge.classList.toggle("badge-chg", n > 0);
  badge.classList.toggle("badge-muted", n === 0);
}

/* Default option values for a spec — mirrors what the batch endpoint applies for options:{}. */
function defaultsFor(spec) {
  const o = {};
  (spec.options || []).forEach(opt => { o[opt.key] = opt.default; });
  return o;
}

function bitsBadge(bits, level) {
  return bits == null ? el("span", "dash-empty", "—") : el("span", "badge " + level, "≈" + Math.round(bits));
}

function dashRow(value, bits, level) {
  const row = el("div", "dash-row");
  row.appendChild(el("code", null, value));
  row.appendChild(bitsBadge(bits, level));
  const btn = el("button", "copy-btn", "Copy");
  btn.type = "button";
  btn.setAttribute("aria-label", "Copy value");
  btn.addEventListener("click", () => copy(value, btn));
  row.appendChild(btn);
  return row;
}

async function generateDashboard() {
  const btn = $("#dash-generate");
  if (btn.dataset.busy) return;
  const count = clampCount($("#dash-count").value, 100);
  const cards = [...$("#dash-grid").querySelectorAll(".dash-card")].filter(c => c.querySelector('input[type="checkbox"]').checked);
  if (!cards.length) { toast("Select at least one generator"); return; }
  const reqs = cards.map(c => ({ type: c.dataset.id, options: {}, count: state.byId[c.dataset.id].random === false ? 1 : count }));
  setBusy(btn, true, "Generating…");
  try {
    const res = await fetch("/api/generate/batch", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(reqs),
    });
    const data = await res.json();
    const byType = {};
    data.results.forEach(r => (byType[r.type] = r));
    cards.forEach(card => {
      const spec = state.byId[card.dataset.id];
      const r = byType[card.dataset.id];
      const box = card.querySelector(".dash-values");
      box.innerHTML = "";
      if (!r || r.error) {
        card.dataset.state = "error";
        box.appendChild(el("div", "dash-empty", "⚠ " + (r ? r.error : "no result")));
        return;
      }
      card.dataset.state = "done";
      // Batch generated with defaults (options:{}), so estimate entropy from those same defaults.
      const bits = entropyBits(spec, defaultsFor(spec));
      const level = bitsLevel(bits);
      r.values.forEach(v => box.appendChild(dashRow(v, bits, level)));
    });
  } catch (e) { toast("Generation failed"); }
  finally { setBusy(btn, false); }
}

/* ── text diff ──────────────────────────────────────── */
const diffState = { payload: null, mode: "inline", timer: null };

function initDiff() {
  const a = $("#diff-a"), b = $("#diff-b");
  a.value = LS.get("diffA", "");
  b.value = LS.get("diffB", "");
  $("#diff-ws").checked = LS.get("diffWs", false);
  $("#diff-case").checked = LS.get("diffCase", false);
  $("#diff-gran").value = LS.get("diffGran", "word");
  $("#diff-live").checked = LS.get("diffLive", false);
  diffState.mode = LS.get("diffMode", "inline");
  syncModeButtons();

  $("#diff-run").addEventListener("click", runDiff);
  $("#diff-clear").addEventListener("click", () => { a.value = ""; b.value = ""; persistDiff(); clearDiff(); });
  $("#diff-swap").addEventListener("click", () => { const t = a.value; a.value = b.value; b.value = t; persistDiff(); updateDiffButtons(); if ($("#diff-live").checked) runDiff(); });
  $("#diff-copy").addEventListener("click", () => {
    if (diffState.payload && diffState.payload.unified) copy(diffState.payload.unified);
  });

  // Mode toggle re-renders the cached payload — never re-fetches.
  $("#diff-mode").addEventListener("click", e => {
    const seg = e.target.closest(".seg");
    if (!seg) return;
    diffState.mode = seg.dataset.mode;
    LS.set("diffMode", diffState.mode);
    syncModeButtons();
    if (diffState.payload) renderDiff();
  });

  [a, b].forEach(t => t.addEventListener("input", onDiffInput));
  ["diff-ws", "diff-case", "diff-gran"].forEach(id =>
    $("#" + id).addEventListener("change", () => { persistDiff(); if ($("#diff-live").checked) runDiff(); }));
  $("#diff-live").addEventListener("change", () => { LS.set("diffLive", $("#diff-live").checked); if ($("#diff-live").checked) runDiff(); });

  window.addEventListener("resize", () => { if (diffState.payload) renderDiff(); });
  updateDiffButtons();
}

// Enable Swap/Clear only with content, Copy-unified only with a computed diff.
function updateDiffButtons() {
  const hasText = !!($("#diff-a").value || $("#diff-b").value);
  $("#diff-swap").disabled = !hasText;
  $("#diff-clear").disabled = !hasText;
  $("#diff-copy").disabled = !(diffState.payload && diffState.payload.unified);
}

function onDiffInput() {
  persistDiff();
  updateDiffButtons();
  if ($("#diff-live").checked) { clearTimeout(diffState.timer); diffState.timer = setTimeout(runDiff, 160); }
}

function persistDiff() {
  LS.set("diffA", $("#diff-a").value);
  LS.set("diffB", $("#diff-b").value);
  LS.set("diffWs", $("#diff-ws").checked);
  LS.set("diffCase", $("#diff-case").checked);
  LS.set("diffGran", $("#diff-gran").value);
}

async function runDiff() {
  const btn = $("#diff-run");
  if (btn.dataset.busy) return;
  const body = {
    text1: $("#diff-a").value, text2: $("#diff-b").value,
    ignore_whitespace: $("#diff-ws").checked, ignore_case: $("#diff-case").checked,
    granularity: $("#diff-gran").value,
  };
  setBusy(btn, true, "Comparing…");
  try {
    const res = await fetch("/api/diff", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await res.json();
    if (!res.ok) { diffError(data.detail || "Diff failed"); return; }
    diffState.payload = data;
    renderDiff();
  } catch (e) { diffError(String(e)); }
  finally { setBusy(btn, false); updateDiffButtons(); }
}

function renderDiff() {
  const p = diffState.payload, box = $("#diff-result");
  box.innerHTML = "";
  renderSummary(p ? p.stats : null);
  if (!p) return;
  if (p.stats.identical) {
    const msg = (!$("#diff-a").value && !$("#diff-b").value) ? "Enter text in both panes to compare." : "No differences.";
    box.appendChild(el("div", "diff-empty", msg));
    return;
  }
  // Side-by-side degrades to inline on narrow screens.
  const narrow = window.matchMedia("(max-width: 760px)").matches;
  const mode = narrow ? "inline" : diffState.mode;
  (mode === "split" ? buildSplit : buildInline)(box, p.rows);
}

function buildSplit(box, rows) {
  const grid = el("div", "diff-grid split");
  rows.forEach(r => {
    const lcls = sideClass(r, "left"), rcls = sideClass(r, "right");
    grid.appendChild(gutterEl("left " + lcls, r.left ? r.left.num : null));
    grid.appendChild(cellEl("left " + lcls, r.left));
    grid.appendChild(gutterEl("right " + rcls, r.right ? r.right.num : null));
    grid.appendChild(cellEl("right " + rcls, r.right));
  });
  box.appendChild(grid);
}

function buildInline(box, rows) {
  const grid = el("div", "diff-grid inline");
  rows.forEach(r => {
    if (r.type === "equal") inlineLine(grid, " ", r.left.num, "", r.left);
    else if (r.type === "add") inlineLine(grid, "+", r.right.num, "add", r.right);
    else if (r.type === "remove") inlineLine(grid, "-", r.left.num, "remove", r.left);
    else { inlineLine(grid, "-", r.left.num, "remove", r.left); inlineLine(grid, "+", r.right.num, "add", r.right); }
  });
  box.appendChild(grid);
}

function inlineLine(grid, sign, num, cls, side) {
  const g = el("div", "gutter " + cls);
  g.textContent = sign + " " + (num != null ? num : "");
  grid.appendChild(g);
  grid.appendChild(cellEl(cls, side));
}

function gutterEl(cls, num) {
  return el("div", "gutter " + cls, num != null ? String(num) : "");
}

function cellEl(cls, side) {
  const cell = el("div", "cell " + cls);
  if (!side) { cell.classList.add("filler"); return cell; }
  (side.segs || []).forEach(s => cell.appendChild(el("span", s.hl ? "hl" : null, s.text)));
  return cell;
}

function sideClass(r, which) {
  if (r.type === "equal") return "equal";
  if (r.type === "change") return "change";
  if (r.type === "remove") return which === "left" ? "remove" : "";
  if (r.type === "add") return which === "right" ? "add" : "";
  return "";
}

function renderSummary(stats) {
  const box = $("#diff-summary");
  box.innerHTML = "";
  if (!stats) return;
  const chip = (cls, txt) => box.appendChild(el("span", "badge " + cls, txt));
  chip("badge-add", "+" + stats.added + " added");
  chip("badge-del", "−" + stats.removed + " removed");
  chip("badge-chg", stats.changed + " changed");
  chip("badge-muted", stats.similarity + "% similar");
}

function diffError(msg) {
  $("#diff-summary").innerHTML = "";
  const box = $("#diff-result");
  box.innerHTML = "";
  box.appendChild(el("div", "diff-empty is-error", "⚠ " + msg));
}

function clearDiff() {
  diffState.payload = null;
  $("#diff-result").innerHTML = "";
  $("#diff-summary").innerHTML = "";
  updateDiffButtons();
}

function syncModeButtons() {
  document.querySelectorAll("#diff-mode .seg").forEach(s => s.classList.toggle("is-active", s.dataset.mode === diffState.mode));
}

/* ── keyboard shortcuts ─────────────────────────────── */
function initShortcuts() {
  document.addEventListener("keydown", e => {
    const tag = (e.target.tagName || "").toLowerCase();
    const typing = tag === "input" || tag === "textarea" || tag === "select";
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      const v = activeViewName();
      if (v === "dashboard") generateDashboard();
      else if (v === "diff") runDiff();
      else generate();
      return;
    }
    if (e.key === "/" && !typing && !e.metaKey && !e.ctrlKey && !e.altKey && activeViewName() === "single") {
      e.preventDefault();
      $("#gen-filter").focus();
    }
  });
  $("#gen-filter").addEventListener("keydown", e => {
    if (e.key === "Escape") { e.target.value = ""; e.target.dispatchEvent(new Event("input", { bubbles: true })); e.target.blur(); }
  });
}

/* ── clipboard + toast ──────────────────────────────── */
async function copy(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = el("textarea"); ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); ta.remove();
  }
  if (btn) { btn.classList.add("copied"); btn.textContent = "Copied"; setTimeout(() => { btn.classList.remove("copied"); btn.textContent = "Copy"; }, 1100); }
  else toast("Copied to clipboard");
}

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 1400);
}

boot();
