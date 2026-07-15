import { LOCAL_BY_ID, detectInput, entropyBitsFor, mergeSpecs, runLocal } from "./local-tools.js";
import { compareText } from "./local-diff.js";
import { renderQr } from "./qr-render.js";

"use strict";

const LS = {
  get(key, fallback) {
    try { const value = localStorage.getItem(`fs:${key}`); return value == null ? fallback : JSON.parse(value); }
    catch (_) { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem(`fs:${key}`, JSON.stringify(value)); } catch (_) { /* preferences are optional */ }
  },
};
const $ = (selector, root = document) => root.querySelector(selector);
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
};
const state = { specs: [], byId: {}, current: null, liveTimer: null, metadataFallback: false, pendingInput: null, selectionToken: 0, runToken: 0 };
const PASSWORD_RULE_KEYS = new Set(["length", "lowercase", "uppercase", "digits", "symbols", "min_lowercase", "min_uppercase", "min_digits", "min_symbols", "custom_symbols", "required_chars", "excluded_chars", "exclude_ambiguous"]);

async function boot() {
  initTheme();
  initTabs();
  wireControls();
  initDiff();
  initShortcuts();
  await loadMetadata();
  buildSidebar();
  buildDashboard();
  const last = LS.get("lastTool", "password");
  selectTool(state.byId[last] ? last : state.specs[0].id);
  activateView(LS.get("lastView", "single"));
  registerServiceWorker();
  if (new URLSearchParams(location.search).get("selftest") === "1") runBrowserSelfTests();
}

async function loadMetadata() {
  let remote = [];
  try {
    const response = await fetch("/api/tools", { cache: "no-store", headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`metadata returned ${response.status}`);
    remote = await response.json();
  } catch (_) {
    state.metadataFallback = true;
  }
  state.specs = mergeSpecs(remote);
  state.byId = Object.fromEntries(state.specs.map(spec => [spec.id, spec]));
}

function initTheme() {
  $("#theme-toggle").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    LS.set("theme", next);
    const meta = $('meta[name="theme-color"]');
    if (meta) meta.content = next === "dark" ? "#09090b" : "#ffffff";
  });
}

function initTabs() {
  const tabs = $("#tabs");
  tabs.addEventListener("click", event => {
    const button = event.target.closest(".tab");
    if (button) activateView(button.dataset.view);
  });
  tabs.addEventListener("keydown", event => {
    const current = event.target.closest(".tab");
    if (!current) return;
    const buttons = [...tabs.querySelectorAll(".tab")]; const index = buttons.indexOf(current); let next;
    if (event.key === "ArrowRight") next = (index + 1) % buttons.length;
    else if (event.key === "ArrowLeft") next = (index - 1 + buttons.length) % buttons.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = buttons.length - 1;
    else return;
    event.preventDefault(); activateView(buttons[next].dataset.view); buttons[next].focus();
  });
}

function activateView(view) {
  if (!document.querySelector(`.tab[data-view="${view}"]`)) view = "single";
  document.querySelectorAll(".tab").forEach(tab => {
    const active = tab.dataset.view === view;
    tab.classList.toggle("is-active", active); tab.setAttribute("aria-selected", String(active)); tab.tabIndex = active ? 0 : -1;
  });
  document.querySelectorAll(".view").forEach(panel => panel.classList.toggle("is-active", panel.id === `view-${view}`));
  LS.set("lastView", view);
}
function activeViewName() {
  const active = document.querySelector(".view.is-active");
  return active ? active.id.replace("view-", "") : "single";
}

function favoriteIds() { return new Set(LS.get("favorites", [])); }
function groupedSpecs() {
  const groups = new Map(); const favorites = favoriteIds();
  const add = (category, spec) => { if (!groups.has(category)) groups.set(category, []); groups.get(category).push(spec); };
  state.specs.filter(spec => favorites.has(spec.id)).forEach(spec => add("Favorites", spec));
  state.specs.forEach(spec => add(spec.category || "Other", spec));
  return [...groups.entries()];
}
function buildSidebar() {
  const list = $("#gen-list"); list.replaceChildren();
  for (const [category, specs] of groupedSpecs()) {
    const group = el("div", "gen-group"); group.dataset.category = category;
    group.appendChild(el("div", "gen-group-label", category));
    for (const spec of specs) {
      const button = el("button", "gen-item"); button.type = "button"; button.dataset.id = spec.id;
      button.setAttribute("role", "option"); button.setAttribute("aria-selected", "false"); button.tabIndex = -1;
      button.appendChild(el("span", "gi-label", spec.label));
      button.appendChild(el("span", "gi-mode", "local"));
      button.addEventListener("click", () => selectTool(spec.id)); group.appendChild(button);
    }
    list.appendChild(group);
  }
  const empty = el("div", "gen-empty", "No tools match."); empty.hidden = true; list.appendChild(empty);
  $("#gen-filter").oninput = applyFilter;
  $("#gen-filter").onkeydown = filterKeydown;
  list.onkeydown = listKeydown;
  applyFilter();
}
function visibleItems() { return [...document.querySelectorAll(".gen-item")].filter(item => !item.hidden); }
function applyFilter() {
  const query = $("#gen-filter").value.trim().toLowerCase();
  document.querySelectorAll(".gen-item").forEach(item => {
    const spec = state.byId[item.dataset.id];
    item.hidden = !!query && !`${spec.label} ${spec.id} ${spec.category} ${spec.description}`.toLowerCase().includes(query);
  });
  document.querySelectorAll(".gen-group").forEach(group => { group.hidden = ![...group.querySelectorAll(".gen-item")].some(item => !item.hidden); });
  const visible = visibleItems(); $(".gen-empty").hidden = visible.length > 0;
  $("#gen-count").textContent = query ? `${new Set(visible.map(item => item.dataset.id)).size} of ${state.specs.length}` : `${state.specs.length} local tools`;
}
function filterKeydown(event) {
  const items = visibleItems();
  if (event.key === "ArrowDown" && items.length) { event.preventDefault(); items[0].focus(); }
  else if (event.key === "Enter" && items.length) { event.preventDefault(); selectTool(items[0].dataset.id); items[0].focus(); }
  else if (event.key === "Escape") { event.target.value = ""; applyFilter(); event.target.blur(); }
}
function listKeydown(event) {
  const item = event.target.closest(".gen-item"); if (!item) return;
  const items = visibleItems(); const index = items.indexOf(item); let next;
  if (event.key === "ArrowDown") next = items[Math.min(items.length - 1, index + 1)];
  else if (event.key === "ArrowUp" && index === 0) { event.preventDefault(); $("#gen-filter").focus(); return; }
  else if (event.key === "ArrowUp") next = items[index - 1];
  else if (event.key === "Home") next = items[0];
  else if (event.key === "End") next = items[items.length - 1];
  else if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectTool(item.dataset.id); return; }
  else return;
  event.preventDefault(); if (next) next.focus();
}

function fieldsFor(spec) { return [...(spec.inputs || []), ...(spec.options || [])]; }
function savedOptions(id) { return LS.get(`safeOpts:${id}`, {}); }
function canPersistField(field) { return field.persist !== false && !field.sensitive && ["bool", "int", "select"].includes(field.type); }
function defaultsFor(spec) { return Object.fromEntries(fieldsFor(spec).map(field => [field.key, field.default])); }
function selectTool(id, incoming = null) {
  const spec = state.byId[id]; if (!spec) return;
  state.selectionToken += 1; state.current = id; LS.set("lastTool", id); renderVisual(null);
  const runButton = $("#generate"); if (runButton.dataset.busy) setBusy(runButton, false);
  document.querySelectorAll(".gen-item").forEach(item => {
    const active = item.dataset.id === id;
    item.classList.toggle("is-active", active); item.setAttribute("aria-selected", String(active)); item.tabIndex = active ? 0 : -1;
    if (active) item.setAttribute("aria-current", "true"); else item.removeAttribute("aria-current");
  });
  $("#gen-title").textContent = spec.label; $("#gen-desc").textContent = spec.description;
  renderNotices([]); renderOptions(spec); updateFavoriteButton(); renderPresets();
  if (incoming != null) populateIncoming(spec, incoming);
  $("#count-wrap").hidden = !spec.random; $("#count").max = Math.min(1000, spec.max_count || 1000);
  renderStrength(spec, readOptions()); clearOutput(spec.random ? "Creating values locally…" : "Enter input above, then run the tool.");
  if (spec.random) generate();
}
function populateIncoming(spec, incoming) {
  const first = fieldsFor(spec).find(field => field.persist === false || ["text", "string", "password"].includes(field.type));
  const input = first && $("#options-form").querySelector(`[data-key="${CSS.escape(first.key)}"]`);
  if (input) { input.value = incoming; input.dispatchEvent(new Event("input", { bubbles: true })); input.focus(); }
}
function updateFavoriteButton() {
  const active = favoriteIds().has(state.current); const button = $("#favorite");
  button.textContent = active ? "★" : "☆"; button.setAttribute("aria-pressed", String(active));
  button.setAttribute("aria-label", active ? "Remove tool from favorites" : "Add tool to favorites");
}
function toggleFavorite() {
  const favorites = favoriteIds();
  if (favorites.has(state.current)) favorites.delete(state.current); else favorites.add(state.current);
  LS.set("favorites", [...favorites]); buildSidebar(); updateFavoriteButton();
  document.querySelectorAll(`.gen-item[data-id="${CSS.escape(state.current)}"]`).forEach(item => { item.classList.add("is-active"); item.setAttribute("aria-selected", "true"); });
}

function renderOptions(spec) {
  const form = $("#options-form"); form.replaceChildren(); const saved = savedOptions(spec.id);
  const inputGroup = el("div", "input-stack"); const optionGrid = el("div", "opt-grid"); const toggles = el("div", "opt-toggles");
  for (const field of fieldsFor(spec)) {
    const value = canPersistField(field) && Object.prototype.hasOwnProperty.call(saved, field.key) ? saved[field.key] : field.default;
    const node = buildField(field, value); node.dataset.fieldKey = field.key;
    if ((spec.inputs || []).some(item => item.key === field.key) || ["text", "file", "password"].includes(field.type)) inputGroup.appendChild(node);
    else if (field.type === "bool") toggles.appendChild(node);
    else optionGrid.appendChild(node);
  }
  if (inputGroup.children.length) form.appendChild(inputGroup);
  if (optionGrid.children.length) form.appendChild(optionGrid);
  if (toggles.children.length) form.appendChild(toggles);
  updateConditionals(); updateSuggestions();
}
function buildField(field, value) {
  if (field.type === "bool") {
    const label = el("label", "field check"); const input = el("input"); input.type = "checkbox"; input.checked = !!value;
    bindField(input, field); label.append(input, el("span", null, field.label)); return label;
  }
  const label = el("label", `field${["text", "file", "password"].includes(field.type) ? " full" : ""}`);
  const heading = el("span", "field-heading"); heading.appendChild(el("span", null, field.label));
  if (field.sensitive) heading.appendChild(el("small", "private-note", "Never stored"));
  label.appendChild(heading);
  let input;
  if (field.type === "select") {
    input = el("select");
    for (const choice of field.choices || []) {
      const option = el("option", null, choice.label); option.value = String(choice.value);
      if (String(choice.value) === String(value)) option.selected = true; input.appendChild(option);
    }
  } else if (field.type === "text" && !field.sensitive) {
    input = el("textarea"); input.value = value ?? "";
  } else if (field.type === "file") {
    input = el("input"); input.type = "file";
  } else {
    input = el("input");
    input.type = field.type === "int" ? "number" : field.type === "password" || field.sensitive ? "password" : "text";
    if (field.type === "int") { if (field.min != null) input.min = field.min; if (field.max != null) input.max = field.max; }
    input.value = value ?? "";
  }
  if (field.placeholder) input.placeholder = field.placeholder;
  if (field.max_length) input.maxLength = field.max_length;
  if (field.required) input.required = true;
  if (field.autocomplete) input.autocomplete = field.autocomplete;
  bindField(input, field);
  if (field.sensitive && input.type === "password") {
    const wrap = el("div", "secret-field"); wrap.appendChild(input);
    const reveal = el("button", "secret-action", "Reveal"); reveal.type = "button"; reveal.setAttribute("aria-pressed", "false");
    reveal.addEventListener("click", () => {
      const showing = input.type === "text"; input.type = showing ? "password" : "text";
      reveal.textContent = showing ? "Reveal" : "Hide"; reveal.setAttribute("aria-pressed", String(!showing));
    });
    const clear = el("button", "secret-action", "Clear"); clear.type = "button";
    clear.addEventListener("click", () => { input.value = ""; input.dispatchEvent(new Event("input", { bubbles: true })); input.focus(); });
    wrap.append(reveal, clear); label.appendChild(wrap);
  } else label.appendChild(input);
  return label;
}
function bindField(input, field) { input.dataset.key = field.key; input.dataset.type = field.type; input.dataset.persist = String(canPersistField(field)); input.dataset.sensitive = String(!!field.sensitive); }
function readOptions(root = $("#options-form")) {
  const result = {};
  root.querySelectorAll("[data-key]").forEach(input => {
    if (input.dataset.type === "bool") result[input.dataset.key] = input.checked;
    else if (input.dataset.type === "int") result[input.dataset.key] = input.value === "" ? null : Number(input.value);
    else if (input.dataset.type === "select") {
      const number = Number(input.value); result[input.dataset.key] = /^-?\d+(\.\d+)?$/.test(input.value) && Number.isFinite(number) ? number : input.value;
    } else if (input.dataset.type === "file") result[input.dataset.key] = input.files[0] || null;
    else result[input.dataset.key] = input.value;
  });
  return result;
}
function persistSafeOptions() {
  const safe = {};
  $("#options-form").querySelectorAll('[data-persist="true"]').forEach(input => {
    safe[input.dataset.key] = input.dataset.type === "bool" ? input.checked : input.dataset.type === "int" ? Number(input.value) : input.value;
  });
  LS.set(`safeOpts:${state.current}`, safe);
}
function updateConditionals() {
  const form = $("#options-form"); const charset = form.querySelector('[data-key="charset"]'); const custom = form.querySelector('[data-key="custom_charset"]');
  if (charset && custom) { const active = charset.value === "custom"; custom.disabled = !active; custom.setAttribute("aria-disabled", String(!active)); custom.closest(".field").classList.toggle("is-disabled", !active); }
  const mode = form.querySelector('[data-key="mode"]');
  if (state.current === "jwt_debugger" && mode) {
    ["token", "header", "payload", "expected_issuer", "expected_audience"].forEach(key => {
      const field = form.querySelector(`[data-field-key="${key}"]`); if (!field) return;
      field.hidden = mode.value === "sign" ? ["token", "expected_issuer", "expected_audience"].includes(key) : ["header", "payload"].includes(key);
    });
  }
}
function updateSuggestions() {
  const box = $("#smart-suggestions"); box.replaceChildren();
  const textInput = [...$("#options-form").querySelectorAll("textarea, input[type=text], input[type=password]")].find(input => input.value.trim().length >= 8);
  const suggestions = textInput ? detectInput(textInput.value).filter(item => item.id !== state.current && state.byId[item.id]) : [];
  box.hidden = suggestions.length === 0;
  if (!suggestions.length) return;
  box.appendChild(el("span", "muted", "Looks like:"));
  for (const suggestion of suggestions) {
    const button = el("button", "suggestion", suggestion.label); button.type = "button";
    button.addEventListener("click", () => selectTool(suggestion.id, textInput.value)); box.appendChild(button);
  }
}

function renderPresets() {
  const bar = $("#preset-bar"); const supported = state.current === "password" || state.current === "password_policy";
  bar.hidden = !supported; if (!supported) return;
  const presets = LS.get("passwordPresets", {}); const select = $("#preset-select"); select.replaceChildren(new Option("Current settings", ""));
  for (const name of Object.keys(presets).sort()) select.appendChild(new Option(name, name));
  $("#preset-delete").disabled = true;
}
function savePreset() {
  if (!(state.current === "password" || state.current === "password_policy")) return;
  const name = prompt("Preset name"); if (!name || !name.trim()) return;
  const raw = readOptions();
  const persistable = new Set(fieldsFor(state.byId[state.current]).filter(canPersistField).map(field => field.key));
  const values = Object.fromEntries(Object.entries(raw).filter(([key]) => PASSWORD_RULE_KEYS.has(key) && persistable.has(key)));
  const presets = LS.get("passwordPresets", {}); presets[name.trim().slice(0, 60)] = values; LS.set("passwordPresets", presets); renderPresets(); $("#preset-select").value = name.trim().slice(0, 60); $("#preset-delete").disabled = false; toast("Rules preset saved locally");
}
function applyPreset() {
  const name = $("#preset-select").value; $("#preset-delete").disabled = !name; if (!name) return;
  const values = LS.get("passwordPresets", {})[name]; if (!values) return;
  for (const [key, value] of Object.entries(values)) {
    const input = $("#options-form").querySelector(`[data-key="${CSS.escape(key)}"]`); if (!input) continue;
    if (input.dataset.type === "bool") input.checked = !!value; else input.value = value;
  }
  $("#options-form").dispatchEvent(new Event("input", { bubbles: true }));
}
function deletePreset() {
  const name = $("#preset-select").value; if (!name) return;
  const presets = LS.get("passwordPresets", {}); delete presets[name]; LS.set("passwordPresets", presets); renderPresets(); toast("Preset deleted");
}

function renderStrength(spec, options) {
  const box = $("#strength"); const bits = entropyBitsFor(spec && spec.id, options);
  if (bits == null) { box.hidden = true; return; }
  const level = bits < 60 ? "weak" : bits < 90 ? "fair" : "strong";
  box.hidden = false; box.className = `strength ${level}`; $(".strength-fill", box).dataset.level = level;
  $(".strength-label", box).textContent = `≈ ${Math.round(bits)} bits · ${level}`;
}
function renderNotices(warnings) {
  const box = $("#tool-notices"); box.replaceChildren();
  const local = el("span", "notice local-notice", "● Browser-local · no input sent"); box.appendChild(local);
  if (state.metadataFallback) box.appendChild(el("span", "notice warning-notice", "Offline metadata fallback"));
  for (const warning of warnings || []) box.appendChild(el("span", "notice warning-notice", `⚠ ${warning}`));
}

function wireControls() {
  $("#favorite").addEventListener("click", toggleFavorite);
  $("#generate").addEventListener("click", generate);
  $("#copy-all").addEventListener("click", copyAll);
  $("#download").addEventListener("click", downloadOutput);
  $("#clear").addEventListener("click", clearCurrentTool);
  $("#preset-save").addEventListener("click", savePreset);
  $("#preset-select").addEventListener("change", applyPreset);
  $("#preset-delete").addEventListener("click", deletePreset);
  const count = $("#count"); count.value = clampCount(LS.get("count", 1), 1000);
  count.addEventListener("change", () => { count.value = clampCount(count.value, Number(count.max) || 1000); LS.set("count", Number(count.value)); if ($("#live").checked) generate(); });
  const live = $("#live"); live.checked = LS.get("live", false);
  live.addEventListener("change", () => { LS.set("live", live.checked); if (live.checked) generate(); });
  $("#options-form").addEventListener("input", () => {
    updateConditionals(); persistSafeOptions(); updateSuggestions(); renderStrength(state.byId[state.current], readOptions());
    if (live.checked) { clearTimeout(state.liveTimer); state.liveTimer = setTimeout(generate, 180); }
  });
  $("#dash-generate").addEventListener("click", generateDashboard);
  $("#dash-all").addEventListener("click", () => toggleAllDashboard(true));
  $("#dash-none").addEventListener("click", () => toggleAllDashboard(false));
  const dashCount = $("#dash-count"); dashCount.value = clampCount(LS.get("dashCount", 1), 100);
  dashCount.addEventListener("change", () => { dashCount.value = clampCount(dashCount.value, 100); LS.set("dashCount", Number(dashCount.value)); });
}
function clampCount(value, max) { return Math.max(1, Math.min(max, Math.floor(Number(value) || 1))); }
function setBusy(button, busy, label) {
  if (busy) { if (button.dataset.busy) return false; button.dataset.busy = "true"; button.dataset.label = button.textContent; button.disabled = true; button.textContent = label; }
  else { delete button.dataset.busy; button.disabled = false; button.textContent = button.dataset.label || button.textContent; delete button.dataset.label; }
  return true;
}
async function generate() {
  const button = $("#generate"); if (!setBusy(button, true, state.byId[state.current].random ? "Generating…" : "Running…")) return;
  const toolId = state.current; const selectionToken = state.selectionToken; const runToken = ++state.runToken;
  const spec = state.byId[toolId]; const count = spec.random ? clampCount($("#count").value, spec.max_count || 1000) : 1;
  renderVisual(null);
  try {
    const result = await runLocal(spec.id, readOptions(), count);
    if (selectionToken !== state.selectionToken || runToken !== state.runToken || toolId !== state.current) return;
    renderOutput(result.values); renderNotices(result.warnings); renderVisual(result.meta);
  } catch (error) {
    if (selectionToken === state.selectionToken && runToken === state.runToken && toolId === state.current) renderError(error.message || String(error));
  } finally {
    if (selectionToken === state.selectionToken && runToken === state.runToken && toolId === state.current) setBusy(button, false);
  }
}
function clearCurrentTool() {
  state.selectionToken += 1; state.runToken += 1;
  const runButton = $("#generate"); if (runButton.dataset.busy) setBusy(runButton, false);
  $("#options-form").querySelectorAll('[data-persist="false"], [data-sensitive="true"]').forEach(input => {
    if (input.type === "file") input.value = ""; else if (input.dataset.type === "bool") input.checked = false; else input.value = "";
  });
  clearOutput("Cleared from memory. Run the tool when ready."); renderNotices([]); renderVisual(null); updateSuggestions();
}
function clearOutput(message) {
  const output = $("#output"); output.replaceChildren(); $("#output-cols").hidden = true;
  const box = el("div", "output-empty"); box.append(el("div", "glyph", "🔑"), el("div", "msg", message), el("div", "hint", "Ctrl/Cmd + Enter runs the current tool")); output.appendChild(box); $("#output-count").textContent = "Output";
}
function renderVisual(meta) {
  const box = $("#visual-output");
  if (meta && meta.qr_text) renderQr(box, meta.qr_text, meta.qr_label || "Enrollment QR code");
  else { box.replaceChildren(); box.hidden = true; }
}
const byteLength = value => new TextEncoder().encode(value).length;
function renderOutput(values) {
  const output = $("#output"); output.replaceChildren();
  if (!values.length) { clearOutput("No output."); return; }
  const spec = state.byId[state.current]; const bits = entropyBitsFor(spec.id, readOptions()); $("#output-cols").hidden = false;
  values.forEach((value, index) => output.appendChild(outputRow(String(value), index, bits, spec.random)));
  $("#output-count").textContent = `${values.length} ${values.length === 1 ? "value" : "values"}${bits == null ? "" : ` · ≈${Math.round(bits)} bits each`}`;
}
function outputRow(value, index, bits, canReroll) {
  const row = el("li", "out-row"); row.appendChild(el("span", "cell-idx", String(index + 1)));
  row.appendChild(el("code", "cell-val", value)); row.appendChild(el("span", "cell-num", String(value.length))); row.appendChild(el("span", "cell-num", String(byteLength(value))));
  const bitCell = el("span", "cell-bits");
  if (bits == null) bitCell.appendChild(el("span", "empty-bits", "—")); else bitCell.appendChild(el("span", `badge ${bits < 60 ? "weak" : bits < 90 ? "fair" : "strong"}`, `≈${Math.round(bits)}`));
  row.appendChild(bitCell); const actions = el("div", "row-actions");
  if (canReroll) {
    const reroll = el("button", "reroll-btn", "↻"); reroll.type = "button"; reroll.title = "Regenerate this value"; reroll.setAttribute("aria-label", "Regenerate this value");
    reroll.addEventListener("click", async () => {
      const toolId = state.current; const selectionToken = state.selectionToken;
      try {
        const result = await runLocal(toolId, readOptions(), 1);
        if (selectionToken !== state.selectionToken || toolId !== state.current || !row.isConnected) return;
        row.replaceWith(outputRow(result.values[0], index, bits, true)); renderNotices(result.warnings); renderVisual(result.meta);
      } catch (error) { if (selectionToken === state.selectionToken && toolId === state.current) toast(error.message); }
    }); actions.appendChild(reroll);
  }
  const copyButton = el("button", "copy-btn", "Copy"); copyButton.type = "button"; copyButton.addEventListener("click", () => copy(value, copyButton)); actions.appendChild(copyButton); row.appendChild(actions); return row;
}
function renderError(message) {
  const output = $("#output"); output.replaceChildren(el("li", "empty is-error", `⚠ ${message}`)); $("#output-cols").hidden = true; $("#output-count").textContent = "Error"; renderVisual(null);
}
function currentValues() { return [...$("#output").querySelectorAll(".out-row code")].map(code => code.textContent); }
function copyAll() { const values = currentValues(); if (!values.length) return toast("Nothing to copy"); copy(values.join("\n")); }
function csvCell(value) { return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value; }
function downloadOutput() {
  const values = currentValues(); if (!values.length) return toast("Nothing to download");
  const format = $("#export-format").value; let content, extension, mime;
  if (format === "json") { content = JSON.stringify({ tool: state.current, values }, null, 2); extension = "json"; mime = "application/json"; }
  else if (format === "csv") { content = `value\n${values.map(csvCell).join("\n")}\n`; extension = "csv"; mime = "text/csv"; }
  else { content = `${values.join("\n")}\n`; extension = "txt"; mime = "text/plain"; }
  const anchor = el("a"); anchor.href = URL.createObjectURL(new Blob([content], { type: mime })); anchor.download = `${state.current}-output.${extension}`; anchor.click(); URL.revokeObjectURL(anchor.href); toast("Output exported; inputs were not included");
}

function dashboardSpecs() { return state.specs.filter(spec => spec.random && spec.batchable !== false); }
function buildDashboard() {
  const specs = dashboardSpecs(); const selected = new Set(LS.get("dashSelected", specs.map(spec => spec.id))); const grid = $("#dash-grid"); grid.replaceChildren();
  for (const spec of specs) {
    const card = el("div", "dash-card"); card.dataset.id = spec.id; const head = el("label", "dash-card-head"); const checkbox = el("input"); checkbox.type = "checkbox"; checkbox.checked = selected.has(spec.id); checkbox.setAttribute("aria-label", `Include ${spec.label}`);
    checkbox.addEventListener("change", () => { card.classList.toggle("is-selected", checkbox.checked); persistDashboard(); }); head.append(checkbox, el("span", "name", spec.label), el("span", "badge badge-muted", "local")); card.appendChild(head);
    const values = el("div", "dash-values"); values.appendChild(el("div", "dash-empty", "Not generated")); card.appendChild(values); card.classList.toggle("is-selected", checkbox.checked); grid.appendChild(card);
  }
  updateDashboardState();
}
function toggleAllDashboard(enabled) { $("#dash-grid").querySelectorAll(".dash-card").forEach(card => { const input = card.querySelector("input"); input.checked = enabled; card.classList.toggle("is-selected", enabled); }); persistDashboard(); }
function persistDashboard() { LS.set("dashSelected", [...$("#dash-grid").querySelectorAll(".dash-card")].filter(card => card.querySelector("input").checked).map(card => card.dataset.id)); updateDashboardState(); }
function updateDashboardState() {
  const selected = [...$("#dash-grid").querySelectorAll("input")].filter(input => input.checked).length;
  $("#dash-selected").textContent = `${selected} of ${dashboardSpecs().length} selected`; $("#dash-generate").disabled = selected === 0;
}
async function generateDashboard() {
  const button = $("#dash-generate"); if (!setBusy(button, true, "Generating…")) return;
  const count = clampCount($("#dash-count").value, 100); const cards = [...$("#dash-grid").querySelectorAll(".dash-card")].filter(card => card.querySelector("input").checked);
  try {
    await Promise.all(cards.map(async card => {
      const spec = state.byId[card.dataset.id]; const box = card.querySelector(".dash-values"); box.replaceChildren();
      try {
        const result = await runLocal(spec.id, defaultsFor(spec), Math.min(count, spec.max_count || count)); const bits = entropyBitsFor(spec.id, defaultsFor(spec));
        result.values.forEach(value => { const row = el("div", "dash-row"); row.appendChild(el("code", null, value)); if (bits != null) row.appendChild(el("span", `badge ${bits < 60 ? "weak" : bits < 90 ? "fair" : "strong"}`, `≈${Math.round(bits)}`)); const copyButton = el("button", "copy-btn", "Copy"); copyButton.type = "button"; copyButton.onclick = () => copy(value, copyButton); row.appendChild(copyButton); box.appendChild(row); });
      } catch (error) { box.appendChild(el("div", "dash-empty is-error", `⚠ ${error.message}`)); }
    }));
  } finally { setBusy(button, false); }
}

const diffState = { payload: null, mode: LS.get("diffMode", "inline"), timer: null };
function initDiff() {
  const left = $("#diff-a"), right = $("#diff-b");
  left.value = ""; right.value = ""; $("#diff-ws").checked = LS.get("diffWs", false); $("#diff-case").checked = LS.get("diffCase", false); $("#diff-gran").value = LS.get("diffGran", "word"); $("#diff-live").checked = LS.get("diffLive", false); syncDiffMode();
  $("#diff-run").onclick = runDiff; $("#diff-clear").onclick = () => { left.value = ""; right.value = ""; clearDiff(); };
  $("#diff-swap").onclick = () => { [left.value, right.value] = [right.value, left.value]; updateDiffButtons(); if ($("#diff-live").checked) runDiff(); };
  $("#diff-copy").onclick = () => { if (diffState.payload) copy(diffState.payload.unified); };
  $("#diff-mode").onclick = event => { const button = event.target.closest(".seg"); if (!button) return; diffState.mode = button.dataset.mode; LS.set("diffMode", diffState.mode); syncDiffMode(); if (diffState.payload) renderDiff(); };
  [left, right].forEach(input => input.addEventListener("input", () => { updateDiffButtons(); if ($("#diff-live").checked) { clearTimeout(diffState.timer); diffState.timer = setTimeout(runDiff, 180); } }));
  ["diff-ws", "diff-case", "diff-gran"].forEach(id => $("#" + id).addEventListener("change", () => { LS.set(id === "diff-ws" ? "diffWs" : id === "diff-case" ? "diffCase" : "diffGran", $("#" + id).type === "checkbox" ? $("#" + id).checked : $("#" + id).value); if ($("#diff-live").checked) runDiff(); }));
  $("#diff-live").addEventListener("change", () => { LS.set("diffLive", $("#diff-live").checked); if ($("#diff-live").checked) runDiff(); });
  window.addEventListener("resize", () => { if (diffState.payload) renderDiff(); }); updateDiffButtons();
}
function updateDiffButtons() { const hasText = !!($("#diff-a").value || $("#diff-b").value); $("#diff-swap").disabled = !hasText; $("#diff-clear").disabled = !hasText; $("#diff-copy").disabled = !diffState.payload; }
function runDiff() {
  const button = $("#diff-run"); if (!setBusy(button, true, "Comparing…")) return;
  try {
    diffState.payload = compareText($("#diff-a").value, $("#diff-b").value, { ignore_whitespace: $("#diff-ws").checked, ignore_case: $("#diff-case").checked, granularity: $("#diff-gran").value }); renderDiff();
  } catch (error) { diffError(error.message); }
  finally { setBusy(button, false); updateDiffButtons(); }
}
function renderDiff() {
  const payload = diffState.payload; const box = $("#diff-result"); box.replaceChildren(); renderDiffSummary(payload.stats);
  if (payload.stats.identical) { box.appendChild(el("div", "diff-empty", $("#diff-a").value || $("#diff-b").value ? "No differences." : "Enter text in both panes to compare.")); return; }
  const narrow = matchMedia("(max-width: 760px)").matches; (narrow || diffState.mode === "inline" ? buildInlineDiff : buildSplitDiff)(box, payload.rows);
}
function buildInlineDiff(box, rows) {
  const grid = el("div", "diff-grid inline");
  for (const row of rows) {
    if (row.type === "equal") inlineDiffLine(grid, " ", row.left.num, "", row.left);
    else if (row.type === "add") inlineDiffLine(grid, "+", row.right.num, "add", row.right);
    else if (row.type === "remove") inlineDiffLine(grid, "-", row.left.num, "remove", row.left);
    else { inlineDiffLine(grid, "-", row.left.num, "remove", row.left); inlineDiffLine(grid, "+", row.right.num, "add", row.right); }
  }
  box.appendChild(grid);
}
function inlineDiffLine(grid, sign, number, className, side) { grid.append(el("div", `gutter ${className}`, `${sign} ${number ?? ""}`), diffCell(className, side)); }
function buildSplitDiff(box, rows) {
  const grid = el("div", "diff-grid split");
  for (const row of rows) {
    const leftClass = diffSideClass(row, "left"), rightClass = diffSideClass(row, "right");
    grid.append(el("div", `gutter left ${leftClass}`, row.left ? String(row.left.num) : ""), diffCell(`left ${leftClass}`, row.left), el("div", `gutter right ${rightClass}`, row.right ? String(row.right.num) : ""), diffCell(`right ${rightClass}`, row.right));
  }
  box.appendChild(grid);
}
function diffCell(className, side) { const cell = el("div", `cell ${className}`); if (!side) { cell.classList.add("filler"); return cell; } for (const segment of side.segs || [{ text: side.text }]) cell.appendChild(el("span", segment.hl ? "hl" : null, segment.text)); return cell; }
function diffSideClass(row, side) { if (row.type === "equal") return "equal"; if (row.type === "change") return "change"; if (row.type === "remove") return side === "left" ? "remove" : ""; if (row.type === "add") return side === "right" ? "add" : ""; return ""; }
function renderDiffSummary(stats) { const box = $("#diff-summary"); box.replaceChildren(el("span", "badge badge-add", `+${stats.added} added`), el("span", "badge badge-del", `−${stats.removed} removed`), el("span", "badge badge-chg", `${stats.changed} changed`), el("span", "badge badge-muted", `${stats.similarity}% similar`)); }
function diffError(message) { $("#diff-summary").replaceChildren(); $("#diff-result").replaceChildren(el("div", "diff-empty is-error", `⚠ ${message}`)); }
function clearDiff() { diffState.payload = null; $("#diff-summary").replaceChildren(); $("#diff-result").replaceChildren(); updateDiffButtons(); }
function syncDiffMode() { document.querySelectorAll("#diff-mode .seg").forEach(button => button.classList.toggle("is-active", button.dataset.mode === diffState.mode)); }

function initShortcuts() {
  document.addEventListener("keydown", event => {
    const typing = ["input", "textarea", "select"].includes((event.target.tagName || "").toLowerCase());
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") { event.preventDefault(); const view = activeViewName(); if (view === "dashboard") generateDashboard(); else if (view === "diff") runDiff(); else generate(); }
    else if (event.key === "/" && !typing && !event.ctrlKey && !event.metaKey && !event.altKey && activeViewName() === "single") { event.preventDefault(); $("#gen-filter").focus(); }
  });
}
async function copy(text, button = null) {
  try { await navigator.clipboard.writeText(text); }
  catch (_) { const input = el("textarea"); input.value = text; document.body.appendChild(input); input.select(); document.execCommand("copy"); input.remove(); }
  if (button) { button.classList.add("copied"); button.textContent = "Copied"; setTimeout(() => { button.classList.remove("copied"); button.textContent = "Copy"; }, 1100); }
  else toast("Copied to clipboard");
}
let toastTimer;
function toast(message) { const box = $("#toast"); box.textContent = message; box.classList.add("show"); clearTimeout(toastTimer); toastTimer = setTimeout(() => box.classList.remove("show"), 1800); }
function registerServiceWorker() { if ("serviceWorker" in navigator && location.protocol !== "file:") navigator.serviceWorker.register("/static/sw.js", { scope: "/" }).catch(() => {}); }
async function runBrowserSelfTests() {
  const tests = [];
  const check = (name, condition) => tests.push({ name, ok: !!condition });
  try {
    check("Base64 UTF-8", (await runLocal("base64_text", { text: "hello", mode: "encode", padding: true }, 1)).values[0] === "aGVsbG8=");
    check("SHA-256", (await runLocal("hash", { text: "abc", algorithm: "sha256" }, 1)).values[0] === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check("MD5 compatibility", (await runLocal("hash", { text: "abc", algorithm: "md5" }, 1)).values[0] === "900150983cd24fb0d6963f7d28e17f72");
    check("UUID v4", /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test((await runLocal("uuid", { version: 4, hyphens: true }, 1)).values[0]));
  } catch (_) { tests.push({ name: "self-test runtime", ok: false }); }
  const failed = tests.filter(test => !test.ok); console.info("fast-secrets browser self-tests", tests); toast(failed.length ? `${failed.length} browser self-test(s) failed` : `${tests.length} browser self-tests passed`);
}

boot();
