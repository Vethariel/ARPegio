/* ─────────────────────────────────────
   NAVEGACIÓN
───────────────────────────────────── */
function switchView(viewId) {
  document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach((t) => t.classList.remove('active'));

  const target = document.getElementById('view-' + viewId);
  if (target) target.classList.add('active');

  const tab = document.querySelector('.nav-tab[data-view="' + viewId + '"]');
  if (tab) tab.classList.add('active');

  const settings = document.querySelector('.nav-settings');
  if (settings) settings.classList.toggle('active', viewId === 'ajustes');
}

document.querySelectorAll('[data-view]').forEach(el => {
  el.addEventListener('click', () => switchView(el.dataset.view));
});

/* ─────────────────────────────────────
   TIMESTAMP
───────────────────────────────────── */
function updateTs() {
  const n = new Date();
  const p = v => String(v).padStart(2, '0');
  const str = `${n.getFullYear()}-${p(n.getMonth()+1)}-${p(n.getDate())} · ${p(n.getHours())}:${p(n.getMinutes())}:${p(n.getSeconds())}`;
  const el = document.getElementById('nav-ts');
  if (el) el.textContent = str;
}
setInterval(updateTs, 1000);
updateTs();

/* ─────────────────────────────────────
   ESTADO ALERTAS
───────────────────────────────────── */
let filteredAlerts = [];
let currentFilter = 'Todas';
let selectedAlertIndex = 0;

function selectAlertRow(row, idx) {
  document.querySelectorAll('.siem-table tbody tr').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');
  selectedAlertIndex = idx;
  ArpegioRender.renderAlertDetail(filteredAlerts[idx]);
}

function applyAlertFilter(name) {
  currentFilter = name;
  filteredAlerts = ArpegioData.filterAlerts(name);
  selectedAlertIndex = 0;
  ArpegioRender.renderAlertTable(filteredAlerts, 0);
  if (filteredAlerts.length) {
    ArpegioRender.renderAlertDetail(filteredAlerts[0]);
    const first = document.querySelector('#alerts-tbody tr');
    if (first) first.classList.add('selected');
  }
}

/* ─────────────────────────────────────
   FILTROS
───────────────────────────────────── */
document.querySelectorAll('.filter-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    const parent = chip.closest('.alertas-filters');
    parent.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    applyAlertFilter(chip.textContent.trim());
  });
});

/* ─────────────────────────────────────
   LABORATORIO — ventanas reales
───────────────────────────────────── */
let currentScenario = null;

function getActiveTheta() {
  const slider = document.getElementById("theta-slider");
  const idx = slider ? parseInt(slider.value, 10) : ArpegioData.getSliderIndexForPercentile(95);
  return ArpegioData.getThetaForPercentile(ArpegioData.getPercentileFromSliderIndex(idx));
}

function getThreshold() {
  return getActiveTheta();
}

function setLabLabel(iconName, text, stateClass) {
  const label = document.getElementById('lab-detected-label');
  if (!label) return;
  label.className = `lab-status-label ${stateClass}`;
  if (iconName) {
    label.innerHTML =
      ArpegioIcons.icon(iconName, { size: 14 }) + `<span>${text}</span>`;
  } else {
    label.innerHTML = `<span>${text}</span>`;
  }
}

function termLine(prompt, message, kind = 'info') {
  const cls = kind === 'err' ? 't-err' : kind === 'ok' ? 't-ok' : 't-info';
  return `<div><span class="t-prompt">${prompt}</span> <span class="${cls}">${ArpegioIcons.terminalPrefix(kind)} ${message}</span></div>`;
}

function setKeyStatus(iconName, text, color) {
  const status = document.getElementById('key-status');
  if (!status) return;
  status.className = 'key-status-line';
  status.style.color = color;
  status.innerHTML = ArpegioIcons.icon(iconName, { size: 12 }) + `<span>${text}</span>`;
}

function selectScenario(btn, scenarioId) {
  const scenario = ArpegioData.getLabScenario(scenarioId);
  if (!scenario) return;

  document.querySelectorAll(".scenario-btn").forEach((b) => b.classList.remove("selected"));
  btn.classList.add("selected");
  currentScenario = scenario;

  document.getElementById("lab-scenario-name").textContent = scenario.display_name;
  const descEl = document.getElementById("lab-scenario-desc");
  if (descEl) {
    descEl.textContent = scenario.note
      ? `${scenario.description} — ${scenario.note}`
      : scenario.description;
    descEl.style.color = scenario.note ? "var(--amber)" : "var(--muted)";
  }
  const timeEl = document.getElementById("lab-scenario-time");
  if (timeEl) {
    const ws = ArpegioData.getState().labScenarios?.window_size || 50;
    timeEl.textContent = `Ventana ${ws} tramas · ${scenario.source} · ${ArpegioData.fmtTime(scenario.t_start)} · label ${scenario.label}`;
  }
}

function updateTheta(val) {
  const idx = parseInt(val, 10);
  const p = ArpegioData.getPercentileFromSliderIndex(idx);
  ArpegioRender.renderLabTheta(p);
}

async function runScenario() {
  if (!currentScenario) return;

  const runBtn = document.querySelector("#view-lab .btn-primary");
  if (runBtn) runBtn.disabled = true;

  const scenario = currentScenario;
  const terminal = document.getElementById("lab-terminal");
  const ts = ArpegioData.fmtTime(scenario.t_start);
  const ws = ArpegioData.getState().labScenarios?.window_size || 50;
  const pipelineMse = scenario.reconstruction_error;

  terminal.innerHTML += [
    termLine(ts, `Cargando ventana real: ${scenario.display_name} (${scenario.label})`, "info"),
    termLine(ts, `Extrayendo ${ws} tramas de ${scenario.source} → features L2`, "info"),
    termLine(ts, ArpegioData.formatLabFeatureSummary(scenario.features), "ok"),
  ].join("");
  terminal.scrollTop = terminal.scrollHeight;

  let score;
  let usedFallback = false;
  try {
    if (!ArpegioInference.isReady()) {
      terminal.innerHTML += termLine("[sistema]", "Cargando modelo ONNX…", "info");
      terminal.scrollTop = terminal.scrollHeight;
      await ArpegioInference.load();
      ArpegioInference.setStatusBadge();
    }
    terminal.innerHTML += termLine(ts, "Forward pass autoencoder (ONNX Runtime Web · WASM)", "ok");
    terminal.scrollTop = terminal.scrollHeight;
    score = await ArpegioInference.score(scenario.features);
  } catch (err) {
    usedFallback = true;
    score = pipelineMse;
    terminal.innerHTML += termLine(
      "[error]",
      `Inferencia ONNX falló (${err.message}) · usando MSE del pipeline offline`,
      "err"
    );
  }

  const theta = getActiveTheta();
  const detected = score > theta;
  const color = detected ? "var(--danger)" : "#8B7355";
  const barMax =
    parseFloat(document.getElementById("lab-bar-max")?.textContent) ||
    Math.max(score, theta * 2, 1.5);

  const bar = document.getElementById("lab-bar");
  const scoreEl = document.getElementById("lab-score");
  const label = document.getElementById("lab-detected-label");

  bar.style.width = Math.min(100, (score / barMax) * 100).toFixed(0) + "%";
  bar.style.background = detected ? scenario.color : "#8B7355";
  scoreEl.textContent = ArpegioData.fmtScore(score);
  scoreEl.style.color = color;

  if (detected) {
    setLabLabel("alert-triangle", "ANOMALÍA DETECTADA", "is-alert");
    label.style.color = scenario.color;
  } else {
    setLabLabel("check-circle", "TRÁFICO NORMAL", "is-ok");
    label.style.color = "#8B7355";
  }

  const p = ArpegioData.getPercentileFromSliderIndex(
    parseInt(document.getElementById("theta-slider")?.value || "5", 10)
  );

  const lines = [
    termLine(
      ts,
      detected
        ? `MSE=${score.toFixed(4)} > θ=${ArpegioData.fmtTheta(theta)} (p${p}) → ANOMALÍA`
        : `MSE=${score.toFixed(4)} ≤ θ=${ArpegioData.fmtTheta(theta)} (p${p}) → NORMAL`,
      detected ? "err" : "ok"
    ),
  ];

  if (!usedFallback) {
    const drift = Math.abs(score - pipelineMse);
    lines.push(
      termLine(
        ts,
        `Paridad pipeline: navegador=${score.toFixed(6)} · offline=${pipelineMse.toFixed(6)} · Δ=${drift.toExponential(2)}`,
        drift < 1e-3 ? "ok" : "info"
      )
    );
  }

  if (scenario.note && !detected) {
    lines.push(termLine(ts, scenario.note, "info"));
  } else if (detected) {
    lines.push(
      termLine(ts, `Etiqueta ground-truth: ${scenario.label} · decisión coherente con el lab`, "info")
    );
  }

  terminal.innerHTML += lines.join("");
  terminal.scrollTop = terminal.scrollHeight;
  if (runBtn) runBtn.disabled = false;
}

function resetLab() {
  document.getElementById("lab-bar").style.width = "0%";
  document.getElementById("lab-bar").style.background = "var(--danger)";
  document.getElementById("lab-score").textContent = "—";
  const label = document.getElementById("lab-detected-label");
  setLabLabel(null, "SIN EJECUCIÓN", "is-idle");
  if (label) label.style.color = "";
  document.getElementById("lab-score").style.color = "var(--faint)";
  document.getElementById("lab-terminal").innerHTML = termLine(
    "[sistema]",
    "Selecciona un escenario y pulsa Ejecutar · inferencia ONNX en el navegador",
    "info"
  );
}

function initLab(labScenarios) {
  if (!labScenarios) return;
  const firstId = ArpegioRender.renderLab(labScenarios);
  resetLab();
  if (firstId) {
    const btn = document.querySelector(`[data-scenario-id="${firstId}"]`);
    if (btn) selectScenario(btn, firstId);
  }
}

/* ─────────────────────────────────────
   AGENTE IA
───────────────────────────────────── */
let agentMode = "preventivo";

function validateKey() {
  const key = document.getElementById("api-key-input")?.value?.trim() || "";
  ArpegioGemini.syncInputs(document.getElementById("api-key-input")?.value || "");
  if (key) {
    ArpegioGemini.setApiKey(key);
    setKeyStatus("check", "API key guardada · lista para Gemini", "#8B7355");
  } else {
    ArpegioGemini.clearApiKey();
    setKeyStatus("x", "La API key no puede estar vacía", "var(--danger)");
  }
}

function clearKey() {
  document.getElementById("api-key-input").value = "";
  const settings = document.getElementById("settings-api-key-input");
  if (settings) settings.value = "";
  ArpegioGemini.clearApiKey();
  const status = document.getElementById("key-status");
  status.className = "";
  status.textContent = "Sin clave configurada · detección local activa";
  status.style.color = "var(--faint)";
  const out = document.getElementById("agent-gemini-output");
  if (out) {
    out.textContent = "Configura tu API key y pulsa «Generar informe». La clave solo se usa en este navegador.";
  }
  ArpegioGemini.setAgentDot("idle");
}

function setMode(el, mode) {
  agentMode = mode;
  document.querySelectorAll(".mode-option").forEach((m) => m.classList.remove("active"));
  el.classList.add("active");
  const title = document.querySelector(".agent-output-title");
  if (title) {
    const dot = title.querySelector(".agent-status-dot");
    title.innerHTML = "";
    if (dot) title.appendChild(dot);
    title.appendChild(document.createTextNode(` Informe del agente — Modo ${mode}`));
  }
}

async function runAgent() {
  const keyInput = document.getElementById("api-key-input");
  const key = (keyInput?.value || ArpegioGemini.getApiKeyFromInputs() || "").trim();
  if (!key) {
    setKeyStatus("x", "La API key no puede estar vacía", "var(--danger)");
    keyInput?.focus();
    return;
  }

  ArpegioGemini.setApiKey(key);
  ArpegioGemini.syncInputs(keyInput?.value || key);

  const btn = document.getElementById("btn-agent-generate");
  const out = document.getElementById("agent-gemini-output");
  if (!out) return;

  if (btn) btn.disabled = true;
  out.textContent = "Consultando Gemini…";
  ArpegioGemini.setAgentDot("loading");

  try {
    const state = ArpegioData.getState();
    const alert = filteredAlerts[selectedAlertIndex] || filteredAlerts[0] || null;
    if (agentMode === "reactivo" && !alert) {
      throw new Error("No hay alertas en el replay para generar un plan reactivo");
    }
    const text = await ArpegioGemini.generate(agentMode, state, alert);
    ArpegioGemini.renderIntoElement(out, text);
    setKeyStatus("check", "Informe generado · API key activa", "#8B7355");
    ArpegioGemini.setAgentDot("ready");
  } catch (err) {
    console.error(err);
    out.textContent = err.message;
    ArpegioGemini.setAgentDot("error");
  } finally {
    if (btn) btn.disabled = false;
  }
}

function syncAgentKeyFromSettings() {
  const settings = document.getElementById("settings-api-key-input");
  const main = document.getElementById("api-key-input");
  if (settings && main && settings.value && !main.value) {
    main.value = settings.value;
    ArpegioGemini.setApiKey(settings.value.trim());
  }
}

/* ─────────────────────────────────────
   INICIALIZACIÓN — datos reales
───────────────────────────────────── */
function exportCurrentAlert() {
  const alert = filteredAlerts[selectedAlertIndex];
  if (alert) ArpegioData.exportAlertJSON(alert);
}

async function initArpegio() {
  const banner = document.getElementById('data-load-error');
  ArpegioGemini.init();
  ArpegioInference.setStatusBadge();
  ArpegioInference.load().then(() => ArpegioInference.setStatusBadge());
  try {
    const { metrics, alerts, windowScores, labelConfig, labScenarios } = await ArpegioData.load();

    ArpegioRender.renderNav(metrics);
    ArpegioRender.renderMonitor(metrics, alerts, windowScores);
    ArpegioRender.renderSettings(metrics, labelConfig);
    ArpegioRender.renderAgentSummary(metrics, alerts);
    ArpegioRender.renderAgentCalibrations(metrics, labScenarios);
    ArpegioRender.renderAgentReplayLog(alerts);
    ArpegioRender.renderTimeline(labelConfig);
    ArpegioRender.renderNetwork(alerts, metrics);
    initLab(labScenarios);

    filteredAlerts = alerts;
    ArpegioRender.renderAlertTable(alerts, 0);
    if (alerts.length) {
      ArpegioRender.renderAlertDetail(alerts[0]);
    }

    const exportBtn = document.getElementById('btn-export-csv');
    if (exportBtn) {
      exportBtn.addEventListener('click', () => ArpegioData.exportAlertsCSV());
    }
    const exportAlertBtn = document.getElementById('btn-export-alert');
    if (exportAlertBtn) {
      exportAlertBtn.addEventListener('click', exportCurrentAlert);
    }

    const settingsKey = document.getElementById('settings-api-key-input');
    if (settingsKey) {
      settingsKey.addEventListener('change', syncAgentKeyFromSettings);
    }
    if (ArpegioGemini.hasApiKey()) {
      setKeyStatus('check', 'API key en sesión · lista para Gemini', '#8B7355');
    }
  } catch (err) {
    console.error(err);
    if (banner) banner.hidden = false;
    const msg = document.createElement('div');
    msg.className = 'data-error-banner';
    msg.textContent = `No se pudieron cargar los datos del pipeline. Ejecuta prioritize_alerts.py y sirve la app desde la raíz del repo. (${err.message})`;
    document.querySelector('.shell')?.prepend(msg);
  }
}

document.addEventListener('DOMContentLoaded', initArpegio);
