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
  document.getElementById('nav-ts').textContent = str;
}
setInterval(updateTs, 1000);
updateTs();

/* ─────────────────────────────────────
   TIMELINE (Red)
───────────────────────────────────── */
(function buildTimeline() {
  const tl = document.getElementById('red-tl');
  if (!tl) return;
  const blocks = [
    {w:6,t:'n'},{w:8,t:'n'},{w:10,t:'n'},{w:7,t:'n'},{w:9,t:'n'},
    {w:5,t:'n'},{w:8,t:'n'},{w:4,t:'a'},{w:3,t:'n'},{w:7,t:'n'},
    {w:6,t:'n'},{w:9,t:'n'},{w:5,t:'a'},{w:6,t:'a'},{w:4,t:'n'},
    {w:7,t:'n'},{w:8,t:'a'},{w:6,t:'a'},{w:5,t:'n'},{w:4,t:'n'}
  ];
  const tot = blocks.reduce((s,b) => s + b.w, 0);
  blocks.forEach(b => {
    const d = document.createElement('div');
    d.style.cssText = `flex-basis:${(b.w/tot*100).toFixed(1)}%;height:100%;border-radius:2px;`;
    if (b.t === 'n') {
      d.style.background = 'rgba(139,115,85,0.28)';
    } else {
      d.style.background = 'rgba(255,77,0,0.45)';
      d.style.border = '1px solid rgba(255,77,0,0.50)';
      d.style.boxShadow = '0 0 4px rgba(255,77,0,0.20)';
    }
    tl.appendChild(d);
  });
})();

/* ─────────────────────────────────────
   CONTADORES ANIMADOS
───────────────────────────────────── */
let pkts = 1284703;
setInterval(() => {
  pkts += Math.floor(Math.random() * 100 + 30);
  const el = document.getElementById('red-pkts');
  if (el) el.textContent = pkts.toLocaleString('es-ES');
}, 1200);

/* ─────────────────────────────────────
   ALERTAS — selección fila
───────────────────────────────────── */
function selectAlert(row) {
  document.querySelectorAll('.siem-table tr').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');
}

/* ─────────────────────────────────────
   FILTROS
───────────────────────────────────── */
document.querySelectorAll('.filter-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    const parent = chip.closest('.alertas-filters');
    parent.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
  });
});

/* ─────────────────────────────────────
   LABORATORIO
───────────────────────────────────── */
let currentScenario = { name: 'ARP Spoofing', score: 0.97, color: '#FF4D00' };

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

function selectScenario(btn, name, score, color) {
  document.querySelectorAll('.scenario-btn').forEach(b => b.classList.remove('selected'));
  btn.classList.add('selected');
  currentScenario = { name, score, color };
  document.getElementById('lab-scenario-name').textContent = name;
}

function updateTheta(val) {
  const percentiles = {70:0.072,75:0.085,80:0.096,85:0.105,90:0.114,95:0.134,99:0.186};
  const p = parseInt(val);
  let theta = 0.072 + (p - 70) * 0.004;
  // Approximate
  if (p <= 70) theta = 0.072;
  else if (p >= 99) theta = 0.186;
  else theta = 0.072 + (p - 70) * 0.0038;
  const t = theta.toFixed(3);
  document.getElementById('theta-display').textContent = t;
  document.getElementById('bar-theta').textContent = t;
}

function runScenario() {
  const { name, score, color } = currentScenario;
  const detected = score > 0.114;
  const bar = document.getElementById('lab-bar');
  const scoreEl = document.getElementById('lab-score');
  const label = document.getElementById('lab-detected-label');
  const terminal = document.getElementById('lab-terminal');

  bar.style.width = (score * 100).toFixed(0) + '%';
  bar.style.background = color;
  scoreEl.textContent = score.toFixed(2);
  scoreEl.style.color = color;

  if (detected) {
    setLabLabel('alert-triangle', 'ANOMALÍA DETECTADA', 'is-alert');
    label.style.color = color;
  } else {
    setLabLabel('check-circle', 'TRÁFICO NORMAL', 'is-ok');
    label.style.color = '#8B7355';
  }

  const now = new Date();
  const p = v => String(v).padStart(2, '0');
  const ts = `[${p(now.getHours())}:${p(now.getMinutes())}:${p(now.getSeconds())}]`;
  const line1 = termLine(ts, `Ejecutando: ${name}`, 'info');
  const line2 = termLine(
    ts,
    detected
      ? `MSE=${score.toFixed(4)} › θ → ANOMALÍA`
      : `MSE=${score.toFixed(4)} ≤ θ → NORMAL`,
    detected ? 'err' : 'ok'
  );
  terminal.innerHTML += line1 + line2;
  terminal.scrollTop = terminal.scrollHeight;
}

function resetLab() {
  document.getElementById('lab-bar').style.width = '0%';
  document.getElementById('lab-score').textContent = '—';
  const label = document.getElementById('lab-detected-label');
  setLabLabel(null, 'SIN EJECUCIÓN', 'is-idle');
  if (label) label.style.color = '';
  document.getElementById('lab-score').style.color = 'var(--faint)';
  document.getElementById('lab-terminal').innerHTML =
    termLine('[sistema]', 'Laboratorio reiniciado · listo para nueva ejecución', 'info');
}

/* ─────────────────────────────────────
   AGENTE IA
───────────────────────────────────── */
function validateKey() {
  const key = document.getElementById('api-key-input').value;
  if (key.startsWith('AIza') && key.length > 20) {
    setKeyStatus('check', 'Clave válida · agente IA habilitado', '#8B7355');
  } else {
    setKeyStatus('x', 'Formato inválido · debe comenzar con AIza', 'var(--danger)');
  }
}

function clearKey() {
  document.getElementById('api-key-input').value = '';
  const status = document.getElementById('key-status');
  status.className = '';
  status.textContent = 'Sin clave configurada · detección local activa';
  status.style.color = 'var(--faint)';
}

function setMode(el, mode) {
  document.querySelectorAll('.mode-option').forEach(m => m.classList.remove('active'));
  el.classList.add('active');
  const title = document.querySelector('.agent-output-title');
  if (title) {
    const dot = title.querySelector('.agent-status-dot');
    title.innerHTML = '';
    if (dot) title.appendChild(dot);
    title.appendChild(document.createTextNode(` Informe del agente — Modo ${mode}`));
  }
}
