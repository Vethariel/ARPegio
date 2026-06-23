/** Renderizado dinámico conectado a datos reales. */
const ArpegioRender = (function () {
  const LABEL_COLORS = {
    normal: "rgba(139,115,85,0.28)",
    arp_spoof: "rgba(255,77,0,0.55)",
    mac_flood: "rgba(255,107,26,0.55)",
    port_scan: "rgba(232,163,23,0.45)",
    arp_recon: "rgba(232,163,23,0.55)",
  };

  const THREAT_LABEL_SHORT = {
    arp_spoof: "ARP SPOOF",
    mac_flood: "MAC FLOOD",
    port_scan: "PORT SCAN",
    arp_recon: "RECON ARP",
    unknown: "ANOMALÍA",
  };

  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function renderNav(metrics) {
    const theta = ArpegioData.fmtTheta(metrics.threshold);
    document.querySelectorAll(".theta-badge").forEach((el) => {
      el.textContent = `θ = ${theta}`;
    });
  }

  function renderMonitor(metrics, alerts, windowScores) {
    const theta = metrics.threshold;
    const fp = metrics.per_class?.normal;
    const tiers = ArpegioData.countByTier(alerts);

    setText("kpi-theta", ArpegioData.fmtTheta(theta));
    setText("kpi-auc", Number(metrics.auc_roc).toFixed(3));
    setText("kpi-alerts", String(alerts.length));
    setText("kpi-theta-p", String(metrics.threshold_percentile || 95));
    setText("kpi-test-size", String(metrics.test_size || "—"));
    setText(
      "kpi-alerts-sub",
      `${tiers.crit} críticas · ${tiers.med} media · ${tiers.low} baja`
    );
    setText(
      "kpi-fp",
      fp ? ArpegioData.fmtPct(fp.rate_pct) : "—"
    );
    setText(
      "kpi-fp-sub",
      fp ? `${fp.detected} de ${fp.total} ventanas normales` : "—"
    );

    const auc = Number(metrics.auc_roc);
    setText("kpi-theta-purpose", `Regla de decisión: MSE > ${ArpegioData.fmtTheta(theta)} → alerta`);
    setText(
      "kpi-auc-purpose",
      auc >= 0.95 ? "Separación excelente entre clases" : auc >= 0.9 ? "Separación buena" : "Revisar calibración"
    );
    setText(
      "kpi-alerts-purpose",
      `${alerts.length} ventanas superaron θ y requieren revisión`
    );
    setText(
      "kpi-fp-purpose",
      fp && fp.detected > 0
        ? "Tráfico benigno alertado — subir θ reduce ruido"
        : "Sin normales alertados con este θ"
    );

    renderAlertStrip(alerts.slice(0, 3), theta);
    if (windowScores?.windows?.length) {
      renderHistogram(windowScores, theta, metrics);
    }

    const pkts = windowScores?.windows?.reduce((s, w) => s + (w.total_packets || 0), 0);
    if (pkts) setText("red-pkts", pkts.toLocaleString("es-ES"));
  }

  function renderAlertStrip(alerts, theta) {
    const strip = document.getElementById("alert-strip");
    if (!strip) return;
    strip.innerHTML = alerts
      .map((a) => {
        const tier = ArpegioData.tierFromPriority(a.priority_score);
        return `<div class="alert-strip-row" title="MSE = error de reconstrucción · prioridad = severidad + frecuencia + impacto">
          <span class="badge ${tier}">${ArpegioData.tierLabel(tier)}</span>
          <span style="font-size:12px;font-weight:500">${ArpegioData.threatName(a.inferred_threat)}</span>
          <span style="font-family:var(--font-mono);font-size:10px;color:var(--muted);margin-left:auto">MSE</span>
          <span style="font-family:var(--font-mono);font-size:11px;color:${ArpegioData.scoreColor(a.reconstruction_error, theta)}">${ArpegioData.fmtScore(a.reconstruction_error)}</span>
          <span style="font-family:var(--font-mono);font-size:10px;color:var(--muted)">${ArpegioData.fmtTime(a.t_start)}</span>
        </div>`;
      })
      .join("");
  }

  function renderHistLegend(threshold, displayMax, oTotal) {
    const el = document.getElementById("hist-legend");
    if (!el) return;
    el.innerHTML = `
      <div class="hist-legend-item">
        <span class="hist-legend-swatch" style="background:rgba(139,115,85,0.72)"></span>
        <div>
          <div class="hist-legend-name">Marrón — tráfico normal real</div>
          <div class="hist-legend-desc">Ventanas etiquetadas como benignas en el PCAP. La mayoría debe quedar a la izquierda de θ.</div>
        </div>
      </div>
      <div class="hist-legend-item">
        <span class="hist-legend-swatch" style="background:rgba(255,77,0,0.78)"></span>
        <div>
          <div class="hist-legend-name">Naranja — ataque real</div>
          <div class="hist-legend-desc">Ventanas con ataque inyectado en el lab (ARP spoof, MAC flood, etc.). Deben superar θ para ser detectadas.</div>
        </div>
      </div>
      <div class="hist-legend-item">
        <span class="hist-legend-swatch line"></span>
        <div>
          <div class="hist-legend-name">Línea θ = ${ArpegioData.fmtTheta(threshold)}</div>
          <div class="hist-legend-desc">Umbral de alerta. A la izquierda el modelo no alerta; a la derecha genera entrada en la cola SOC.</div>
        </div>
      </div>
      <div class="hist-legend-item">
        <span class="hist-legend-swatch zone"></span>
        <div>
          <div class="hist-legend-name">Zona silenciosa</div>
          <div class="hist-legend-desc">MSE bajo θ — el autoencoder reconstruye bien; no hay alerta.</div>
        </div>
      </div>
      <div class="hist-legend-item">
        <span class="hist-legend-swatch zone-alert"></span>
        <div>
          <div class="hist-legend-name">Zona de alerta</div>
          <div class="hist-legend-desc">MSE sobre θ — anomalía según el modelo; revisar en vista Alertas.</div>
        </div>
      </div>
      ${oTotal ? `<div class="hist-legend-item">
        <span class="hist-legend-swatch" style="background:transparent;border:1px dashed var(--muted)"></span>
        <div>
          <div class="hist-legend-name">Barra punteada — outliers</div>
          <div class="hist-legend-desc">Errores &gt; ${displayMax.toFixed(1)} fuera de escala. Casos extremos (p. ej. recon ARP) no se ven en detalle aquí.</div>
        </div>
      </div>` : ""}
    `;
  }

  function renderHistVerdict(tp, fp, tn, fn, threshold) {
    const el = document.getElementById("hist-verdict");
    if (!el) return;
    const attackTotal = tp + fn;
    const normalTotal = tn + fp;
    const detectPct = attackTotal ? Math.round((tp / attackTotal) * 100) : 0;
    const fpPct = normalTotal ? Math.round((fp / normalTotal) * 100) : 0;
    let fnNote = "";
    if (fn > 0) {
      fnNote = ` ${fn} ataque${fn > 1 ? "s" : ""} no superó θ (p. ej. port_scan con MSE bajo).`;
    }
    el.innerHTML = `<strong>Conclusión:</strong> con θ = ${ArpegioData.fmtTheta(threshold)}, el modelo detecta <strong>${tp}/${attackTotal}</strong> ataques (${detectPct}%) y genera <strong>${fp}</strong> falsa${fp === 1 ? "" : "s"} alarma${fp === 1 ? "" : "s"} en ${normalTotal} ventanas normales (${fpPct}%).${fnNote}`;
  }

  function renderHistConfusion(tp, fp, tn, fn) {
    const el = document.getElementById("hist-confusion");
    if (!el) return;
    el.innerHTML = `
      <table class="confusion-table">
        <thead>
          <tr>
            <th></th>
            <th>Modelo: sin alerta</th>
            <th>Modelo: alerta</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="label-cell">Real: normal</td>
            <td class="cell-tn" title="Verdadero negativo — correcto">${tn} TN</td>
            <td class="cell-fp" title="Falso positivo — ruido operativo">${fp} FP</td>
          </tr>
          <tr>
            <td class="label-cell">Real: ataque</td>
            <td class="cell-fn" title="Falso negativo — ataque no detectado">${fn} FN</td>
            <td class="cell-tp" title="Verdadero positivo — ataque detectado">${tp} TP</td>
          </tr>
        </tbody>
      </table>
      <div class="confusion-caption">Matriz de confusión sobre ${tp + fp + tn + fn} ventanas. TN/TP = aciertos · FP = alarmas innecesarias · FN = ataques perdidos.</div>
    `;
  }

  function renderHistogram(windowScores, threshold, metrics) {
    const svg = document.getElementById("monitor-histogram");
    if (!svg) return;

    const windows = windowScores.windows;
    const errors = windows.map((w) => w.reconstruction_error);

    const sorted = [...errors].sort((a, b) => a - b);
    const p95 = sorted[Math.floor(sorted.length * 0.95)] || 1;
    const displayMax = Math.max(1.2, Math.min(p95 * 1.05, 2.0));

    // Bins adaptados: zoom en θ (normales/FP) y en el clúster de ataque (~1.2)
    const edges = [
      0,
      threshold * 0.5,
      threshold * 0.85,
      threshold,
      threshold * 1.15,
      0.2,
      0.35,
      0.6,
      0.9,
      1.1,
      displayMax,
    ];
    const uniqueEdges = edges.filter((v, i, a) => i === 0 || v > a[i - 1] + 1e-6);
    const bins = uniqueEdges.length - 1;
    const counts = Array.from({ length: bins }, () => ({ normal: 0, attack: 0 }));
    const overflow = { normal: 0, attack: 0 };
    let maxErr = 0;

    windows.forEach((w) => {
      maxErr = Math.max(maxErr, w.reconstruction_error);
      const isNormal = w.label === "normal";
      const e = w.reconstruction_error;
      if (e > displayMax) {
        if (isNormal) overflow.normal++;
        else overflow.attack++;
        return;
      }
      let idx = bins - 1;
      for (let i = 0; i < bins; i++) {
        if (e >= uniqueEdges[i] && e < uniqueEdges[i + 1]) {
          idx = i;
          break;
        }
        if (i === bins - 1) idx = i;
      }
      if (isNormal) counts[idx].normal++;
      else counts[idx].attack++;
    });

    let tp = 0, fp = 0, tn = 0, fn = 0;
    windows.forEach((w) => {
      const pred = w.reconstruction_error > threshold;
      const actual = w.label !== "normal";
      if (pred && actual) tp++;
      else if (pred && !actual) fp++;
      else if (!pred && !actual) tn++;
      else fn++;
    });

    const maxCount = Math.max(1, ...counts.map((c) => c.normal + c.attack), overflow.normal + overflow.attack);
    const W = 900;
    const H = 130;
    const topPad = 36;
    const padL = 28;
    const padR = 88;
    const plotW = W - padL - padR;
    const barGap = 3;
    const innerW = plotW - (bins + 1) * barGap;
    const barWidths = counts.map((_, i) => {
      const span = uniqueEdges[i + 1] - uniqueEdges[i];
      return Math.max(8, (span / displayMax) * innerW);
    });
    const totalBarW = barWidths.reduce((s, w) => s + w, 0) + bins * barGap;
    const scale = innerW / totalBarW;
    const scaledWidths = barWidths.map((w) => w * scale);

    let xCursor = padL;
    const barPositions = scaledWidths.map((w) => {
      const x = xCursor;
      xCursor += w + barGap;
      return { x, w };
    });

    const thetaX = padL + (threshold / displayMax) * innerW;

    let bars = "";
    counts.forEach((c, i) => {
      const { x, w } = barPositions[i];
      const total = c.normal + c.attack;
      const nH = (c.normal / maxCount) * (H - 8);
      const aH = (c.attack / maxCount) * (H - 8);
      const baseY = topPad + H;
      if (c.normal) {
        bars += `<rect x="${x}" y="${baseY - nH}" width="${w}" height="${Math.max(nH, total ? 2 : 0)}" fill="rgba(139,115,85,0.72)" rx="1"/>`;
      }
      if (c.attack) {
        bars += `<rect x="${x}" y="${baseY - nH - aH}" width="${w}" height="${Math.max(aH, total ? 2 : 0)}" fill="rgba(255,77,0,0.78)" rx="1"/>`;
      }
    });

    const ox = xCursor;
    const oBarW = Math.max(12, scaledWidths[bins - 1] || 14);
    const oTotal = overflow.normal + overflow.attack;
    const onH = (overflow.normal / maxCount) * (H - 8);
    const oaH = (overflow.attack / maxCount) * (H - 8);
    const baseY = topPad + H;
    if (overflow.normal) {
      bars += `<rect x="${ox}" y="${baseY - onH}" width="${oBarW}" height="${Math.max(onH, 2)}" fill="rgba(139,115,85,0.45)" stroke="rgba(139,115,85,0.5)" stroke-width="0.5" stroke-dasharray="2 2" rx="1"/>`;
    }
    if (overflow.attack) {
      bars += `<rect x="${ox}" y="${baseY - onH - oaH}" width="${oBarW}" height="${Math.max(oaH, 2)}" fill="rgba(255,77,0,0.50)" stroke="rgba(255,77,0,0.5)" stroke-width="0.5" stroke-dasharray="2 2" rx="1"/>`;
    }

    let attackBinIdx = 0;
    let attackMax = 0;
    counts.forEach((c, i) => {
      if (c.attack > attackMax) {
        attackMax = c.attack;
        attackBinIdx = i;
      }
    });
    const attackBar = barPositions[attackBinIdx];
    const attackCx = attackBar ? attackBar.x + attackBar.w / 2 : padL + innerW * 0.85;

    let fpBinIdx = -1;
    counts.forEach((c, i) => {
      const mid = (uniqueEdges[i] + uniqueEdges[i + 1]) / 2;
      if (mid > threshold && c.normal > 0 && fpBinIdx < 0) fpBinIdx = i;
    });
    const fpBar = fpBinIdx >= 0 ? barPositions[fpBinIdx] : null;

    let fnBinIdx = -1;
    counts.forEach((c, i) => {
      const mid = (uniqueEdges[i] + uniqueEdges[i + 1]) / 2;
      if (mid < threshold && c.attack > 0) fnBinIdx = i;
    });
    const fnBar = fnBinIdx >= 0 ? barPositions[fnBinIdx] : null;

    const tick = (v) => padL + (v / displayMax) * innerW;
    const tickLabels = [0, threshold, 0.5, 1.0].filter((v) => v <= displayMax);

    let callouts = "";
    if (attackMax > 0) {
      callouts += `
        <rect x="${attackCx - 52}" y="4" width="104" height="22" rx="3" fill="rgba(13,17,23,0.92)" stroke="rgba(255,77,0,0.5)"/>
        <text x="${attackCx}" y="18" text-anchor="middle" fill="#FF6B1A" font-family="IBM Plex Sans" font-size="8" font-weight="600">${attackMax} ataques detectados</text>
        <line x1="${attackCx}" y1="26" x2="${attackCx}" y2="${baseY - (attackMax / maxCount) * (H - 8) - 4}" stroke="rgba(255,77,0,0.4)" stroke-width="1"/>
      `;
    }
    if (fp > 0 && fpBar) {
      const fx = fpBar.x + fpBar.w / 2;
      callouts += `
        <rect x="${Math.min(thetaX + 8, padL + innerW - 90)}" y="4" width="82" height="22" rx="3" fill="rgba(13,17,23,0.92)" stroke="rgba(232,163,23,0.5)"/>
        <text x="${Math.min(thetaX + 49, padL + innerW - 49)}" y="18" text-anchor="middle" fill="#E8A317" font-family="IBM Plex Sans" font-size="8" font-weight="600">${fp} FP — ruido</text>
        <line x1="${fx}" y1="26" x2="${fx}" y2="${baseY - 20}" stroke="rgba(232,163,23,0.4)" stroke-width="1"/>
      `;
    }
    if (fn > 0 && fnBar) {
      const fx = fnBar.x + fnBar.w / 2;
      callouts += `
        <rect x="${Math.max(padL, fx - 42)}" y="${baseY - 48}" width="84" height="22" rx="3" fill="rgba(13,17,23,0.92)" stroke="rgba(255,77,0,0.45)"/>
        <text x="${Math.max(padL, fx)}" y="${baseY - 34}" text-anchor="middle" fill="#FF4D00" font-family="IBM Plex Sans" font-size="8" font-weight="600">${fn} FN — no detectado</text>
      `;
    }

    svg.innerHTML = `
      <rect x="${padL}" y="${topPad}" width="${Math.max(0, thetaX - padL)}" height="${H}" fill="rgba(139,115,85,0.05)" rx="2"/>
      <rect x="${thetaX}" y="${topPad}" width="${padL + innerW - thetaX}" height="${H}" fill="rgba(255,77,0,0.04)" rx="2"/>
      ${bars}
      ${callouts}
      <line x1="${thetaX}" y1="${topPad}" x2="${thetaX}" y2="${baseY}" stroke="#FF6B1A" stroke-width="2" stroke-dasharray="5 4"/>
      <text x="${thetaX + 4}" y="${topPad + 12}" fill="#FF6B1A" font-family="IBM Plex Mono" font-size="9" font-weight="600">θ ${ArpegioData.fmtTheta(threshold)}</text>
      <line x1="${padL}" y1="${baseY}" x2="${padL + innerW}" y2="${baseY}" stroke="rgba(61,43,31,0.4)" stroke-width="0.5"/>
      ${tickLabels.map((v) => `<text x="${tick(v)}" y="${baseY + 14}" fill="${v === threshold ? '#FF6B1A' : '#6B7280'}" font-family="IBM Plex Mono" font-size="8">${v === threshold ? 'θ' : v.toFixed(v === 0 ? 2 : 1)}</text>`).join("")}
      <text x="${ox + oBarW / 2}" y="${baseY + 14}" text-anchor="middle" fill="#6B7280" font-family="IBM Plex Mono" font-size="7">&gt;${displayMax.toFixed(1)}</text>
      ${oTotal ? `<text x="${ox + oBarW + 4}" y="${topPad + H / 2}" fill="#6B7280" font-family="IBM Plex Mono" font-size="7">${oTotal} outlier${oTotal > 1 ? 's' : ''}</text>` : ""}
    `;

    renderHistLegend(threshold, displayMax, oTotal);
    renderHistVerdict(tp, fp, tn, fn, threshold);
    renderHistConfusion(tp, fp, tn, fn);
  }

  function renderAlertTable(alerts, selectedIdx = 0) {
    const tbody = document.getElementById("alerts-tbody");
    if (!tbody) return;
    const theta = ArpegioData.getState().threshold;

    tbody.innerHTML = alerts
      .map((a, i) => {
        const tier = ArpegioData.tierFromPriority(a.priority_score);
        const sel = i === selectedIdx ? "selected" : "";
        return `<tr class="${sel}" data-alert-idx="${i}" onclick="selectAlertRow(this, ${i})">
          <td><span style="font-family:var(--font-mono);font-size:13px;font-weight:500;color:${ArpegioData.scoreColor(a.reconstruction_error, theta)}">${ArpegioData.fmtScore(a.reconstruction_error)}</span></td>
          <td><span class="badge ${tier}">${ArpegioData.tierLabel(tier)}</span></td>
          <td style="font-size:12px;font-weight:500">${ArpegioData.threatName(a.inferred_threat)}</td>
          <td style="font-family:var(--font-mono);font-size:11px;color:var(--muted)">${ArpegioData.formatOrigin(a)}</td>
          <td style="font-family:var(--font-mono);font-size:10px;color:var(--muted)">${ArpegioData.fmtTime(a.t_start)}</td>
          <td><span class="badge ${tier}">Activa</span></td>
        </tr>`;
      })
      .join("");
  }

  function renderAlertDetail(alert) {
    if (!alert) return;
    const theta = ArpegioData.getState().threshold;
    const mse = alert.reconstruction_error;
    const excess = mse - theta;
    const barPct = Math.min(100, (mse / Math.max(mse, theta * 2)) * 100);

    setText("detail-title", `Detalle — ${ArpegioData.threatName(alert.inferred_threat)}`);
    setText("detail-mse", ArpegioData.fmtScore(mse));
    const excessText = excess > 0
      ? `excedido en +${excess.toFixed(3)}`
      : `bajo umbral (${excess.toFixed(3)})`;
    setText("detail-theta-line", `θ = ${ArpegioData.fmtTheta(theta)} · ${excessText}`);

    const bar = document.getElementById("detail-mse-bar");
    if (bar) {
      bar.style.width = `${barPct}%`;
      bar.style.background = excess > 0 ? "var(--danger)" : "var(--normal)";
    }

    const featuresEl = document.getElementById("detail-features");
    if (featuresEl) {
      featuresEl.innerHTML = ArpegioData.FEATURES.map(
        (key) => `<div class="feature-row">
          <span class="feature-key">${key}</span>
          <span class="feature-val ${ArpegioData.featureHighlight(key, alert)}">${ArpegioData.formatFeatureValue(key, alert[key])}</span>
        </div>`
      ).join("");
    }

    const inferEl = document.getElementById("detail-inference");
    if (inferEl) {
      inferEl.innerHTML = ArpegioData.threatInference(alert.inferred_threat) +
        ` Etiqueta ground-truth: <strong style="color:var(--text)">${alert.label}</strong>. Prioridad compuesta: <code style="font-family:var(--font-mono);color:var(--amber)">${Number(alert.priority_score).toFixed(2)}</code>.`;
    }

    const kaliScore = document.getElementById("topo-kali-score");
    if (kaliScore) {
      kaliScore.textContent = `MSE: ${ArpegioData.fmtScore(mse)}`;
    }
  }

  function renderSettings(metrics, labelConfig) {
    const theta = ArpegioData.fmtTheta(metrics.threshold);
    const fp = metrics.per_class?.normal;

    setText("settings-theta", `${theta} (percentil ${metrics.threshold_percentile})`);
    setText("settings-auc", Number(metrics.auc_roc).toFixed(3));
    setText("settings-window", `${labelConfig.window_size} tramas · victima2 replay`);
    setText("settings-train", `${metrics.train_size} train · ${metrics.val_size} val · ${metrics.test_size} test`);

  }

  function renderAgentSummary(metrics, alerts) {
    const el = document.getElementById("agent-summary-text");
    if (!el) return;
    const fp = metrics.per_class?.normal;
    const theta = ArpegioData.fmtTheta(metrics.threshold);
    const fpPct = fp ? ArpegioData.fmtPct(fp.rate_pct) : "—";
    el.innerHTML = `El modelo ha observado <strong>${alerts.length} alertas</strong> en el replay de victima2 (${metrics.test_size} ventanas). La tasa de falsos positivos actual (${fpPct}) ${fp && fp.rate_pct <= 5 ? "está dentro del rango aceptable" : "requiere revisión"}, con θ = ${theta} (p${metrics.threshold_percentile}).`;
  }

  function renderTimeline(labelConfig) {
    const tl = document.getElementById("red-tl");
    if (!tl || !labelConfig?.label_intervals?.length) return;

    const intervals = labelConfig.label_intervals;
    const t0 = intervals[0][0];
    const t1 = intervals[intervals.length - 1][1];
    const total = t1 - t0;

    tl.innerHTML = "";
    intervals.forEach(([start, end, label]) => {
      const d = document.createElement("div");
      const w = ((end - start) / total) * 100;
      d.style.cssText = `flex-basis:${w.toFixed(2)}%;height:100%;border-radius:2px;`;
      const isNormal = label === "normal";
      d.style.background = LABEL_COLORS[label] || "rgba(255,77,0,0.45)";
      if (!isNormal) {
        d.style.border = "1px solid rgba(255,77,0,0.35)";
      }
      d.title = `${label} · ${ArpegioData.fmtClock(start)}–${ArpegioData.fmtClock(end)}`;
      tl.appendChild(d);
    });

    const labels = document.getElementById("red-tl-labels");
    if (labels) {
      const marks = [0, 0.25, 0.5, 0.75, 1].map((f) => {
        const t = t0 + total * f;
        return `<span style="font-family:var(--font-mono);font-size:9px;color:var(--faint)">${ArpegioData.fmtClock(t)}</span>`;
      });
      labels.innerHTML = marks.join("");
    }
  }

  function setNodeState(nodeId, dotState, statusText, useAlertIcon = false) {
    const item = document.getElementById(`red-node-${nodeId}`);
    if (!item) return;
    const dot = item.querySelector(".node-dot");
    const status = item.querySelector(".node-status");
    if (dot) dot.className = `node-dot ${dotState}`;
    if (!status) return;
    if (useAlertIcon && dotState === "alert") {
      status.className = "node-status alert icon-label";
      status.innerHTML =
        ArpegioIcons.icon("alert-triangle", { size: 12 }) + `<span>${statusText}</span>`;
    } else {
      status.className = `node-status ${dotState}`;
      status.textContent = statusText;
    }
  }

  function renderNetwork(alerts, metrics) {
    const dominant = ArpegioData.dominantThreat(alerts);
    const topAlert = alerts[0];
    const threatKey = dominant?.[0];
    const threatCount = dominant?.[1] || 0;
    const threatShort = THREAT_LABEL_SHORT[threatKey] || "ANOMALÍA";

    setNodeState("alpine1", "normal", "Normal");
    setNodeState(
      "alpine2",
      alerts.length ? "warn" : "normal",
      alerts.length ? `Sensor · ${alerts.length} alertas` : "Sensor activo"
    );
    setNodeState(
      "kali",
      threatCount ? "alert" : "normal",
      threatCount ? `${threatShort} · ${threatCount}×` : "Sin actividad",
      Boolean(threatCount)
    );
    setNodeState("ovs", "warn", "Espejo L2");

    const kaliThreat = document.getElementById("topo-kali-threat");
    if (kaliThreat) {
      kaliThreat.textContent = threatCount ? threatShort : "INACTIVO";
      kaliThreat.setAttribute("fill", threatCount ? "#FF4D00" : "#6B7280");
    }

    const alpine2Status = document.getElementById("topo-alpine2-status");
    if (alpine2Status) {
      alpine2Status.textContent = alerts.length ? "MONITOREO" : "NORMAL";
      alpine2Status.setAttribute("fill", alerts.length ? "#E8A317" : "#8B7355");
    }

    const kaliScore = document.getElementById("topo-kali-score");
    if (kaliScore && topAlert) {
      kaliScore.textContent = `MSE: ${ArpegioData.fmtScore(topAlert.reconstruction_error)}`;
    } else if (kaliScore) {
      kaliScore.textContent = "MSE: —";
    }

    const kaliNode = document.getElementById("topo-kali-node");
    if (kaliNode) {
      kaliNode.setAttribute("stroke", threatCount ? "#FF4D00" : "rgba(61,43,31,0.45)");
      if (threatCount) {
        kaliNode.setAttribute("filter", "url(#f-danger)");
      } else {
        kaliNode.removeAttribute("filter");
      }
    }

    if (typeof ArpegioIcons !== "undefined") {
      ArpegioIcons.hydrateIcons(document.getElementById("red-node-kali"));
    }
  }

  function agentBullet(text) {
    return `<div class="agent-bullet"><span data-icon="chevron-right" data-icon-size="12" data-icon-class="icon"></span><span>${text}</span></div>`;
  }

  function renderAgentCalibrations(metrics, labScenarios) {
    const el = document.getElementById("agent-calibration-bullets");
    if (!el) return;

    const fp = metrics.per_class?.normal;
    const theta = ArpegioData.fmtTheta(metrics.threshold);
    const p = metrics.threshold_percentile || 95;
    const pcts = labScenarios?.theta_percentiles || {};
    const bullets = [];

    bullets.push(
      `θ operativo: <span style="color:var(--amber)">${theta}</span> (p${p}) · regla MSE &gt; θ`
    );

    if (fp) {
      const fpLine =
        fp.rate_pct <= 5
          ? `FP en normales: ${ArpegioData.fmtPct(fp.rate_pct)} (${fp.detected}/${fp.total}) — aceptable`
          : `FP en normales: ${ArpegioData.fmtPct(fp.rate_pct)} — subir a p99 (θ≈${ArpegioData.fmtTheta(pcts["99"])}) reduciría ruido`;
      bullets.push(fpLine);
    }

    const portScan = metrics.per_class?.port_scan;
    if (portScan && portScan.detected === 0 && portScan.total > 0) {
      bullets.push(
        `FN documentado: port_scan ${portScan.detected}/${portScan.total} — bajar θ mejoraría recall pero sube FP`
      );
    }

    if (pcts["90"] && pcts["99"]) {
      bullets.push(
        `Rango validación: p90=${ArpegioData.fmtTheta(pcts["90"])} · p95=${theta} · p99=${ArpegioData.fmtTheta(pcts["99"])}`
      );
    }

    el.innerHTML = bullets.map(agentBullet).join("");
    if (typeof ArpegioIcons !== "undefined") {
      ArpegioIcons.hydrateIcons(el);
    }
  }

  function renderAgentReplayLog(alerts) {
    const el = document.getElementById("agent-replay-log");
    if (!el) return;

    const top = alerts.slice(0, 6);
    if (!top.length) {
      el.innerHTML = `<div style="font-size:11px;color:var(--faint);padding:8px 0">Sin alertas en el replay.</div>`;
      return;
    }

    el.innerHTML = top
      .map((a) => {
        const tier = ArpegioData.tierFromPriority(a.priority_score);
        return `<div class="intervention-item">
          <div class="intervention-ts">${ArpegioData.fmtTime(a.t_start)}</div>
          <div class="intervention-body">
            <div class="intervention-action">${ArpegioData.threatName(a.inferred_threat)} · ${a.source}</div>
            <div class="intervention-detail">MSE=${ArpegioData.fmtScore(a.reconstruction_error)} · label ${a.label} · prioridad ${Number(a.priority_score).toFixed(2)}</div>
          </div>
          <span class="badge ${tier}">${ArpegioData.tierLabel(tier)}</span>
        </div>`;
      })
      .join("");
  }

  const SCENARIO_ICONS = {
    arp_spoof: "zap",
    mac_flood: "layers",
    port_scan: "search",
    arp_recon: "radar",
    normal: "check-circle",
  };

  function renderLab(labScenarios) {
    const grid = document.getElementById("scenario-grid");
    if (!grid || !labScenarios?.scenarios?.length) return null;

    grid.innerHTML = labScenarios.scenarios
      .map((s, i) => {
        const extraClass = s.danger ? "danger-btn" : "";
        const selected = i === 0 ? "selected" : "";
        const mseTag = `MSE ${ArpegioData.fmtScore(s.reconstruction_error)}`;
        const detectTag = s.detected_at_default_theta
          ? "· genera alerta con θ p95"
          : "· no alerta con θ p95";

        if (s.id === "normal") {
          return `<div class="scenario-btn ${selected}" style="grid-column:span 2" data-scenario-id="${s.id}" onclick="selectScenario(this,'${s.id}')">
            <div style="display:flex;gap:16px;align-items:center">
              <div class="scenario-icon" data-icon="check-circle" data-icon-size="18"></div>
              <div>
                <div class="scenario-name">${s.display_name}</div>
                <div class="scenario-desc">${s.description}<br><span class="scenario-mse-hint">${mseTag} ${detectTag}</span></div>
              </div>
            </div>
          </div>`;
        }

        return `<div class="scenario-btn ${extraClass} ${selected}" data-scenario-id="${s.id}" onclick="selectScenario(this,'${s.id}')">
          <div class="scenario-icon" data-icon="${SCENARIO_ICONS[s.id] || "zap"}" data-icon-size="18"></div>
          <div class="scenario-name">${s.display_name}</div>
          <div class="scenario-desc">${s.description}<br><span class="scenario-mse-hint">${mseTag} ${detectTag}</span></div>
        </div>`;
      })
      .join("");

    if (typeof ArpegioIcons !== "undefined") {
      ArpegioIcons.hydrateIcons(grid);
    }

    const p = labScenarios.threshold_percentile || 95;
    renderLabTheta(p);

    const barMax = document.getElementById("lab-bar-max");
    const maxMse = Math.max(
      ...labScenarios.scenarios.map((s) => s.reconstruction_error),
      labScenarios.threshold * 2,
      1.5
    );
    if (barMax) barMax.textContent = maxMse.toFixed(2);

    return labScenarios.scenarios[0].id;
  }

  function renderLabTheta(percentile) {
    const p = percentile || ArpegioData.getState().labScenarios?.threshold_percentile || 95;
    const theta = ArpegioData.getThetaForPercentile(p);
    setText("theta-display", `${ArpegioData.fmtTheta(theta)} (p${p})`);
    setText("bar-theta", ArpegioData.fmtTheta(theta));
    const slider = document.getElementById("theta-slider");
    if (slider) slider.value = ArpegioData.getSliderIndexForPercentile(p);
  }

  return {
    renderNav,
    renderMonitor,
    renderAlertStrip,
    renderAlertTable,
    renderAlertDetail,
    renderSettings,
    renderAgentSummary,
    renderAgentCalibrations,
    renderAgentReplayLog,
    renderNetwork,
    renderTimeline,
    renderLab,
    renderLabTheta,
  };
})();
