/** Carga y utilidades de datos reales del pipeline ARPegio. */
const ArpegioData = (function () {
  const FEATURES = [
    "arp_rate",
    "arp_req_reply_ratio",
    "mac_entropy",
    "unique_src_macs",
    "unique_dst_macs",
    "frame_len_mean",
    "frame_len_std",
    "frame_len_min",
    "frame_len_max",
    "broadcast_ratio",
    "total_packets",
  ];

  const THREAT_LABELS = {
    mac_flood: "MAC Flood",
    arp_spoof: "ARP Spoofing",
    port_scan: "Escaneo SYN",
    arp_recon: "Recon ARP",
    unknown: "Desconocido",
  };

  const THREAT_INFERENCE = {
    mac_flood:
      "Saturación de tabla CAM: muchas MACs únicas en una ventana corta. Patrón típico de MAC flooding sobre el segmento.",
    arp_spoof:
      "Alta tasa ARP con desbalance request/reply. Consistente con envenenamiento de caché ARP (MITM L2).",
    port_scan:
      "Tráfico homogéneo en longitud de trama. Compatible con barrido de puertos a nivel L2/L3.",
    arp_recon:
      "Actividad ARP elevada con ratio request/reply alto. Descubrimiento de hosts en el /24.",
    unknown:
      "Anomalía en error de reconstrucción sin patrón L2 claro en las heurísticas del priorizador.",
  };

  const FILTER_MAP = {
    Todas: () => true,
    Crítico: (a) => tierFromPriority(a.priority_score) === "crit",
    Media: (a) => tierFromPriority(a.priority_score) === "med",
    Baja: (a) => tierFromPriority(a.priority_score) === "low",
    "ARP Spoof": (a) => a.inferred_threat === "arp_spoof" || a.label === "arp_spoof",
    "MAC Flood": (a) => a.inferred_threat === "mac_flood" || a.label === "mac_flood",
    Escaneo: (a) => a.inferred_threat === "port_scan" || a.label === "port_scan",
    "Recon ARP": (a) => a.inferred_threat === "arp_recon" || a.label === "arp_recon",
  };

  const THETA_PERCENTILES = [70, 75, 80, 85, 90, 95, 99];

  let state = {
    metrics: null,
    alerts: [],
    windowScores: null,
    labelConfig: null,
    labScenarios: null,
    threshold: 0.114,
  };

  function parseCSV(text) {
    const lines = text.trim().split("\n");
    const headers = lines[0].split(",");
    return lines.slice(1).map((line) => {
      const values = line.split(",");
      const row = {};
      headers.forEach((h, i) => {
        const v = values[i];
        if (["t_start", "t_end", "reconstruction_error", "severity", "impact", "frequency", "priority_score"].includes(h) ||
            FEATURES.includes(h)) {
          row[h] = v === "" ? null : Number(v);
        } else if (h === "is_anomaly") {
          row[h] = v === "True";
        } else {
          row[h] = v;
        }
      });
      return row;
    });
  }

  async function fetchJSON(path) {
    const res = await fetch(path);
    if (!res.ok) throw new Error(`No se pudo cargar ${path} (${res.status})`);
    return res.json();
  }

  async function fetchText(path) {
    const res = await fetch(path);
    if (!res.ok) throw new Error(`No se pudo cargar ${path} (${res.status})`);
    return res.text();
  }

  async function load() {
    const [metrics, alertsText, labelConfig] = await Promise.all([
      fetchJSON("results/metrics.json"),
      fetchText("results/alerts_prioritized.csv"),
      fetchJSON("config/label_intervals.json"),
    ]);

    let windowScores = null;
    let labScenarios = null;
    try {
      windowScores = await fetchJSON("results/window_scores.json");
    } catch {
      windowScores = null;
    }
    try {
      labScenarios = await fetchJSON("results/lab_scenarios.json");
    } catch {
      labScenarios = null;
    }

    const alerts = parseCSV(alertsText).sort(
      (a, b) => b.priority_score - a.priority_score
    );

    state = {
      metrics,
      alerts,
      windowScores,
      labelConfig,
      labScenarios,
      threshold: metrics.threshold,
    };
    return state;
  }

  function getState() {
    return state;
  }

  function fmtTheta(v) {
    return Number(v).toFixed(3);
  }

  function fmtPct(v, digits = 1) {
    return `${Number(v).toFixed(digits)}%`;
  }

  function fmtScore(v) {
    const n = Number(v);
    if (n >= 10) return n.toFixed(1);
    if (n >= 1) return n.toFixed(2);
    return n.toFixed(3);
  }

  function fmtTime(epoch) {
    const d = new Date(Number(epoch) * 1000);
    const p = (n) => String(n).padStart(2, "0");
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }

  function fmtClock(epoch) {
    const d = new Date(Number(epoch) * 1000);
    const p = (n) => String(n).padStart(2, "0");
    return `${p(d.getHours())}:${p(d.getMinutes())}`;
  }

  function threatName(key) {
    return THREAT_LABELS[key] || key;
  }

  function tierFromPriority(score) {
    const s = Number(score);
    if (s >= 0.75) return "crit";
    if (s >= 0.55) return "med";
    return "low";
  }

  function tierLabel(tier) {
    return { crit: "Crítico", med: "Media", low: "Baja" }[tier] || "Baja";
  }

  function scoreColor(mse, threshold) {
    const r = Number(mse) / Math.max(Number(threshold), 1e-9);
    if (r >= 1.5) return "var(--danger)";
    if (r >= 1) return "var(--amber)";
    return "var(--low)";
  }

  function formatOrigin(alert) {
    const t = alert.inferred_threat;
    if (t === "mac_flood") {
      return `${alert.unique_src_macs} MACs · ${alert.source}`;
    }
    if (t === "arp_spoof") {
      return `arp ${alert.arp_rate} · ${alert.unique_src_macs} MAC`;
    }
    if (t === "arp_recon") {
      return `ARP sweep · ratio ${Number(alert.arp_req_reply_ratio).toFixed(2)}`;
    }
    if (t === "port_scan") {
      return `scan · σ ${Number(alert.frame_len_std).toFixed(1)} B`;
    }
    return `${alert.source} · 50 tramas`;
  }

  function formatFeatureValue(key, value) {
    if (value == null) return "—";
    if (key === "total_packets" || key.includes("unique_") || key.includes("_min") || key.includes("_max")) {
      return String(Math.round(value));
    }
    if (key.startsWith("frame_len")) {
      return `${Number(value).toFixed(1)} B`;
    }
    if (key.includes("ratio") || key === "arp_rate") {
      return Number(value).toFixed(3);
    }
    return Number(value).toFixed(2);
  }

  function featureHighlight(key, alert) {
    const t = alert.inferred_threat;
    if (t === "mac_flood" && (key === "unique_src_macs" || key === "mac_entropy")) return "hi";
    if (t === "arp_spoof" && (key === "arp_rate" || key === "arp_req_reply_ratio")) return "hi";
    if (t === "arp_recon" && key === "arp_rate") return "hi";
    if (t === "port_scan" && key === "frame_len_std") return "hi";
    return "";
  }

  function countByTier(alerts) {
    const counts = { crit: 0, med: 0, low: 0 };
    alerts.forEach((a) => counts[tierFromPriority(a.priority_score)]++);
    return counts;
  }

  function filterAlerts(name) {
    const fn = FILTER_MAP[name] || FILTER_MAP.Todas;
    return state.alerts.filter(fn);
  }

  function getLabScenarios() {
    return state.labScenarios?.scenarios || [];
  }

  function getLabScenario(id) {
    return state.labScenarios?.scenarios?.find((s) => s.id === id) || null;
  }

  function getPercentileFromSliderIndex(idx) {
    return THETA_PERCENTILES[idx] ?? 95;
  }

  function getSliderIndexForPercentile(p) {
    const i = THETA_PERCENTILES.indexOf(p);
    return i >= 0 ? i : THETA_PERCENTILES.indexOf(95);
  }

  function getThetaForPercentile(p) {
    const key = String(p);
    const fromLab = state.labScenarios?.theta_percentiles?.[key];
    if (fromLab != null) return fromLab;
    return state.threshold;
  }

  function formatLabFeatureSummary(features) {
    const keys = [
      "arp_rate",
      "arp_req_reply_ratio",
      "unique_src_macs",
      "mac_entropy",
      "frame_len_mean",
    ];
    return keys
      .map((k) => `${k}=${formatFeatureValue(k, features[k])}`)
      .join(" · ");
  }

  function exportAlertsCSV() {
    const header = Object.keys(state.alerts[0] || {}).join(",");
    const rows = state.alerts.map((a) =>
      Object.values(a)
        .map((v) => (typeof v === "string" && v.includes(",") ? `"${v}"` : v))
        .join(",")
    );
    const blob = new Blob([[header, ...rows].join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "alerts_prioritized.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportAlertJSON(alert) {
    if (!alert) return;
    const blob = new Blob([JSON.stringify(alert, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const threat = alert.inferred_threat || alert.label || "alert";
    a.href = url;
    a.download = `alert_${threat}_${Math.round(alert.t_start)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function dominantThreat(alerts) {
    const counts = {};
    alerts.forEach((a) => {
      const t = a.inferred_threat || a.label || "unknown";
      counts[t] = (counts[t] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1])[0] || null;
  }

  return {
    FEATURES,
    load,
    getState,
    fmtTheta,
    fmtPct,
    fmtScore,
    fmtTime,
    fmtClock,
    threatName,
    tierFromPriority,
    tierLabel,
    scoreColor,
    formatOrigin,
    formatFeatureValue,
    featureHighlight,
    countByTier,
    filterAlerts,
    exportAlertsCSV,
    exportAlertJSON,
    dominantThreat,
    getLabScenarios,
    getLabScenario,
    getThetaForPercentile,
    getPercentileFromSliderIndex,
    getSliderIndexForPercentile,
    THETA_PERCENTILES,
    formatLabFeatureSummary,
    threatInference: (k) => THREAT_INFERENCE[k] || THREAT_INFERENCE.unknown,
  };
})();
