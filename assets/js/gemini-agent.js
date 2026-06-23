/** Agente Gemini BYOK — informes preventivo / reactivo con contexto del pipeline. */
const ArpegioGemini = (function () {
  const MODEL = "gemini-3.1-flash-lite";
  const API_URL = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent`;
  const STORAGE_KEY = "arpegio_gemini_key";

  let apiKey = "";

  const SYSTEM_PROMPTS = {
    preventivo: `Eres un analista SOC experto en redes IEEE 802.3 y detección de anomalías L2.
Trabajas sobre ARPegio: autoencoder no supervisado + priorización de alertas en un lab GNS3 (192.168.1.0/24).
Modo PREVENTIVO: recomiendas calibración de θ, reducción de falsos positivos y validación antes de incidentes.
Responde siempre en español, conciso, con viñetas. Usa LaTeX para símbolos matemáticos: $\\theta$, $\\mathrm{MSE}$, $\\mathrm{FP}$, $\\mathrm{FN}$ (delimitadores $...$).
No inventes cifras: usa solo el contexto proporcionado.
Si falta información, dilo explícitamente.`,

    reactivo: `Eres un analista SOC experto en mitigación L2 en laboratorios virtuales.
Trabajas sobre ARPegio tras una alerta del autoencoder (MSE > θ).
Modo REACTIVO: propones pasos prácticos de contención en el lab (Alpine, Kali, OVS) sin asumir firewalls empresariales.
Responde en español con pasos numerados. Usa LaTeX inline ($\\theta$, $\\mathrm{MSE}$) para magnitudes técnicas.
Sé específico según el tipo de amenaza (arp_spoof, mac_flood, port_scan, arp_recon).
No inventes métricas ni acciones ya ejecutadas.`,
  };

  function loadKeyFromSession() {
    try {
      const stored = sessionStorage.getItem(STORAGE_KEY);
      if (stored) apiKey = stored;
    } catch {
      /* sessionStorage no disponible */
    }
  }

  function setApiKey(key) {
    apiKey = (key || "").trim();
    try {
      if (apiKey) sessionStorage.setItem(STORAGE_KEY, apiKey);
      else sessionStorage.removeItem(STORAGE_KEY);
    } catch {
      /* ignore */
    }
  }

  function clearApiKey() {
    setApiKey("");
  }

  function hasApiKey() {
    return Boolean(apiKey);
  }

  function getApiKeyFromInputs() {
    const main = document.getElementById("api-key-input");
    const settings = document.getElementById("settings-api-key-input");
    const key = (main?.value || settings?.value || apiKey || "").trim();
    return key;
  }

  function syncInputs(value) {
    const main = document.getElementById("api-key-input");
    const settings = document.getElementById("settings-api-key-input");
    if (main && main.value !== value) main.value = value;
    if (settings && settings.value !== value) settings.value = value;
  }

  function init() {
    loadKeyFromSession();
    if (apiKey) syncInputs(apiKey);
  }

  function pickFeatures(alert) {
    if (!alert) return {};
    return ArpegioData.FEATURES.reduce((acc, key) => {
      acc[key] = alert[key];
      return acc;
    }, {});
  }

  function buildUserPrompt(state, mode, alert) {
    const { metrics, alerts, labScenarios } = state;
    const perClass = metrics.per_class || {};
    const top5 = alerts.slice(0, 5).map((a) => ({
      threat: a.inferred_threat,
      label: a.label,
      mse: a.reconstruction_error,
      priority: a.priority_score,
      t_start: a.t_start,
    }));
    const scenarios = (labScenarios?.scenarios || []).map((s) => ({
      id: s.id,
      mse: s.reconstruction_error,
      detected_at_theta: s.detected_at_default_theta,
      note: s.note,
    }));

    const shared = `Métricas: θ=${metrics.threshold} (p${metrics.threshold_percentile}), AUC=${metrics.auc_roc}, test=${metrics.test_size} ventanas
FP en normales: ${perClass.normal?.rate_pct ?? "—"}% (${perClass.normal?.detected ?? "—"}/${perClass.normal?.total ?? "—"})
Detección por clase: ${JSON.stringify(perClass)}
Percentiles θ validación: ${JSON.stringify(labScenarios?.theta_percentiles || {})}
Escenarios laboratorio: ${JSON.stringify(scenarios)}
Top 5 alertas priorizadas: ${JSON.stringify(top5)}`;

    if (mode === "preventivo") {
      return `${shared}

Genera un informe PREVENTIVO para el operador:
1) Evaluación del θ actual (trade-off FP/FN; menciona port_scan si aplica)
2) 3–5 recomendaciones de calibración o monitoreo proactivo
3) Qué escenarios del laboratorio re-ejecutar para validar cambios`;
    }

    const a = alert || alerts[0];
    if (!a) {
      return `${shared}\n\nNo hay alertas en el replay. Indica que no puedes generar un plan reactivo sin una alerta.`;
    }

    return `${shared}

Alerta seleccionada para mitigación:
${JSON.stringify({
  threat: a.inferred_threat,
  label: a.label,
  mse: a.reconstruction_error,
  theta: metrics.threshold,
  priority: a.priority_score,
  source: a.source,
  features: pickFeatures(a),
})}

Topología: Kali 192.168.1.99 (atacante), Alpine-1 .10, Alpine-2 .20 (sensor victima2), OVS troncal. Captura pasiva L2.

Genera un plan REACTIVO:
1) Confirmación de amenaza (breve)
2) Pasos de contención en el lab (numerados, según ${a.inferred_threat})
3) Verificación post-mitigación (qué observar en MSE/features)
4) Riesgo residual y seguimiento`;
  }

  async function generate(mode, state, alert) {
    const key = getApiKeyFromInputs();
    if (!key) throw new Error("Introduce una API key antes de generar el informe");
    setApiKey(key);

    const body = {
      systemInstruction: {
        parts: [{ text: SYSTEM_PROMPTS[mode] || SYSTEM_PROMPTS.preventivo }],
      },
      contents: [
        {
          role: "user",
          parts: [{ text: buildUserPrompt(state, mode, alert) }],
        },
      ],
      generationConfig: {
        temperature: 0.35,
        maxOutputTokens: 2048,
      },
    };

    const res = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": key,
      },
      body: JSON.stringify(body),
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = data.error?.message || `Error HTTP ${res.status}`;
      throw new Error(msg);
    }

    const text = (data.candidates || [])
      .flatMap((c) => c.content?.parts || [])
      .map((p) => p.text || "")
      .join("")
      .trim();

    if (!text) throw new Error("Gemini devolvió una respuesta vacía");
    return text;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /** Reserva bloques LaTeX antes del formateo Markdown/HTML. */
  function extractMath(text) {
    const blocks = [];
    let n = 0;

    const withoutDisplay = text.replace(/\$\$([\s\S]+?)\$\$/g, (_, math) => {
      const id = `\uE000MATH${n++}\uE001`;
      blocks.push({ id, math, display: true });
      return id;
    });

    const withoutInline = withoutDisplay.replace(/(?<![\\$])\$([^$\n]+?)\$(?!\$)/g, (_, math) => {
      const id = `\uE000MATH${n++}\uE001`;
      blocks.push({ id, math, display: false });
      return id;
    });

    return { text: withoutInline, blocks };
  }

  function restoreMath(html, blocks) {
    let out = html;
    blocks.forEach(({ id, math, display }) => {
      const delim = display ? `$$${math}$$` : `$${math}$`;
      out = out.split(id).join(delim);
    });
    return out;
  }

  function formatResponse(text) {
    const lines = escapeHtml(text).split("\n");
    const html = [];
    let inList = false;

    const closeList = () => {
      if (inList) {
        html.push("</ul>");
        inList = false;
      }
    };

    lines.forEach((line) => {
      const trimmed = line.trim();
      if (!trimmed) {
        closeList();
        html.push("<br>");
        return;
      }

      let content = trimmed
        .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
        .replace(/`([^`]+)`/g, '<code style="font-family:var(--font-mono);color:var(--amber)">$1</code>');

      if (/^#{1,3}\s+/.test(trimmed)) {
        closeList();
        content = content.replace(/^#{1,3}\s+/, "");
        html.push(`<div style="font-weight:600;color:var(--text);margin:12px 0 6px">${content}</div>`);
        return;
      }

      if (/^[-*•]\s+/.test(trimmed) || /^\d+[.)]\s+/.test(trimmed)) {
        if (!inList) {
          html.push('<ul style="margin:6px 0 6px 18px;padding:0">');
          inList = true;
        }
        content = content.replace(/^[-*•]\s+/, "").replace(/^\d+[.)]\s+/, "");
        html.push(`<li style="margin-bottom:4px">${content}</li>`);
        return;
      }

      closeList();
      html.push(`<p style="margin:0 0 8px">${content}</p>`);
    });

    closeList();
    return html.join("");
  }

  function renderMath(element) {
    if (!element || typeof renderMathInElement !== "function") return;
    renderMathInElement(element, {
      delimiters: [
        { left: "$$", right: "$$", display: true },
        { left: "$", right: "$", display: false },
        { left: "\\(", right: "\\)", display: false },
        { left: "\\[", right: "\\]", display: true },
      ],
      throwOnError: false,
      errorColor: "#FF4D00",
      strict: false,
    });
  }

  function renderIntoElement(element, text) {
    if (!element) return;
    const { text: protectedText, blocks } = extractMath(text);
    element.innerHTML = restoreMath(formatResponse(protectedText), blocks);
    renderMath(element);
  }

  function setAgentDot(state) {
    const dot = document.querySelector(".agent-status-dot");
    if (!dot) return;
    dot.style.background =
      state === "error" ? "var(--danger)" : state === "ready" ? "var(--normal)" : "var(--amber)";
    dot.style.animation = state === "loading" ? "dot-pulse 1.5s ease-in-out infinite" : "none";
  }

  return {
    MODEL,
    init,
    setApiKey,
    clearApiKey,
    hasApiKey,
    getApiKeyFromInputs,
    syncInputs,
    generate,
    formatResponse,
    renderIntoElement,
    renderMath,
    setAgentDot,
  };
})();
