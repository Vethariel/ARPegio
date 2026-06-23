/** Agente Gemini BYOK — informes, herramientas, chat y streaming. */
const ArpegioGemini = (function () {
  const MODEL = "gemini-3.1-flash-lite";
  const API_BASE = "https://generativelanguage.googleapis.com/v1beta/models";
  const STORAGE_KEY = "arpegio_gemini_key";
  const MAX_TOOL_ROUNDS = 6;

  let apiKey = "";
  let lastResult = null;
  let chatContents = [];
  let sessionOptions = null;

  const THETA_PERCENTILES = ["70", "75", "80", "85", "90", "95", "99"];

  const RESPONSE_SCHEMA = {
    type: "OBJECT",
    properties: {
      veredicto: {
        type: "STRING",
        enum: ["confirmada", "sospechosa", "falso_positivo_probable", "indeterminada"],
      },
      confianza: { type: "NUMBER" },
      theta_recomendado_percentil: {
        type: "STRING",
        enum: [...THETA_PERCENTILES, "ninguno"],
      },
      escenario_lab_sugerido: {
        type: "STRING",
        enum: ["arp_spoof", "mac_flood", "port_scan", "arp_recon", "normal", "ninguno"],
      },
      resumen: { type: "STRING" },
      acciones: { type: "ARRAY", items: { type: "STRING" } },
      comandos_lab: { type: "ARRAY", items: { type: "STRING" } },
    },
    required: ["veredicto", "confianza", "resumen", "acciones", "comandos_lab"],
  };

  const VEREDICTO_LABELS = {
    confirmada: "Confirmada",
    sospechosa: "Sospechosa",
    falso_positivo_probable: "FP probable",
    indeterminada: "Indeterminada",
  };

  const VEREDICTO_TIER = {
    confirmada: "crit",
    sospechosa: "med",
    falso_positivo_probable: "low",
    indeterminada: "med",
  };

  const MODE_GUIDANCE = {
    preventivo: {
      focus:
        "Calibración proactiva de θ, reducción de FP, validación antes de incidentes. NO planes de contención activa.",
      resumen_sections:
        "1) Evaluación del θ actual y trade-off FP/FN · 2) Simulación de percentiles (usa simulate_theta si hace falta) · 3) Escenarios lab a re-ejecutar · 4) Checklist pre-incidente",
      acciones_style: "Pasos de calibración y monitoreo preventivo",
      comandos_lab: "Lista vacía salvo verificación pasiva",
      veredicto_hint: "Usa indeterminada salvo análisis de alerta concreta",
    },
    reactivo: {
      focus:
        "Contención L2 tras alerta o anomalía detectada. Playbook Alpine/Kali/OVS. Criterios de cierre operativo.",
      resumen_sections:
        "1) Confirmación de amenaza · 2) Contención inmediata (pasos numerados) · 3) Verificación post-mitigación (MSE/features) · 4) Riesgo residual",
      acciones_style: "Pasos de mitigación ordenados por urgencia",
      comandos_lab: "Comandos shell concretos para el lab (ip, arp, ovs-vsctl, etc.)",
      veredicto_hint: "confirmada | sospechosa | falso_positivo_probable según evidencia",
    },
  };

  const SYSTEM_PROMPTS = {
    preventivo: `Eres analista SOC experto en IEEE 802.3 y detección L2 con ARPegio (autoencoder + priorización, lab GNS3).
Modo PREVENTIVO: calibración y prevención, no mitigación activa.
Tienes herramientas: simulate_theta, get_alert, list_alerts, get_lab_scenario — úsalas para datos precisos antes del informe.
Responde en español. LaTeX en resumen ($\\theta$, $\\mathrm{MSE}$, $\\mathrm{FP}$, $\\mathrm{FN}$).
El informe final debe ser JSON según el esquema.`,

    reactivo: `Eres analista SOC experto en mitigación L2 en laboratorio virtual (Alpine, Kali .99, OVS, victima2).
Modo REACTIVO: contención tras MSE > θ. Playbooks por arp_spoof, mac_flood, port_scan, arp_recon.
Tienes herramientas: simulate_theta, get_alert, get_lab_scenario, list_alerts.
Responde en español. LaTeX en resumen. comandos_lab obligatorio con comandos reales cuando aplique.
El informe final debe ser JSON según el esquema.`,

    chat: `Eres el copiloto ARPegio en español. Respuestas concisas con LaTeX ($\\theta$, $\\mathrm{MSE}$).
Puedes usar herramientas para datos del pipeline. No inventes métricas.
Si el operador pregunta por calibración → modo preventivo. Si pide mitigación → modo reactivo.`,
  };

  function loadKeyFromSession() {
    try {
      const stored = sessionStorage.getItem(STORAGE_KEY);
      if (stored) apiKey = stored;
    } catch {
      /* ignore */
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
    return (main?.value || settings?.value || apiKey || "").trim();
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

  function isStreamingEnabled() {
    const el = document.getElementById("agent-stream-toggle");
    return el ? el.checked : true;
  }

  function buildRichContext(state, mode, options = {}) {
    const { metrics, alerts, labScenarios, labelConfig } = state;
    const {
      intent = "general",
      alert = null,
      labRun = null,
      labScenario = null,
      sliderTheta = null,
      sliderPercentile = null,
    } = options;

    const defaultTheta = metrics.threshold;
    const ctx = {
      intent,
      mode,
      metrics: {
        theta_operativo: defaultTheta,
        theta_percentile: metrics.threshold_percentile,
        auc_roc: metrics.auc_roc,
        test_size: metrics.test_size,
        per_class: metrics.per_class || {},
      },
      theta_slider: sliderTheta
        ? { percentil: sliderPercentile, valor: sliderTheta }
        : null,
      matriz_confusion_theta_operativo:
        ArpegioData.computeConfusionAtThreshold(defaultTheta),
      matriz_confusion_theta_slider:
        sliderTheta != null
          ? ArpegioData.computeConfusionAtThreshold(sliderTheta)
          : null,
      theta_percentiles: labScenarios?.theta_percentiles || {},
      escenarios_lab: (labScenarios?.scenarios || []).map((s) => ({
        id: s.id,
        mse: s.reconstruction_error,
        detected_at_default_theta: s.detected_at_default_theta,
        note: s.note,
      })),
      top_alertas: alerts.slice(0, 8).map((a) => ArpegioData.alertSummary(a)),
    };

    if (alert) {
      ctx.alerta_seleccionada = ArpegioData.alertSummary(alert);
      ctx.coherencia_label =
        ctx.alerta_seleccionada.label === ctx.alerta_seleccionada.label_interval;
    }
    if (labScenario) {
      ctx.escenario_activo = {
        id: labScenario.id,
        label: labScenario.label,
        mse_pipeline: labScenario.reconstruction_error,
        note: labScenario.note,
      };
    }
    if (labRun) ctx.ultima_ejecucion_lab = labRun;
    return ctx;
  }

  function intentInstructions(intent, mode) {
    const map = {
      general:
        mode === "preventivo"
          ? "Informe preventivo global."
          : "Plan reactivo con alerta seleccionada o top de cola.",
      alert: "Consulta desde Alertas sobre la alerta seleccionada.",
      monitor: "Consulta desde Monitor — interpreta histograma y matriz TN/FP/FN/TP.",
      lab: "Consulta desde Laboratorio tras inferencia ONNX.",
    };
    return map[intent] || map.general;
  }

  function buildUserPrompt(state, mode, options = {}) {
    const guidance = MODE_GUIDANCE[mode] || MODE_GUIDANCE.preventivo;
    const ctx = buildRichContext(state, mode, options);

    return `${intentInstructions(options.intent || "general", mode)}

${guidance.focus}

Estructura obligatoria del campo resumen:
${guidance.resumen_sections}

acciones: ${guidance.acciones_style}
comandos_lab: ${guidance.comandos_lab}
veredicto: ${guidance.veredicto_hint}
theta_recomendado_percentil: 70|75|80|85|90|95|99|ninguno
escenario_lab_sugerido: id escenario|ninguno

Usa herramientas si necesitas simular θ o detallar alertas antes de responder.

Contexto inicial:
${JSON.stringify(ctx, null, 2)}

Genera el informe JSON final.`;
  }

  function normalizeThetaPercentile(value) {
    if (value == null || value === "" || value === "ninguno") return null;
    const n = parseInt(String(value), 10);
    return THETA_PERCENTILES.includes(String(n)) ? n : null;
  }

  function normalizeLabScenario(value) {
    if (!value || value === "ninguno") return null;
    const allowed = ["arp_spoof", "mac_flood", "port_scan", "arp_recon", "normal"];
    return allowed.includes(value) ? value : null;
  }

  function parseStructuredResponse(raw) {
    try {
      const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
      if (!parsed.resumen) throw new Error("JSON sin resumen");
      return {
        veredicto: parsed.veredicto || "indeterminada",
        confianza: Number(parsed.confianza) || 0,
        theta_recomendado_percentil: normalizeThetaPercentile(
          parsed.theta_recomendado_percentil
        ),
        escenario_lab_sugerido: normalizeLabScenario(parsed.escenario_lab_sugerido),
        resumen: parsed.resumen,
        acciones: Array.isArray(parsed.acciones) ? parsed.acciones : [],
        comandos_lab: Array.isArray(parsed.comandos_lab) ? parsed.comandos_lab : [],
      };
    } catch {
      return {
        veredicto: "indeterminada",
        confianza: 0,
        theta_recomendado_percentil: null,
        escenario_lab_sugerido: null,
        resumen: typeof raw === "string" ? raw : "Sin respuesta estructurada.",
        acciones: [],
        comandos_lab: [],
      };
    }
  }

  function extractParts(candidate) {
    return candidate?.content?.parts || [];
  }

  function getFunctionCalls(parts) {
    return parts.filter((p) => p.functionCall).map((p) => p.functionCall);
  }

  function getTextFromParts(parts) {
    return parts
      .filter((p) => p.text)
      .map((p) => p.text)
      .join("")
      .trim();
  }

  async function callGemini(body) {
    const key = getApiKeyFromInputs();
    if (!key) throw new Error("Introduce una API key antes de generar el informe");
    setApiKey(key);

    const res = await fetch(`${API_BASE}/${MODEL}:generateContent`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": key,
      },
      body: JSON.stringify(body),
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error?.message || `Error HTTP ${res.status}`);
    }
    return data;
  }

  async function streamGemini(body, onChunk) {
    const key = getApiKeyFromInputs();
    if (!key) throw new Error("Introduce una API key");
    setApiKey(key);

    const res = await fetch(
      `${API_BASE}/${MODEL}:streamGenerateContent?alt=sse`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": key,
        },
        body: JSON.stringify(body),
      }
    );

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error?.message || `Error HTTP ${res.status}`);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let fullText = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (!line.startsWith("data:")) continue;
        const payload = line.slice(5).trim();
        if (!payload || payload === "[DONE]") continue;
        try {
          const json = JSON.parse(payload);
          const parts = extractParts(json.candidates?.[0]);
          const chunk = getTextFromParts(parts);
          if (chunk && chunk.length >= fullText.length) {
            fullText = chunk;
            if (onChunk) onChunk(chunk, fullText);
          }
        } catch {
          /* línea SSE parcial */
        }
      }
    }
    return fullText;
  }

  async function runToolLoop(contents, systemText, generationConfig, onStatus) {
    const tools = ArpegioAgentTools.getToolConfig();
    let messages = [...contents];

    for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
      if (onStatus) onStatus(`Razonando${round ? ` (herramienta ${round})` : ""}…`);

      const data = await callGemini({
        systemInstruction: { parts: [{ text: systemText }] },
        contents: messages,
        tools,
        toolConfig: { functionCallingConfig: { mode: "AUTO" } },
        generationConfig: generationConfig || { temperature: 0.3, maxOutputTokens: 2048 },
      });

      const candidate = data.candidates?.[0];
      const parts = extractParts(candidate);
      const calls = getFunctionCalls(parts);

      if (!calls.length) {
        messages.push({ role: "model", parts });
        return { parts, messages, text: getTextFromParts(parts) };
      }

      messages.push({ role: "model", parts });

      const responseParts = calls.map((call) => {
        const result = ArpegioAgentTools.execute(call.name, call.args || {});
        if (onStatus) onStatus(`Herramienta: ${call.name}…`);
        return {
          functionResponse: {
            name: call.name,
            response: { result },
          },
        };
      });

      messages.push({ role: "user", parts: responseParts });
    }

    throw new Error("Demasiadas llamadas a herramientas");
  }

  async function generate(mode, state, options = {}) {
    sessionOptions = { mode, state, options };
    clearChat(false);

    const userPrompt = buildUserPrompt(state, mode, options);
    const contents = [{ role: "user", parts: [{ text: userPrompt }] }];

    const onStatus = (msg) => {
      const out = document.getElementById("agent-gemini-output");
      if (out) out.textContent = msg;
    };

    const toolResult = await runToolLoop(
      contents,
      SYSTEM_PROMPTS[mode],
      { temperature: 0.3 },
      onStatus
    );

    onStatus("Generando informe estructurado…");

    const finalData = await callGemini({
      systemInstruction: { parts: [{ text: SYSTEM_PROMPTS[mode] }] },
      contents: [
        ...toolResult.messages,
        {
          role: "user",
          parts: [
            {
              text: "Con toda la información y herramientas ya consultadas, emite ÚNICAMENTE el JSON del informe según el esquema.",
            },
          ],
        },
      ],
      generationConfig: {
        temperature: 0.25,
        maxOutputTokens: 2048,
        responseMimeType: "application/json",
        responseSchema: RESPONSE_SCHEMA,
      },
    });

    const text = getTextFromParts(extractParts(finalData.candidates?.[0]));
    if (!text) throw new Error("Gemini devolvió una respuesta vacía");

    lastResult = parseStructuredResponse(text);

    chatContents = [
      { role: "user", parts: [{ text: userPrompt }] },
      {
        role: "model",
        parts: [{ text: `Informe generado. Veredicto: ${lastResult.veredicto}.` }],
      },
    ];

    return lastResult;
  }

  async function sendChat(userText) {
    if (!userText?.trim()) return null;
    if (!sessionOptions) {
      throw new Error("Genera un informe primero para iniciar el chat contextual.");
    }

    if (!getApiKeyFromInputs()) throw new Error("Introduce una API key");

    appendChatBubble("user", userText.trim());
    chatContents.push({ role: "user", parts: [{ text: userText.trim() }] });

    const stream = isStreamingEnabled();
    const assistantEl = appendChatBubble("model", stream ? "" : "…");

    const toolResult = await runToolLoop(
      [...chatContents],
      SYSTEM_PROMPTS.chat,
      { temperature: 0.4, maxOutputTokens: 1536 },
      (msg) => {
        if (assistantEl && !stream) assistantEl.textContent = msg;
      }
    );

    let fullText = toolResult.text;

    if (!fullText) {
      const body = {
        systemInstruction: { parts: [{ text: SYSTEM_PROMPTS.chat }] },
        contents: toolResult.messages,
        generationConfig: { temperature: 0.4, maxOutputTokens: 1536 },
      };

      if (stream && assistantEl) {
        fullText = await streamGemini(body, (_chunk, accumulated) => {
          renderIntoElement(assistantEl, accumulated, { partialCode: true });
        });
        renderIntoElement(assistantEl, fullText);
      } else {
        const data = await callGemini(body);
        fullText = getTextFromParts(extractParts(data.candidates?.[0]));
        if (assistantEl) renderIntoElement(assistantEl, fullText);
      }
    } else if (assistantEl) {
      renderIntoElement(assistantEl, fullText);
    }

    if (!fullText) fullText = "Sin respuesta.";
    chatContents.push({ role: "model", parts: [{ text: fullText }] });
    return fullText;
  }

  function clearChat(resetSession = true) {
    chatContents = [];
    if (resetSession) sessionOptions = null;
    const thread = document.getElementById("agent-chat-thread");
    if (thread) thread.innerHTML = "";
  }

  function appendChatBubble(role, text) {
    const thread = document.getElementById("agent-chat-thread");
    if (!thread) return null;

    const wrap = document.createElement("div");
    wrap.className = `agent-chat-bubble agent-chat-${role}`;
    const label = role === "user" ? "Operador" : "Agente";
    wrap.innerHTML = `<div class="agent-chat-role">${label}</div><div class="agent-chat-text"></div>`;
    const textEl = wrap.querySelector(".agent-chat-text");
    if (text) renderIntoElement(textEl, text);
    thread.appendChild(wrap);
    thread.scrollTop = thread.scrollHeight;
    return textEl;
  }

  function getLastResult() {
    return lastResult;
  }

  function renderList(title, items, className) {
    if (!items?.length) return "";
    const lis = items
      .map((item) => `<li>${escapeHtml(String(item))}</li>`)
      .join("");
    return `<div class="agent-result-section">
      <div class="agent-result-section-title">${title}</div>
      <ul class="${className}">${lis}</ul>
    </div>`;
  }

  function renderCommandList(title, items) {
    if (!items?.length) return "";
    const blocks = items
      .map((item) => {
        const code = escapeHtml(String(item).replace(/\n$/, ""));
        return `<div class="agent-code-wrap"><pre class="agent-code-block"><code>${code}</code></pre></div>`;
      })
      .join("");
    return `<div class="agent-result-section">
      <div class="agent-result-section-title">${title}</div>
      ${blocks}
    </div>`;
  }

  function renderAgentResult(container, result) {
    if (!container || !result) return;
    lastResult = result;

    const verdictEl = document.getElementById("agent-verdict-bar");
    const actionsEl = document.getElementById("agent-structured-actions");
    const tier = VEREDICTO_TIER[result.veredicto] || "med";
    const verdictLabel = VEREDICTO_LABELS[result.veredicto] || result.veredicto;
    const confPct = Math.round(Math.min(1, Math.max(0, result.confianza)) * 100);

    if (verdictEl) {
      verdictEl.hidden = false;
      verdictEl.innerHTML = `
        <span class="badge ${tier}">${verdictLabel}</span>
        <span class="agent-verdict-conf">Confianza ${confPct}%</span>
        ${result.theta_recomendado_percentil ? `<span class="agent-verdict-meta">θ sugerido: p${result.theta_recomendado_percentil}</span>` : ""}
        ${result.escenario_lab_sugerido ? `<span class="agent-verdict-meta">Lab: ${result.escenario_lab_sugerido}</span>` : ""}
      `;
    }

    const narrative = document.getElementById("agent-gemini-output");
    if (narrative) renderIntoElement(narrative, result.resumen);

    if (actionsEl) {
      const buttons = [];
      if (result.theta_recomendado_percentil) {
        buttons.push(
          `<button type="button" class="btn-ghost agent-action-btn" onclick="applyAgentSuggestedTheta()">Aplicar θ p${result.theta_recomendado_percentil}</button>`
        );
      }
      if (result.escenario_lab_sugerido) {
        buttons.push(
          `<button type="button" class="btn-ghost agent-action-btn" onclick="openAgentSuggestedScenario()">Abrir escenario ${result.escenario_lab_sugerido}</button>`
        );
      }
      actionsEl.hidden =
        !buttons.length && !result.acciones?.length && !result.comandos_lab?.length;
      actionsEl.innerHTML =
        (buttons.length ? `<div class="agent-action-btns">${buttons.join("")}</div>` : "") +
        renderList("Acciones recomendadas", result.acciones, "agent-action-list") +
        renderCommandList("Comandos de laboratorio", result.comandos_lab);
      renderMath(actionsEl);
    }

    const chatPanel = document.getElementById("agent-chat-panel");
    if (chatPanel) chatPanel.hidden = false;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function extractMath(text) {
    const blocks = [];
    let n = 0;
    const withoutDisplay = text.replace(/\$\$([\s\S]+?)\$\$/g, (_, math) => {
      const id = `\uE000MATH${n++}\uE001`;
      blocks.push({ id, math, display: true });
      return id;
    });
    const withoutInline = withoutDisplay.replace(
      /(?<![\\$])\$([^$\n]+?)\$(?!\$)/g,
      (_, math) => {
        const id = `\uE000MATH${n++}\uE001`;
        blocks.push({ id, math, display: false });
        return id;
      }
    );
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

  const FENCE_COMPLETE = /```([a-zA-Z0-9_-]*)\s*\n([\s\S]*?)```/g;
  const FENCE_OPEN = /```([a-zA-Z0-9_-]*)\s*\n([\s\S]*)$/;

  function splitMarkdownSegments(text, allowPartial = false) {
    const segments = [];
    let last = 0;
    const re = new RegExp(FENCE_COMPLETE.source, "g");
    let match;

    while ((match = re.exec(text)) !== null) {
      if (match.index > last) {
        segments.push({ type: "text", content: text.slice(last, match.index) });
      }
      segments.push({
        type: "code",
        lang: match[1],
        content: match[2],
        partial: false,
      });
      last = match.index + match[0].length;
    }

    let tail = text.slice(last);
    if (allowPartial) {
      const open = tail.match(FENCE_OPEN);
      if (open) {
        const before = tail.slice(0, open.index);
        if (before) segments.push({ type: "text", content: before });
        segments.push({
          type: "code",
          lang: open[1],
          content: open[2],
          partial: true,
        });
        return segments;
      }
    }

    if (tail) segments.push({ type: "text", content: tail });
    return segments;
  }

  function renderCodeBlock({ lang, content, partial = false }) {
    const language = (lang || "text").toLowerCase() || "text";
    const code = escapeHtml(String(content).replace(/\n$/, ""));
    const langBadge =
      language && language !== "text"
        ? `<span class="agent-code-lang">${escapeHtml(language)}</span>`
        : "";
    const partialClass = partial ? " agent-code-partial" : "";
    return `<div class="agent-code-wrap">${langBadge}<pre class="agent-code-block${partialClass}"><code class="language-${escapeHtml(language)}">${code}</code></pre></div>`;
  }

  function formatResponseLines(text) {
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
        .replace(/`([^`]+)`/g, '<code class="agent-inline-code">$1</code>');

      if (/^#{1,3}\s+/.test(trimmed)) {
        closeList();
        content = content.replace(/^#{1,3}\s+/, "");
        html.push(
          `<div class="agent-md-heading">${content}</div>`
        );
        return;
      }
      if (/^[-*•]\s+/.test(trimmed) || /^\d+[.)]\s+/.test(trimmed)) {
        if (!inList) {
          html.push('<ul class="agent-md-list">');
          inList = true;
        }
        content = content.replace(/^[-*•]\s+/, "").replace(/^\d+[.)]\s+/, "");
        html.push(`<li>${content}</li>`);
        return;
      }
      closeList();
      html.push(`<p class="agent-md-p">${content}</p>`);
    });
    closeList();
    return html.join("");
  }

  function formatTextSegment(text) {
    if (!text) return "";
    const { text: protectedText, blocks } = extractMath(text);
    return restoreMath(formatResponseLines(protectedText), blocks);
  }

  function formatResponse(text, options = {}) {
    const segments = splitMarkdownSegments(text, options.partialCode);
    if (!segments.length) return "";
    return segments
      .map((seg) =>
        seg.type === "code" ? renderCodeBlock(seg) : formatTextSegment(seg.content)
      )
      .join("");
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

  function renderIntoElement(element, text, options = {}) {
    if (!element) return;
    element.innerHTML = formatResponse(text, options);
    renderMath(element);
  }

  function setAgentDot(state) {
    const dot = document.querySelector(".agent-status-dot");
    if (!dot) return;
    dot.style.background =
      state === "error"
        ? "var(--danger)"
        : state === "ready"
          ? "var(--normal)"
          : "var(--amber)";
    dot.style.animation =
      state === "loading" ? "dot-pulse 1.5s ease-in-out infinite" : "none";
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
    sendChat,
    clearChat,
    getLastResult,
    formatResponse,
    renderIntoElement,
    renderAgentResult,
    renderMath,
    setAgentDot,
    isStreamingEnabled,
  };
})();
