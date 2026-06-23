/** Herramientas locales del agente — datos reales del pipeline ARPegio. */
const ArpegioAgentTools = (function () {
  let getRuntime = () => ({});

  function init(runtimeProvider) {
    getRuntime = runtimeProvider;
  }

  function simulateTheta(args) {
    const p = parseInt(String(args?.percentile || "95"), 10);
    const theta = ArpegioData.getThetaForPercentile(p);
    const confusion = ArpegioData.computeConfusionAtThreshold(theta);
    const state = ArpegioData.getState();
    const alerts = (state.alerts || []).filter((a) => a.reconstruction_error > theta);
    return {
      percentil: p,
      theta,
      matriz_confusion: confusion,
      alertas_generadas: alerts.length,
      alertas_por_threat: alerts.reduce((acc, a) => {
        const t = a.inferred_threat || a.label;
        acc[t] = (acc[t] || 0) + 1;
        return acc;
      }, {}),
    };
  }

  function getAlert(args) {
    const state = ArpegioData.getState();
    const alerts = state.alerts || [];
    if (args?.threat) {
      const found = alerts.find(
        (a) => a.inferred_threat === args.threat || a.label === args.threat
      );
      return found ? ArpegioData.alertSummary(found) : { error: "Alerta no encontrada" };
    }
    const idx = parseInt(String(args?.index ?? "0"), 10);
    if (idx < 0 || idx >= alerts.length) {
      return { error: `Índice fuera de rango (0-${alerts.length - 1})` };
    }
    return ArpegioData.alertSummary(alerts[idx]);
  }

  function getLabScenario(args) {
    const id = args?.scenario_id;
    const scenario = ArpegioData.getLabScenario(id);
    if (!scenario) return { error: `Escenario ${id} no encontrado` };
    return {
      id: scenario.id,
      label: scenario.label,
      mse: scenario.reconstruction_error,
      detected_at_default_theta: scenario.detected_at_default_theta,
      note: scenario.note,
      features: scenario.features,
    };
  }

  function listAlerts(args) {
    const limit = Math.min(20, Math.max(1, parseInt(String(args?.limit || "5"), 10)));
    let alerts = ArpegioData.getState().alerts || [];
    if (args?.threat) {
      alerts = alerts.filter(
        (a) => a.inferred_threat === args.threat || a.label === args.threat
      );
    }
    return {
      total: alerts.length,
      items: alerts.slice(0, limit).map((a) => ArpegioData.alertSummary(a)),
    };
  }

  const HANDLERS = {
    simulate_theta: simulateTheta,
    get_alert: getAlert,
    get_lab_scenario: getLabScenario,
    list_alerts: listAlerts,
  };

  const DECLARATIONS = [
    {
      name: "simulate_theta",
      description:
        "Simula TN/FP/FN/TP y alertas si θ fuera el percentil p70–p99 sobre window_scores del replay.",
      parameters: {
        type: "OBJECT",
        properties: {
          percentile: {
            type: "STRING",
            enum: ["70", "75", "80", "85", "90", "95", "99"],
          },
        },
        required: ["percentile"],
      },
    },
    {
      name: "get_alert",
      description: "Detalle de una alerta por índice en la cola priorizada (0 = top) o por tipo de amenaza.",
      parameters: {
        type: "OBJECT",
        properties: {
          index: { type: "STRING", description: "Índice 0-based en cola priorizada" },
          threat: {
            type: "STRING",
            enum: ["arp_spoof", "mac_flood", "port_scan", "arp_recon"],
          },
        },
      },
    },
    {
      name: "get_lab_scenario",
      description: "Features y MSE de un escenario del laboratorio.",
      parameters: {
        type: "OBJECT",
        properties: {
          scenario_id: {
            type: "STRING",
            enum: ["arp_spoof", "mac_flood", "port_scan", "arp_recon", "normal"],
          },
        },
        required: ["scenario_id"],
      },
    },
    {
      name: "list_alerts",
      description: "Lista alertas priorizadas, opcionalmente filtradas por amenaza.",
      parameters: {
        type: "OBJECT",
        properties: {
          limit: { type: "STRING", description: "Máximo a devolver (1-20)" },
          threat: {
            type: "STRING",
            enum: ["arp_spoof", "mac_flood", "port_scan", "arp_recon"],
          },
        },
      },
    },
  ];

  function execute(name, args) {
    const handler = HANDLERS[name];
    if (!handler) return { error: `Herramienta desconocida: ${name}` };
    try {
      return handler(args || {});
    } catch (err) {
      return { error: err.message };
    }
  }

  function getToolConfig() {
    return [{ functionDeclarations: DECLARATIONS }];
  }

  return {
    init,
    execute,
    getToolConfig,
    DECLARATIONS,
  };
})();
