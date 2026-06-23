# ARPegio — Detección de Anomalías en Redes LAN (IEEE 802.3)

Sistema de detección no supervisada con autoencoder sobre features L2 extraídas de capturas PCAP en un laboratorio virtual GNS3. La demo web estática vive en la raíz del repositorio.

## Demo web

Publicada en [vethariel.github.io/ARPegio/](https://vethariel.github.io/ARPegio/).

```bash
# Desde la raíz del proyecto
python -m http.server 8080
# Abrir http://localhost:8080/
```

### Vistas

| Vista | Contenido |
|-------|-----------|
| **Monitor** | Métricas del pipeline, histograma de MSE, θ interactivo |
| **Red** | Topología del lab y timeline de eventos |
| **Alertas** | Cola priorizada desde `results/alerts_prioritized.csv` |
| **Laboratorio** | Inferencia ONNX en el navegador + escenarios reales |
| **Agente** | Informes Gemini BYOK, chat y herramientas locales |
| **Ajustes** | API key, umbral y notas del modelo |

Al cargar, la demo lee `results/metrics.json`, `results/alerts_prioritized.csv`, `results/window_scores.json`, `results/lab_scenarios.json` y `config/label_intervals.json`. Regenerar artefactos con `prioritize_alerts.py` (y entrenamiento previo si hace falta).

### Agente IA (Gemini BYOK)

- **Modo preventivo** — calibración de θ, trade-off FP/FN, checklist pre-incidente.
- **Modo reactivo** — planes de mitigación L2 con comandos de laboratorio.
- **Informe estructurado** — veredicto, confianza, θ sugerido, escenario lab, acciones.
- **Herramientas locales** — `simulate_theta`, `get_alert`, `list_alerts`, `get_lab_scenario`.
- **Chat de seguimiento** — preguntas contextuales tras el informe (p. ej. «¿qué pasa con θ en p99?»).
- **Streaming** opcional en el chat; LaTeX (KaTeX) y bloques de código markdown en informe y chat.

La API key se guarda solo en `sessionStorage` del navegador y se envía directamente a Google AI Studio. Obtener clave en [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey). Modelo: `gemini-3.1-flash-lite`.

Botones contextuales en Monitor, Alertas y Laboratorio abren el agente con el contexto ya cargado.

## Laboratorio de captura

Topología GNS3 en `192.168.1.0/24`:

| Nodo | IP | Rol |
|------|-----|-----|
| Alpine-1 | 192.168.1.10 | Víctima / captura `victima1` |
| Alpine-2 | 192.168.1.20 | Víctima / captura `victima2` |
| Kali | 192.168.1.99 | Atacante |
| OVS | — | Switch; captura integrada GNS3 |

Secuencia de ataques documentada en `config/label_intervals.json` y en `docs/articulo.tex` (ARP spoof, MAC flood, port scan, ARP recon).

## Estructura del proyecto

```
Deteccion_Ataques_LAN_IA/
├── index.html                  # Demo web ARPegio (servir desde raíz)
├── assets/
│   ├── css/arpegio.css
│   └── js/
│       ├── icons.js
│       ├── data.js             # carga JSON/CSV del pipeline
│       ├── render.js           # render dinámico de vistas
│       ├── inference.js        # inferencia ONNX en navegador
│       ├── agent-tools.js      # herramientas locales del agente
│       ├── gemini-agent.js     # agente Gemini BYOK
│       └── arpegio.js
├── config/
│   └── label_intervals.json    # intervalos de etiquetado por ataque
├── data/
│   ├── raw/pcap/               # victima1.pcapng, victima2.pcapng
│   └── processed/
│       └── features_l2_labeled.csv
├── docs/
│   ├── articulo.tex            # paper IEEE
│   └── articulo.pdf
├── models/                     # autoencoder.pt, autoencoder.onnx, scaler.*
├── results/                    # métricas, alertas, escenarios lab, scores
├── scripts/
│   ├── extract_features.py     # extracción L2 con Scapy
│   ├── train_autoencoder.py    # entrenamiento AE + export ONNX
│   ├── export_onnx.py          # ONNX + scaler.json para el navegador
│   ├── prioritizer.py          # motor de priorización
│   └── prioritize_alerts.py    # genera artefactos en results/
├── refs/arpegio.html           # mockup de referencia (no es la app activa)
├── pyproject.toml
└── uv.lock
```

## Requisitos

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- Navegador moderno (para ONNX Runtime Web y la demo)

## Pipeline

```bash
# Instalar dependencias
uv sync

# 1. Extraer features L2 desde PCAPs
uv run python scripts/extract_features.py

# 2. Entrenar autoencoder (exporta ONNX al final)
uv run python scripts/train_autoencoder.py

# 3. Priorizar alertas y exportar JSON para la demo
uv run python scripts/prioritize_alerts.py
```

Exportar ONNX sin reentrenar:

```bash
uv run python scripts/export_onnx.py
```

## Resultados actuales

Entrenamiento solo con tráfico normal; θ en percentil 95 (`≈ 0.114`).

| Métrica | Valor |
|---------|-------|
| AUC-ROC | 0.998 |
| FP en tráfico normal | 4% (3/75 ventanas) |
| `arp_spoof` / `mac_flood` / `arp_recon` | 100% detectados |
| `port_scan` | 0/1 (FN documentado en lab) |

El escenario `port_scan` aparece como caso honesto en la vista Laboratorio para discutir límites del umbral.

## Reproducibilidad

El paper describe el motor de priorización de forma genérica; en el repositorio la lógica reside en `scripts/prioritizer.py` y el punto de entrada es `scripts/prioritize_alerts.py`.

## Datos

| Recurso | Descripción |
|---------|-------------|
| `data/raw/pcap/` | Capturas en lab GNS3 (~35 min, 5 tipos de tráfico) |
| `data/processed/features_l2_labeled.csv` | 959 ventanas, features L2 + label |

## Labels de ataque

| Label | Señal principal |
|-------|-----------------|
| `normal` | Tráfico baseline |
| `arp_spoof` | Alta tasa ARP, bajo req/reply |
| `mac_flood` | 50 MACs únicas, entropía alta |
| `port_scan` | Tramas pequeñas y uniformes |
| `arp_recon` | ARP rate = 1.0 al final de captura |

## Estado del proyecto

- [x] Extracción L2 desde PCAPs propios (Scapy)
- [x] Autoencoder no supervisado + umbral por percentil
- [x] Motor de priorización de alertas
- [x] Demo web con datos reales del pipeline
- [x] Inferencia ONNX en navegador (Laboratorio)
- [x] Agente Gemini: preventivo/reactivo, tools, chat, streaming
- [x] Render markdown (bloques ``` y LaTeX) en informe y chat
- [ ] Ejecución remota de mitigaciones en el lab (extensión futura)
