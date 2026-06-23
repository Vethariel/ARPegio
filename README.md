# ARPegio — Detección de Anomalías en Redes LAN (IEEE 802.3)

Sistema de detección no supervisada con autoencoder sobre features L2 extraídas de capturas PCAP en laboratorio virtual. La demo web estática vive en la raíz del repositorio.

## Demo web

```bash
# Desde la raíz del proyecto
python -m http.server 8080
# Abrir http://localhost:8080/
```

La interfaz incluye seis vistas (Monitor, Red, Alertas, Laboratorio, Agente, Ajustes). El agente Gemini es opcional (BYOK); la detección local se conectará en pasos siguientes.

## Estructura del proyecto

```
Deteccion_Ataques_LAN_IA/
├── index.html                  # Demo web ARPegio (servir desde raíz)
├── assets/
│   ├── css/arpegio.css
│   └── js/arpegio.js
├── config/
│   └── label_intervals.json    # Ventanas temporales de etiquetado por ataque
├── data/
│   ├── raw/
│   │   └── pcap/               # Capturas propias (victima1, victima2)
│   └── processed/
│       └── features_l2_labeled.csv
├── docs/
│   ├── articulo.tex            # Paper IEEE
│   └── articulo.pdf
├── scripts/
│   ├── extract_features.py     # Extracción L2 con Scapy
│   ├── train_autoencoder.py    # Entrenamiento AE + umbral
│   ├── prioritizer.py          # Motor de priorización (severidad/frecuencia/impacto)
│   └── prioritize_alerts.py    # Genera alertas ordenadas en results/
├── models/                     # autoencoder.pt, scaler.pkl, threshold.npy
├── results/                    # metrics.json, training_loss.png, alerts_prioritized.csv
├── pyproject.toml
└── uv.lock
```

## Requisitos

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Uso

```bash
# Instalar dependencias
uv sync

# Extraer features L2 desde PCAPs y generar CSV etiquetado
uv run python scripts/extract_features.py

# Entrenar autoencoder (GPU CUDA si está disponible)
uv run python scripts/train_autoencoder.py

# Priorizar alertas sobre victima2
uv run python scripts/prioritize_alerts.py
```

## Reproducibilidad

El paper describe el motor de priorización de forma genérica; en el
repositorio la lógica reside en `scripts/prioritizer.py` y el punto de
entrada para generar alertas ordenadas es `scripts/prioritize_alerts.py`
(no existe un archivo `prioritization_engine.py`).

## Datos

| Recurso | Descripción |
|---------|-------------|
| `data/raw/pcap/` | Capturas en red VirtualBox (~35 min, 5 tipos de tráfico) |
| `data/processed/features_l2_labeled.csv` | 959 ventanas, features L2 + label |

## Labels de ataque

| Label | Señal principal |
|-------|-----------------|
| `normal` | Tráfico baseline |
| `arp_spoof` | Alta tasa ARP, bajo req/reply |
| `mac_flood` | 50 MACs únicas, entropía alta |
| `port_scan` | Tramas pequeñas y uniformes |
| `arp_recon` | ARP rate = 1.0 al final de captura |

## Próximos pasos

- [x] Entrenar autoencoder (solo tráfico normal)
- [x] Calibrar umbral estadístico (percentil 95)
- [x] Motor de priorización de alertas
- [ ] Agente IA: modos preventivo y reactivo
