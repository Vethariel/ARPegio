"""Genera alertas priorizadas a partir del modelo entrenado."""

import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from prioritizer import prioritize_alerts
from train_autoencoder import (
    DATA_PATH,
    FEATURES,
    MODEL_DIR,
    RANDOM_STATE,
    RESULTS_DIR,
    VAL_FRACTION,
    Autoencoder,
    MAC_FLOOD_SAMPLE,
    reconstruction_errors,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]

SCENARIO_ORDER = ["arp_spoof", "mac_flood", "port_scan", "arp_recon", "normal"]

SCENARIO_META = {
    "arp_spoof": {
        "display_name": "ARP Spoofing",
        "color": "#FF4D00",
        "danger": True,
        "description": "Envenenamiento de caché ARP · ventana real de victima2",
    },
    "mac_flood": {
        "display_name": "MAC Flood",
        "color": "#FF6B1A",
        "danger": False,
        "description": "Saturación tabla CAM · 50 MACs únicas por ventana",
    },
    "port_scan": {
        "display_name": "Escaneo de puertos",
        "color": "#E8A317",
        "danger": False,
        "description": "Única ventana port_scan del lab · caso FN documentado",
    },
    "arp_recon": {
        "display_name": "Recon ARP",
        "color": "#E8A317",
        "danger": False,
        "description": "Descubrimiento ARP activo · ventana real victima2",
    },
    "normal": {
        "display_name": "Tráfico normal",
        "color": "#8B7355",
        "danger": False,
        "description": "Baseline benigno · ventana típica sin anomalía",
    },
}


def pick_representative_window(sub_df: pd.DataFrame, label: str) -> pd.Series:
    if len(sub_df) == 1:
        return sub_df.iloc[0]
    if label == "normal":
        target = sub_df["reconstruction_error"].median()
    else:
        target = sub_df["reconstruction_error"].median()
    idx = (sub_df["reconstruction_error"] - target).abs().idxmin()
    return sub_df.loc[idx]


def export_lab_scenarios(
    eval_df: pd.DataFrame,
    errors: np.ndarray,
    threshold: float,
    val_errs: np.ndarray,
    window_size: int = 50,
) -> dict:
    eval_df = eval_df.copy()
    eval_df["reconstruction_error"] = errors

    percentiles = {
        str(p): float(np.percentile(val_errs, p))
        for p in (70, 75, 80, 85, 90, 95, 99)
    }

    scenarios = []
    for key in SCENARIO_ORDER:
        sub = eval_df[eval_df["label"] == key]
        if sub.empty:
            continue
        row = pick_representative_window(sub, key)
        meta = SCENARIO_META[key]
        mse = float(row["reconstruction_error"])
        detected = bool(mse > threshold)
        note = None
        if key == "port_scan" and not detected:
            note = "FN del paper: MSE por debajo de θ — el modelo no alertó esta ventana"

        scenarios.append(
            {
                "id": key,
                "display_name": meta["display_name"],
                "label": key,
                "color": meta["color"],
                "danger": meta["danger"],
                "description": meta["description"],
                "note": note,
                "reconstruction_error": mse,
                "detected_at_default_theta": detected,
                "t_start": float(row["t_start"]),
                "t_end": float(row["t_end"]),
                "source": row["source"],
                "features": {f: float(row[f]) for f in FEATURES},
            }
        )

    return {
        "threshold": threshold,
        "threshold_percentile": 95,
        "window_size": window_size,
        "theta_percentiles": percentiles,
        "scenarios": scenarios,
    }


def get_validation_errors(model, scaler, device) -> np.ndarray:
    df = pd.read_csv(DATA_PATH)
    mac_flood = df[df["label"] == "mac_flood"].sample(MAC_FLOOD_SAMPLE, random_state=42)
    df_balanced = pd.concat(
        [df[df["label"] != "mac_flood"], mac_flood], ignore_index=True
    )
    normal_v1 = df_balanced[
        (df_balanced["source"] == "victima1") & (df_balanced["label"] == "normal")
    ].sample(frac=1, random_state=RANDOM_STATE)
    n_val = max(1, int(len(normal_v1) * VAL_FRACTION))
    val = normal_v1.iloc[:n_val]
    x_val = scaler.transform(val[FEATURES])
    x_val_t = torch.FloatTensor(x_val).to(device)
    return reconstruction_errors(model, x_val_t)


def load_artifacts(device):
    with open(MODEL_DIR / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    threshold = float(np.load(MODEL_DIR / "threshold.npy"))
    model = Autoencoder(len(FEATURES)).to(device)
    model.load_state_dict(
        torch.load(MODEL_DIR / "autoencoder.pt", map_location=device, weights_only=True)
    )
    model.eval()
    return model, scaler, threshold


def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model, scaler, threshold = load_artifacts(device)

    df = pd.read_csv(DATA_PATH)
    mac_flood = df[df["label"] == "mac_flood"].sample(MAC_FLOOD_SAMPLE, random_state=42)
    df_balanced = pd.concat(
        [df[df["label"] != "mac_flood"], mac_flood], ignore_index=True
    )

    eval_df = df_balanced[df_balanced["source"] == "victima2"].reset_index(drop=True)
    x = scaler.transform(eval_df[FEATURES])
    x_t = torch.FloatTensor(x).to(device)
    errors = reconstruction_errors(model, x_t)

    alerts = prioritize_alerts(eval_df, errors, threshold)
    out_path = RESULTS_DIR / "alerts_prioritized.csv"
    alerts.to_csv(out_path, index=False)

    summary = {
        "total_windows": int(len(eval_df)),
        "alerts": int(len(alerts)),
        "threshold": threshold,
        "top_alert": alerts.iloc[0].to_dict() if len(alerts) else None,
    }
    with open(RESULTS_DIR / "alerts_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)

    window_scores = {
        "threshold": threshold,
        "windows": [
            {
                "reconstruction_error": float(err),
                "label": row["label"],
                "is_anomaly": bool(err > threshold),
                "t_start": float(row["t_start"]),
                "t_end": float(row["t_end"]),
                "total_packets": int(row["total_packets"]),
            }
            for err, row in zip(errors, eval_df.to_dict("records"))
        ],
    }
    with open(RESULTS_DIR / "window_scores.json", "w", encoding="utf-8") as f:
        json.dump(window_scores, f, indent=2)

    val_errs = get_validation_errors(model, scaler, device)
    lab_scenarios = export_lab_scenarios(eval_df, errors, threshold, val_errs)
    lab_path = RESULTS_DIR / "lab_scenarios.json"
    with open(lab_path, "w", encoding="utf-8") as f:
        json.dump(lab_scenarios, f, indent=2)

    print(f"Ventanas evaluadas (victima2): {len(eval_df)}")
    print(f"Alertas generadas: {len(alerts)}")
    print(f"Guardado: {out_path}")
    print(f"Escenarios lab: {lab_path}")
    if len(alerts):
        print("\nTop 5 alertas por prioridad:")
        cols = [
            "label",
            "inferred_threat",
            "priority_score",
            "severity",
            "frequency",
            "impact",
        ]
        print(alerts[cols].head(5).to_string(index=False))


if __name__ == "__main__":
    main()
