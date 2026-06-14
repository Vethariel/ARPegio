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
    RESULTS_DIR,
    Autoencoder,
    MAC_FLOOD_SAMPLE,
    reconstruction_errors,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


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

    print(f"Ventanas evaluadas (victima2): {len(eval_df)}")
    print(f"Alertas generadas: {len(alerts)}")
    print(f"Guardado: {out_path}")
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
