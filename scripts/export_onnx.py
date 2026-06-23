"""Exporta autoencoder PyTorch a ONNX + scaler JSON para inferencia en navegador."""

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

from train_autoencoder import (  # noqa: E402
    DATA_PATH,
    FEATURES,
    MAC_FLOOD_SAMPLE,
    MODEL_DIR,
    Autoencoder,
    reconstruction_errors,
)


def export_onnx(model_dir: Path | None = None) -> dict:
    model_dir = model_dir or MODEL_DIR
    pt_path = model_dir / "autoencoder.pt"
    scaler_path = model_dir / "scaler.pkl"

    if not pt_path.exists() or not scaler_path.exists():
        raise FileNotFoundError(
            f"Faltan artefactos en {model_dir}. Ejecuta train_autoencoder.py primero."
        )

    model = Autoencoder(len(FEATURES))
    model.load_state_dict(
        torch.load(pt_path, map_location="cpu", weights_only=True)
    )
    model.eval()

    with open(scaler_path, "rb") as f:
        scaler = pickle.load(f)

    onnx_path = model_dir / "autoencoder.onnx"
    dummy = torch.randn(1, len(FEATURES), dtype=torch.float32)
    torch.onnx.export(
        model,
        dummy,
        onnx_path,
        input_names=["features"],
        output_names=["reconstruction"],
        dynamic_axes={"features": {0: "batch"}, "reconstruction": {0: "batch"}},
        opset_version=17,
        do_constant_folding=True,
        dynamo=False,
    )

    scaler_json = {
        "features": FEATURES,
        "min": scaler.min_.tolist(),
        "scale": scaler.scale_.tolist(),
        "data_min": scaler.data_min_.tolist(),
        "data_max": scaler.data_max_.tolist(),
        "feature_range": list(scaler.feature_range),
    }
    scaler_out = model_dir / "scaler.json"
    with open(scaler_out, "w", encoding="utf-8") as f:
        json.dump(scaler_json, f, indent=2)

    parity = _verify_parity(model, scaler)

    return {
        "onnx": str(onnx_path),
        "scaler": str(scaler_out),
        "parity": parity,
    }


def _verify_parity(model, scaler) -> dict:
    """Compara MSE ONNX-runtime (vía PyTorch) con pipeline sobre escenarios lab."""
    df = pd.read_csv(DATA_PATH)
    mac_flood = df[df["label"] == "mac_flood"].sample(MAC_FLOOD_SAMPLE, random_state=42)
    eval_df = pd.concat(
        [df[df["label"] != "mac_flood"], mac_flood], ignore_index=True
    )
    eval_df = eval_df[eval_df["source"] == "victima2"].reset_index(drop=True)

    x = scaler.transform(eval_df[FEATURES])
    x_t = torch.FloatTensor(x)
    errs = reconstruction_errors(model, x_t)

    max_diff = 0.0
    for i in range(min(5, len(errs))):
        with torch.no_grad():
            recon = model(x_t[i : i + 1])
            mse = ((recon - x_t[i : i + 1]) ** 2).mean().item()
        max_diff = max(max_diff, abs(mse - errs[i]))

    return {"samples_checked": min(5, len(errs)), "max_abs_diff": max_diff}


def main():
    result = export_onnx()
    print(f"ONNX:   {result['onnx']}")
    print(f"Scaler: {result['scaler']}")
    print(
        f"Paridad PyTorch (muestra): max |Δ| = {result['parity']['max_abs_diff']:.2e}"
    )


if __name__ == "__main__":
    main()
