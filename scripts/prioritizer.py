"""Motor de priorización de alertas (severidad, frecuencia, impacto)."""

from __future__ import annotations

import numpy as np
import pandas as pd

WEIGHTS = {"severity": 0.5, "frequency": 0.3, "impact": 0.2}
FREQ_WINDOW = 10

IMPACT_BY_THREAT = {
    "mac_flood": 1.0,
    "arp_spoof": 0.9,
    "port_scan": 0.7,
    "arp_recon": 0.6,
    "unknown": 0.5,
}


def infer_threat_type(row: pd.Series) -> str:
    if row["unique_src_macs"] >= 20:
        return "mac_flood"
    if row["arp_rate"] >= 0.5:
        if row["arp_req_reply_ratio"] < 1.0:
            return "arp_spoof"
        return "arp_recon"
    if row["frame_len_std"] < 5.0:
        return "port_scan"
    return "unknown"


def compute_frequency(anomaly_flags: np.ndarray, window: int = FREQ_WINDOW) -> np.ndarray:
    n = len(anomaly_flags)
    freqs = np.zeros(n, dtype=float)
    for i in range(n):
        start = max(0, i - window + 1)
        freqs[i] = anomaly_flags[start : i + 1].mean()
    return freqs


def prioritize_alerts(
    df: pd.DataFrame,
    errors: np.ndarray,
    threshold: float,
) -> pd.DataFrame:
    anomaly = errors > threshold
    threats = df.apply(infer_threat_type, axis=1)
    impact = threats.map(IMPACT_BY_THREAT).astype(float)
    severity = np.minimum(errors / max(threshold, 1e-9), 1.0)

    out = df.copy()
    out["reconstruction_error"] = errors
    out["is_anomaly"] = anomaly
    out["inferred_threat"] = threats
    out["severity"] = severity
    out["impact"] = impact

    prioritized = []
    for source, group in out.groupby("source", sort=False):
        idx = group.index.to_numpy()
        freq = compute_frequency(group["is_anomaly"].to_numpy())
        score = (
            WEIGHTS["severity"] * group["severity"].to_numpy()
            + WEIGHTS["frequency"] * freq
            + WEIGHTS["impact"] * group["impact"].to_numpy()
        )
        part = group.copy()
        part["frequency"] = freq
        part["priority_score"] = score
        prioritized.append(part)

    result = pd.concat(prioritized).sort_index()
    alert_mask = result["is_anomaly"]
    alerts = result.loc[alert_mask].sort_values("priority_score", ascending=False)
    return alerts
