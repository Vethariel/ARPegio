from collections import Counter
import json
from pathlib import Path

import numpy as np
import pandas as pd
from scapy.all import ARP, Ether, rdpcap
from scipy.stats import entropy

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "config" / "label_intervals.json"
PCAP_DIR = PROJECT_ROOT / "data" / "raw" / "pcap"
OUTPUT_DIR = PROJECT_ROOT / "data" / "processed"

FEATURE_SUMMARY_COLS = [
    "arp_rate",
    "mac_entropy",
    "unique_src_macs",
    "frame_len_std",
]


def load_config(config_path=None):
    path = config_path or CONFIG_PATH
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def get_label(t_start, t_end, label_intervals):
    mid = (t_start + t_end) / 2
    for t0, t1, lbl in label_intervals:
        if t0 <= mid <= t1:
            return lbl
    return "normal"


def extract_l2_features(pcap_file, source_name, window_size, label_intervals):
    packets = rdpcap(str(pcap_file))
    windows = []

    for i in range(0, len(packets), window_size):
        window = packets[i : i + window_size]

        timestamps = [float(p.time) for p in window if Ether in p]
        if not timestamps:
            continue
        t_start = timestamps[0]
        t_end = timestamps[-1]

        src_macs = [p[Ether].src for p in window if Ether in p]
        dst_macs = [p[Ether].dst for p in window if Ether in p]

        arp_pkts = [p for p in window if ARP in p]
        arp_req = [p for p in arp_pkts if p[ARP].op == 1]
        arp_rep = [p for p in arp_pkts if p[ARP].op == 2]

        lengths = [len(p) for p in window if Ether in p]

        mac_counts = Counter(src_macs)
        mac_entropy = entropy(list(mac_counts.values())) if mac_counts else 0

        windows.append(
            {
                "source": source_name,
                "t_start": t_start,
                "t_end": t_end,
                "arp_rate": len(arp_pkts) / len(window),
                "arp_req_reply_ratio": len(arp_req) / (len(arp_rep) + 1e-6),
                "mac_entropy": mac_entropy,
                "unique_src_macs": len(set(src_macs)),
                "unique_dst_macs": len(set(dst_macs)),
                "frame_len_mean": np.mean(lengths) if lengths else 0,
                "frame_len_std": np.std(lengths) if lengths else 0,
                "frame_len_min": np.min(lengths) if lengths else 0,
                "frame_len_max": np.max(lengths) if lengths else 0,
                "broadcast_ratio": sum(
                    1 for m in dst_macs if m == "ff:ff:ff:ff:ff:ff"
                )
                / (len(dst_macs) + 1e-6),
                "total_packets": len(window),
                "label": get_label(t_start, t_end, label_intervals),
            }
        )

    return pd.DataFrame(windows)


def main():
    config = load_config()
    label_intervals = [tuple(row) for row in config["label_intervals"]]
    window_size = config["window_size"]
    output_path = OUTPUT_DIR / config["output"]

    frames = []
    for entry in config["pcap_sources"]:
        pcap_path = PCAP_DIR / entry["file"]
        if not pcap_path.exists():
            raise FileNotFoundError(f"No se encontró el PCAP: {pcap_path}")
        print(f"Leyendo {pcap_path.name} ...")
        frames.append(
            extract_l2_features(
                pcap_path,
                entry["source"],
                window_size,
                label_intervals,
            )
        )

    df = pd.concat(frames, ignore_index=True)

    print(f"\nVentanas totales: {len(df)}")
    print("\nDistribución de labels (combinado):")
    print(df["label"].value_counts())
    print("\nDistribución por fuente:")
    print(df.groupby(["source", "label"]).size().unstack(fill_value=0))

    print("\nMuestra por clase (combinado):")
    for label in sorted(df["label"].unique()):
        print(f"\n--- {label} ---")
        print(
            df.loc[df["label"] == label, FEATURE_SUMMARY_COLS]
            .describe()
            .round(3)
            .to_string()
        )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"\nGuardado en {output_path}")


if __name__ == "__main__":
    main()
