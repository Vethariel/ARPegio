import pickle
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = PROJECT_ROOT / "data" / "processed" / "features_l2_labeled.csv"
MODEL_DIR = PROJECT_ROOT / "models"
RESULTS_DIR = PROJECT_ROOT / "results"

FEATURES = [
    "arp_rate",
    "arp_req_reply_ratio",
    "mac_entropy",
    "unique_src_macs",
    "unique_dst_macs",
    "frame_len_mean",
    "frame_len_std",
    "frame_len_min",
    "frame_len_max",
    "broadcast_ratio",
    "total_packets",
]

MAC_FLOOD_SAMPLE = 116
EPOCHS = 100
BATCH_SIZE = 16
LR = 1e-3
THRESHOLD_PERCENTILE = 95


class Autoencoder(nn.Module):
    def __init__(self, input_dim: int):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 8),
            nn.ReLU(),
            nn.Linear(8, 4),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(4, 8),
            nn.ReLU(),
            nn.Linear(8, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


def reconstruction_errors(model, x_tensor):
    with torch.no_grad():
        recon = model(x_tensor)
        return ((recon - x_tensor) ** 2).mean(dim=1).cpu().numpy()


def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Dispositivo: {device}")
    if device.type == "cuda":
        print(f"GPU: {torch.cuda.get_device_name(0)}")

    df = pd.read_csv(DATA_PATH)

    mac_flood = df[df["label"] == "mac_flood"].sample(
        MAC_FLOOD_SAMPLE, random_state=42
    )
    df_balanced = pd.concat(
        [df[df["label"] != "mac_flood"], mac_flood], ignore_index=True
    )

    print("\nDistribución balanceada:")
    print(df_balanced["label"].value_counts())

    train = df_balanced[
        (df_balanced["source"] == "victima1") & (df_balanced["label"] == "normal")
    ]
    test = df_balanced[df_balanced["source"] == "victima2"]

    print(f"\nTrain (normal victima1): {len(train)}")
    print(f"Test  (victima2):        {len(test)}")

    scaler = StandardScaler()
    x_train = scaler.fit_transform(train[FEATURES])
    x_test = scaler.transform(test[FEATURES])
    y_test = test["label"].values

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    with open(MODEL_DIR / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    x_train_t = torch.FloatTensor(x_train).to(device)
    loader = DataLoader(
        TensorDataset(x_train_t), batch_size=BATCH_SIZE, shuffle=True
    )

    model = Autoencoder(len(FEATURES)).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    criterion = nn.MSELoss()

    losses = []
    for epoch in range(EPOCHS):
        model.train()
        epoch_loss = 0.0
        for (batch,) in loader:
            out = model(batch)
            loss = criterion(out, batch)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
        avg = epoch_loss / len(loader)
        losses.append(avg)
        if (epoch + 1) % 20 == 0:
            print(f"Epoch {epoch + 1:3d}/{EPOCHS} — loss: {avg:.6f}")

    model.eval()
    train_errs = reconstruction_errors(model, x_train_t)
    threshold = float(np.percentile(train_errs, THRESHOLD_PERCENTILE))
    print(f"\nUmbral (percentil {THRESHOLD_PERCENTILE}): {threshold:.6f}")

    x_test_t = torch.FloatTensor(x_test).to(device)
    test_errs = reconstruction_errors(model, x_test_t)

    y_pred = np.where(test_errs > threshold, "ataque", "normal")
    y_true = np.where(y_test == "normal", "normal", "ataque")

    print("\nReporte de clasificación (binario normal vs ataque):")
    print(classification_report(y_true, y_pred, zero_division=0))

    y_true_bin = (y_true == "ataque").astype(int)
    auc = roc_auc_score(y_true_bin, test_errs)
    print(f"AUC-ROC: {auc:.4f}")

    print("\nDetección por clase (victima2):")
    for label in sorted(test["label"].unique()):
        mask = y_test == label
        detected = (test_errs[mask] > threshold).sum()
        total = mask.sum()
        print(f"  {label:12s}: {detected}/{total} detectadas ({100*detected/total:.1f}%)")

    torch.save(model.state_dict(), MODEL_DIR / "autoencoder.pt")
    np.save(MODEL_DIR / "threshold.npy", threshold)
    print(f"\nModelo:   {MODEL_DIR / 'autoencoder.pt'}")
    print(f"Umbral:   {MODEL_DIR / 'threshold.npy'}")
    print(f"Scaler:   {MODEL_DIR / 'scaler.pkl'}")

    plt.figure(figsize=(8, 4))
    plt.plot(losses)
    plt.title("Loss de entrenamiento (MSE)")
    plt.xlabel("Epoch")
    plt.ylabel("MSE")
    plt.tight_layout()
    loss_path = RESULTS_DIR / "training_loss.png"
    plt.savefig(loss_path)
    print(f"Curva:    {loss_path}")


if __name__ == "__main__":
    main()
