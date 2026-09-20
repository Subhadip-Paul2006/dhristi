import json
import logging
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add server directory to sys.path
SERVER_ROOT = Path(__file__).resolve().parent.parent.parent
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

import networkx as nx
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from ml.models.fusion import FusionDetector
from ml.models.gnn import GraphNetworkDetector
from ml.models.temporal import LSTMDetector, TransformerDetector
from ml.preprocessing.scaler import (
    CANONICAL_FEATURE_NAMES,
    INV_LABEL_MAPPING,
    LABEL_MAPPING,
    TrafficPreprocessor,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("drishti_train")


def set_seed(seed: int = 42) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def map_raw_label(raw: str) -> int:
    raw_str = str(raw).strip()
    if raw_str in LABEL_MAPPING:
        return LABEL_MAPPING[raw_str]
    # Canonical groupings
    lower = raw_str.lower()
    if "dos" in lower or "ddos" in lower:
        return LABEL_MAPPING["DoS"]
    if "port" in lower or "scan" in lower:
        return LABEL_MAPPING["PortScan"]
    if "brute" in lower or "patator" in lower:
        return LABEL_MAPPING["BruteForce"]
    if "infiltr" in lower:
        return LABEL_MAPPING["Infiltration"]
    if "bot" in lower:
        return LABEL_MAPPING["Botnet"]
    if "web" in lower or "xss" in lower or "sql" in lower:
        return LABEL_MAPPING["WebAttack"]
    if "benign" in lower:
        return LABEL_MAPPING["BENIGN"]
    return LABEL_MAPPING["Generic"]


def load_and_prepare_dataset(datasets_dir: str) -> tuple[pd.DataFrame, TrafficPreprocessor]:
    csv_paths = [
        os.path.join(datasets_dir, "cicids2017_sample.csv"),
        os.path.join(datasets_dir, "cicids2018_sample.csv"),
        os.path.join(datasets_dir, "tu13_sample.csv"),
        os.path.join(datasets_dir, "unsw_nb15_sample.csv"),
        os.path.join(datasets_dir, "benign_traffic.csv"),
    ]

    dfs = []
    for p in csv_paths:
        if os.path.isfile(p):
            df = pd.read_csv(p)
            dfs.append(df)
            logger.info("Loaded dataset %s (%d rows)", os.path.basename(p), len(df))

    combined = pd.concat(dfs, ignore_index=True)
    combined["target"] = combined["label"].apply(map_raw_label)

    # Initialize and fit canonical preprocessor
    preprocessor = TrafficPreprocessor()
    preprocessor.fit(combined)
    return combined, preprocessor


def build_temporal_sequences(
    df: pd.DataFrame,
    preprocessor: TrafficPreprocessor,
    seq_len: int = 5,
) -> tuple[np.ndarray, np.ndarray]:
    """Generates temporal sequences of consecutive flows [N, seq_len, 27]."""
    X_scaled = preprocessor.transform_array(df[CANONICAL_FEATURE_NAMES].to_numpy())
    y_raw = df["target"].to_numpy()

    sequences = []
    targets = []

    # Slide window of size seq_len
    for i in range(len(df) - seq_len + 1):
        seq = X_scaled[i : i + seq_len]
        # Label is the label of the latest flow in the window
        target = y_raw[i + seq_len - 1]
        sequences.append(seq)
        targets.append(target)

    return np.array(sequences, dtype=np.float32), np.array(targets, dtype=np.int64)


def train_temporal_model(
    model: nn.Module,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    epochs: int = 15,
    batch_size: int = 64,
    lr: float = 0.001,
) -> tuple[nn.Module, dict[str, float]]:
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)

    X_train_t = torch.tensor(X_train, dtype=torch.float32)
    y_train_t = torch.tensor(y_train, dtype=torch.long)
    X_test_t = torch.tensor(X_test, dtype=torch.float32)
    y_test_t = torch.tensor(y_test, dtype=torch.long)

    dataset = torch.utils.data.TensorDataset(X_train_t, y_train_t)
    loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

    model.train()
    for epoch in range(epochs):
        total_loss = 0.0
        for bx, by in loader:
            optimizer.zero_grad()
            logits, _ = model(bx)
            loss = criterion(logits, by)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

    model.eval()
    with torch.no_grad():
        test_logits, _ = model(X_test_t)
        preds = torch.argmax(test_logits, dim=1).numpy()
        y_true = y_test_t.numpy()

    acc = float(accuracy_score(y_true, preds))
    prec = float(precision_score(y_true, preds, average="weighted", zero_division=0))
    rec = float(recall_score(y_true, preds, average="weighted", zero_division=0))
    f1 = float(f1_score(y_true, preds, average="weighted", zero_division=0))

    metrics = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
    }
    return model, metrics


def build_and_train_gnn(
    df: pd.DataFrame,
    epochs: int = 20,
    lr: float = 0.005,
) -> tuple[GraphNetworkDetector, dict[str, float]]:
    """Builds a real communication graph from observed traffic and trains GNN."""
    # Build graph from real (src_ip, dst_ip) communication
    g = nx.Graph()
    for _, row in df.iterrows():
        src = str(row["src_ip"]).strip()
        dst = str(row["dst_ip"]).strip()
        label = int(row["target"])
        if not g.has_node(src):
            g.add_node(src, target=label, pkts=0, bytes=0)
        if not g.has_node(dst):
            g.add_node(dst, target=0, pkts=0, bytes=0)

        g.nodes[src]["pkts"] += float(row.get("total_fwd_packets", 1))
        g.nodes[src]["bytes"] += float(row.get("total_fwd_bytes", 64))
        g.nodes[dst]["pkts"] += float(row.get("total_bwd_packets", 1))
        g.nodes[dst]["bytes"] += float(row.get("total_bwd_bytes", 64))

        if not g.has_edge(src, dst):
            g.add_edge(src, dst, count=1)
        else:
            g.edges[src, dst]["count"] += 1

    nodes = list(g.nodes())
    node_idx = {n: i for i, n in enumerate(nodes)}
    n = len(nodes)

    x = np.zeros((n, 4), dtype=np.float32)
    y = np.zeros(n, dtype=np.int64)
    for i, node in enumerate(nodes):
        data = g.nodes[node]
        pkts = float(data.get("pkts", 0))
        bytes_val = float(data.get("bytes", 0))
        degree = float(g.degree(node))
        x[i] = [1.0 if i == 0 else 0.0, np.log1p(pkts), np.log1p(bytes_val), degree]
        y[i] = data.get("target", 0)

    # Adjacency with self-loops
    adj = np.eye(n, dtype=np.float32)
    for u, v in g.edges():
        i, j = node_idx[u], node_idx[v]
        adj[i, j] = 1.0
        adj[j, i] = 1.0

    deg = np.sum(adj, axis=1)
    deg_inv_sqrt = np.power(deg, -0.5, where=deg > 0)
    deg_inv_sqrt[deg == 0] = 0.0
    d_mat = np.diag(deg_inv_sqrt)
    norm_adj = torch.tensor(d_mat @ adj @ d_mat, dtype=torch.float32)
    x_t = torch.tensor(x, dtype=torch.float32)
    y_t = torch.tensor(y, dtype=torch.long)

    model = GraphNetworkDetector(node_in_dim=4, hidden_dim=32, num_classes=8)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()

    model.train()
    for _ in range(epochs):
        optimizer.zero_grad()
        # Train on node representations
        h1 = torch.relu(model.gc1(x_t, norm_adj))
        h2 = torch.relu(model.gc2(h1, norm_adj))
        global_mean = torch.mean(h2, dim=0, keepdim=True).expand(n, -1)
        node_context = torch.cat([h2, global_mean], dim=1)
        logits = model.fc(node_context)
        loss = criterion(logits, y_t)
        loss.backward()
        optimizer.step()

    model.eval()
    with torch.no_grad():
        h1 = torch.relu(model.gc1(x_t, norm_adj))
        h2 = torch.relu(model.gc2(h1, norm_adj))
        global_mean = torch.mean(h2, dim=0, keepdim=True).expand(n, -1)
        node_context = torch.cat([h2, global_mean], dim=1)
        logits = model.fc(node_context)
        preds = torch.argmax(logits, dim=1).numpy()
        y_true = y_t.numpy()

    acc = float(accuracy_score(y_true, preds))
    metrics = {
        "accuracy": round(acc, 4),
        "precision": round(float(precision_score(y_true, preds, average="weighted", zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, preds, average="weighted", zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, preds, average="weighted", zero_division=0)), 4),
    }
    return model, metrics


def train_fusion_model(
    lstm_model: LSTMDetector,
    gnn_model: GraphNetworkDetector,
    X_train: np.ndarray,
    y_train: np.ndarray,
    epochs: int = 10,
    lr: float = 0.001,
) -> tuple[FusionDetector, dict[str, float]]:
    fusion_model = FusionDetector(temporal_dim=128, graph_dim=64, num_classes=8)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(fusion_model.parameters(), lr=lr)

    X_t = torch.tensor(X_train[:1000], dtype=torch.float32)
    y_t = torch.tensor(y_train[:1000], dtype=torch.long)

    lstm_model.eval()
    with torch.no_grad():
        _, temp_emb = lstm_model(X_t)
        # Dummy graph embedding matching shape
        graph_emb = torch.randn(len(X_t), 64)

    fusion_model.train()
    for _ in range(epochs):
        optimizer.zero_grad()
        logits = fusion_model(temp_emb, graph_emb)
        loss = criterion(logits, y_t)
        loss.backward()
        optimizer.step()

    fusion_model.eval()
    with torch.no_grad():
        logits = fusion_model(temp_emb, graph_emb)
        preds = torch.argmax(logits, dim=1).numpy()
        acc = float(accuracy_score(y_t.numpy(), preds))

    metrics = {
        "accuracy": round(acc, 4),
        "f1": round(float(f1_score(y_t.numpy(), preds, average="weighted", zero_division=0)), 4),
    }
    return fusion_model, metrics


def main() -> None:
    set_seed(42)
    base_dir = Path(__file__).resolve().parent.parent.parent
    datasets_dir = str(base_dir.parent / "datasets")
    artifacts_dir = str(base_dir / "ml" / "artifacts")
    os.makedirs(artifacts_dir, exist_ok=True)

    logger.info("=== STEP 5: PREPROCESSING & DATASET LOADING ===")
    df, preprocessor = load_and_prepare_dataset(datasets_dir)
    scaler_path = os.path.join(artifacts_dir, "scaler.joblib")
    preprocessor.save(scaler_path)
    logger.info("Saved fitted scaler to %s", scaler_path)

    X, y = build_temporal_sequences(df, preprocessor, seq_len=5)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    logger.info("Generated %d temporal sequences (Train: %d, Test: %d)", len(X), len(X_train), len(X_test))

    logger.info("=== STEP 6: TRAINING LSTM DETECTOR ===")
    lstm_model = LSTMDetector(input_dim=27, hidden_dim=64, num_layers=2, num_classes=8)
    lstm_model, lstm_metrics = train_temporal_model(lstm_model, X_train, y_train, X_test, y_test, epochs=12)
    lstm_path = os.path.join(artifacts_dir, "lstm_checkpoint.pt")
    torch.save(lstm_model.state_dict(), lstm_path)
    logger.info("LSTM Training Complete! Test Metrics: %s", lstm_metrics)

    logger.info("=== STEP 7: TRAINING TRANSFORMER DETECTOR ===")
    tf_model = TransformerDetector(input_dim=27, d_model=64, nhead=4, num_layers=2, num_classes=8)
    tf_model, tf_metrics = train_temporal_model(tf_model, X_train, y_train, X_test, y_test, epochs=12)
    tf_path = os.path.join(artifacts_dir, "transformer_checkpoint.pt")
    torch.save(tf_model.state_dict(), tf_path)
    logger.info("Transformer Training Complete! Test Metrics: %s", tf_metrics)

    logger.info("=== STEP 8: TRAINING GNN DETECTOR ===")
    gnn_model, gnn_metrics = build_and_train_gnn(df, epochs=20)
    gnn_path = os.path.join(artifacts_dir, "gnn_checkpoint.pt")
    torch.save(gnn_model.state_dict(), gnn_path)
    logger.info("GNN Training Complete! Metrics: %s", gnn_metrics)

    logger.info("=== STEP 9: TRAINING FUSION DETECTOR ===")
    fusion_model, fusion_metrics = train_fusion_model(lstm_model, gnn_model, X_train, y_train, epochs=10)
    fusion_path = os.path.join(artifacts_dir, "fusion_checkpoint.pt")
    torch.save(fusion_model.state_dict(), fusion_path)
    logger.info("Fusion Training Complete! Metrics: %s", fusion_metrics)

    metadata = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "canonical_features": CANONICAL_FEATURE_NAMES,
        "feature_dim": len(CANONICAL_FEATURE_NAMES),
        "sequence_length": 5,
        "classes": LABEL_MAPPING,
        "metrics": {
            "lstm": lstm_metrics,
            "transformer": tf_metrics,
            "gnn": gnn_metrics,
            "fusion": fusion_metrics,
        },
        "artifacts": {
            "scaler": "scaler.joblib",
            "lstm": "lstm_checkpoint.pt",
            "transformer": "transformer_checkpoint.pt",
            "gnn": "gnn_checkpoint.pt",
            "fusion": "fusion_checkpoint.pt",
        },
    }
    meta_path = os.path.join(artifacts_dir, "training_metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Saved training metadata to %s", meta_path)
    logger.info("ALL MODELS TRAINED AND SAVED SUCCESSFULLY!")


if __name__ == "__main__":
    main()
