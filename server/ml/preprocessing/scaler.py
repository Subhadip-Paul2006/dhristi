# Drishti v0.1 — canonical feature contract & preprocessor | Phase 02
from __future__ import annotations

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler

# Canonical 27 numerical flow features matching datasets/*.csv and feature_extractor.py
CANONICAL_FEATURE_NAMES: list[str] = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    "bwd_iat_mean",
    "bwd_iat_std",
    "flag_syn_count",
    "flag_ack_count",
    "flag_fin_count",
    "flag_rst_count",
    "flag_psh_count",
    "flag_urg_count",
    "fwd_avg_bytes_per_pkt",
    "bwd_avg_bytes_per_pkt",
    "active_mean",
    "idle_mean",
    "port_scan_score",
    "mean_ttl",
    "mean_tcp_window",
    "payload_entropy",
]

# Canonical Threat Classes across datasets
LABEL_MAPPING: dict[str, int] = {
    "BENIGN": 0,
    "DoS": 1,
    "PortScan": 2,
    "BruteForce": 3,
    "Infiltration": 4,
    "Botnet": 5,
    "WebAttack": 6,
    "Generic": 7,
}
INV_LABEL_MAPPING: dict[int, str] = {v: k for k, v in LABEL_MAPPING.items()}


class TrafficPreprocessor:
    """Preprocesses canonical 27-feature vectors using a fitted RobustScaler.

    STRICT GUARANTEE:
    Live traffic is ONLY transformed with pre-fitted weights.
    Never fits or adapts on live inference traffic.
    """

    def __init__(self) -> None:
        self.scaler = RobustScaler()
        self.is_fitted = False
        self.feature_names = list(CANONICAL_FEATURE_NAMES)

    def fit(self, df: pd.DataFrame) -> TrafficPreprocessor:
        """Fit scaler on offline training dataset dataframe."""
        X = df[self.feature_names].fillna(0.0).to_numpy(dtype=np.float32)
        # Clip inf values if any
        X = np.nan_to_num(X, nan=0.0, posinf=1e7, neginf=-1e7)
        self.scaler.fit(X)
        self.is_fitted = True
        return self

    def transform_dict(self, feature_dict: dict[str, float]) -> np.ndarray:
        """Transform a single feature dictionary into a normalized 1D vector (length 27)."""
        raw = [float(feature_dict.get(k, 0.0)) for k in self.feature_names]
        arr = np.array([raw], dtype=np.float32)
        arr = np.nan_to_num(arr, nan=0.0, posinf=1e7, neginf=-1e7)
        if self.is_fitted:
            scaled = self.scaler.transform(arr)
            return scaled[0]
        return arr[0]

    def transform_array(self, X: np.ndarray) -> np.ndarray:
        """Transform a 2D array of features of shape (N, 27)."""
        X_clean = np.nan_to_num(X, nan=0.0, posinf=1e7, neginf=-1e7)
        if self.is_fitted:
            return self.scaler.transform(X_clean).astype(np.float32)
        return X_clean.astype(np.float32)

    def save(self, filepath: str) -> None:
        """Persist fitted scaler to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(
            {
                "scaler": self.scaler,
                "is_fitted": self.is_fitted,
                "feature_names": self.feature_names,
                "label_mapping": LABEL_MAPPING,
            },
            filepath,
        )

    @classmethod
    def load(cls, filepath: str) -> TrafficPreprocessor:
        """Load pre-fitted scaler from disk."""
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Scaler artifact not found at {filepath}")
        data = joblib.load(filepath)
        instance = cls()
        instance.scaler = data["scaler"]
        instance.is_fitted = data.get("is_fitted", True)
        instance.feature_names = data.get("feature_names", list(CANONICAL_FEATURE_NAMES))
        return instance
