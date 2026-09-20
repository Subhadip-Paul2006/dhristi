# Drishti v0.1 — multi-modal feature fusion model | Phase 02
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F


class FusionDetector(nn.Module):
    """Fuses temporal window representation (from LSTM/Transformer) with graph topology embedding (from GNN).

    Input:
      - temporal_emb: [batch_size, temporal_dim] (e.g. 128 from BiLSTM or 64 from Transformer)
      - graph_emb: [batch_size, graph_dim] (e.g. 64 from GNN)
    Produces:
      - fused_logits: [batch_size, num_classes=8]
      - fused_confidence: [batch_size]
    """

    def __init__(
        self,
        temporal_dim: int = 128,
        graph_dim: int = 64,
        num_classes: int = 8,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        fused_dim = temporal_dim + graph_dim
        self.fusion_mlp = nn.Sequential(
            nn.Linear(fused_dim, 96),
            nn.BatchNorm1d(96),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(96, 48),
            nn.ReLU(),
            nn.Linear(48, num_classes),
        )

    def forward(self, temporal_emb: torch.Tensor, graph_emb: torch.Tensor) -> torch.Tensor:
        # Match batch sizes if needed
        if temporal_emb.size(0) != graph_emb.size(0):
            graph_emb = graph_emb.expand(temporal_emb.size(0), -1)
        combined = torch.cat([temporal_emb, graph_emb], dim=1)
        logits = self.fusion_mlp(combined)
        return logits
