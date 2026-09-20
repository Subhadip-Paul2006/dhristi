# Drishti v0.1 — future attack forecasting deep learning models | Phase 03
# Multi-step forecasting architectures: LSTM, Transformer, Temporal GNN, and Multimodal Fusion
from __future__ import annotations

import math
from typing import Any
import torch
import torch.nn as nn
import torch.nn.functional as F

from ml.models.gnn import GraphConvolution
from ml.models.temporal import PositionalEncoding


class BaseForecaster(nn.Module):
    """Abstract base class for multi-step network behaviour forecasters.

    Predicts future behavior at horizon steps t+1, t+2, t+3 (default horizon=3).
    Output shape: [batch_size, horizon, num_classes]
    """

    def __init__(self, input_dim: int = 27, horizon: int = 3, num_classes: int = 5) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.horizon = horizon
        self.num_classes = num_classes


class LSTMForecaster(BaseForecaster):
    """Bidirectional LSTM with temporal attention and multi-step forecasting projection.

    Consumes sliding window sequence [B, seq_len=5, feature_dim=27].
    Produces:
      - forecast_logits: [B, horizon=3, num_classes=5]
      - temporal_emb: [B, hidden_dim * 2 = 128]
    """

    def __init__(
        self,
        input_dim: int = 27,
        hidden_dim: int = 64,
        num_layers: int = 2,
        horizon: int = 3,
        num_classes: int = 5,
        dropout: float = 0.2,
    ) -> None:
        super().__init__(input_dim=input_dim, horizon=horizon, num_classes=num_classes)
        self.hidden_dim = hidden_dim
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.attention = nn.Linear(hidden_dim * 2, 1)

        # Multi-step projection head producing logits for [t+1, t+2, t+3]
        self.forecast_heads = nn.ModuleList([
            nn.Sequential(
                nn.Linear(hidden_dim * 2, 64),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(64, num_classes),
            )
            for _ in range(horizon)
        ])

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        # x: [B, seq_len, input_dim]
        lstm_out, _ = self.lstm(x)  # [B, seq_len, 2 * hidden_dim]
        attn_weights = F.softmax(self.attention(lstm_out), dim=1)  # [B, seq_len, 1]
        context = torch.sum(attn_weights * lstm_out, dim=1)  # [B, 2 * hidden_dim]

        # Multi-step forecasts: list of [B, num_classes] -> stacked to [B, horizon, num_classes]
        step_logits = [head(context) for head in self.forecast_heads]
        stacked_logits = torch.stack(step_logits, dim=1)  # [B, horizon, num_classes]
        return stacked_logits, context


class TransformerForecaster(BaseForecaster):
    """Transformer Encoder with multi-step autoregressive projection heads.

    Consumes sliding window sequence [B, seq_len=5, feature_dim=27].
    Produces:
      - forecast_logits: [B, horizon=3, num_classes=5]
      - temporal_emb: [B, d_model = 64]
    """

    def __init__(
        self,
        input_dim: int = 27,
        d_model: int = 64,
        nhead: int = 4,
        num_layers: int = 2,
        dim_feedforward: int = 128,
        horizon: int = 3,
        num_classes: int = 5,
        dropout: float = 0.2,
    ) -> None:
        super().__init__(input_dim=input_dim, horizon=horizon, num_classes=num_classes)
        self.d_model = d_model
        self.input_projection = nn.Linear(input_dim, d_model)
        self.pos_encoder = PositionalEncoding(d_model=d_model)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True,
            activation="relu",
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        # Multi-step projection heads for horizon steps
        self.forecast_heads = nn.ModuleList([
            nn.Sequential(
                nn.Linear(d_model, 64),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(64, num_classes),
            )
            for _ in range(horizon)
        ])

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        # x: [B, seq_len, input_dim]
        proj = self.input_projection(x)
        encoded = self.pos_encoder(proj)
        out = self.transformer_encoder(encoded)  # [B, seq_len, d_model]
        pooled = torch.mean(out, dim=1)  # [B, d_model]

        step_logits = [head(pooled) for head in self.forecast_heads]
        stacked_logits = torch.stack(step_logits, dim=1)  # [B, horizon, num_classes]
        return stacked_logits, pooled


class TemporalGraphForecaster(nn.Module):
    """Evaluates topology dynamics across temporal graphs [Graph_t-2, Graph_t-1, Graph_t].

    Consumes:
      - node_features: [N, 4]
      - norm_adj: [N, N]
      - temporal_graph_features: [B, 8] (node delta, edge delta, packet rate delta, new edge ratio, etc.)
    Produces:
      - forecast_logits: [B, horizon=3, num_classes=5]
      - graph_emb: [B, 64]
    """

    def __init__(
        self,
        node_in_dim: int = 4,
        spatial_hidden_dim: int = 32,
        temporal_graph_dim: int = 8,
        horizon: int = 3,
        num_classes: int = 5,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.horizon = horizon
        self.num_classes = num_classes

        # Spatial GNN layers on current graph topology
        self.gc1 = GraphConvolution(node_in_dim, spatial_hidden_dim)
        self.gc2 = GraphConvolution(spatial_hidden_dim, spatial_hidden_dim)
        self.dropout = nn.Dropout(dropout)

        # Temporal topological velocity encoder
        self.temporal_encoder = nn.Sequential(
            nn.Linear(temporal_graph_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 32),
        )

        # Fused graph representation: (spatial target + spatial mean = 64) + velocity (32) -> 64
        self.graph_fusion = nn.Sequential(
            nn.Linear(spatial_hidden_dim * 2 + 32, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
        )

        self.forecast_heads = nn.ModuleList([
            nn.Sequential(
                nn.Linear(64, 32),
                nn.ReLU(),
                nn.Linear(32, num_classes),
            )
            for _ in range(horizon)
        ])

    def forward(
        self,
        node_features: torch.Tensor,
        norm_adj: torch.Tensor,
        temporal_graph_features: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        # Spatial convolution on current graph
        h1 = F.relu(self.gc1(node_features, norm_adj))
        h1 = self.dropout(h1)
        h2 = F.relu(self.gc2(h1, norm_adj))  # [N, spatial_hidden_dim]

        target_emb = h2[0:1]  # Target device is always index 0
        global_mean = torch.mean(h2, dim=0, keepdim=True)
        spatial_emb = torch.cat([target_emb, global_mean], dim=1)  # [1, 64]

        # Process temporal graph dynamics
        if temporal_graph_features is None:
            temporal_graph_features = torch.zeros((spatial_emb.size(0), 8), device=spatial_emb.device)
        elif temporal_graph_features.dim() == 1:
            temporal_graph_features = temporal_graph_features.unsqueeze(0)

        # Match batch size if needed
        if spatial_emb.size(0) != temporal_graph_features.size(0):
            spatial_emb = spatial_emb.expand(temporal_graph_features.size(0), -1)

        temp_velocity = self.temporal_encoder(temporal_graph_features)  # [B, 32]
        fused_graph = self.graph_fusion(torch.cat([spatial_emb, temp_velocity], dim=1))  # [B, 64]

        step_logits = [head(fused_graph) for head in self.forecast_heads]
        stacked_logits = torch.stack(step_logits, dim=1)  # [B, horizon, num_classes]
        return stacked_logits, fused_graph


class FusionForecaster(nn.Module):
    """Multimodal fusion forecaster combining temporal sequences with dynamic graph topology.

    Consumes:
      - temporal_emb: [B, temporal_dim] (128 from LSTM or 64 from Transformer)
      - graph_emb: [B, graph_dim] (64 from TemporalGraphForecaster)
    Produces:
      - forecast_logits: [B, horizon=3, num_classes=5]
    """

    def __init__(
        self,
        temporal_dim: int = 128,
        graph_dim: int = 64,
        horizon: int = 3,
        num_classes: int = 5,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.horizon = horizon
        self.num_classes = num_classes
        fused_dim = temporal_dim + graph_dim

        self.backbone = nn.Sequential(
            nn.Linear(fused_dim, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 64),
            nn.ReLU(),
        )

        self.forecast_heads = nn.ModuleList([
            nn.Sequential(
                nn.Linear(64, 32),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(32, num_classes),
            )
            for _ in range(horizon)
        ])

    def forward(self, temporal_emb: torch.Tensor, graph_emb: torch.Tensor) -> torch.Tensor:
        if temporal_emb.size(0) != graph_emb.size(0):
            graph_emb = graph_emb.expand(temporal_emb.size(0), -1)
        fused = torch.cat([temporal_emb, graph_emb], dim=1)
        hidden = self.backbone(fused)  # [B, 64]

        step_logits = [head(hidden) for head in self.forecast_heads]
        return torch.stack(step_logits, dim=1)  # [B, horizon, num_classes]
