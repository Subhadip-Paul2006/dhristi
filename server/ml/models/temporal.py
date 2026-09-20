# Drishti v0.1 — temporal neural network models (LSTM & Transformer) | Phase 02
from __future__ import annotations

import math
import torch
import torch.nn as nn
import torch.nn.functional as F


class BaseTemporalModel(nn.Module):
    """Abstract base for temporal sequence detectors consuming canonical 27-feature windows."""

    def __init__(self, input_dim: int = 27, num_classes: int = 8) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.num_classes = num_classes


class LSTMDetector(BaseTemporalModel):
    """Bidirectional LSTM with temporal attention pooling for sliding traffic windows.

    Input tensor shape: [batch_size, seq_len=5, feature_dim=27]
    Output: logits [batch_size, num_classes], embedding [batch_size, hidden_dim * 2]
    """

    def __init__(
        self,
        input_dim: int = 27,
        hidden_dim: int = 64,
        num_layers: int = 2,
        num_classes: int = 8,
        dropout: float = 0.2,
    ) -> None:
        super().__init__(input_dim=input_dim, num_classes=num_classes)
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
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim * 2, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_classes),
        )

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        # x: [B, T, D]
        lstm_out, _ = self.lstm(x)  # [B, T, 2 * H]
        # Attention weights over time steps
        attn_weights = F.softmax(self.attention(lstm_out), dim=1)  # [B, T, 1]
        context = torch.sum(attn_weights * lstm_out, dim=1)  # [B, 2 * H]
        logits = self.fc(context)  # [B, num_classes]
        return logits, context


class PositionalEncoding(nn.Module):
    def __init__(self, d_model: int, max_len: int = 32) -> None:
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", pe.unsqueeze(0))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.pe[:, : x.size(1)]


class TransformerDetector(BaseTemporalModel):
    """Multi-Head Self-Attention Transformer encoder for sliding traffic window sequences.

    Input tensor shape: [batch_size, seq_len=5, feature_dim=27]
    Output: logits [batch_size, num_classes], embedding [batch_size, d_model]
    """

    def __init__(
        self,
        input_dim: int = 27,
        d_model: int = 64,
        nhead: int = 4,
        num_layers: int = 2,
        dim_feedforward: int = 128,
        num_classes: int = 8,
        dropout: float = 0.2,
    ) -> None:
        super().__init__(input_dim=input_dim, num_classes=num_classes)
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
        self.fc = nn.Sequential(
            nn.Linear(d_model, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_classes),
        )

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        # x: [B, T, D]
        proj = self.input_projection(x)  # [B, T, d_model]
        encoded = self.pos_encoder(proj)
        out = self.transformer_encoder(encoded)  # [B, T, d_model]
        # Mean pooling across sequence dimension
        pooled = torch.mean(out, dim=1)  # [B, d_model]
        logits = self.fc(pooled)
        return logits, pooled
