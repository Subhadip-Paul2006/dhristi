# Drishti v0.1 — graph neural network (GNN) model | Phase 02
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F


class GraphConvolution(nn.Module):
    """Simple graph convolution layer: H' = ReLU(A * H * W)."""

    def __init__(self, in_features: int, out_features: int) -> None:
        super().__init__()
        self.linear = nn.Linear(in_features, out_features, bias=True)

    def forward(self, x: torch.Tensor, norm_adj: torch.Tensor) -> torch.Tensor:
        # norm_adj: [N, N], x: [N, in_features]
        ax = torch.matmul(norm_adj, x)
        return self.linear(ax)


class GraphNetworkDetector(nn.Module):
    """Graph Neural Network detector evaluating communication graph topology.

    Consumes:
      - node_features: [N, node_in_dim=4]
      - norm_adj: [N, N] (normalized symmetric adjacency matrix)
    Produces:
      - logits: [1, num_classes=8]
      - graph_embedding: [1, hidden_dim=32]
    """

    def __init__(
        self,
        node_in_dim: int = 4,
        hidden_dim: int = 32,
        num_classes: int = 8,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.gc1 = GraphConvolution(node_in_dim, hidden_dim)
        self.gc2 = GraphConvolution(hidden_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim * 2, 32),
            nn.ReLU(),
            nn.Linear(32, num_classes),
        )

    def forward(self, node_features: torch.Tensor, norm_adj: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        # Layer 1
        h1 = F.relu(self.gc1(node_features, norm_adj))
        h1 = self.dropout(h1)
        # Layer 2
        h2 = F.relu(self.gc2(h1, norm_adj))  # [N, hidden_dim]

        # Target node readout (index 0 is target device) + graph global mean
        target_embedding = h2[0:1]  # [1, hidden_dim]
        global_mean = torch.mean(h2, dim=0, keepdim=True)  # [1, hidden_dim]
        graph_embedding = torch.cat([target_embedding, global_mean], dim=1)  # [1, 2 * hidden_dim]

        logits = self.fc(graph_embedding)  # [1, num_classes]
        return logits, graph_embedding
