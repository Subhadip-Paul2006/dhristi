from collections import deque
from dataclasses import dataclass, field
import logging
import time
from typing import Any
import networkx as nx
import numpy as np
import torch

logger = logging.getLogger("drishti")


@dataclass
class GraphSnapshot:
    timestamp: float
    num_nodes: int
    num_edges: int
    total_packets: int
    total_bytes: int
    conn_count: int
    target_degree: int
    edges: set[tuple[str, str]] = field(default_factory=set)
    protocol_distribution: dict[int, int] = field(default_factory=dict)


class NetworkGraphEngine:
    """Constructs dynamic communication graph strictly from observed network flows.

    Nodes: Observed IP hosts (target device and communication peers).
    Edges: Real 5-tuple communications with bidirectional packet/byte attribution.
    ZERO FABRICATION: Only actual observed communication creates nodes/edges.
    Maintains temporal sequence: [Graph_t-2, Graph_t-1, Graph_t]
    """

    def __init__(self, target_ip: str) -> None:
        self.target_ip = target_ip.strip()
        self.graph = nx.Graph()
        self.history: deque[GraphSnapshot] = deque(maxlen=3)
        self._last_snapshot_time: float = time.time()
        # Ensure target device node exists
        self.graph.add_node(
            self.target_ip,
            is_target=True,
            packet_count=0,
            byte_count=0,
            conn_count=0,
            protocols={},
        )
        self.snapshot()


    def update_from_flows(self, flows: list[Any]) -> None:
        """Update network graph topology from real FlowRecords."""
        for flow in flows:
            src = getattr(flow, "src_ip", "").strip()
            dst = getattr(flow, "dst_ip", "").strip()
            if not src or not dst:
                continue

            # Update nodes
            for ip in (src, dst):
                if not self.graph.has_node(ip):
                    self.graph.add_node(
                        ip,
                        is_target=(ip == self.target_ip),
                        packet_count=0,
                        byte_count=0,
                        conn_count=0,
                    )
                node_data = self.graph.nodes[ip]
                node_data["packet_count"] += getattr(flow, "total_packets", 1)
                node_data["byte_count"] += getattr(flow, "total_bytes", 64)
                node_data["conn_count"] += 1

            # Update edge
            edge_key = (src, dst)
            if not self.graph.has_edge(src, dst):
                self.graph.add_edge(
                    src,
                    dst,
                    packet_count=0,
                    byte_count=0,
                    protocol=getattr(flow, "protocol", 6),
                    sport=getattr(flow, "src_port", 0),
                    dport=getattr(flow, "dst_port", 0),
                    duration=getattr(flow, "duration", 0.1),
                )
            edge_data = self.graph.edges[src, dst]
            edge_data["packet_count"] += getattr(flow, "total_packets", 1)
            edge_data["byte_count"] += getattr(flow, "total_bytes", 64)

    def get_graph_tensors(self) -> tuple[torch.Tensor, torch.Tensor]:
        """Convert graph into PyTorch (node_features, adjacency_matrix) tensors.

        node_features shape: [N, 4] -> [is_target, log(packets+1), log(bytes+1), degree]
        adjacency_matrix shape: [N, N] (normalized symmetrically)
        """
        nodes = list(self.graph.nodes())
        n = max(1, len(nodes))
        node_idx = {node: i for i, node in enumerate(nodes)}

        # Node features: 4-dim
        x = np.zeros((n, 4), dtype=np.float32)
        for i, node in enumerate(nodes):
            data = self.graph.nodes[node]
            pkts = float(data.get("packet_count", 0))
            bytes_val = float(data.get("byte_count", 0))
            degree = float(self.graph.degree(node))
            is_target = 1.0 if data.get("is_target") else 0.0
            x[i] = [
                is_target,
                np.log1p(pkts),
                np.log1p(bytes_val),
                degree,
            ]

        # Adjacency with self-loops
        adj = np.eye(n, dtype=np.float32)
        for u, v in self.graph.edges():
            i, j = node_idx[u], node_idx[v]
            adj[i, j] = 1.0
            adj[j, i] = 1.0

        # Degree normalization: D^(-0.5) * A * D^(-0.5)
        deg = np.sum(adj, axis=1)
        deg_inv_sqrt = np.power(deg, -0.5, where=deg > 0)
        deg_inv_sqrt[deg == 0] = 0.0
        d_mat = np.diag(deg_inv_sqrt)
        norm_adj = d_mat @ adj @ d_mat

        return torch.tensor(x, dtype=torch.float32), torch.tensor(norm_adj, dtype=torch.float32)

    def to_dict(self) -> dict[str, Any]:
        """Returns JSON-serializable graph structure for UI or telemetry."""
        nodes = []
        for n, data in self.graph.nodes(data=True):
            nodes.append({
                "id": n,
                "is_target": data.get("is_target", False),
                "packet_count": data.get("packet_count", 0),
                "byte_count": data.get("byte_count", 0),
            })
        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({
                "source": u,
                "target": v,
                "packet_count": data.get("packet_count", 0),
                "byte_count": data.get("byte_count", 0),
            })
        return {"nodes": nodes, "edges": edges}

    def snapshot(self) -> GraphSnapshot:
        """Captures a snapshot of the current graph state into temporal history [Graph_t-2, Graph_t-1, Graph_t]."""
        num_nodes = self.graph.number_of_nodes()
        num_edges = self.graph.number_of_edges()
        total_packets = sum(data.get("packet_count", 0) for _, data in self.graph.nodes(data=True))
        total_bytes = sum(data.get("byte_count", 0) for _, data in self.graph.nodes(data=True))
        conn_count = sum(data.get("conn_count", 0) for _, data in self.graph.nodes(data=True))
        target_degree = self.graph.degree(self.target_ip) if self.graph.has_node(self.target_ip) else 0

        edge_set = set()
        proto_dist: dict[int, int] = {}
        for u, v, d in self.graph.edges(data=True):
            edge_set.add((min(u, v), max(u, v)))
            p = d.get("protocol", 6)
            proto_dist[p] = proto_dist.get(p, 0) + 1

        snap = GraphSnapshot(
            timestamp=time.time(),
            num_nodes=num_nodes,
            num_edges=num_edges,
            total_packets=total_packets,
            total_bytes=total_bytes,
            conn_count=conn_count,
            target_degree=target_degree,
            edges=edge_set,
            protocol_distribution=proto_dist,
        )
        self.history.append(snap)
        self._last_snapshot_time = snap.timestamp
        return snap

    def get_temporal_graph_features(self) -> np.ndarray:
        """Computes 8-dim topological velocity vector across temporal graph history [G_t-2, G_t-1, G_t].

        Features:
        0: delta_nodes (nodes_t - nodes_t-1)
        1: delta_edges (edges_t - edges_t-1)
        2: delta_packets_log (log1p(pkts_t) - log1p(pkts_t-1))
        3: delta_bytes_log (log1p(bytes_t) - log1p(bytes_t-1))
        4: target_degree_delta
        5: new_edge_ratio (fraction of edges in G_t not in G_t-1)
        6: topological_velocity (sqrt(delta_nodes^2 + delta_edges^2))
        7: history_depth (count of stored snapshots, 1.0 to 3.0)
        """
        feats = np.zeros(8, dtype=np.float32)
        if len(self.history) < 2:
            feats[7] = float(len(self.history))
            return feats

        curr = self.history[-1]
        prev = self.history[-2]

        d_nodes = float(curr.num_nodes - prev.num_nodes)
        d_edges = float(curr.num_edges - prev.num_edges)
        d_pkts = float(np.log1p(curr.total_packets) - np.log1p(prev.total_packets))
        d_bytes = float(np.log1p(curr.total_bytes) - np.log1p(prev.total_bytes))
        d_deg = float(curr.target_degree - prev.target_degree)

        # New edges ratio
        new_edges = curr.edges - prev.edges
        new_edge_ratio = float(len(new_edges) / max(1, len(curr.edges)))

        topo_velocity = float(np.sqrt(d_nodes**2 + d_edges**2))

        feats[0] = d_nodes
        feats[1] = d_edges
        feats[2] = d_pkts
        feats[3] = d_bytes
        feats[4] = d_deg
        feats[5] = new_edge_ratio
        feats[6] = topo_velocity
        feats[7] = float(len(self.history))
        return feats

    def get_graph_dynamics_summary(self) -> list[str]:
        """Returns human-readable explainability descriptions of actual observed graph changes."""
        if len(self.history) < 2:
            return ["Initial communication graph established (single observation window)"]

        curr = self.history[-1]
        prev = self.history[-2]
        dynamics = []

        d_nodes = curr.num_nodes - prev.num_nodes
        d_edges = curr.num_edges - prev.num_edges
        if d_nodes > 0 or d_edges > 0:
            dynamics.append(f"Topological expansion: +{d_nodes} peer node(s), +{d_edges} communication edge(s)")
        elif d_nodes == 0 and d_edges == 0:
            dynamics.append("Stable network topology (no new communication peers)")

        new_edges = curr.edges - prev.edges
        if new_edges:
            sample_peer = next(iter(new_edges))
            other_ip = sample_peer[1] if sample_peer[0] == self.target_ip else sample_peer[0]
            dynamics.append(f"New communication edge established with {other_ip}")

        d_deg = curr.target_degree - prev.target_degree
        if d_deg >= 2:
            dynamics.append(f"Target connection fan-out increased (+{d_deg} active peers)")

        return dynamics

