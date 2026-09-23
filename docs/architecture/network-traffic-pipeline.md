# 🌊 Network Traffic Pipeline & Session Tracking

> **Parent Specification:** [RESEARCH.md](../../RESEARCH.md) · [TRD.md](../../TRD.md)  
> **Source Module:** `server/app/services/traffic/`, `agent/drishti_watch.py`

---

## 1. Multi-Plane Traffic Ingestion

Drishti ingests network telemetry without requiring destructive active probing:

![Drishti Network Traffic Flow](../../assets/svg/network/traffic-flow.svg)

1. **Kernel Driver Layer:**
   - **Linux:** `AF_PACKET` socket with `mmap` zero-copy ring buffer.
   - **macOS:** `/dev/bpf*` Berkley Packet Filter interface.
   - **Windows:** Npcap / WinPcap kernel driver in promiscuous mode.
2. **Decapsulation Seam:**
   - Decodes Ethernet (L2), IPv4/IPv6 (L3), and TCP/UDP/ICMP (L4) headers.
   - Discards packet payloads to guarantee confidentiality and avoid data leakage.
3. **Capture Adapter Plugins:**
   - Supports Scapy 2.5 streaming, TShark background capture, and Zeek connection log parsing.

---

## 2. 5-Tuple Aggregation & Flow Tracking

![Drishti Low-Level Packet Pipeline](../../assets/svg/traffic/packet-flow.svg)

Incoming packets are grouped into bidirectional session flows:
$$\text{Flow Key} = \text{hash}(\min(\text{src}, \text{dst}), \max(\text{src}, \text{dst}), \min(\text{sport}, \text{dport}), \max(\text{sport}, \text{dport}), \text{proto})$$

- **Sliding Window Buffer:** Tracks flow metrics over 10-second sliding windows with 5-second strides.
- **Session Eviction:** Flows are finalized and dispatched to the analytics core upon receiving TCP FIN/RST or after a 60-second inactivity timeout.

---

## 3. 27-Feature Canonical Vector

![Drishti Traffic Analysis Pipeline](../../assets/svg/traffic/traffic-analysis.svg)

For each active flow, Drishti computes a 27-dimensional canonical statistical feature vector:

1. **Packet Lengths (7):** Mean, standard deviation, max, min, forward mean, backward mean, skewness.
2. **Inter-Arrival Times (6):** Flow IAT mean, standard deviation, max, forward IAT mean, backward IAT mean, flow duration.
3. **TCP Flags & Ratios (8):** SYN count, ACK count, SYN-to-ACK ratio, RST count, PSH count, FIN count, download-to-upload ratio, packet ratio.
4. **Entropy & Symmetry (6):** Destination port entropy $H(\text{dst\_port})$, byte rate, packet rate, flow symmetry score.

---

## 4. Anomaly Detection & MITRE Mapping

- **Statistical Outlier Detection:** Z-score thresholding on sliding window baselines ($\mu \pm 3\sigma$).
- **MITRE ATT&CK Correlation:**
  - High SYN-to-ACK ratio ($> 5.0$) $\to$ **T1046 Network Service Scanning**.
  - High asymmetric outbound bytes with periodic beaconing $\to$ **T1041 Exfiltration Over C2 Channel**.
  - Internal SMB/Kerberos traffic spikes $\to$ **T1021 Remote Services / Lateral Movement**.
