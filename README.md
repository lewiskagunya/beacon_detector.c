# C-Based Network Beacon Detector (Layer 2)

A high-performance Network Intrusion Detection System (NIDS) logic written in C. This tool utilizes Linux Raw Sockets to perform **Temporal Analysis** on network traffic to identify Command & Control (C2) heartbeats.

## 🚀 Key Features
- **Raw Socket Integration:** Operates at Layer 2 (Data Link) to bypass standard kernel overhead.
- **Temporal Analysis:** Calculates microsecond variance ($\Delta T$) between packets.
- **Jitter-Aware Detection:** Implements a sliding window "Confidence Score" to filter out human noise.
- **Zero-Dependency:** Uses standard Linux headers (`sys/socket.h`, `sys/time.h`).

## 🧠 How the Logic Works
Unlike signature-based firewalls, this engine tracks the **rhythm** of traffic.
1. It stores the `last_seen` timestamp for every unique IP.
2. It calculates the `current_delta` (gap between packets).
3. If the `variance` (gap difference) is < 0.1s consistently for 5+ packets, it flags the IP as an automated Beacon.

## 🛠️ Usage
```bash
gcc src/beacon_detector.c -o beacon_detector
sudo ./beacon_detector
