# adaptive_metrics_tuned.py
# Runs the tuned adaptive Kitsune version and saves packet-level + summary metrics.

import time
import numpy as np
import pandas as pd
import psutil
from Kitsune import Kitsune

# -------------------------
# Dataset path
# -------------------------
path = "mirai.pcap"
packet_limit = np.inf

# -------------------------
# Base Kitsune model parameters
# -------------------------
maxAE = 10
FMgrace = 5000
ADgrace = 50000
learning_rate = 0.1
hidden_ratio = 0.75
sensitivity = 1

# -------------------------
# Tuned adaptive-threshold parameters
# -------------------------
adaptive_window_size = 2000
adaptive_z = 3.5
adaptive_min_samples = 300
adaptive_use_log = False

enable_drift = True
drift_window_size = 100
drift_min_count = 100
drift_cv_threshold = 0.10
hard_ceiling_factor = 3.0

# Known attack start used in original Mirai demo
attack_start_index = 70000
execution_start_index = FMgrace + ADgrace + 1

print("Starting tuned adaptive-threshold Kitsune run...")

# -------------------------
# Create Kitsune with adaptive threshold enabled
# -------------------------
NIDS = Kitsune(
    path,
    packet_limit,
    maxAE,
    FMgrace,
    ADgrace,
    learning_rate,
    hidden_ratio,
    sensitivity,
    use_adaptive_threshold=True,
    adaptive_window_size=adaptive_window_size,
    adaptive_z=adaptive_z,
    adaptive_min_samples=adaptive_min_samples,
    adaptive_use_log=adaptive_use_log,
    enable_drift=enable_drift,
    drift_window_size=drift_window_size,
    drift_min_count=drift_min_count,
    drift_cv_threshold=drift_cv_threshold,
    hard_ceiling_factor=hard_ceiling_factor,
)

# -------------------------
# Storage for packet-level metrics
# -------------------------
RMSEs = []
thresholds = []
alerts = []
means = []
stds = []
drift_counts = []
drift_adapted = []
packet_indices = []

# Process resource monitor
proc = psutil.Process()
cpu_samples = []
ram_samples = []

start_time = time.time()
i = 0

# -------------------------
# Main processing loop
# -------------------------
while True:
    rmse = NIDS.proc_next_packet()
    if rmse == -1:
        break

    packet_indices.append(i)
    RMSEs.append(rmse)

    if len(NIDS.threshold_history) > 0:
        thresholds.append(NIDS.threshold_history[-1])
        alerts.append(NIDS.alert_history[-1])
        means.append(NIDS.mean_history[-1])
        stds.append(NIDS.std_history[-1])
        drift_counts.append(NIDS.drift_count_history[-1])
        drift_adapted.append(NIDS.drift_adapted_history[-1])
    else:
        thresholds.append(None)
        alerts.append(0)
        means.append(None)
        stds.append(None)
        drift_counts.append(None)
        drift_adapted.append(False)

    # Sample resource usage every 2000 packets
    if i % 2000 == 0:
        cpu_samples.append(psutil.cpu_percent(interval=None))
        ram_samples.append(proc.memory_info().rss / (1024 * 1024))

    # Print progress every 10000 packets
    if i % 10000 == 0:
        print(f"Processed {i} packets...")

    i += 1

end_time = time.time()

# -------------------------
# Compute summary metrics
# -------------------------
total_packets = len(RMSEs)
runtime_sec = end_time - start_time
packets_per_sec = total_packets / runtime_sec if runtime_sec > 0 else None

pre_attack_alerts = 0
post_attack_alerts = 0
first_post_attack_alert = None

for idx in range(total_packets):
    if idx < attack_start_index:
        if alerts[idx] == 1:
            pre_attack_alerts += 1
    else:
        if alerts[idx] == 1:
            post_attack_alerts += 1
            if first_post_attack_alert is None:
                first_post_attack_alert = idx

detection_latency = None
if first_post_attack_alert is not None:
    detection_latency = first_post_attack_alert - attack_start_index

summary = {
    "total_packets": total_packets,
    "FMgrace": FMgrace,
    "ADgrace": ADgrace,
    "runtime_sec": runtime_sec,
    "packets_per_sec": packets_per_sec,
    "execution_start_index": execution_start_index,
    "attack_start_index": attack_start_index,
    "adaptive_window_size": adaptive_window_size,
    "adaptive_z": adaptive_z,
    "adaptive_min_samples": adaptive_min_samples,
    "adaptive_use_log": adaptive_use_log,
    "enable_drift": enable_drift,
    "drift_window_size": drift_window_size,
    "drift_min_count": drift_min_count,
    "drift_cv_threshold": drift_cv_threshold,
    "hard_ceiling_factor": hard_ceiling_factor,
    "pre_attack_alerts": pre_attack_alerts,
    "post_attack_alerts": post_attack_alerts,
    "first_post_attack_alert": first_post_attack_alert,
    "detection_latency_packets": detection_latency,
    "avg_cpu_percent_sampled": float(np.mean(cpu_samples)) if cpu_samples else None,
    "peak_ram_mb": float(np.max(ram_samples)) if ram_samples else None,
    "avg_ram_mb": float(np.mean(ram_samples)) if ram_samples else None,
}

# -------------------------
# Save packet-level metrics
# -------------------------
packet_df = pd.DataFrame({
    "packet_index": packet_indices,
    "rmse": RMSEs,
    "adaptive_threshold": thresholds,
    "alert": alerts,
    "rolling_mean": means,
    "rolling_std": stds,
    "drift_count": drift_counts,
    "drift_adapted": drift_adapted,
})
packet_df.to_csv("adaptive_model_packet_metrics_tuned.csv", index=False)

# -------------------------
# Save summary metrics
# -------------------------
summary_df = pd.DataFrame([summary])
summary_df.to_csv("adaptive_model_summary_metrics_tuned.csv", index=False)

print("\nTuned adaptive model summary:")
for k, v in summary.items():
    print(f"{k}: {v}")

print("\nSaved files:")
print(" - adaptive_model_packet_metrics_tuned.csv")
print(" - adaptive_model_summary_metrics_tuned.csv")