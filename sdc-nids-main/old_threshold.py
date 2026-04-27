import os
import time
import numpy as np
import pandas as pd
import psutil
from Kitsune import Kitsune

# -------------------------
# Configuration
# -------------------------
path = "mirai.pcap"
packet_limit = np.inf

maxAE = 10
FMgrace = 5000
ADgrace = 50000
learning_rate = 0.1
hidden_ratio = 0.75
sensitivity = 1

# Known attack onset used in original example comments
attack_start_index = 70000
execution_start_index = FMgrace + ADgrace + 1

# -------------------------
# Build ORIGINAL Kitsune model (fixed-threshold mode)
# -------------------------
print("Starting old/original model baseline run...")

NIDS = Kitsune(
    path,
    packet_limit,
    maxAE,
    FMgrace,
    ADgrace,
    learning_rate,
    hidden_ratio,
    sensitivity,
    use_adaptive_threshold=False,   # explicitly keep OLD logic
    adaptive_window_size=1000,      # unused in old mode, kept for clarity
    adaptive_z=3.0,                 # unused in old mode
    adaptive_min_samples=100,       # unused in old mode
    adaptive_use_log=False,         # unused in old mode
    enable_drift=False,             # unused in old mode
    drift_window_size=100,          # unused in old mode
    drift_min_count=50,             # unused in old mode
    drift_cv_threshold=0.20,        # unused in old mode
    hard_ceiling_factor=3.0         # unused in old mode
)

RMSEs = []
alerts = []
thresholds = []
packet_indices = []

proc = psutil.Process(os.getpid())
cpu_samples = []
ram_samples = []
sample_points = []

start_time = time.time()
i = 0

while True:
    rmse = NIDS.proc_next_packet()
    if rmse == -1:
        break

    RMSEs.append(rmse)
    packet_indices.append(i)

    # Old fixed threshold = phi * sensitivity
    current_threshold = NIDS.phi * NIDS.AnomDetector.sensitivity
    thresholds.append(current_threshold)

    # Alerts only count after training has completed
    if NIDS.AnomDetector.n_trained > (
        NIDS.AnomDetector.FM_grace_period + NIDS.AnomDetector.AD_grace_period
    ):
        alert = int(rmse > current_threshold)
    else:
        alert = 0

    alerts.append(alert)

    # Sample resource usage every 2000 packets
    if i % 2000 == 0:
        cpu_samples.append(psutil.cpu_percent(interval=None))
        ram_samples.append(proc.memory_info().rss / (1024 * 1024))
        sample_points.append(i)
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
    "runtime_sec": runtime_sec,
    "packets_per_sec": packets_per_sec,
    "FMgrace": FMgrace,
    "ADgrace": ADgrace,
    "execution_start_index": execution_start_index,
    "attack_start_index": attack_start_index,
    "phi": NIDS.phi,
    "fixed_threshold": NIDS.phi * NIDS.AnomDetector.sensitivity,
    "pre_attack_alerts": pre_attack_alerts,
    "post_attack_alerts": post_attack_alerts,
    "first_post_attack_alert": first_post_attack_alert,
    "detection_latency_packets": detection_latency,
    "avg_cpu_percent_sampled": float(np.mean(cpu_samples)) if cpu_samples else None,
    "peak_ram_mb": float(np.max(ram_samples)) if ram_samples else None,
    "avg_ram_mb": float(np.mean(ram_samples)) if ram_samples else None,
}

# -------------------------
# Save outputs
# -------------------------
packet_df = pd.DataFrame({
    "packet_index": packet_indices,
    "rmse": RMSEs,
    "fixed_threshold": thresholds,
    "alert": alerts
})
packet_df.to_csv("old_model_packet_metrics.csv", index=False)

summary_df = pd.DataFrame([summary])
summary_df.to_csv("old_model_summary_metrics.csv", index=False)

print("\nOld model baseline summary:")
for k, v in summary.items():
    print(f"{k}: {v}")

print("\nSaved files:")
print(" - old_model_packet_metrics.csv")
print(" - old_model_summary_metrics.csv")