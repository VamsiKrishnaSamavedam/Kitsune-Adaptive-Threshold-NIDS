# Project Setup and Execution Guide

## 1. Clone Repository

git clone https://github.com/VamsiKrishnaSamavedam/Kitsune-Adaptive-Threshold-NIDS.git
cd Kitsune-Adaptive-Threshold-NIDS

---

## 2. Install Dependencies

pip install -r requirements.txt

Make sure tshark is installed and added to PATH.

---

## 3. Dataset

The project uses the Mirai dataset.

Place the following file in the root directory:

mirai.pcap

---

## 4. Run Old Model (Baseline)

python baseline_metrics_old.py

Outputs:

* old_model_packet_metrics.csv
* old_model_summary_metrics.csv

---

## 5. Run Adaptive Model

python adaptive_metrics.py

Outputs:

* adaptive_model_packet_metrics.csv
* adaptive_model_summary_metrics.csv

---

## 6. Run Tuned Adaptive Model

python adaptive_metrics_tuned.py

---

## 7. Visualization

Use the provided Jupyter Notebook or plotting scripts to visualize:

* RMSE vs threshold
* anomaly detection behavior
* comparison between models

---

## 8. What Works

* Adaptive thresholding
* Drift detection
* Real-time RMSE evaluation
* Comparison with baseline

---

## 9. Limitations

* Requires PCAP dataset
* Performance depends on parameter tuning
* Not optimized for very high-speed real-time deployment

---

## 10. Expected Results

* Old model → fixed threshold
* Adaptive model → dynamic threshold
* Tuned model → improved stability

---

## Author

Vamsi Krishna
