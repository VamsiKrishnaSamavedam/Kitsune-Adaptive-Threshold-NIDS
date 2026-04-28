# 🚀 Kitsune Adaptive Threshold Network Intrusion Detection System

## 📌 Overview

This project enhances the original Kitsune Network Intrusion Detection System (NIDS) by replacing the static threshold mechanism with a self-calibrating adaptive threshold.

The system detects anomalies in network traffic using reconstruction error (RMSE) from an ensemble of autoencoders and dynamically adjusts its decision boundary in real-time.

---

## ❗ Problem in Original Kitsune

The original Kitsune uses a fixed threshold:

ϕ = max(training RMSE)

### Limitations:

* ❌ No adaptation to changing network behavior
* ❌ Sensitive to noise during training
* ❌ Threshold remains static in dynamic environments
* ❌ High false positives or false negatives

---

## 💡 Proposed Solution: Adaptive Threshold

We introduced a **self-calibrating threshold mechanism**:

### Core Idea:

threshold = μ + z × σ

Where:

* μ = mean of recent RMSE values
* σ = standard deviation
* z = sensitivity parameter

---

## 🔥 Key Enhancements

### 1. Sliding Window

* Maintains recent RMSE values
* Enables real-time adaptation

---

### 2. Adaptive Threshold

* Dynamically updates threshold based on live data
* Replaces static φ from training

---

### 3. Drift Detection

* Uses coefficient of variation (CV)
* Detects stable shifts in data distribution

---

### 4. Drift Buffer

* Temporarily stores anomalous points
* Prevents immediate contamination of baseline

---

### 5. Hard Ceiling Protection

* Prevents large attack spikes from entering baseline
* Avoids threshold explosion

---

## 🧠 System Pipeline

PCAP → FeatureExtractor → KitNET → RMSE → AdaptiveThreshold → Alert

---

## 📂 Project Structure

* `Kitsune.py` → Core pipeline (modified with adaptive logic)
* `adaptive_threshold.py` → Self-calibrating threshold implementation
* `adaptive_metrics.py` → Evaluation for adaptive model
* `adaptive_metrics_tuned.py` → Tuned parameter evaluation
* `baseline_metrics_old.py` → Original model baseline

---

## 📊 Dataset

* Mirai botnet dataset
* Contains:

  * Normal traffic (training phase)
  * Attack traffic (execution phase)

---

## 📈 Results

Compared models:

| Model               | Behavior                       |
| ------------------- | ------------------------------ |
| Old Model           | Fixed threshold, no adaptation |
| Adaptive Model      | Dynamic threshold              |
| Tuned Model (z=3.5) | Balanced sensitivity           |
| Tuned Model (z=4.0) | More conservative detection    |

### Observations:

* Adaptive model maintains stable threshold
* Handles distribution shifts effectively
* Reduces impact of noise
* Improves robustness over static model

---

## ⚙️ Technologies Used

* Python
* NumPy
* Scikit-learn (indirect via KitNET)
* Matplotlib
* SciPy

---

## 🎯 Conclusion

The adaptive threshold approach significantly improves the robustness of Kitsune in dynamic environments by:

* Eliminating dependency on a static threshold
* Handling drift safely
* Maintaining detection sensitivity without overfitting

---

## 👨‍💻 Author

Vamsi Krishna
