# adaptive_threshold.py
# This file implements a self-calibrating threshold on top of Kitsune RMSE scores.

from collections import deque
import numpy as np


class AdaptiveThreshold:
    def __init__(
        self,
        window_size=1000,          # main trusted sliding window size
        z=3.0,                     # threshold = mean + z*std
        min_samples=100,           # minimum samples before threshold becomes active
        use_log=False,             # optional log transform of RMSE scores
        eps=1e-12,                 # small value to avoid divide-by-zero
        enable_drift=False,        # enable drift handling for benign regime shifts
        drift_window_size=100,     # temporary buffer for above-threshold points
        drift_min_count=50,        # minimum buffered points before drift check
        drift_cv_threshold=0.20,   # stability check using coefficient of variation
        hard_ceiling_factor=3.0,   # reject extremely large spikes from drift adaptation
    ):
        self.window_size = window_size
        self.z = z
        self.min_samples = min_samples
        self.use_log = use_log
        self.eps = eps

        # Main trusted window used to compute threshold
        self.window = deque(maxlen=window_size)

        # Optional benign-drift adaptation support
        self.enable_drift = enable_drift
        self.drift_window_size = drift_window_size
        self.drift_min_count = drift_min_count
        self.drift_cv_threshold = drift_cv_threshold
        self.hard_ceiling_factor = hard_ceiling_factor
        self.drift_buffer = deque(maxlen=drift_window_size)

    def _transform(self, value):
        value = float(value)
        if self.use_log:
            return np.log(value + self.eps)
        return value

    def _window_stats(self):
        if len(self.window) == 0:
            return {
                "mean": None,
                "std": None,
                "threshold": None,
                "ready": False,
                "window_count": 0,
            }

        arr = np.asarray(self.window, dtype=float)
        mean = float(arr.mean())
        std = float(arr.std())
        threshold = mean + self.z * max(std, self.eps)

        return {
            "mean": mean,
            "std": std,
            "threshold": threshold,
            "ready": len(arr) >= self.min_samples,
            "window_count": len(arr),
        }

    def _drift_stats(self):
        if len(self.drift_buffer) == 0:
            return {
                "drift_mean": None,
                "drift_std": None,
                "drift_cv": None,
                "drift_count": 0,
            }

        arr = np.asarray(self.drift_buffer, dtype=float)
        mean = float(arr.mean())
        std = float(arr.std())
        cv = std / max(abs(mean), self.eps)

        return {
            "drift_mean": mean,
            "drift_std": std,
            "drift_cv": cv,
            "drift_count": len(arr),
        }

    def _drift_is_stable(self, current_threshold):
        if not self.enable_drift:
            return False

        stats = self._drift_stats()

        # Need enough suspicious points first
        if stats["drift_count"] < self.drift_min_count:
            return False

        # Buffer must be stable, not wildly varying
        if stats["drift_cv"] is None or stats["drift_cv"] > self.drift_cv_threshold:
            return False

        # Reject obviously huge attack spikes
        if current_threshold is not None and stats["drift_mean"] > current_threshold * self.hard_ceiling_factor:
            return False

        return True

    def evaluate(self, score):
        transformed_score = self._transform(score)
        stats = self._window_stats()

        # Warm-up phase: fill baseline window first
        if not stats["ready"]:
            self.window.append(transformed_score)
            stats = self._window_stats()
            drift_stats = self._drift_stats()

            return {
                "score": float(score),
                "transformed_score": transformed_score,
                "threshold": stats["threshold"],
                "mean": stats["mean"],
                "std": stats["std"],
                "ready": stats["ready"],
                "is_anomaly": False,
                "window_count": stats["window_count"],
                "drift_count": drift_stats["drift_count"],
                "drift_mean": drift_stats["drift_mean"],
                "drift_std": drift_stats["drift_std"],
                "drift_cv": drift_stats["drift_cv"],
                "drift_adapted": False,
            }

        threshold = stats["threshold"]
        is_anomaly = transformed_score > threshold
        drift_adapted = False

        if not is_anomaly:
            # Trusted normal point updates the main baseline window
            self.window.append(transformed_score)

            # If normal resumes, clear drift evidence
            if len(self.drift_buffer) > 0:
                self.drift_buffer.clear()
        else:
            # Suspicious point goes into drift buffer first
            if self.enable_drift:
                self.drift_buffer.append(transformed_score)

                # If this looks like sustained benign drift, adapt
                if self._drift_is_stable(threshold):
                    for val in list(self.drift_buffer):
                        self.window.append(val)
                    self.drift_buffer.clear()
                    drift_adapted = True
                    is_anomaly = False

        stats = self._window_stats()
        drift_stats = self._drift_stats()

        return {
            "score": float(score),
            "transformed_score": transformed_score,
            "threshold": stats["threshold"],
            "mean": stats["mean"],
            "std": stats["std"],
            "ready": stats["ready"],
            "is_anomaly": bool(is_anomaly),
            "window_count": stats["window_count"],
            "drift_count": drift_stats["drift_count"],
            "drift_mean": drift_stats["drift_mean"],
            "drift_std": drift_stats["drift_std"],
            "drift_cv": drift_stats["drift_cv"],
            "drift_adapted": drift_adapted,
        }