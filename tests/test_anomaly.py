"""Standalone anomaly detector sanity check (no verifier required)."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "verifier"))

import numpy as np

from signet_verifier.anomaly import (
    AnomalyDetector,
    _legit_window,
    _rogue_window,
    build_training_set,
)


def main() -> None:
    print("Building training set ...")
    t0 = time.perf_counter()
    X, y = build_training_set(n_legit=120, n_rogue=40, seed=0)
    print(f"  {len(X)} samples, {X.shape[1]}d features ({(time.perf_counter()-t0)*1000:.0f} ms)\n")

    print("Training quantum + RBF ...")
    t0 = time.perf_counter()
    det = AnomalyDetector()
    report = det.fit(X, y)
    print(f"  fit time:     {time.perf_counter()-t0:.1f}s")
    print(f"  quantum AUC = {report.quantum_auc:.3f}")
    print(f"  rbf AUC     = {report.rbf_auc:.3f}")
    print(f"  serving     = {report.chosen}\n")

    rng = np.random.default_rng(99)
    t0 = time.time()

    print("Scoring 5 legit windows:")
    for i in range(5):
        envs = _legit_window(rng, t0)
        print(f"  legit {i}: score = {det.score_envelopes(envs):.3f}")

    print("\nScoring 5 rogue windows:")
    for i in range(5):
        envs = _rogue_window(rng, t0)
        print(f"  rogue {i}: score = {det.score_envelopes(envs):.3f}")


if __name__ == "__main__":
    main()
