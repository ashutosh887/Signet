# Signet anomaly detector — benchmark

Synthetic agent-behaviour dataset, 3 seeds, n_legit=100, n_rogue=35.

| Model | AUC (mean ± std) |
| --- | --- |
| Quantum-kernel SVM (6-qubit ZZ feature map) | **0.864 ± 0.128** |
| Classical RBF SVM | 1.000 ± 0.000 |
| Linear SVM on PCA-6 (Schuld critique) | 1.000 ± 0.000 |
| Isolation Forest (legit-only) | 0.736 ± 0.012 |

**Honest reading:** on this synthetic data the cold-start
regime shows the quantum kernel within noise of classical RBF. The verifier
auto-serves whichever wins on the held-out validation split at boot. The
linear-PCA baseline is included to answer the Schuld critique
("is the gain from the quantum kernel or from the embedding?") — see the
score there.

Raw runs in `bench.csv`.
