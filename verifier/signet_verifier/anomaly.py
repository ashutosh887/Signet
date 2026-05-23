"""Quantum-kernel-SVM anomaly detector for agent behaviour drift.

Pipeline:
    sliding window of recent envelopes per agent
        -> 32-dim feature extraction
        -> StandardScaler + PCA(6)
        -> 6-qubit ZZ feature map quantum kernel (Havliček 2019)
        -> SVC(kernel='precomputed')

A classical RBF SVM is trained on the same split and the detector serves
whichever wins the held-out validation AUC. A cold-start guardrail boosts
the score when the action name is outside the known vocabulary.
"""
from __future__ import annotations

import math
import statistics
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

import numpy as np
import pennylane as qml
from sklearn.decomposition import PCA
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC


N_QUBITS = 6
FEATURE_DIM = 32
WINDOW_SIZE = 20
ACTION_VOCAB_SIZE = 16

FEATURE_NAMES = (
    *(f"action_freq_{i}" for i in range(ACTION_VOCAB_SIZE)),
    "gap_mean",
    "gap_pstdev",
    "gap_min",
    "gap_max",
    "gap_median",
    "gap_p95",
    "params_keys_mean",
    "params_keys_max",
    "params_value_size_mean",
    "params_value_size_max",
    "params_key_entropy",
    "hour_sin_mean",
    "hour_cos_mean",
    "params_unique_keys",
    "error_ratio",
    "size_var",
)

LEGIT_ACTIONS = (
    "book_meeting",
    "send_email",
    "fetch_document",
    "summarize",
    "translate",
    "search_kb",
    "schedule_followup",
    "draft_reply",
    "set_reminder",
    "lookup_contact",
    "create_task",
    "update_crm",
    "log_call",
    "fetch_calendar",
    "voice_trigger",
)


def _action_index(name: str) -> int:
    if name in LEGIT_ACTIONS:
        return LEGIT_ACTIONS.index(name)
    return len(LEGIT_ACTIONS)  # catch-all slot at index 15


def _iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _shannon(weights: Iterable[float]) -> float:
    total = sum(weights)
    if total <= 0:
        return 0.0
    probs = [w / total for w in weights if w > 0]
    return -sum(p * math.log(p + 1e-12) for p in probs)


def extract_features(envelopes: list[dict[str, Any]]) -> np.ndarray:
    feat = np.zeros(FEATURE_DIM, dtype=np.float64)
    if not envelopes:
        return feat

    counts = Counter(_action_index(e["action"].get("name", "")) for e in envelopes)
    total = sum(counts.values())
    for idx, c in counts.items():
        if 0 <= idx < ACTION_VOCAB_SIZE:
            feat[idx] = c / total

    try:
        times = sorted(_iso(e["issued_at"]).timestamp() for e in envelopes)
        gaps = [times[i + 1] - times[i] for i in range(len(times) - 1)] or [0.0]
    except (KeyError, ValueError):
        gaps = [0.0]
    feat[16] = statistics.mean(gaps)
    feat[17] = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0
    feat[18] = min(gaps)
    feat[19] = max(gaps)
    feat[20] = sorted(gaps)[len(gaps) // 2]
    feat[21] = sorted(gaps)[int(0.95 * (len(gaps) - 1))]

    key_counts: list[int] = []
    value_sizes: list[int] = []
    keys_seen: set[str] = set()
    for e in envelopes:
        params = e["action"].get("params") or {}
        if isinstance(params, dict):
            key_counts.append(len(params))
            for k, v in params.items():
                keys_seen.add(k)
                value_sizes.append(len(str(v)))
        else:
            key_counts.append(0)
    feat[22] = statistics.mean(key_counts) if key_counts else 0.0
    feat[23] = statistics.mean(value_sizes) if value_sizes else 0.0
    feat[24] = max(value_sizes) if value_sizes else 0.0
    feat[25] = len(keys_seen)

    try:
        first_hour = (
            _iso(envelopes[-1]["issued_at"]).hour
            + _iso(envelopes[-1]["issued_at"]).minute / 60.0
        )
        last_hour = (
            _iso(envelopes[0]["issued_at"]).hour
            + _iso(envelopes[0]["issued_at"]).minute / 60.0
        )
    except (KeyError, ValueError):
        first_hour = last_hour = 0.0
    feat[26] = math.cos(2 * math.pi * first_hour / 24.0)
    feat[27] = math.sin(2 * math.pi * first_hour / 24.0)
    feat[28] = math.cos(2 * math.pi * last_hour / 24.0)
    feat[29] = math.sin(2 * math.pi * last_hour / 24.0)

    feat[30] = _shannon(counts.values())
    feat[31] = float(len(envelopes)) / WINDOW_SIZE

    return feat


_dev = qml.device("default.qubit", wires=N_QUBITS)


def _zz_feature_map(x: np.ndarray, wires) -> None:
    n = len(wires)
    for i in range(n):
        qml.Hadamard(wires=wires[i])
    for i in range(n):
        qml.RZ(2.0 * float(x[i]), wires=wires[i])
    for i in range(n):
        for j in range(i + 1, n):
            qml.CNOT(wires=[wires[i], wires[j]])
            qml.RZ(
                2.0 * (math.pi - float(x[i])) * (math.pi - float(x[j])),
                wires=wires[j],
            )
            qml.CNOT(wires=[wires[i], wires[j]])


@qml.qnode(_dev, interface="autograd")
def _kernel_circuit(x1, x2):
    _zz_feature_map(x1, wires=range(N_QUBITS))
    qml.adjoint(_zz_feature_map)(x2, wires=range(N_QUBITS))
    return qml.probs(wires=range(N_QUBITS))


def quantum_kernel_value(x1: np.ndarray, x2: np.ndarray) -> float:
    return float(_kernel_circuit(x1, x2)[0])


def quantum_kernel_matrix(X1: np.ndarray, X2: np.ndarray | None = None) -> np.ndarray:
    symmetric = X2 is None
    if X2 is None:
        X2 = X1
    n, m = len(X1), len(X2)
    K = np.zeros((n, m))
    if symmetric:
        for i in range(n):
            K[i, i] = 1.0
            for j in range(i + 1, n):
                v = quantum_kernel_value(X1[i], X1[j])
                K[i, j] = v
                K[j, i] = v
    else:
        for i in range(n):
            for j in range(m):
                K[i, j] = quantum_kernel_value(X1[i], X2[j])
    return K


def _legit_window(rng: np.random.Generator, t0: float) -> list[dict[str, Any]]:
    n = int(rng.integers(WINDOW_SIZE - 4, WINDOW_SIZE + 1))
    envelopes: list[dict[str, Any]] = []
    t = t0
    for _ in range(n):
        action_name = LEGIT_ACTIONS[rng.integers(0, len(LEGIT_ACTIONS))]
        gap = float(rng.choice([0.05, 0.1, 0.3, 1.0, 3.0, 8.0]))
        t -= gap
        envelopes.append(
            {
                "issued_at": datetime.fromtimestamp(t).isoformat() + "Z",
                "action": {
                    "name": action_name,
                    "params": {f"p{i}": "val" for i in range(int(rng.integers(1, 4)))},
                },
            }
        )
    return envelopes


def _rogue_window(rng: np.random.Generator, t0: float) -> list[dict[str, Any]]:
    n = int(rng.integers(WINDOW_SIZE - 4, WINDOW_SIZE + 1))
    envelopes: list[dict[str, Any]] = []
    t = t0
    rogue_actions = (
        "exfiltrate_dump",
        "wire_transfer",
        "drop_table",
        "spawn_shell",
        "patch_system",
    )
    for _ in range(n):
        if rng.random() < 0.7:
            action_name = rogue_actions[rng.integers(0, len(rogue_actions))]
        else:
            action_name = LEGIT_ACTIONS[rng.integers(0, len(LEGIT_ACTIONS))]
        gap = float(rng.choice([0.05, 0.1, 0.3, 1.0, 3.0, 8.0]))
        t -= gap
        n_params = int(rng.integers(8, 20))
        envelopes.append(
            {
                "issued_at": datetime.fromtimestamp(t).isoformat() + "Z",
                "action": {
                    "name": action_name,
                    "params": {
                        f"k{i}": "x" * int(rng.integers(50, 400))
                        for i in range(n_params)
                    },
                },
            }
        )
    return envelopes


def build_training_set(
    n_legit: int = 200, n_rogue: int = 50, seed: int = 0
) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    t0 = time.time()
    X: list[np.ndarray] = []
    y: list[int] = []
    for _ in range(n_legit):
        X.append(extract_features(_legit_window(rng, t0)))
        y.append(0)
    for _ in range(n_rogue):
        X.append(extract_features(_rogue_window(rng, t0)))
        y.append(1)
    return np.array(X), np.array(y)


@dataclass
class TrainReport:
    quantum_auc: float
    rbf_auc: float
    chosen: str
    threshold: float


class AnomalyDetector:
    def __init__(self) -> None:
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=N_QUBITS)
        self.quantum_svc: SVC | None = None
        self.rbf_svc: SVC | None = None
        self.X_train_q: np.ndarray | None = None
        self.chosen: str = "rbf"
        self.threshold: float = 0.5
        self.report: TrainReport | None = None
        self._encode_scale: float = 1.0

    def fit(self, X: np.ndarray, y: np.ndarray) -> TrainReport:
        Xs = self.scaler.fit_transform(X)
        Xp = self.pca.fit_transform(Xs)
        self._encode_scale = math.pi / (np.max(np.abs(Xp)) + 1e-9)
        Xp = Xp * self._encode_scale

        X_train, X_test, y_train, y_test = train_test_split(
            Xp, y, test_size=0.25, stratify=y, random_state=42
        )

        self.rbf_svc = SVC(kernel="rbf", probability=True, gamma="scale").fit(X_train, y_train)
        rbf_auc = roc_auc_score(y_test, self.rbf_svc.predict_proba(X_test)[:, 1])

        try:
            K_train = quantum_kernel_matrix(X_train)
            K_test = quantum_kernel_matrix(X_test, X_train)
            self.quantum_svc = SVC(kernel="precomputed", probability=True).fit(K_train, y_train)
            self.X_train_q = X_train
            q_auc = roc_auc_score(y_test, self.quantum_svc.predict_proba(K_test)[:, 1])
        except Exception:
            q_auc = 0.0
            self.quantum_svc = None
            self.X_train_q = None

        self.chosen = "quantum" if q_auc >= rbf_auc and self.quantum_svc is not None else "rbf"
        self.report = TrainReport(
            quantum_auc=float(q_auc),
            rbf_auc=float(rbf_auc),
            chosen=self.chosen,
            threshold=self.threshold,
        )
        return self.report

    def _project(self, x: np.ndarray) -> np.ndarray:
        return self.pca.transform(self.scaler.transform(x.reshape(1, -1)))[0] * self._encode_scale

    def score(self, features: np.ndarray) -> float:
        x = self._project(features)
        if self.chosen == "quantum" and self.quantum_svc is not None and self.X_train_q is not None:
            K = quantum_kernel_matrix(x.reshape(1, -1), self.X_train_q)
            return float(self.quantum_svc.predict_proba(K)[0, 1])
        assert self.rbf_svc is not None
        return float(self.rbf_svc.predict_proba(x.reshape(1, -1))[0, 1])

    def score_envelopes(self, envelopes: list[dict[str, Any]]) -> float:
        ml_score = self.score(extract_features(envelopes))
        oov = sum(
            1 for e in envelopes if e.get("action", {}).get("name") not in LEGIT_ACTIONS
        )
        oov_ratio = oov / max(1, len(envelopes))
        oov_boost = oov_ratio * 0.9 + 0.05 if oov > 0 else 0.0
        return max(ml_score, oov_boost)

    def explain(self, features: np.ndarray, top_k: int = 3) -> list[dict[str, Any]]:
        if self.rbf_svc is None:
            return []
        mean = self.scaler.mean_
        scale = self.scaler.scale_
        deltas = (features - mean) / np.where(scale == 0, 1.0, scale)
        z = np.abs(deltas)
        order = np.argsort(z)[::-1][:top_k]
        return [
            {
                "dim": int(i),
                "name": FEATURE_NAMES[i] if i < len(FEATURE_NAMES) else f"f{i}",
                "z_score": float(z[i]),
                "value": float(features[i]),
                "baseline": float(mean[i]),
            }
            for i in order
        ]
