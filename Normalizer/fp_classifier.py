"""
ML-based false-positive classifier scaffold for SafeFix-K8s Normalizer.

This module loads an optional pre-trained model (joblib) and exposes an
API to predict whether a raw finding (hit) is likely a false positive.

Model path (default): Normalizer/model/fp_classifier.joblib

Feature design (lightweight, text + metadata):
- tool one-hot (limited set mapped to small indices)
- message length, title length
- presence of secret-like tokens
- file path patterns (charts/, values.yaml, tests/, examples/)
- rule_id family (CKV_*, KSV*, C-*, Yamllint, KubeConform)
- severity words in message/title (critical/high/low/deprecated/schema/helm)

If the model file is missing or scikit-learn is not installed, the classifier
is disabled and always returns False (do not filter).
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Dict, Any, List

try:
    import joblib  # type: ignore
    _HAS_JOBLIB = True
except Exception:
    _HAS_JOBLIB = False


TOOLS = [
    "KubeConform", "KubeLinter", "Polaris", "Checkov", "Trivy", "Kubescape",
    "KubeScore", "Yamllint", "KubeAudit", "Conftest", "RBACPolice", "Pluto", "Gitleaks"
]
TOOL_INDEX = {t: i for i, t in enumerate(TOOLS)}


def _bool(s: str, *subs: str) -> int:
    s = (s or "").lower()
    return 1 if any(sub.lower() in s for sub in subs) else 0


def _strlen(s: str) -> int:
    return len(s or "")


def extract_features(hit: Dict[str, Any]) -> List[float]:
    tool = str(hit.get("tool", ""))
    filep = str(hit.get("file", ""))
    title = str(hit.get("title", ""))
    msg = str(hit.get("message", ""))
    rid = str(hit.get("rule_id", ""))

    # One-hot (sparse) tool vector as few indices; we’ll compress to a small set of indicators
    tool_ix = TOOL_INDEX.get(tool, -1)
    tool_feats = [0.0] * len(TOOLS)
    if tool_ix >= 0:
        tool_feats[tool_ix] = 1.0

    # File/path indicators
    f_charts = _bool(filep, "charts/", "chart.yaml")
    f_values = _bool(filep, "values.yaml")
    f_tests = _bool(filep, "tests/", "test/")
    f_examples = _bool(filep, "examples/", "example", "samples/")
    f_helm = _bool(filep, "helm/", "templates/")

    # Message/title characteristics
    m_len = _strlen(msg)
    t_len = _strlen(title)
    has_secret_like = _bool(msg + " " + title, "password=", "token=", "apikey", "api_key", "secret", "match:")
    has_schema = _bool(msg + " " + title, "schema", "invalid", "missing property", "kubeconform")
    has_deprecated = _bool(msg + " " + title, "deprecated")
    has_helm = _bool(msg + " " + title, "helm")

    # Rule id family
    rid_ckv = rid.startswith("CKV_")
    rid_ksv = rid.startswith("KSV")
    rid_kube = rid.startswith("C-")
    rid_yaml = _bool(tool, "Yamllint")

    # Severity hints in free text
    sev_crit = _bool(msg + " " + title, "critical")
    sev_high = _bool(msg + " " + title, "high")
    sev_low = _bool(msg + " " + title, "low", "style", "formatting")

    return tool_feats + [
        float(f_charts), float(f_values), float(f_tests), float(f_examples), float(f_helm),
        float(m_len), float(t_len), float(has_secret_like), float(has_schema), float(has_deprecated), float(has_helm),
        float(rid_ckv), float(rid_ksv), float(rid_kube), float(rid_yaml),
        float(sev_crit), float(sev_high), float(sev_low)
    ]


class FPClassifier:
    def __init__(self, model_path: str | None = None, threshold: float = 0.6) -> None:
        self.threshold = float(threshold)
        self.available = False
        self.model = None
        self.model_path = None
        if not _HAS_JOBLIB:
            return
        try:
            default_path = Path(__file__).parent / "model" / "fp_classifier.joblib"
            path = Path(model_path) if model_path else default_path
            if path.exists():
                self.model = joblib.load(str(path))
                self.available = True
                self.model_path = str(path)
        except Exception:
            self.available = False
            self.model = None
            self.model_path = None

    def predict_proba(self, hit: Dict[str, Any]) -> float:
        if not self.available or self.model is None:
            return 0.0
        try:
            feats = [extract_features(hit)]
            # Expect scikit-learn compatible estimator with predict_proba
            if hasattr(self.model, "predict_proba"):
                proba = self.model.predict_proba(feats)
                # Assume binary classifier [neg,pos] where pos=FP
                if hasattr(proba, "tolist"):
                    proba = proba.tolist()
                return float(proba[0][1])
            # Fallback: decision_function mapped via sigmoid
            if hasattr(self.model, "decision_function"):
                import math
                d = float(self.model.decision_function(feats)[0])
                return 1.0 / (1.0 + math.exp(-d))
        except Exception:
            return 0.0
        return 0.0

    def is_false_positive(self, hit: Dict[str, Any]) -> bool:
        p = self.predict_proba(hit)
        return p >= self.threshold
