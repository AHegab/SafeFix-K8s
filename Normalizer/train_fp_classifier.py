#!/usr/bin/env python3
"""
Train an ML false-positive classifier for SafeFix-K8s Normalizer.

Usage:
  python Normalizer/train_fp_classifier.py \
    --data Normalizer/data/fp_training_samples.json \
    --out Normalizer/model/fp_classifier.joblib

Data format (JSON array or JSONL):
  {"tool": "Kubescape", "file": "...", "title": "...", "message": "...", "rule_id": "C-0057", "label": "fp"}
  label in {"fp", "tp"} (false positive, true positive)
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
from typing import List, Dict, Any

import numpy as np  # type: ignore

try:
    from sklearn.linear_model import LogisticRegression  # type: ignore
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split
    import joblib  # type: ignore
    _HAS_SK = True
except Exception:
    _HAS_SK = False

from fp_classifier import extract_features


def load_dataset(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    data: List[Dict[str, Any]] = []
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            data = obj
    except json.JSONDecodeError:
        # JSON Lines fallback
        for line in text.splitlines():
            s = line.strip()
            if not s:
                continue
            try:
                data.append(json.loads(s))
            except json.JSONDecodeError:
                continue
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="Normalizer/data/fp_training_samples.json")
    ap.add_argument("--out", default="Normalizer/model/fp_classifier.joblib")
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--max-iter", type=int, default=300)
    args = ap.parse_args()

    if not _HAS_SK:
        print("[ERROR] scikit-learn and joblib are required to train the model. Install with: pip install scikit-learn joblib numpy")
        return

    data_path = Path(args.data)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows = load_dataset(data_path)
    if not rows:
        print(f"[ERROR] No training data found at {data_path}")
        return

    X: List[List[float]] = []
    y: List[int] = []
    for r in rows:
        label = str(r.get("label", "")).lower()
        if label not in {"fp", "tp"}:
            continue
        y.append(1 if label == "fp" else 0)
        X.append(extract_features(r))

    if not X:
        print("[ERROR] No valid rows in dataset (missing labels)")
        return

    Xnp = np.array(X, dtype=float)
    ynp = np.array(y, dtype=int)

    Xtr, Xte, ytr, yte = train_test_split(Xnp, ynp, test_size=args.test_size, random_state=42, stratify=ynp)
    clf = LogisticRegression(max_iter=args.max_iter, class_weight="balanced", solver="lbfgs")
    clf.fit(Xtr, ytr)
    preds = clf.predict(Xte)
    print("[Report] Validation split")
    print(classification_report(yte, preds, target_names=["true_positive", "false_positive"]))

    joblib.dump(clf, str(out_path))
    print(f"[OK] Saved model to {out_path}")


if __name__ == "__main__":
    main()
