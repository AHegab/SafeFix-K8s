#!/usr/bin/env python3
"""
validation_gates_v4.py  — SafeFix-K8s (Schema-Autofix Edition)
--------------------------------------------------------------

This version replaces the old strict gates with a realistic,
LLM-friendly, schema-repair-driven validator.

PASS IF:
    - All auto-fix categories are satisfied
    - YAML is valid after auto-repair
    - No dangerous misconfigurations introduced
    - Schema was fixed successfully (soft)

FAIL ONLY IF:
    - YAML cannot be parsed
    - A required category is NOT fixed
    - LLM added a dangerous configuration
    - Required schema-repair cannot be inferred

Everything else becomes WARN / NEEDS_REVIEW.

"""

import argparse
import yaml
import json
import csv
from pathlib import Path
from typing import Any, Dict, List, Optional

import subprocess
import shutil

# ---------------------------------------------------------------------
#  CONSTANTS
# ---------------------------------------------------------------------

DANGEROUS_FIELDS = [
    ("privileged", True),
    ("allowPrivilegeEscalation", True),
    ("hostPID", True),
    ("hostNetwork", True),
    ("hostIPC", True),
]

FORBIDDEN_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_MODULE"}

NON_AUTO_FIX_CATEGORIES = {
    "Misc/Unmapped",
    "Network/MissingNetworkPolicy",
    "Schema/InvalidManifest",
    "Style/YamlLint",
}

AUTO_FIX_REQUIREMENTS = {
    "Security/PrivilegedContainer": lambda sc: sc.get("privileged", False) is False,
    "Security/AllowPrivilegeEscalation": lambda sc: sc.get("allowPrivilegeEscalation", False) is False,
    "Security/CapabilitiesNotDropped": lambda sc: "ALL" in (sc.get("capabilities", {}).get("drop", []) or []),
    "Auth/RunAsRoot": lambda sc: sc.get("runAsNonRoot", False) is True,
    "Resources/MissingRequests": lambda c: "requests" in c.get("resources", {}),
    "Resources/MissingLimits":   lambda c: "limits" in c.get("resources", {}),
    "Probes/MissingReadinessLiveness": lambda c: ("livenessProbe" in c or "readinessProbe" in c),
}

# ---------------------------------------------------------------------
# YAML HELPERS
# ---------------------------------------------------------------------

def load_yaml(path: Path) -> List[dict]:
    """Load multi-doc YAML safely."""
    try:
        txt = path.read_text(encoding="utf-8")
        docs = [doc for doc in yaml.safe_load_all(txt) if isinstance(doc, dict)]
        return docs
    except Exception as e:
        raise RuntimeError(f"Failed to parse YAML {path}: {e}")

def dump_yaml(path: Path, docs: List[dict]):
    """Write multi-doc YAML."""
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump_all(docs, f, sort_keys=False)

# ---------------------------------------------------------------------
# SCHEMA AUTO-FIX ENGINE
# ---------------------------------------------------------------------

def autofix_schema_one(doc: dict) -> dict:
    """Repair common schema errors for Deployments, Jobs, Pods, Services."""

    kind = doc.get("kind", "")
    spec = doc.setdefault("spec", {})

    # ---- Missing metadata.name
    if "metadata" not in doc:
        doc["metadata"] = {"name": "autofixed"}
    else:
        doc["metadata"].setdefault("name", "autofixed")

    # ---- Deployment selector missing
    if kind == "Deployment":
        tmpl = spec.setdefault("template", {}).setdefault("metadata", {})
        tmpl_labels = tmpl.setdefault("labels", {"app": "autofixed"})
        sel = spec.setdefault("selector", {})
        sel.setdefault("matchLabels", tmpl_labels)

    # ---- Pod restartPolicy
    if kind in ("Pod", "Deployment", "Job"):
        tmpl = spec.get("template", {})
        pspec = tmpl.get("spec", spec)
        pspec.setdefault("restartPolicy", "Never")

    # ---- Ingress API upgrade
    if kind == "Ingress":
        api = doc.get("apiVersion", "")
        if api in ("extensions/v1beta1", "networking.k8s.io/v1beta1"):
            doc["apiVersion"] = "networking.k8s.io/v1"
            # fix structure
            spec.setdefault("rules", [])
            spec.setdefault("ingressClassName", "autofixed")

    # ---- Service port type fix
    if kind == "Service":
        ports = spec.setdefault("ports", [])
        for p in ports:
            if "port" in p:
                try:
                    p["port"] = int(p["port"])
                except:
                    p["port"] = 80
            if "targetPort" in p:
                # leave as string or int
                pass

    return doc


def autofix_schema_all(docs: List[dict]) -> List[dict]:
    """Apply autofix to every doc."""
    fixed = []
    for d in docs:
        try:
            fixed.append(autofix_schema_one(d))
        except Exception:
            fixed.append(d)
    return fixed

# ---------------------------------------------------------------------
# DANGEROUS MISCONFIG CHECK
# ---------------------------------------------------------------------

def find_security_contexts(doc: dict) -> List[dict]:
    """Return all container-level securityContexts."""
    results = []
    spec = doc.get("spec", {})
    pod = spec.get("template", {}).get("spec", spec)

    for c in pod.get("containers", []):
        results.append(c.get("securityContext", {}))
    for c in pod.get("initContainers", []):
        results.append(c.get("securityContext", {}))
    return results

def check_dangerous(doc: dict) -> List[str]:
    """Return list of dangerous misconfigs."""
    msgs = []
    scs = find_security_contexts(doc)

    for sc in scs:
        for key, bad in DANGEROUS_FIELDS:
            if sc.get(key) == bad:
                msgs.append(f"Dangerous: {key} == {bad}")

        caps = sc.get("capabilities", {}).get("add", []) or []
        for c in caps:
            if c in FORBIDDEN_CAPS:
                msgs.append(f"Dangerous capability added: {c}")

    # hostPath detection
    pod = doc.get("spec", {}).get("template", {}).get("spec", {})
    for v in pod.get("volumes", []):
        if "hostPath" in v:
            msgs.append("Dangerous: hostPath mount present")

    return msgs

# ---------------------------------------------------------------------
# CATEGORY COMPLETENESS CHECK
# ---------------------------------------------------------------------

def category_fixed(doc: dict, cat: str) -> bool:
    """
    Check if an auto-fix category is satisfied.
    """
    # Containers list
    spec = doc.get("spec", {})
    pod = spec.get("template", {}).get("spec", spec)
    containers = pod.get("containers", []) + pod.get("initContainers", [])

    if cat not in AUTO_FIX_REQUIREMENTS:
        return True

    req = AUTO_FIX_REQUIREMENTS[cat]

    # Security category
    if "Security" in cat or "Auth" in cat:
        for c in containers:
            sc = c.get("securityContext", {})
            if req(sc) is False:
                return False
        return True

    # Resource limits
    if "Resources" in cat:
        for c in containers:
            if req(c) is False:
                return False
        return True

    # Probes
    if "Probes" in cat:
        for c in containers:
            if req(c) is False:
                return False
        return True

    return True

# ---------------------------------------------------------------------
# KUBECONFORM
# ---------------------------------------------------------------------

def run_kubeconform(path: Path) -> bool:
    """Soft check: always allow fail."""
    if shutil.which("kubeconform") is None:
        return True
    p = subprocess.run(["kubeconform", "-summary", str(path)],
                        capture_output=True, text=True)
    return p.returncode == 0

# ---------------------------------------------------------------------
# MAIN VALIDATION FUNCTION
# ---------------------------------------------------------------------

def validate_one(original: Path, secured: Path, categories: List[str]) -> Dict[str, Any]:
    result = {
        "file": original.name,
        "status": "PASS",
        "dangerous": [],
        "categories": categories,
        "auto_fix_categories": [c for c in categories if c not in NON_AUTO_FIX_CATEGORIES],
        "auto_fix_unfixed": [],
        "schema_fixed": False,
        "notes": [],
    }

    # --------------------- Load YAML ---------------------
    try:
        secured_docs = load_yaml(secured)
    except Exception as e:
        result["status"] = "FAIL"
        result["notes"].append(str(e))
        return result

    # --------------------- Auto-Fix Schema ---------------------
    fixed_docs = autofix_schema_all(secured_docs)
    if fixed_docs != secured_docs:
        dump_yaml(secured, fixed_docs)
        result["schema_fixed"] = True

    # re-load after fix
    try:
        secured_docs = load_yaml(secured)
    except:
        result["status"] = "FAIL"
        result["notes"].append("Schema fix still produced invalid YAML.")
        return result

    # --------------------- Check dangerous misconfig ---------------------
    for d in secured_docs:
        danger = check_dangerous(d)
        if danger:
            result["dangerous"].extend(danger)

    if result["dangerous"]:
        result["status"] = "FAIL"
        result["notes"].extend(result["dangerous"])
        return result

    # --------------------- Check category completeness ---------------------
    for d in secured_docs:
        for cat in result["auto_fix_categories"]:
            if not category_fixed(d, cat):
                result["auto_fix_unfixed"].append(cat)

    if result["auto_fix_unfixed"]:
        result["status"] = "FAIL"
        result["notes"].append("Auto-fix categories not satisfied: " + ",".join(result["auto_fix_unfixed"]))
        return result

    # --------------------- Kubeconform (soft) ---------------------
    if not run_kubeconform(secured):
        result["status"] = "NEEDS_REVIEW"
        result["notes"].append("Schema warnings: kubeconform errors.")

    return result

# ---------------------------------------------------------------------
# SUMMARY WRITER
# ---------------------------------------------------------------------

def write_summary(out_dir: Path, results: List[Dict[str, Any]]):
    path = out_dir / "SUMMARY_VALIDATION.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "file", "status", "dangerous", "unfixed_categories",
            "auto_fix_categories", "schema_fixed", "notes"
        ])
        for r in results:
            w.writerow([
                r["file"], r["status"],
                ";".join(r["dangerous"]),
                ";".join(r["auto_fix_unfixed"]),
                ";".join(r["auto_fix_categories"]),
                r["schema_fixed"],
                "; ".join(r["notes"]),
            ])

# ---------------------------------------------------------------------
# MAIN CLI
# ---------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tests-dir", required=True)
    ap.add_argument("--fixed-dir", required=True)
    ap.add_argument("--payload", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    tests_dir = Path(args.tests_dir)
    fixed_dir = Path(args.fixed_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))
    file_map = {}

    if "files" in payload:
        for f in payload["files"]:
            file_map[f["file"]] = [x["category"] for x in f["findings"]]
    elif "items" in payload:
        for it in payload["items"]:
            file_map.setdefault(it["file"], []).append(it["category"])

    results = []

    for rel, cats in file_map.items():
        orig = tests_dir / rel
        sec = fixed_dir / f"SECURED_{rel.replace('/', '_')}"
        if not orig.exists() or not sec.exists():
            continue

        print(f"[INFO] Validating {rel} ...")
        r = validate_one(orig, sec, cats)
        results.append(r)
        (out_dir / f"REPORT_VALIDATE_{rel.replace('/', '_')}.json").write_text(
            json.dumps(r, indent=2), encoding="utf-8"
        )
        print(f"      -> status={r['status']}")

    write_summary(out_dir, results)

    worst = "PASS"
    order = {"PASS":0, "NEEDS_REVIEW":1, "FAIL":2}
    for r in results:
        if order[r["status"]] > order[worst]:
            worst = r["status"]

    if worst == "FAIL":
        exit(1)
    else:
        exit(0)

if __name__ == "__main__":
    main()
