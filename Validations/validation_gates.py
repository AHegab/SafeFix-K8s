"""
validation_gates.py

Validates LLM-secured YAML files produced by multi_llm_orchestrator.py.

Inputs
------
--tests-dir      : Directory of original test YAML files (the sources referenced in payload).
--fixed-dir      : Directory containing SECURED_* files (output of LLM fixes).
--payload        : Path to the "Actual-only" LLM payload JSON (to know categories per file).
--out-dir        : Directory to write reports (per-file JSON + SUMMARY.csv).
--require-schema : (flag) If set, fail a file when kubeconform fails (if installed). Otherwise just record result.
--fail-on        : comma list of severities to treat as exit(1). Default: FAIL
                   Allowed values: PASS, NEEDS_REVIEW, FAIL
 

What it does
------------
- Loads payload to map each original file -> allowed categories.
- For each SECURED_* file:
    * Locates the corresponding original YAML file.
    * Computes a structural diff to RFC-6902-like ops (add/replace/remove, with JSON pointers).
    * Applies validation gates:
        G1: Identity immutability (kind/name/namespace)
        G2: Image immutability (containers/initContainers image)
        G3: Scope compliance (only paths corresponding to the file's categories are changed)
        G4: Minimalism (disallow "bonus" fields like arbitrary probes/resources unless category requires)
        G5: Category-specific assertions (e.g., ImagePullPolicy->IfNotPresent; securityContext hardening)
        G6: HostPath remediation (removed or replaced)
        G7: RBAC wildcard narrowing (no '*' in verbs/resources; narrowed relative to original)
        G8: Optional schema validation via kubeconform (if available)
- Writes REPORT_<file>.json and SUMMARY.csv.

Exit code
---------
0 if all files are below configured fail-on severity. 1 otherwise.

Author: SafeFix-K8s
"""

import argparse, json, os, re, subprocess, sys
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
import yaml
from copy import deepcopy

# ---------------- I/O helpers ----------------
def read_json(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))

def read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore")

def write_text(p: Path, s: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding="utf-8")

def yaml_load_all(s: str) -> List[Any]:
    try:
        docs = list(yaml.safe_load_all(s))
        return [d for d in docs if d is not None]
    except yaml.YAMLError:
        return []

def yaml_dump_all(docs: List[Any]) -> str:
    return yaml.safe_dump_all(docs, sort_keys=False, default_flow_style=False)

# -------------- Payload mapping --------------
def load_categories(payload_path: Path) -> Dict[str, List[str]]:
    """
    Returns { file_rel_path: [categories...] }
    Defensive against category as str or list, and duplicates.
    """
    m: Dict[str, List[str]] = {}
    if not payload_path or not payload_path.exists():
        return m
    payload = read_json(payload_path)
    for f in payload.get("files", []):
        rel = f.get("file")
        cats: List[str] = []
        for x in (f.get("findings") or []):
            c = x.get("category")
            if isinstance(c, list):
                cats.extend([str(i) for i in c if i])
            elif c is not None:
                cats.append(str(c))
        cats = sorted(set(cats))
        if rel:
            m[normalize_rel(rel)] = cats
    return m

def normalize_rel(rel: str) -> str:
    # repo-internal canonical form uses forward slashes
    return rel.replace("\\", "/")

def infer_original_from_secured_name(tests_dir: Path, secured_file: Path) -> Optional[Path]:
    """
    SECURED_{safeRel} where safeRel = rel with / and \ replaced by _ and .. stripped.
    We can't perfectly invert, so we attempt mapping using tests_dir walk.
    """
    target = secured_file.name[len("SECURED_"):]
    for p in tests_dir.rglob("*"):
        if p.is_file():
            rel = normalize_rel(str(p.relative_to(tests_dir)))
            safe = rel.replace("/", "_").replace("\\", "_").replace("..", "")
            if safe == target:
                return p
    return None

# -------------- JSON-pointer diff --------------
def _ptr_escape(s: str) -> str:
    return s.replace("~", "~0").replace("/", "~1")

def _diff(a: Any, b: Any, base: str = "") -> List[Dict[str, Any]]:
    """
    Produce a simple patch list (op, path, value) approximating RFC-6902.
    We model additions, removals, and replacements at object and array keys.
    """
    ops: List[Dict[str, Any]] = []
    if type(a) != type(b):
        ops.append({"op":"replace","path": base or "/", "value": b})
        return ops

    if isinstance(a, dict):
        akeys = set(a.keys()); bkeys = set(b.keys())
        # removals
        for k in sorted(akeys - bkeys):
            ops.append({"op":"remove","path": f"{base}/{_ptr_escape(k)}" if base else f"/{_ptr_escape(k)}"})
        # additions
        for k in sorted(bkeys - akeys):
            ops.append({"op":"add","path": f"{base}/{_ptr_escape(k)}" if base else f"/{_ptr_escape(k)}","value": b[k]})
        # recursive compares
        for k in sorted(akeys & bkeys):
            ops += _diff(a[k], b[k], f"{base}/{_ptr_escape(k)}" if base else f"/{_ptr_escape(k)}")
        return ops

    if isinstance(a, list):
        if a == b:
            return ops
        minlen = min(len(a), len(b))
        for i in range(minlen):
            if a[i] != b[i]:
                ops.append({"op":"replace","path": f"{base}/{i}","value": b[i]})
        if len(b) > len(a):
            for i in range(len(a), len(b)):
                ops.append({"op":"add","path": f"{base}/{i}","value": b[i]})
        elif len(a) > len(b):
            for i in reversed(range(len(b), len(a))):
                ops.append({"op":"remove","path": f"{base}/{i}"})
        return ops

    if a != b:
        ops.append({"op":"replace","path": base or "/", "value": b})
    return ops

# -------------- Category ↔ path rules --------------
CATEGORY_PATH_RULES = {
    # Image policy only; must NOT change the image name/tag/digest.
    "ImagePullPolicy": [
        "/spec/template/spec/containers/*/imagePullPolicy",
        "/spec/template/spec/initContainers/*/imagePullPolicy"
    ],

    # Basic hardening
    "RunAsNonRoot": [
        "/spec/template/spec/containers/*/securityContext/runAsNonRoot",
        "/spec/template/spec/initContainers/*/securityContext/runAsNonRoot"
    ],
    "ReadOnlyRootFilesystem": [
        "/spec/template/spec/containers/*/securityContext/readOnlyRootFilesystem",
        "/spec/template/spec/initContainers/*/securityContext/readOnlyRootFilesystem"
    ],
    "NoPrivilegeEscalation": [
        "/spec/template/spec/containers/*/securityContext/allowPrivilegeEscalation",
        "/spec/template/spec/initContainers/*/securityContext/allowPrivilegeEscalation"
    ],
    "DropCapabilities": [
        "/spec/template/spec/containers/*/securityContext/capabilities",
        "/spec/template/spec/initContainers/*/securityContext/capabilities"
    ],

    # Host flags
    "HostNetwork": ["/spec/template/spec/hostNetwork"],
    "HostPID":     ["/spec/template/spec/hostPID"],
    "HostIPC":     ["/spec/template/spec/hostIPC"],

    # Volumes
    "HostPath": [
        "/spec/template/spec/volumes/*/hostPath",
        "/spec/template/spec/volumes/*/emptyDir",
        "/spec/template/spec/containers/*/volumeMounts/*/readOnly",
        "/spec/template/spec/initContainers/*/volumeMounts/*/readOnly"
    ],

    # Probes category (only if explicitly asked)
    "ProbesMissing": [
        "/spec/template/spec/containers/*/livenessProbe",
        "/spec/template/spec/containers/*/readinessProbe",
        "/spec/template/spec/initContainers/*/livenessProbe",
        "/spec/template/spec/initContainers/*/readinessProbe",
    ],

    # RBAC
    "RBACWildcard": [
        "/rules/*/verbs/*",
        "/rules/*/resources/*",
        "/rules/*/apiGroups/*",
        "/rules/*/resourceNames/*",
    ],
}

FORBIDDEN_EXACT = {"/kind", "/metadata/name", "/metadata/namespace", "/metadata/generateName"}
FORBIDDEN_SEGMENTS = {"/image", "/spec/replicas"}  # don’t touch images/replicas at all
# Also forbid top-level metadata labels/annotations unless a category whitelists (none do here).
FORBIDDEN_PREFIXES = {"/metadata/labels", "/metadata/annotations"}

# -------------- Matching helpers --------------
def ptr_matches(pattern: str, path: str) -> bool:
    # "*" wildcard matcher on single path segment
    p_segs = [s for s in pattern.split("/") if s]
    x_segs = [s for s in path.split("/") if s]
    if len(x_segs) < len(p_segs):
        return False
    for i, p in enumerate(p_segs):
        if p == "*":
            continue
        if i >= len(x_segs):
            return False
        if p != x_segs[i]:
            return False
    return True

def any_match(patterns: List[str], path: str) -> bool:
    return any(ptr_matches(pat, path) for pat in patterns)

# -------------- Gates --------------
def gate_identity_immutable(path: str) -> Optional[str]:
    if path in FORBIDDEN_EXACT:
        return f"G1 Identity change forbidden at {path}"
    if any(path.startswith(pref) for pref in FORBIDDEN_PREFIXES):
        return f"G1 metadata labels/annotations not allowed: {path}"
    return None

def gate_image_immutable(path: str) -> Optional[str]:
    if any(seg in path for seg in FORBIDDEN_SEGMENTS):
        if "/imagePullPolicy" in path:
            return None  # allowed separately
        return f"G2 Image/replicas change forbidden: {path}"
    return None

def gate_scope(path: str, categories: List[str]) -> Optional[str]:
    if not categories:
        return f"G3 No categories for file; change not allowed: {path}"
    allowed: List[str] = []
    for c in categories:
        allowed += CATEGORY_PATH_RULES.get(c, [])
    if not allowed:
        return f"G3 Unknown categories for file; no changes allowed: {path}"
    if not any_match(allowed, path):
        return f"G3 Path not allowed by categories {categories}: {path}"
    return None

def gate_minimalism(op: Dict[str, Any], categories: List[str]) -> Optional[str]:
    path = op.get("path","")
    # Disallow adding arbitrary env/resources/ports unless explicitly requested categories (none here).
    if any(x in path for x in ["/env", "/resources", "/ports", "/args", "/command"]):
        return f"G4 Minimalism: bonus field not allowed: {path}"
    # Probes only if ProbesMissing present
    if ("Probe" in path or "/livenessProbe" in path or "/readinessProbe" in path):
        if "ProbesMissing" not in categories:
            return f"G4 Probes not in scope: {path}"
    return None

def gate_category_specific(op: Dict[str, Any], categories: List[str]) -> Optional[str]:
    path = op.get("path",""); value = op.get("value")
    # Enforce specific values
    if "ImagePullPolicy" in categories and path.endswith("/imagePullPolicy"):
        if value not in ("IfNotPresent", "Always"):
            return f"G5 ImagePullPolicy must be IfNotPresent/Always, got: {value}"
        if value != "IfNotPresent":
            return f"G5 Use IfNotPresent, not {value}"
    if "NoPrivilegeEscalation" in categories and path.endswith("/securityContext/allowPrivilegeEscalation"):
        if value not in (False, "false"):
            return f"G5 allowPrivilegeEscalation must be false"
    if "RunAsNonRoot" in categories and path.endswith("/securityContext/runAsNonRoot"):
        if value not in (True, "true"):
            return f"G5 runAsNonRoot must be true"
    if "ReadOnlyRootFilesystem" in categories and path.endswith("/securityContext/readOnlyRootFilesystem"):
        if value not in (True, "true"):
            return f"G5 readOnlyRootFilesystem must be true"
    if "DropCapabilities" in categories and "/securityContext/capabilities" in path:
        if isinstance(value, dict):
            drop = value.get("drop") or []
            if not drop:
                return f"G5 capabilities: 'drop' must be non-empty (prefer ['ALL'])"
        else:
            return f"G5 capabilities must be an object with 'drop'"
    if "HostPath" in categories:
        if "/volumes/" in path and path.endswith("/hostPath"):
            if op.get("op") != "remove":
                return f"G5 hostPath should be removed; replacement must be emptyDir in a separate op"
        if path.endswith("/emptyDir"):
            # ok if present
            pass
    return None

def gate_rbac(original_doc: Dict[str,Any], fixed_doc: Dict[str,Any], categories: List[str]) -> Optional[str]:
    if "RBACWildcard" not in categories:
        return None
    # quick scan: ensure no "*" in rules verbs/resources
    def has_wildcard_rules(doc: Dict[str,Any]) -> bool:
        for r in (doc or {}).get("rules", []) or []:
            for k in ("verbs","resources","apiGroups","resourceNames"):
                v = r.get(k) or []
                if isinstance(v, list) and any(x == "*" for x in v):
                    return True
        return False
    if has_wildcard_rules(fixed_doc):
        return "G7 RBACWildcard: '*' still present in rules; must be narrowed"

    # Also ensure narrowed vs original if possible (simple heuristic)
    def score(doc: Dict[str,Any]) -> Tuple[int,int]:
        vcount = 0; rcount = 0
        for r in (doc or {}).get("rules", []) or []:
            v = r.get("verbs") or []; rs = r.get("resources") or []
            if isinstance(v, list): vcount += len(v)
            if isinstance(rs, list): rcount += len(rs)
        return vcount, rcount

    ov, orc = score(original_doc); fv, frc = score(fixed_doc)
    if fv > ov or frc > orc:
        return "G7 RBACWildcard: verbs/resources not narrowed"
    return None

# -------------- kubeconform --------------
def kubeconform_check(yaml_text: str) -> Tuple[bool, str]:
    try:
        p = subprocess.run(
            ["kubeconform", "-summary", "-strict", "-ignore-missing-schemas", "-"],
            input=yaml_text.encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
        )
        ok = (p.returncode == 0)
        return ok, p.stdout.decode("utf-8", errors="ignore")
    except FileNotFoundError:
        return True, "kubeconform not found (skipped)"

# -------------- Main validation --------------
def classify(issues: List[str]) -> str:
    """
    Severity classifier:
      - FAIL: any G1/G2/G5/G7 violation
      - NEEDS_REVIEW: minimalism/scope/kubeconform warnings
      - PASS: no issues
    """
    if not issues:
        return "PASS"
    hard = [i for i in issues if i.startswith(("G1","G2","G5","G7"))]
    if hard:
        return "FAIL"
    return "NEEDS_REVIEW"

def extract_first_doc(yaml_text: str) -> Dict[str,Any]:
    docs = yaml_load_all(yaml_text)
    return docs[0] if docs else {}

def main():
    ap = argparse.ArgumentParser(description="Validate LLM-secured YAML files against SafeFix gates.")
    ap.add_argument("--tests-dir", required=True)
    ap.add_argument("--fixed-dir", required=True)
    ap.add_argument("--payload", required=True)
    ap.add_argument("--out-dir", default="output/validation")
    ap.add_argument("--require-schema", action="store_true")
    ap.add_argument("--fail-on", default="FAIL", help="Comma list of severities to fail build on (e.g., FAIL,NEEDS_REVIEW)")
    args = ap.parse_args()

    tests_dir = Path(args.tests_dir).resolve()
    fixed_dir = Path(args.fixed_dir).resolve()
    out_dir   = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    file2cats = load_categories(Path(args.payload))
    fail_on = {s.strip().upper() for s in args.fail_on.split(",") if s.strip()}

    summary_rows = ["file,severity,issues_count"]
    had_blocking = False

    for secured in sorted(fixed_dir.glob("SECURED_*")):
        fixed_text = read_text(secured)
        fixed_docs = yaml_load_all(fixed_text)

        orig_path = infer_original_from_secured_name(tests_dir, secured)
        if not orig_path or not orig_path.exists():
            report = {"file": secured.name, "severity":"FAIL", "issues":["Original file not found for mapping."], "notes":[]}
            write_text(out_dir / f"REPORT_{secured.name}.json", json.dumps(report, indent=2))
            summary_rows.append(f"{secured.name},FAIL,1")
            if "FAIL" in fail_on: had_blocking = True
            continue

        original_text = read_text(orig_path)
        original_docs = yaml_load_all(original_text)

        orig = original_docs[0] if original_docs else {}
        fixd = fixed_docs[0] if fixed_docs else {}

        diffs = _diff(orig, fixd, "")

        # categories for this file (robust, no tuple bug)
        rel_key = normalize_rel(str(orig_path.relative_to(tests_dir)))
        cats = file2cats.get(rel_key, [])
        if isinstance(cats, (tuple, set)):
            cats = list(cats)
        flat: List[str] = []
        for c in cats:
            if isinstance(c, list):
                flat.extend([str(x) for x in c if x])
            elif c is not None:
                flat.append(str(c))
        cats = sorted(set(flat))

        issues: List[str] = []
        notes: List[str]  = []

        # kubeconform (optional)
        ok_schema, schema_out = kubeconform_check(fixed_text)
        notes.append(schema_out.strip())
        if args.require_schema and not ok_schema:
            issues.append("Schema: kubeconform failed")

        # Apply gates per op
        for op in diffs:
            path = op.get("path","")

            m = gate_identity_immutable(path)
            if m: issues.append(m)
            m = gate_image_immutable(path)
            if m: issues.append(m)
            m = gate_scope(path, cats)
            if m: issues.append(m)
            m = gate_minimalism(op, cats)
            if m: issues.append(m)
            m = gate_category_specific(op, cats)
            if m: issues.append(m)

        # Extra RBAC gate if the doc looks like a Role/ClusterRole
        if (orig.get("kind") in ("Role","ClusterRole")) or (fixd.get("kind") in ("Role","ClusterRole")):
            m = gate_rbac(orig, fixd, cats)
            if m: issues.append(m)

        severity = classify(issues)

        report = {
            "file_fixed": secured.name,
            "file_original": str(orig_path),
            "categories": cats,
            "severity": severity,
            "issues": sorted(set(issues)),
            "diff_ops_count": len(diffs),
            "notes": notes[:5]
        }
        write_text(out_dir / f"REPORT_{secured.name}.json", json.dumps(report, indent=2))
        summary_rows.append(f"{secured.name},{severity},{len(report['issues'])}")

        if severity in fail_on:
            had_blocking = True

    write_text(out_dir / "SUMMARY.csv", "\n".join(summary_rows))
    if had_blocking:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
