#!/usr/bin/env python3
"""
validation_gates.py

Validates LLM-secured YAML files produced by multi_llm_orchestrator.py.

Inputs
------
--tests-dir      : Directory of original test YAML files (the sources referenced in payload).
--fixed-dir      : Directory containing SECURED_* files (output of multi_llm_orchestrator.py).
--payload        : Path to the "Actual-only" LLM payload JSON (to know categories per file).
--out-dir        : Directory to write reports (per-file JSON + SUMMARY.csv).
--require-schema : (flag) If set, fail a file when kubeconform fails (if installed). Otherwise just record result.
--fail-on        : comma list of severities to treat as exit(1). Default: FAIL
                   Allowed values: PASS, NEEDS_REVIEW, FAIL

What it does
------------
- Loads payload to map each original file -> categories present (auto-fix vs non-auto-fix).
- For each payload file, locates:
    * Original YAML file under --tests-dir.
    * Corresponding SECURED_* file under --fixed-dir (same naming as multi_llm_orchestrator.py).
- Computes a structural diff to RFC-6902-like ops (add/replace/remove, with JSON pointers).
- Applies validation gates:
    G1: Identity immutability (kind, metadata.name/namespace/generateName unchanged).
    G2: Image immutability (containers[].image unchanged; imagePullPolicy allowed).
    G3: Category-scoped changes only (all patch paths must be within allowed paths for some auto-fix category).
    G4: Coverage/completeness (if auto-fix categories exist but none are touched, mark NEEDS_REVIEW).
    G5: Optional kubeconform schema validation on SECURED_* file (PASS/NEEDS_REVIEW/FAIL depending on --require-schema).
- Classifies each file as PASS / NEEDS_REVIEW / FAIL based on gate outcomes.
- Writes per-file JSON plus SUMMARY.csv and exits non-zero if severity in --fail-on.

This is intentionally conservative: any unexpected change outside allowed paths
will cause G3 to FAIL, so passing files only changed within pre-approved scopes.
"""

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

# ---------------------- Category policy (align with orchestrator) ----------------------

# Categories that should NOT be auto-fixed by LLM (manual / cluster-specific)
NON_AUTO_FIX_CATEGORIES = {
    "Network/MissingNetworkPolicy",
    "Misc/Unmapped",
    # Optional: make tag pinning manual-only so G0 doesn't scream:
    "Image/TagNotPinned",
}

# Category -> allowed JSON Pointer paths
CATEGORY_PATH_RULES = {
    # Auth / RunAsRoot → runAsNonRoot + non-zero UID
    "Auth/RunAsRoot": [
        "/spec/template/spec/securityContext/runAsNonRoot",
        "/spec/template/spec/securityContext/runAsUser",
        "/spec/template/spec/containers/*/securityContext/runAsNonRoot",
        "/spec/template/spec/containers/*/securityContext/runAsUser",
        "/spec/template/spec/initContainers/*/securityContext/runAsNonRoot",
        "/spec/template/spec/initContainers/*/securityContext/runAsUser",
        "/spec/securityContext/runAsNonRoot",
        "/spec/securityContext/runAsUser",
        "/spec/containers/*/securityContext/runAsNonRoot",
        "/spec/containers/*/securityContext/runAsUser",
        "/spec/initContainers/*/securityContext/runAsNonRoot",
        "/spec/initContainers/*/securityContext/runAsUser",
        # treat changing the whole pod-level securityContext as coverage
        "/spec/template/spec/securityContext",
        "/spec/securityContext",
    ],

    # Image/TagNotPinned → only imagePullPolicy (if you keep it auto-fixable)
    "Image/TagNotPinned": [
        "/spec/template/spec/containers/*/imagePullPolicy",
        "/spec/template/spec/initContainers/*/imagePullPolicy",
        "/spec/containers/*/imagePullPolicy",
        "/spec/initContainers/*/imagePullPolicy",
    ],

    # PodSecurityViolation → seccompProfile + readOnlyRootFilesystem etc.
    "Policy/PodSecurityViolation": [
        # Controller-style pod-level seccomp
        "/spec/template/spec/securityContext/seccompProfile",
        # Controller-style container-level seccomp + readOnlyRootFilesystem
        "/spec/template/spec/containers/*/securityContext/seccompProfile",
        "/spec/template/spec/initContainers/*/securityContext/seccompProfile",
        "/spec/template/spec/containers/*/securityContext/readOnlyRootFilesystem",
        "/spec/template/spec/initContainers/*/securityContext/readOnlyRootFilesystem",
        # Pod-level fallback
        "/spec/securityContext/seccompProfile",
        "/spec/containers/*/securityContext/seccompProfile",
        "/spec/initContainers/*/securityContext/seccompProfile",
        "/spec/containers/*/securityContext/readOnlyRootFilesystem",
        "/spec/initContainers/*/securityContext/readOnlyRootFilesystem",
        # allow setting the whole pod-level securityContext object
        "/spec/template/spec/securityContext",
        "/spec/securityContext",
    ],

    # Security: allowPrivilegeEscalation → must be false
    "Security/AllowPrivilegeEscalation": [
        "/spec/template/spec/containers/*/securityContext/allowPrivilegeEscalation",
        "/spec/template/spec/initContainers/*/securityContext/allowPrivilegeEscalation",
        "/spec/containers/*/securityContext/allowPrivilegeEscalation",
        "/spec/initContainers/*/securityContext/allowPrivilegeEscalation",
    ],

    # Security: capabilities → drop ALL
    "Security/CapabilitiesNotDropped": [
        "/spec/template/spec/containers/*/securityContext/capabilities",
        "/spec/template/spec/initContainers/*/securityContext/capabilities",
        "/spec/containers/*/securityContext/capabilities",
        "/spec/initContainers/*/securityContext/capabilities",
    ],

    # Security: privileged container → must be false
    "Security/PrivilegedContainer": [
        "/spec/template/spec/containers/*/securityContext/privileged",
        "/spec/template/spec/initContainers/*/securityContext/privileged",
        "/spec/containers/*/securityContext/privileged",
        "/spec/initContainers/*/securityContext/privileged",
    ],

    # Probes missing
    "Probes/MissingReadinessLiveness": [
        "/spec/template/spec/containers/*/livenessProbe",
        "/spec/template/spec/containers/*/readinessProbe",
        "/spec/template/spec/initContainers/*/livenessProbe",
        "/spec/template/spec/initContainers/*/readinessProbe",
        "/spec/containers/*/livenessProbe",
        "/spec/containers/*/readinessProbe",
        "/spec/initContainers/*/livenessProbe",
        "/spec/initContainers/*/readinessProbe",
    ],

    # Resources
    "Resources/MissingLimits": [
        "/spec/template/spec/containers/*/resources",
        "/spec/template/spec/initContainers/*/resources",
        "/spec/containers/*/resources",
        "/spec/initContainers/*/resources",
    ],
    "Resources/MissingRequests": [
        "/spec/template/spec/containers/*/resources",
        "/spec/template/spec/initContainers/*/resources",
        "/spec/containers/*/resources",
        "/spec/initContainers/*/resources",
    ],

    # RBAC categories (example)
    "RBAC/Wildcard": [
        "/rules/*/verbs/*",
        "/rules/*/resources/*",
        "/rules/*/apiGroups/*",
        "/rules/*/resourceNames/*",
    ],
    "RBAC/OverlyPermissive": [
        "/rules/*/verbs/*",
        "/rules/*/resources/*",
        "/rules/*/apiGroups/*",
        "/rules/*/resourceNames/*",
    ],

    # schema invalid (selector) – this makes /spec/selector legal
    "Schema/InvalidManifest": [
        "/spec/selector",
    ],
}


# Absolutely forbidden paths to touch
FORBIDDEN_EXACT = {
    "/kind",
    "/metadata/name",
    "/metadata/namespace",
    "/metadata/generateName",
}

# Patterns we never let LLMs touch (except where explicitly allowed)
FORBIDDEN_SEGMENTS = {
    "/image",          # blocks containers[].image; imagePullPolicy handled separately
    "/spec/replicas",  # don't autoscale
}

FORBIDDEN_PREFIXES = {
    "/metadata/labels",
    "/metadata/annotations",
}

# ---------------------- Basic helpers ----------------------


def yaml_load_all(text: str) -> List[Any]:
    if not text.strip():
        return []
    try:
        docs = list(yaml.safe_load_all(text))
        return [d for d in docs if d is not None]
    except yaml.YAMLError:
        return []


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return ""


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# -------------------- JSON-pointer utilities -------------------


def ptr_join(base: str, key: str) -> str:
    if not base or base == "/":
        base = ""
    key = key.replace("~", "~0").replace("/", "~1")
    return base + "/" + key


def ptr_matches(pattern: str, path: str) -> bool:
    """Simple JSON-pointer-ish matcher with '*' wildcard."""
    p_segs = [s for s in pattern.split("/") if s]
    x_segs = [s for s in path.split("/") if s]
    if len(x_segs) < len(p_segs):
        return False
    for i, p in enumerate(p_segs):
        if p == "*":
            continue
        if i >= len(x_segs) or p != x_segs[i]:
            return False
    return True


def allowed_paths_for_categories(categories_auto_fix: List[str]) -> Dict[str, List[str]]:
    allowed: Dict[str, List[str]] = {}
    for c in categories_auto_fix:
        if not c:
            continue
        paths = CATEGORY_PATH_RULES.get(c, [])
        if paths:
            allowed[c] = list(paths)

        # Prefix handling for RBAC/*
        if c.startswith("RBAC/"):
            for base in ("RBAC/Wildcard", "RBAC/OverlyPermissive"):
                for p in CATEGORY_PATH_RULES.get(base, []):
                    allowed.setdefault(c, [])
                    if p not in allowed[c]:
                        allowed[c].append(p)
    return allowed


def categorize_ops_against_categories(
    ops: List[Dict[str, Any]],
    auto_fix_categories: List[str],
) -> Tuple[List[str], List[str]]:
    """
    Infer which categories each op contributes to using CATEGORY_PATH_RULES.
    Returns (categories_fixed, categories_unfixed).
    """
    allowed = allowed_paths_for_categories(auto_fix_categories)
    fixed: set = set()

    for op in ops:
        path = op.get("path", "")
        if not isinstance(path, str):
            continue
        for cat, patterns in allowed.items():
            if any(ptr_matches(pat, path) for pat in patterns):
                fixed.add(cat)

    cats_set = set(auto_fix_categories)
    categories_fixed = sorted(fixed & cats_set)
    categories_unfixed = sorted(cats_set - fixed)
    return categories_fixed, categories_unfixed


# ------------------ Diff builder (RFC-6902-ish) ------------------


def build_diff_ops(orig: Any, new: Any, base_path: str = "") -> List[Dict[str, Any]]:
    """
    Recursive diff to generate add/replace/remove ops.
    Not minimal, but good enough for validation.
    """
    ops: List[Dict[str, Any]] = []

    # Primitive or different types
    if type(orig) != type(new) or not isinstance(orig, (dict, list)) or not isinstance(
        new, (dict, list)
    ):
        if orig != new:
            ops.append(
                {
                    "op": "replace",
                    "path": base_path or "/",
                    "old": orig,
                    "value": new,
                }
            )
        return ops

    if isinstance(orig, dict):
        o_keys = set(orig.keys())
        n_keys = set(new.keys())
        for k in o_keys - n_keys:
            path = ptr_join(base_path, str(k))
            ops.append({"op": "remove", "path": path, "old": orig[k]})
        for k in n_keys - o_keys:
            path = ptr_join(base_path, str(k))
            ops.append({"op": "add", "path": path, "value": new[k]})
        for k in o_keys & n_keys:
            child_path = ptr_join(base_path, str(k))
            ops.extend(build_diff_ops(orig[k], new[k], child_path))
        return ops

    if isinstance(orig, list):
        max_len = max(len(orig), len(new))
        for idx in range(max_len):
            path = ptr_join(base_path, str(idx))
            if idx >= len(orig):
                ops.append({"op": "add", "path": path, "value": new[idx]})
            elif idx >= len(new):
                ops.append({"op": "remove", "path": path, "old": orig[idx]})
            else:
                ops.extend(build_diff_ops(orig[idx], new[idx], path))
        return ops

    return ops


# ----------------------- Payload handling ------------------------


def normalize_payload_to_files(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Expect SafeFix "Actual-only" payload:
      {"files":[{"file": "...", "findings":[{"category": "...", ...}, ...]}, ...]}
    Returns list of {"file": <rel>, "categories": [...]}.
    """
    files = payload.get("files") or []
    out: List[Dict[str, Any]] = []
    for fe in files:
        rel = fe.get("file")
        if not rel:
            continue
        cats = sorted(
            set(
                fd.get("category")
                for fd in (fe.get("findings") or [])
                if fd.get("category")
            )
        )
        out.append({"file": rel, "categories": cats})
    return out


def resolve_yaml_path(tests_dir: Path, file_rel: str) -> Path:
    """
    Try tests_dir / file_rel, else search by basename.
    """
    p = tests_dir / file_rel
    if p.exists():
        return p
    base = Path(file_rel).name
    matches = list(tests_dir.rglob(base))
    if matches:
        return matches[0]
    return p


def safe_rel_name(rel: str) -> str:
    return rel.replace("\\", "_").replace("/", "_").replace("..", "")


# ---------------------- Kubeconform wrapper ----------------------


def run_kubeconform(path: Path) -> Tuple[Optional[bool], str]:
    """
    Run kubeconform on the given file, returning (success, details).
    success=None when kubeconform is not installed.
    """
    try:
        proc = subprocess.run(
            ["kubeconform", "-summary", "-output", "json", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return None, "kubeconform not installed"
    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()
    ok = proc.returncode == 0
    details = stdout or stderr or f"exit code {proc.returncode}"
    return ok, details


# ------------------------- Gate logic ----------------------------


def evaluate_gates_for_file(
    file_rel: str,
    categories: List[str],
    orig_text: str,
    secured_text: str,
) -> Dict[str, Any]:
    """
    Evaluate G0–G4 for a single file (schema gate G5 is added later in main()).

    - G0: YAML parseability
    - G1: Identity immutability (kind / metadata.name / namespace / generateName)
    - G2: Image immutability (no changes to .../image, except imagePullPolicy)
    - G3: Category-scoped changes only (paths must match CATEGORY_PATH_RULES)
    - G4: Coverage: which auto-fix categories actually got patched
    """
    orig_docs = yaml_load_all(orig_text)
    fixed_docs = yaml_load_all(secured_text)

    gates: List[Dict[str, Any]] = []

    # Auto-fix vs manual-only categories
    auto_fix_cats = [c for c in categories if c not in NON_AUTO_FIX_CATEGORIES]
    non_auto_fix_cats = [c for c in categories if c in NON_AUTO_FIX_CATEGORIES]

    # ---------------- G0: YAML parseable ----------------
    if not orig_docs or not fixed_docs:
        gates.append(
            {
                "name": "G0_parseable_yaml",
                "status": "FAIL",
                "details": "Original or secured YAML not parseable.",
            }
        )
        return {
            "file": file_rel,
            "categories_present": categories,
            "categories_auto_fix": auto_fix_cats,
            "non_auto_fix_categories": non_auto_fix_cats,
            "gates": gates,
            "severity": "FAIL",
            "ops": [],
            "auto_fix_stats": {
                "auto_fix_count": len(auto_fix_cats),
                "categories_fixed": [],
                "categories_unfixed": auto_fix_cats,
            },
        }

    # ---------------- Build diff ops (JSON-Patch-ish) ----------------
    max_docs = max(len(orig_docs), len(fixed_docs))
    all_ops: List[Dict[str, Any]] = []
    for i in range(max_docs):
        o = orig_docs[i] if i < len(orig_docs) else None
        n = fixed_docs[i] if i < len(fixed_docs) else None
        all_ops.extend(build_diff_ops(o, n, base_path=""))

    # Normalize empty paths to root
    for op in all_ops:
        if not op.get("path"):
            op["path"] = "/"

    # ---------------- G1: identity immutability ----------------
    g1_status = "PASS"
    g1_details: List[str] = []
    for op in all_ops:
        path = op.get("path", "")
        if path in FORBIDDEN_EXACT:
            g1_status = "FAIL"
            g1_details.append(f"Identity field changed via op at path {path}")
    if not all_ops:
        g1_details.append("No changes detected between original and secured.")
    gates.append(
        {
            "name": "G1_identity_immutability",
            "status": g1_status,
            "details": "; ".join(g1_details) if g1_details else "OK",
        }
    )

    # ---------------- G2: image immutability ----------------
    g2_status = "PASS"
    g2_details: List[str] = []
    for op in all_ops:
        path = op.get("path", "")
        # imagePullPolicy is explicitly allowed
        if "/imagePullPolicy" in path:
            continue
        # Any other /image field must not change
        if path.endswith("/image"):
            g2_status = "FAIL"
            g2_details.append(f"Image field changed at path {path}")
    gates.append(
        {
            "name": "G2_image_immutability",
            "status": g2_status,
            "details": "; ".join(g2_details) if g2_details else "OK",
        }
    )

    # ---------------- G3: category-scoped changes only ----------------
    allowed_map = allowed_paths_for_categories(auto_fix_cats)
    if auto_fix_cats and allowed_map:
        g3_status = "PASS"
        g3_details: List[str] = []

        for op in all_ops:
            path = op.get("path", "")
            if not isinstance(path, str):
                continue

            # Always forbidden
            if path in FORBIDDEN_EXACT:
                g3_status = "FAIL"
                g3_details.append(f"Forbidden exact path changed: {path}")
                continue
            if any(path.startswith(pref) for pref in FORBIDDEN_PREFIXES):
                g3_status = "FAIL"
                g3_details.append(f"Forbidden prefix changed: {path}")
                continue
            # Block segments like /image or /spec/replicas (unless imagePullPolicy)
            if "/imagePullPolicy" not in path and any(seg in path for seg in FORBIDDEN_SEGMENTS):
                g3_status = "FAIL"
                g3_details.append(f"Forbidden segment changed: {path}")
                continue

            # Must be covered by at least one allowed pattern of some auto-fix category
            covered = False
            for _, patterns in allowed_map.items():
                if any(ptr_matches(pat, path) for pat in patterns):
                    covered = True
                    break

            if not covered:
                g3_status = "FAIL"
                g3_details.append(f"Path {path} not allowed by any auto-fix category.")

        gates.append(
            {
                "name": "G3_category_scope",
                "status": g3_status,
                "details": "; ".join(g3_details) if g3_details else "OK",
            }
        )

    elif auto_fix_cats and not allowed_map:
        # We have categories we *intend* to auto-fix, but no rules
        gates.append(
            {
                "name": "G3_category_scope",
                "status": "NEEDS_REVIEW",
                "details": (
                    "Auto-fix categories present but CATEGORY_PATH_RULES has no entries for them; "
                    "manual review needed."
                ),
            }
        )
    else:
        # No auto-fix categories → nothing to enforce
        gates.append(
            {
                "name": "G3_category_scope",
                "status": "SKIP",
                "details": "No auto-fix categories for this file.",
            }
        )

    # ---------------- G4: coverage / completeness ----------------
    if auto_fix_cats:
        # Reuse the same logic as orchestrator: which categories got at least
        # one op on an allowed path?
        categories_fixed, categories_unfixed = categorize_ops_against_categories(
            all_ops, auto_fix_cats
        )

        if categories_unfixed:
            g4_status = "NEEDS_REVIEW"
            g4_details = (
                "Auto-fix categories not touched by any op: "
                + ", ".join(categories_unfixed)
            )
        else:
            g4_status = "PASS"
            g4_details = "All auto-fix categories appear to have at least one op on allowed paths."

        gates.append(
            {
                "name": "G4_coverage",
                "status": g4_status,
                "details": g4_details,
            }
        )
    else:
        categories_fixed, categories_unfixed = [], []
        gates.append(
            {
                "name": "G4_coverage",
                "status": "SKIP",
                "details": "No auto-fix categories to measure coverage for.",
            }
        )

    # ---------------- Overall severity (without schema gate G5) ----------------
    has_fail = any(g["status"] == "FAIL" for g in gates)
    has_needs_review = any(g["status"] == "NEEDS_REVIEW" for g in gates)
    if has_fail:
        severity = "FAIL"
    elif has_needs_review:
        severity = "NEEDS_REVIEW"
    else:
        severity = "PASS"

    return {
        "file": file_rel,
        "categories_present": categories,
        "categories_auto_fix": auto_fix_cats,
        "non_auto_fix_categories": non_auto_fix_cats,
        "gates": gates,
        "severity": severity,
        "ops": all_ops,
        "auto_fix_stats": {
            "auto_fix_count": len(auto_fix_cats),
            "categories_fixed": categories_fixed,
            "categories_unfixed": categories_unfixed,
        },
    }


# --------------------------- Main CLI ---------------------------


def main():
    ap = argparse.ArgumentParser(
        description="Validate SECURED_* YAMLs from SafeFix multi_llm_orchestrator using structural gates."
    )
    ap.add_argument(
        "--tests-dir",
        required=True,
        help="Directory containing original test YAML files.",
    )
    ap.add_argument(
        "--fixed-dir",
        required=True,
        help="Directory containing SECURED_* files (output of multi_llm_orchestrator.py).",
    )
    ap.add_argument(
        "--payload",
        required=True,
        help='Path to "Actual-only" LLM payload JSON (with files[] and findings[].category).',
    )
    ap.add_argument(
        "--out-dir",
        required=True,
        help="Directory to write per-file reports and SUMMARY.csv.",
    )
    ap.add_argument(
        "--require-schema",
        action="store_true",
        help="If set, kubeconform failure causes overall FAIL instead of NEEDS_REVIEW.",
    )
    ap.add_argument(
        "--fail-on",
        default="FAIL",
        help="Comma-separated severities that should cause non-zero exit (default: FAIL).",
    )
    args = ap.parse_args()

    tests_dir = Path(args.tests_dir).resolve()
    fixed_dir = Path(args.fixed_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))
    file_entries = normalize_payload_to_files(payload)

    summary_rows: List[List[str]] = [
        [
            "file",
            "severity",
            "categories_present",
            "categories_auto_fix",
            "categories_unfixed",
            "ops_count",
            "g1",
            "g2",
            "g3",
            "g4",
            "g5",
        ]
    ]

    severities_to_fail = {s.strip().upper() for s in args.fail_on.split(",") if s.strip()}
    severity_rank = {"PASS": 0, "NEEDS_REVIEW": 1, "FAIL": 2}
    overall_max_severity_rank = 0

    for fe in file_entries:
        file_rel = fe["file"]
        categories = fe["categories"]
        auto_fix_cats = [c for c in categories if c not in NON_AUTO_FIX_CATEGORIES]

        orig_path = resolve_yaml_path(tests_dir, file_rel)
        orig_text = read_text(orig_path)

        safe_name = safe_rel_name(file_rel)
        secured_path = fixed_dir / f"SECURED_{safe_name}"
        secured_text = read_text(secured_path)

        if not secured_text:
            # No SECURED file -> NEEDS_REVIEW if we expected fixes, else PASS.
            gates = [
                {
                    "name": "G0_secured_exists",
                    "status": "NEEDS_REVIEW" if auto_fix_cats else "PASS",
                    "details": f"SECURED file not found at {secured_path}",
                }
            ]
            result = {
                "file": file_rel,
                "categories_present": categories,
                "categories_auto_fix": auto_fix_cats,
                "non_auto_fix_categories": [c for c in categories if c in NON_AUTO_FIX_CATEGORIES],
                "gates": gates,
                "severity": "NEEDS_REVIEW" if auto_fix_cats else "PASS",
                "ops": [],
                "auto_fix_stats": {
                    "auto_fix_count": len(auto_fix_cats),
                    "categories_fixed": [],
                    "categories_unfixed": auto_fix_cats,
                },
            }
        else:
            result = evaluate_gates_for_file(
                file_rel=file_rel,
                categories=categories,
                orig_text=orig_text,
                secured_text=secured_text,
            )

        # G5: schema validation on SECURED file (if present)
        if secured_text:
            ok_schema, schema_details = run_kubeconform(secured_path)
        else:
            ok_schema, schema_details = None, "No secured file to validate."

        if ok_schema is None:
            g5_status = "SKIP"
        elif ok_schema:
            g5_status = "PASS"
        else:
            g5_status = "FAIL" if args.require_schema else "NEEDS_REVIEW"

        result.setdefault("gates", [])
        result["gates"].append(
            {
                "name": "G5_schema_validation",
                "status": g5_status,
                "details": schema_details,
            }
        )

        # Final severity including G5
        has_fail = any(g["status"] == "FAIL" for g in result["gates"])
        has_needs_review = any(g["status"] == "NEEDS_REVIEW" for g in result["gates"])
        if has_fail:
            result["severity"] = "FAIL"
        elif has_needs_review:
            result["severity"] = "NEEDS_REVIEW"
        else:
            result["severity"] = "PASS"

        severity = result["severity"]
        overall_max_severity_rank = max(
            overall_max_severity_rank, severity_rank.get(severity, 0)
        )

        # Write per-file JSON
        report_path = out_dir / f"VALIDATION_{safe_name}.json"
        write_text(report_path, json.dumps(result, indent=2))

        # CSV summary row
        cats_unfixed = result.get("auto_fix_stats", {}).get("categories_unfixed", [])
        gates_by_name = {g["name"]: g["status"] for g in result["gates"]}
        summary_rows.append(
            [
                file_rel,
                severity,
                ";".join(categories),
                ";".join(result.get("categories_auto_fix", [])),
                ";".join(cats_unfixed),
                str(len(result.get("ops", []))),
                gates_by_name.get("G1_identity_immutability", ""),
                gates_by_name.get("G2_image_immutability", ""),
                gates_by_name.get("G3_category_scope", ""),
                gates_by_name.get("G4_coverage", ""),
                gates_by_name.get("G5_schema_validation", ""),
            ]
        )

    # Write SUMMARY.csv
    summary_csv = "\n".join([",".join(row) for row in summary_rows])
    write_text(out_dir / "SUMMARY.csv", summary_csv)

    # Exit code based on --fail-on
    max_severity = {v: k for k, v in severity_rank.items()}.get(
        overall_max_severity_rank, "PASS"
    )
    if max_severity in severities_to_fail:
        raise SystemExit(1)
    raise SystemExit(0)


if __name__ == "__main__":
    main()
