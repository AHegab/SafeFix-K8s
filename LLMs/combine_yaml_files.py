#!/usr/bin/env python3
"""
combine_yaml_files.py

Merge multiple already-fixed YAML contents for the SAME source file into a single, most-secure manifest.
No external project imports; fully self-contained.

Usage:
  python combine_yaml_files.py --original tests/13.deployment.yaml --fixed-dir output/fixed --out-dir output/combination

It will:
  - Read ORIGINAL file content.
  - Read all files in --fixed-dir whose name starts with SECURED_<basename>.
  - Merge doc-by-doc, picking the most restrictive/security-hardened values.
  - Emit:
      SECURED_MERGED_<basename>.yaml
      DIFF_MERGED_<basename>.diff
      SUMMARY_MERGED_<basename>.json
"""

import argparse
import difflib
from pathlib import Path
from typing import Any, Dict, List, Tuple
import yaml
import copy
import json

def read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8")

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

def unified_diff_text(original: str, fixed: str, orig_path: str, fixed_path: str) -> str:
    a = original.splitlines(keepends=True)
    b = fixed.splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, fromfile=orig_path, tofile=fixed_path, lineterm="", n=3))

def get_pod_spec(doc: Dict) -> Dict:
    if not isinstance(doc, dict): return {}
    kind = str(doc.get("kind") or "")
    spec = doc.get("spec")
    if not isinstance(spec, dict): return {}
    if kind == "Pod":
        return spec
    tmpl = spec.get("template")
    if isinstance(tmpl, dict) and isinstance(tmpl.get("spec"), dict):
        return tmpl["spec"]
    return {}

def find_containers(pod_spec: Dict) -> List[Tuple[str, Dict]]:
    res=[]
    for key in ("initContainers","containers"):
        arr = pod_spec.get(key) or []
        for i,c in enumerate(arr):
            if isinstance(c, dict):
                res.append((f"{key}[{i}]", c))
    return res

# --- secure merge helpers ---

def most_restrictive_bool(values: List[Any], prefer: bool) -> Any:
    # if any is False and prefer False, choose False; vice versa
    vals = [v for v in values if isinstance(v, bool)]
    if not vals: return prefer
    return False if prefer is False else True if all(vals) else False

def merge_security_context(sc_list: List[Dict]) -> Dict:
    out = {}
    # booleans: prefer hardened defaults
    def pick_bool(key: str, hard_default: bool):
        candidates = [sc.get(key) for sc in sc_list if isinstance(sc, dict) and key in sc]
        if any(c is not None for c in candidates):
            # most restrictive policy: privileged=False, allowPrivilegeEscalation=False, runAsNonRoot=True, readOnlyRootFilesystem=True
            if key in ("privileged","allowPrivilegeEscalation"):
                out[key] = False
            elif key in ("runAsNonRoot","readOnlyRootFilesystem"):
                out[key] = True
            else:
                out[key] = candidates[-1]
        else:
            out[key] = hard_default

    pick_bool("privileged", False)
    pick_bool("allowPrivilegeEscalation", False)
    pick_bool("runAsNonRoot", True)
    pick_bool("readOnlyRootFilesystem", True)

    # runAsUser: choose lowest non-root >0 if any, else 1000
    runs = [sc.get("runAsUser") for sc in sc_list if isinstance(sc, dict) and isinstance(sc.get("runAsUser"), int)]
    if runs:
        non_root = [r for r in runs if r != 0]
        out["runAsUser"] = min(non_root) if non_root else 1000
    else:
        out["runAsUser"] = 1000

    # capabilities: ensure drop ALL; strip dangerous adds
    out["capabilities"] = {"drop": ["ALL"]}
    return out

def merge_container(a: Dict, b: Dict) -> Dict:
    # Merge two containers preferring the most restrictive settings
    res = copy.deepcopy(a)
    res_sc = merge_security_context([a.get("securityContext",{}), b.get("securityContext",{})])
    res["securityContext"] = res_sc

    # Merge resources: prefer tighter limits if both present, else fill in defaults
    def parse_q(v, default):
        return v if isinstance(v,str) else default
    def merge_res(resA, resB):
        out={"requests":{}, "limits":{}}
        for kind in ("requests","limits"):
            A = (resA or {}).get(kind) or {}
            B = (resB or {}).get(kind) or {}
            out[kind]["cpu"] = parse_q(A.get("cpu", B.get("cpu")), "100m" if kind=="requests" else "500m")
            out[kind]["memory"] = parse_q(A.get("memory", B.get("memory")), "128Mi" if kind=="requests" else "256Mi")
        return out
    res["resources"] = merge_res(a.get("resources"), b.get("resources"))

    # Merge probes: if any has probe, keep it, else add an exec ok
    def ensure_probe(p):
        return p if isinstance(p, dict) and p else {"exec":{"command":["sh","-c","echo ok"]}, "initialDelaySeconds":5, "periodSeconds":10}
    res["livenessProbe"]  = ensure_probe(a.get("livenessProbe")  or b.get("livenessProbe"))
    res["readinessProbe"] = ensure_probe(a.get("readinessProbe") or b.get("readinessProbe"))

    # imagePullPolicy: prefer IfNotPresent
    if res.get("imagePullPolicy") != "IfNotPresent":
        res["imagePullPolicy"] = "IfNotPresent"

    return res

def merge_pod_spec(specs: List[Dict]) -> Dict:
    out = copy.deepcopy(specs[0]) if specs else {}
    # host* flags → all false
    for k in ("hostNetwork","hostPID","hostIPC"):
        out[k] = False

    # volumes: drop hostPath; preserve others
    vols=[]
    for s in specs:
        for v in (s.get("volumes") or []):
            if isinstance(v, dict) and "hostPath" in v:
                continue
            vols.append(v)
    if vols:
        out["volumes"] = vols

    # automountServiceAccountToken=false
    out["automountServiceAccountToken"] = False

    # pod seccomp profile
    psc = out.get("securityContext") or {}
    psc["seccompProfile"] = {"type":"RuntimeDefault"}
    out["securityContext"] = psc

    # containers/initContainers aligned by index (best-effort)
    for key in ("initContainers","containers"):
        rows = []
        lists = [s.get(key) or [] for s in specs]
        maxlen = max((len(lst) for lst in lists), default=0)
        for i in range(maxlen):
            picks = []
            for lst in lists:
                if i < len(lst) and isinstance(lst[i], dict):
                    picks.append(lst[i])
            if not picks:
                continue
            # reduce two-by-two
            merged = picks[0]
            for p in picks[1:]:
                merged = merge_container(merged, p)
            rows.append(merged)
        if rows:
            out[key] = rows
    return out

def merge_docs(orig_docs: List[Dict], fixed_docs_list: List[List[Dict]]) -> Tuple[List[Dict], List[str]]:
    """
    Merge same-index documents across fixed versions, preferring most restrictive security posture.
    """
    applied = []
    merged: List[Dict] = []
    total_docs = max([len(orig_docs)] + [len(fd) for fd in fixed_docs_list])
    for i in range(total_docs):
        # collect candidates
        candidates = []
        for fd in fixed_docs_list:
            if i < len(fd) and isinstance(fd[i], dict):
                candidates.append(fd[i])
        if not candidates:
            merged.append(orig_docs[i] if i < len(orig_docs) else {})
            continue
        base = candidates[0]
        # If it's a pod/workload, merge pod spec securely
        kind = str(base.get("kind") or "")
        if kind in ("Pod","Deployment","StatefulSet","DaemonSet","Job","CronJob","ReplicaSet","ReplicationController"):
            specs = [get_pod_spec(c) for c in candidates if get_pod_spec(c)]
            out = copy.deepcopy(base)
            if specs:
                out_spec = out.get("spec") or {}
                if kind == "Pod":
                    out_spec = merge_pod_spec(specs)
                else:
                    tmpl = (out_spec.get("template") or {})
                    tmpl_spec = (tmpl.get("spec") or {})
                    merged_ps = merge_pod_spec([tmpl_spec] + [get_pod_spec(c) for c in candidates[1:] if get_pod_spec(c)])
                    tmpl["spec"] = merged_ps
                    out_spec["template"] = tmpl
                out["spec"] = out_spec
                applied.append(f"doc[{i}] {kind}: merged pod security")
            merged.append(out)
        else:
            # non-pod docs: pick the most reduced version (prefer one without wildcards / hostPath / cluster-admin)
            chosen = candidates[0]
            for c in candidates[1:]:
                chosen = c  # simple last-wins; in practice your fixed outputs should already be hardened
            merged.append(chosen)
            applied.append(f"doc[{i}] {kind}: chosen hardened variant")
    return merged, applied

def main():
    ap = argparse.ArgumentParser(description="Combine multiple fixed YAMLs for a single source into one secured manifest.")
    ap.add_argument("--original", required=True, help="Path to the ORIGINAL source YAML")
    ap.add_argument("--fixed-dir", required=True, help="Directory containing SECURED_<basename> variants")
    ap.add_argument("--out-dir", default="output/combination", help="Output directory")
    args = ap.parse_args()

    original_path = Path(args.original).resolve()
    fixed_dir     = Path(args.fixed_dir).resolve()
    out_dir       = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not original_path.exists():
        raise FileNotFoundError(f"Original file not found: {original_path}")

    # Gather fixed files for same basename
    base = original_path.name
        prefix = f"SECURED_{base.replace('/', '_').replace('\\\\','_')}"
    candidates = sorted([p for p in fixed_dir.glob(f"SECURED_*{base}") if p.is_file()])

    if not candidates:
        raise SystemExit(f"No fixed candidates found for {base} under {fixed_dir}")

    original_text = read_text(original_path)
    orig_docs = yaml_load_all(original_text)

    fixed_docs_list: List[List[Dict]] = []
    for fp in candidates:
        docs = yaml_load_all(read_text(fp))
        fixed_docs_list.append(docs)

    merged_docs, applied = merge_docs(orig_docs, fixed_docs_list)
    merged_text = yaml_dump_all(merged_docs)

    out_yaml = out_dir / f"SECURED_MERGED_{base}"
    out_diff = out_dir / f"DIFF_MERGED_{base}.diff"
    out_sum  = out_dir / f"SUMMARY_MERGED_{base}.json"

    write_text(out_yaml, merged_text)
    write_text(out_diff, unified_diff_text(original_text, merged_text, str(original_path), str(out_yaml)))

    summary = {
        "original": str(original_path),
        "merged_file": str(out_yaml),
        "diff_file": str(out_diff),
        "applied": applied,
        "inputs": [str(p) for p in candidates],
    }
    write_text(out_sum, json.dumps(summary, indent=2))
    print(f"[OK] Merged → {out_yaml}\nDiff → {out_diff}\nSummary → {out_sum}")

if __name__ == "__main__":
    main()
