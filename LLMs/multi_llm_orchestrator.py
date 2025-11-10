#!/usr/bin/env python3
"""
SafeFix-K8s: Multi-LLM Orchestrator (hardened)
- Fan-out to multiple LLM providers to get a "fixed" YAML.
- Apply secure-by-default hygiene (kind-aware placement, resources rule, seccomp).
- Reject illegal edits (e.g., security fields on Services).
- Validate with kubeconform + kubectl --dry-run=server + kube-linter + polaris.
- Choose the first candidate that passes all checks; otherwise fall back to hygiene-only fix.

CLI (examples)
--------------
python multi_llm_orchestrator.py --input input.yaml --models groq,openrouter --timeout 30
python multi_llm_orchestrator.py --input dir/ --models openrouter --hygiene-only

Notes
-----
- Wire your own provider logic in call_model_provider().
- Requires: PyYAML, and external CLIs: kubeconform, kubectl, kube-linter, polaris.
"""

from __future__ import annotations
import re
import argparse
import subprocess
from pathlib import Path
from typing import List, Tuple, Optional

import yaml

# ======================================================================================
# Kind map & constants
# ======================================================================================

KIND_MAP = {
    ("apps/v1", "Deployment"):   {"pod_spec": ("spec", "template", "spec"), "containers": ("spec", "template", "spec", "containers")},
    ("apps/v1", "StatefulSet"):  {"pod_spec": ("spec", "template", "spec"), "containers": ("spec", "template", "spec", "containers")},
    ("apps/v1", "DaemonSet"):    {"pod_spec": ("spec", "template", "spec"), "containers": ("spec", "template", "spec", "containers")},
    ("batch/v1", "Job"):         {"pod_spec": ("spec", "template", "spec"), "containers": ("spec", "template", "spec", "containers")},
    ("batch/v1", "CronJob"):     {"pod_spec": ("spec","jobTemplate","spec","template","spec"), "containers": ("spec","jobTemplate","spec","template","spec","containers")},
    ("v1", "Pod"):               {"pod_spec": ("spec",), "containers": ("spec", "containers")},
}

CONTAINER_SECURITY_FIELDS = {"runAsNonRoot", "allowPrivilegeEscalation", "readOnlyRootFilesystem", "capabilities", "seccompProfile"}
POD_SECURITY_FIELDS = {"runAsUser", "runAsGroup", "fsGroup", "seccompProfile"}

# order set used for rough CPU compare
_CPU_ORDER = ["n", "u", "m", "", "k"]  # trivial ordering for units; good enough for >= check


# ======================================================================================
# Utilities
# ======================================================================================

def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

def npath(p: str) -> str:
    return p.replace("\\", "/").strip()

def run(cmd: List[str], input_text: Optional[str] = None) -> Tuple[int, str, str]:
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE if input_text else None,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate(input_text)
    return p.returncode, out, err

def yaml_load_all(text: str) -> List[dict]:
    docs = list(yaml.safe_load_all(text))
    return [d for d in docs if isinstance(d, dict)]

def yaml_dump_all(docs: List[dict]) -> str:
    return "\n---\n".join(yaml.safe_dump(d, sort_keys=False).rstrip() for d in docs if isinstance(d, dict)) + ("\n" if docs else "")

def deep_get(d: dict, path: Tuple[str, ...]) -> Optional[dict]:
    cur = d
    for seg in path:
        if not isinstance(cur, dict) or seg not in cur:
            return None
        cur = cur[seg]
    return cur

def deep_ensure(d: dict, path: Tuple[str, ...]) -> dict:
    cur = d
    for seg in path:
        nxt = cur.get(seg)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[seg] = nxt
        cur = nxt
    return cur

def first_container_list(d: dict, containers_path: Tuple[str, ...]) -> Optional[List[dict]]:
    cur = deep_get(d, containers_path)
    if isinstance(cur, list):
        return cur
    return None


# ======================================================================================
# Resource normalization
# ======================================================================================

def _cmp_cpu(a: str, b: str) -> int:
    def norm(x: str) -> Tuple[float, str]:
        x = str(x).strip().lower()
        for suf in ["n", "u", "m", "k"]:
            if x.endswith(suf):
                try:
                    return float(x[:-len(suf)] or "0"), suf
                except (ValueError, TypeError):
                    return 0.0, suf
        try:
            return float(x), ""
        except (ValueError, TypeError):
            return 0.0, ""
    va, sa = norm(a)
    vb, sb = norm(b)
    if sa == sb:
        return (va > vb) - (va < vb)
    return (_CPU_ORDER.index(sa) > _CPU_ORDER.index(sb)) - (_CPU_ORDER.index(sa) < _CPU_ORDER.index(sb))

def _cmp_mem(a: str, b: str) -> int:
    SCALE = {"ki": 1e3, "k": 1e3, "mi": 1e6, "m": 1e6, "gi": 1e9, "g": 1e9}
    def val(x: str) -> float:
        x = str(x).strip().lower()
        for suf, mul in SCALE.items():
            if x.endswith(suf):
                try:
                    return float(x[:-len(suf)] or "0") * mul
                except (ValueError, TypeError):
                    return 0.0
        try:
            return float(x)
        except (ValueError, TypeError):
            return 0.0
    va, vb = val(a), val(b)
    return (va > vb) - (va < vb)

def normalize_resources(container: dict) -> List[str]:
    changes = []
    res = container.setdefault("resources", {})
    req = res.setdefault("requests", {})
    lim = res.setdefault("limits", {})
    # defaults
    req.setdefault("cpu", "50m")
    req.setdefault("memory", "64Mi")
    lim.setdefault("cpu", "200m")
    lim.setdefault("memory", "128Mi")
    # ensure limits >= requests
    if _cmp_cpu(lim["cpu"], req["cpu"]) < 0:
        lim["cpu"] = req["cpu"]
        changes.append("resources.limits.cpu>=requests.cpu")
    if _cmp_mem(lim["memory"], req["memory"]) < 0:
        lim["memory"] = req["memory"]
        changes.append("resources.limits.memory>=requests.memory")
    return changes


# ======================================================================================
# Hygiene (kind-aware placement, seccomp, container SC, SA token)
# ======================================================================================

def apply_hygiene(text: str, secure_defaults: bool = True) -> str:
    docs = yaml_load_all(text)
    changed = False

    for d in docs:
        if not isinstance(d, dict):
            continue
        av = str(d.get("apiVersion", "")).strip()
        kd = str(d.get("kind", "")).strip()
        paths = KIND_MAP.get((av, kd))
        if not paths:
            # Non-workload kinds: never touch them
            continue

        # Pod-level security context & SA token
        psc_path = paths["pod_spec"] + ("securityContext",)
        psc = deep_ensure(d, psc_path)

        # Seccomp at pod level (RuntimeDefault)
        if secure_defaults and not isinstance(psc.get("seccompProfile"), dict):
            psc["seccompProfile"] = {"type": "RuntimeDefault"}
            changed = True

        # automountServiceAccountToken at pod spec
        podspec = deep_ensure(d, paths["pod_spec"])
        if "automountServiceAccountToken" not in podspec:
            podspec["automountServiceAccountToken"] = False
            changed = True

        # Optional identity defaults (non-breaking)
        if secure_defaults:
            if "runAsUser" not in psc:
                psc["runAsUser"] = 1000
                changed = True
            if "runAsGroup" not in psc:
                psc["runAsGroup"] = 1000
                changed = True
            if "fsGroup" not in psc:
                psc["fsGroup"] = 2000
                changed = True

        # Container-level securityContext and resources
        containers = first_container_list(d, paths["containers"]) or []
        for c in containers:
            csc = c.setdefault("securityContext", {})
            # Normalize drop: ["ALL"]
            caps = csc.setdefault("capabilities", {})
            drop = caps.get("drop")
            if drop is None:
                caps["drop"] = ["ALL"]
                changed = True
            else:
                if not isinstance(drop, list):
                    drop = [drop]
                drop_set = {str(x).upper() for x in drop}
                if "ALL" not in drop_set:
                    drop_set.add("ALL")
                    caps["drop"] = sorted(drop_set)
                    changed = True

            # APE, RO rootfs, non-root
            if "allowPrivilegeEscalation" not in csc:
                csc["allowPrivilegeEscalation"] = False
                changed = True
            if "readOnlyRootFilesystem" not in csc:
                csc["readOnlyRootFilesystem"] = True
                changed = True
            if "runAsNonRoot" not in csc:
                csc["runAsNonRoot"] = True
                changed = True

            # Container seccomp is optional because pod-level is set; skip to reduce noise

            # Resources rule
            if normalize_resources(c):
                changed = True

    return yaml_dump_all(docs) if changed else text


# ======================================================================================
# Structural sanity checks (reject illegal fields on non-workload kinds)
# ======================================================================================

def structural_sanity(text: str) -> bool:
    try:
        docs = yaml_load_all(text)
        for d in docs:
            if not isinstance(d, dict):
                continue
            av = str(d.get("apiVersion", "")).strip()
            kd = str(d.get("kind", "")).strip()
            spec = d.get("spec", {})
            if (av, kd) not in KIND_MAP:
                # Non-workload kinds must not have pod-only fields at top spec level
                if isinstance(spec, dict) and ("securityContext" in spec or "automountServiceAccountToken" in spec):
                    return False
        return True
    except (yaml.YAMLError, TypeError, ValueError):
        return False


# ======================================================================================
# Validators: kubeconform → kubectl server-dry-run → kube-linter → polaris
# ======================================================================================

def validate_chain(text: str, kubeconform_args: List[str] | None = None) -> Tuple[bool, str]:
    kubeconform_args = kubeconform_args or ["-strict", "-ignore-missing-schemas"]
    ok, reasons = True, []

    code, _, _ = run(["kubeconform", *kubeconform_args], input_text=text)
    if code != 0:
        ok = False; reasons.append("kubeconform")
    # server dry-run
    code, _, _ = run(["kubectl", "apply", "--dry-run=server", "-f", "-"], input_text=text)
    if code != 0:
        ok = False; reasons.append("kubectl-dry-run")
    # kube-linter
    code, _, _ = run(["kube-linter", "lint", "-"], input_text=text)
    if code != 0:
        ok = False; reasons.append("kube-linter")
    # polaris
    # polaris does not read from stdin; write a temp file
    tmp = Path(".safefix_tmp.yaml")
    write_text(tmp, text)
    code, _, _ = run(["polaris", "audit", "--audit-path", str(tmp)])
    try:
        tmp.unlink(missing_ok=True)
    except (OSError, FileNotFoundError):
        pass
    if code != 0:
        ok = False; reasons.append("polaris")

    return ok, ",".join(reasons)


# ======================================================================================
# LLM providers (hook your own logic here)
# ======================================================================================

def call_model_provider(_model: str, _prompt: str, _timeout_s: int) -> Optional[str]:
    """
    TODO: Replace this stub with your existing provider calls.
    It must return a YAML string (single or multi-doc) OR None on failure.

    Suggested contract:
    - Return only YAML text (no code fences).
    - Ensure models are instructed to keep original metadata (name/labels/selectors).
    - Ask the model to avoid adding fields to non-workload kinds.

    For now, we return None to force hygiene-only fallback if no providers are wired.
    """
    return None  # <-- wire your real logic


# ======================================================================================
# Orchestrator
# ======================================================================================

DEFAULT_PROMPT = """You are a Kubernetes security engineer. Return ONLY a Kubernetes YAML that:
- Preserves original object names, labels, selectors, containers and ports.
- Adds secure-by-default settings where valid: pod-level seccompProfile RuntimeDefault, automountServiceAccountToken: false;
  per-container: runAsNonRoot: true, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities.drop: [ALL].
- Do NOT add securityContext or automountServiceAccountToken to non-workload kinds (e.g., Service, ConfigMap).
- Do NOT invent RBAC unless strictly required by existing fields.
- Keep image references unchanged (do not pin or retag).
Return YAML only, no explanations.
"""

def process_one_file(in_path: Path, out_dir: Path, models: List[str], timeout: int, hygiene_only: bool) -> None:
    raw = read_text(in_path)

    candidates: List[Tuple[str, str]] = []  # (origin, yaml_text)

    if not hygiene_only and models:
        for m in models:
            result = call_model_provider(m, DEFAULT_PROMPT + "\n\n---\n" + raw, timeout)
            if result is None:
                continue
            candidates.append((f"model:{m}", result))

    # Always add hygiene-only candidate (deterministic fallback)
    candidates.append(("hygiene", apply_hygiene(raw, secure_defaults=True)))

    # Evaluate candidates
    chosen: Optional[Tuple[str, str]] = None
    last_reject_reason = ""
    for origin, cand in candidates:
        # strip code fences if the model returned them
        cfix = re.sub(r"^\s*```(?:yaml)?\s*|\s*```\s*$", "", cand.strip(), flags=re.IGNORECASE | re.DOTALL)

        # quick structural sanity
        if not structural_sanity(cfix):
            last_reject_reason = f"{origin}: structural_sanity"
            continue

        # validate chain
        ok, reason = validate_chain(cfix)
        if ok:
            chosen = (origin, cfix)
            break
        else:
            last_reject_reason = f"{origin}: {reason}"

    if not chosen:
        # As a last resort, enforce hygiene again (idempotent) and try validate once more
        h2 = apply_hygiene(raw, secure_defaults=True)
        ok, reason = validate_chain(h2)
        if ok:
            chosen = ("hygiene-final", h2)
        else:
            raise SystemExit(f"Failed to produce a valid fix for {in_path.name}. Last reason: {last_reject_reason or reason}")

    origin, fixed = chosen
    # Write outputs
    rel = in_path.name
    out_path = out_dir / rel
    write_text(out_path, fixed)
    print(f"[OK] {rel} <- {origin}")

def discover_inputs(inp: Path) -> List[Path]:
    if inp.is_dir():
        return sorted([p for p in inp.rglob("*") if p.is_file() and p.suffix.lower() in {".yaml", ".yml"}])
    return [inp]

def main():
    ap = argparse.ArgumentParser(description="SafeFix-K8s Multi-LLM Orchestrator (hardened)")
    ap.add_argument("--input", required=True, help="YAML file or directory")
    ap.add_argument("--output", default="output/fixed", help="Output directory for fixed YAMLs")
    ap.add_argument("--models", default="", help="Comma-separated provider names (e.g., groq,openrouter)")
    ap.add_argument("--timeout", type=int, default=30, help="Per-model timeout seconds")
    ap.add_argument("--hygiene-only", action="store_true", help="Skip model calls; apply hygiene/validation only")
    args = ap.parse_args()

    in_path = Path(args.input)
    out_dir = Path(args.output)
    models = [m.strip() for m in args.models.split(",") if m.strip()]

    inputs = discover_inputs(in_path)
    if not inputs:
        raise SystemExit("No YAML files found.")

    out_dir.mkdir(parents=True, exist_ok=True)
    for f in inputs:
        try:
            process_one_file(f, out_dir, models, args.timeout, args.hygiene_only)
        except SystemExit as e:
            print(f"[FAIL] {f.name}: {e}")
        except (SystemExit, KeyboardInterrupt, RuntimeError) as e:
            print(f"[ERR ] {f.name}: {e}")

if __name__ == "__main__":
    main()
