#!/usr/bin/env python3
"""
multi_llm_orchestrator.py  — resilient raw-mode (+ SafeFix v3.6 aware)

- Accepts classic SafeFix payloads ({"files":[...]}) AND raw tool payloads
  ({"version": "...", "items":[...]}).
- Knows how to consume SafeFix normalizer v3.5 payloads (findings with
  snippet + patchHint).
- Adds YAML context (snippet + derived hints) to prompts so LLMs can output
  valid RFC-6902 ops.
- Robustly extracts JSON arrays from messy LLM outputs.
- Provides a deterministic local fallback for common schema categories when
  providers return nothing.
- Category-aware fallback can also apply resources / probes / seccompProfile
  ops from a single strong provider on safe JSON Pointer paths.
- Additional security-aware fallback can apply monotonic-hardening
  securityContext ops (runAsNonRoot, privileged=false, allowPrivilegeEscalation=false,
  capabilities.drop=[ALL]) from a single strong provider on safe paths.
- Some categories are explicitly marked as NON_AUTO_FIX and will not be
  modified by the LLM (they remain vulnerable and are reported as such).
- Gives the LLM explicit allowed JSON Pointer paths per category and forbidden
  paths it must not touch.
- Tracks how many auto-fix categories were actually fixed based on op paths.
- Writes SECURED_*, DIFF_*, REPORT_*.json, REPORT_ALL.csv (with provider
  errors).

Env / flags: same as before.
"""

import argparse
import difflib
import json
import os
import random
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml


# ---------------------- Simple .env loader ----------------------


def load_dotenv_from_root() -> None:
    here = Path.cwd()
    candidates = [
        here / ".env",
        here.parent / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]
    for p in candidates:
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and (k not in os.environ):
                    os.environ[k] = v
            break


load_dotenv_from_root()

# ---------------------- Category policy -------------------------

# Categories that LLMs must NOT auto-fix. They stay vulnerable and require
# human/cluster-specific design. We still pass them in the payload/report,
# but we instruct the model not to emit any patches for them.
NON_AUTO_FIX_CATEGORIES = {
    "Network/MissingNetworkPolicy",  # needs cluster-wide policy design
    "Misc/Unmapped",
    # Often business / org specific:
    "Image/TagNotPinned",
    # Add other categories here if you want them to be "manual-only".
}

# Category -> allowed JSON Pointer paths (aligned with validation_gates.py)
CATEGORY_PATH_RULES: Dict[str, List[str]] = {

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

FORBIDDEN_EXACT = {
    "/kind",
    "/metadata/name",
    "/metadata/namespace",
    "/metadata/generateName",
}
FORBIDDEN_SEGMENTS = {
    "/image",          # forbids changing actual image fields (imagePullPolicy handled separately)
    "/spec/replicas",  # no autoscaling via LLM
}
FORBIDDEN_PREFIXES = {
    "/metadata/labels",
    "/metadata/annotations",
}


# ------------------------- Helpers ------------------------------


def is_safe_security_op(category: str, op: dict) -> bool:
    """
    Guardrail: only accept monotonic-hardening ops for security categories.
    We don't inspect the whole manifest here, just the op shape and value.
    """
    path = op.get("path", "")
    value = op.get("value")

    # PrivilegedContainer: only allow privileged -> false or add false
    if category == "Security/PrivilegedContainer":
        if not path.endswith("/securityContext/privileged"):
            return False
        return value is False  # add/replace with false only

    # AllowPrivilegeEscalation: only allow false
    if category == "Security/AllowPrivilegeEscalation":
        if "/securityContext/allowPrivilegeEscalation" not in path:
            return False
        return value is False

    # CapabilitiesNotDropped: only allow capabilities.drop with ALL, no add
    if category == "Security/CapabilitiesNotDropped":
        if "/securityContext/capabilities" not in path:
            return False
        if not isinstance(value, dict):
            return False
        # Only allow 'drop' key, no 'add'
        if any(k for k in value.keys() if k not in ("drop",)):
            return False
        drop = value.get("drop")
        if not isinstance(drop, list):
            return False
        return "ALL" in drop

    # Auth/RunAsRoot: only allow runAsNonRoot=true and non-zero UID
    if category == "Auth/RunAsRoot":
        if "runAsNonRoot" in path:
            return value is True
        if "runAsUser" in path:
            # must be an int and > 0
            return isinstance(value, int) and value > 0
        return False

    # For other categories we don't enforce special checks here
    return True


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return ""


def write_text(p: Path, s: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding="utf-8")


def yaml_load_all(s: str) -> List[Any]:
    if not s.strip():
        return []
    try:
        docs = list(yaml.safe_load_all(s))
        return [d for d in docs if d is not None]
    except yaml.YAMLError:
        return []


def yaml_dump_all(docs: List[Any]) -> str:
    if not docs:
        return ""
    return yaml.safe_dump_all(docs, sort_keys=False, default_flow_style=False)


def unified_diff_text(original: str, fixed: str, orig_path: str, fixed_path: str) -> str:
    a = original.splitlines(keepends=True)
    b = fixed.splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(a, b, fromfile=orig_path, tofile=fixed_path, lineterm="", n=3)
    )


def get_pod_spec(workload: Dict) -> Optional[Dict]:
    if not isinstance(workload, dict):
        return None
    spec = workload.get("spec")
    if not isinstance(spec, dict):
        return None
    if str(workload.get("kind") or "") == "Pod":
        return spec
    tmpl = spec.get("template")
    if isinstance(tmpl, dict) and isinstance(tmpl.get("spec"), dict):
        return tmpl["spec"]
    return None


# -------------------- JSON Pointer helpers ----------------------


def _pointer_walk(doc: Any, pointer: str, create_missing: bool = False):
    if pointer == "" or pointer == "/":
        return None, None
    parts = [p for p in pointer.split("/") if p != ""]
    cur = doc
    for part in parts[:-1]:
        key = part.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            idx = int(key)
            if idx >= len(cur):
                if create_missing:
                    while len(cur) <= idx:
                        cur.append({})
                else:
                    raise KeyError(pointer)
            cur = cur[idx]
        else:
            if key not in cur:
                if create_missing:
                    cur[key] = {}
                else:
                    raise KeyError(pointer)
            cur = cur[key]
    last = parts[-1].replace("~1", "/").replace("~0", "~")
    return cur, last


def apply_json_patch(doc: Any, patch_ops: List[Dict[str, Any]]) -> Any:
    for op in patch_ops:
        op_type = op.get("op")
        path = op.get("path")
        if not isinstance(op_type, str) or not isinstance(path, str):
            continue
        parent, key = _pointer_walk(doc, path, create_missing=(op_type == "add"))
        if parent is None:
            if op_type in ("add", "replace"):
                doc = op.get("value")
            elif op_type == "remove":
                doc = None
            continue
        if isinstance(parent, list):
            idx = int(key)
            if op_type == "add":
                val = op.get("value")
                if idx == len(parent):
                    parent.append(val)
                elif 0 <= idx < len(parent):
                    parent.insert(idx, val)
            elif op_type == "replace":
                parent[idx] = op.get("value")
            elif op_type == "remove":
                if 0 <= idx < len(parent):
                    parent.pop(idx)
        else:
            if op_type in ("add", "replace"):
                parent[key] = op.get("value")
            elif op_type == "remove":
                if key in parent:
                    del parent[key]
    return doc


# ------------------ Providers & Prompting -----------------------


SYSTEM_PROMPT = (
    "You are SafeFix, a Kubernetes YAML repair assistant.\n"
    "- Your goal is to FIX ALL auto-fix categories listed in the input, using minimal RFC-6902 JSON patches.\n"
    "- Do NOT touch forbidden paths (kind/name/namespace/replicas/image) and do NOT modify non-auto-fix categories.\n"
    "- Only output a STRICT JSON array of RFC-6902 patch objects.\n"
    "- Each object must include: op, path, value (for add/replace).\n"
    "- Never wrap in markdown code fences; no prose, no comments."
)

USER_PROMPT_TEMPLATE = """\
Context:
{context}

Target file (relative): {file}
YAML snippet (truncated):
---
{yaml_snippet}
---

Derived hints:
{derived_hints}

Categories to AUTO-FIX in THIS file only (you MUST consider each of these):
{categories}

Categories that MUST NOT be auto-fixed (leave them as-is, no patches for them):
{non_auto_fix_categories}

Allowed JSON Pointer paths PER CATEGORY (you MUST keep each op.path within the listed paths for its category):
{allowed_paths_block}

Forbidden JSON Pointer paths (you MUST NOT touch any of these; if you do, the patch will be rejected):
{forbidden_paths_block}

Per-category patch hints (from analyzer):
{patch_hints}

Rules:
- Your primary objective: for every auto-fix category, either:
    * emit one or more JSON Patch ops on the allowed paths that fix it, OR
    * leave it unfixed ONLY if it is truly impossible with configuration alone.
- Make minimal, surgical changes; do NOT touch unrelated fields.
- DO NOT modify: kind, metadata.name, metadata.namespace, metadata.generateName, spec.replicas, containers[].image.
- If image is not pinned, you may only adjust imagePullPolicy; never invent a new tag/digest.
- For hostPath mounts, you may remove them or replace with emptyDir if safe, but only if that category is present.
- For RBAC wildcards, narrow verbs to ['get','list'] and resources to the minimal safe baseline.
- Reuse the following canonical patterns when relevant:
    * runAsNonRoot: true
    * runAsUser: 1000
    * allowPrivilegeEscalation: false
    * readOnlyRootFilesystem: true
    * seccompProfile: {{ "type": "RuntimeDefault" }}
    * capabilities: {{ "drop": ["ALL"] }}
    * resources:
        - requests.cpu: "100m", requests.memory: "128Mi"
        - limits.cpu: "200m", limits.memory: "256Mi"
    * HTTP probes:
        - livenessProbe: httpGet path "/healthz", port 8080
        - readinessProbe: httpGet path "/ready",   port 8080

Special guidance (based on categories + hints):
{special_guidance}

Before returning:
- Check that every patch `path` respects the allowed_paths for at least one auto-fix category.
- Check that no patch touches a forbidden path.
- Check that you have addressed as many auto-fix categories as safely possible.

Return ONLY a JSON array with RFC-6902 ops. No extra keys, no wrapper object.
"""


def derive_special_guidance(categories: List[str], patch_hints: List[str]) -> str:
    cats = set([c for c in categories if c])
    g: List[str] = []

    # High-level schema hints
    if (
        "MISSING_KIND" in cats
        or "SCHEMA_VALIDATION_ERROR" in cats
        or "Schema/InvalidManifest" in cats
    ):
        g += [
            "- Ensure required top-level keys exist: apiVersion, kind, metadata.name.",
            "- Choose apiVersion/kind consistent with existing fields; never change metadata.name.",
        ]
    if "MISSING_SELECTOR" in cats or "Schema/InvalidManifest" in cats:
        g += [
            "- For Deployment: add spec.selector.matchLabels that EXACTLY equals spec.template.metadata.labels.",
            "- Do not modify replicas, image, or other fields when fixing selector.",
        ]

    # NEW: strong guidance for security categories
    if any(c in cats for c in [
        "Security/PrivilegedContainer",
        "Security/AllowPrivilegeEscalation",
        "Security/CapabilitiesNotDropped",
        "Auth/RunAsRoot",
        "Policy/PodSecurityViolation",
    ]):
        g += [
            "- For container security issues, ALWAYS modify spec.template.spec.containers[*].securityContext.*",
            "- NEVER put 'privileged', 'allowPrivilegeEscalation', or 'capabilities' under pod-level securityContext (spec.template.spec.securityContext).",
            "- Pod-level securityContext is only for fields like runAsNonRoot, runAsUser, fsGroup, seccompProfile.",
        ]

    # If there are patch hints from the normalizer, surface them explicitly
    clean_hints = [h.strip() for h in patch_hints if isinstance(h, str) and h.strip()]
    if clean_hints:
        g.append("Patch hints from analyzer (one per category instance, deduped):")
        for h in sorted(set(clean_hints)):
            g.append(f"  * {h}")

    return "\n".join(g) if g else "- None."


def derive_hints_from_yaml(docs: List[Dict[str, Any]]) -> str:
    if not docs:
        return "- Could not parse YAML."
    d = docs[0]
    hints = []
    kind = d.get("kind", "")
    if kind:
        hints.append(f"- kind: {kind}")
    apiv = d.get("apiVersion", "")
    if apiv:
        hints.append(f"- apiVersion: {apiv}")
    name = ((d.get("metadata") or {}).get("name")) or ""
    if name:
        hints.append(f"- metadata.name: {name}")
    if (d.get("spec") or {}).get("template"):
        hints.append("- Looks like a controller with spec.template (e.g., Deployment).")
        tmpl = (d.get("spec") or {}).get("template") or {}
        tlabels = ((tmpl.get("metadata") or {}).get("labels") or {})
        if tlabels:
            hints.append(f"- template.labels keys: {', '.join(sorted(tlabels.keys()))}")
    rules = (d.get("rules") or [])
    if rules:
        hints.append(f"- Has RBAC rules (Role/ClusterRole), rules count={len(rules)}.")
    return "\n".join(hints) if hints else "- No obvious structure."


def first_yaml_snippet(text: str, max_chars: int = 1500) -> str:
    if not text:
        return "(empty file or unreadable)"
    s = text.strip()
    return s[:max_chars]


# ---------- JSON Pointer pattern matching (for stats + guidance) ----------


def ptr_matches(pattern: str, path: str) -> bool:
    """
    Simple JSON-pointer-ish matcher with '*' wildcard matching a single segment.
    """
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


def allowed_paths_for_categories(categories: List[str]) -> Dict[str, List[str]]:
    """
    Build a mapping of category -> allowed JSON Pointer paths for that category.
    Includes RBAC prefix handling (any category starting with 'RBAC/').
    """
    out: Dict[str, List[str]] = {}
    cats = [c for c in categories if c]
    for c in cats:
        out[c] = list(CATEGORY_PATH_RULES.get(c, []))

    # Prefix-based fallbacks (RBAC/*)
    if any(c.startswith("RBAC/") for c in cats):
        rbac_paths = CATEGORY_PATH_RULES.get("RBAC/Wildcard", [])
        for c in cats:
            if c.startswith("RBAC/"):
                out.setdefault(c, [])
                for p in rbac_paths:
                    if p not in out[c]:
                        out[c].append(p)

    return out


def categorize_ops_against_categories(
    ops: List[Dict[str, Any]],
    auto_fix_categories: List[str],
) -> Tuple[List[str], List[str]]:
    """
    Use CATEGORY_PATH_RULES to infer which categories each op contributes to.
    Returns (categories_fixed, categories_unfixed) based on presence of at least
    one op on an allowed path for that category.
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


# ---------- Robust HTTP (retry/backoff + tolerant JSON parsing) ----------


def _extract_retry_secs_from_text(text: str) -> Optional[float]:
    m = re.search(r"try again in\s+([0-9]+(?:\.[0-9]+)?)s", text or "", re.IGNORECASE)
    if m:
        try:
            return float(m.group(1))
        except Exception:
            return None
    return None


def _post_json(
    url: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
    *,
    provider: Optional[str] = None,
    max_retries: int = 6,
) -> Tuple[Optional[dict], Optional[str]]:
    session = requests.Session()
    attempt = 0
    lowered_tokens_once = False
    last_err = None

    while True:
        attempt += 1
        try:
            r = session.post(url, headers=headers, json=payload, timeout=90)
            status = r.status_code
            if 200 <= status < 300:
                return r.json(), None

            if status == 402 and provider == "openrouter":
                if not lowered_tokens_once:
                    lowered_tokens_once = True
                    if isinstance(payload, dict) and "max_tokens" in payload:
                        payload["max_tokens"] = max(256, int(payload.get("max_tokens", 512) // 2))
                    else:
                        payload["max_tokens"] = 256
                    continue
                last_err = f"{status} OpenRouter credit/limit"
                return None, last_err

            if status == 429:
                wait = _extract_retry_secs_from_text(r.text) or (
                    min(2**attempt, 30) + random.uniform(0, 0.5)
                )
                time.sleep(wait)
            elif 500 <= status < 600:
                wait = min(2**attempt, 30) + random.uniform(0, 0.5)
                time.sleep(wait)
            else:
                last_err = f"{status} {r.text[:200]}"
                return None, last_err

        except requests.RequestException as e:
            last_err = f"network {e}"
            wait = min(2**attempt, 30) + random.uniform(0, 0.5)
            time.sleep(wait)

        if attempt >= max_retries:
            return None, last_err or "retries exhausted"


def _extract_json_array(text: str) -> Optional[List[dict]]:
    """
    Be tolerant to models returning prose or code fences.
    Strategy:
      1) Strip markdown fences.
      2) Try direct json.loads.
      3) Extract first [...] block.
      4) If that still fails, strip obvious trailing commas and retry.
    """
    if not text:
        return None

    # Strip markdown fences if present
    text = text.strip()
    text = re.sub(r"^```(?:json)?", "", text, flags=re.IGNORECASE).strip()
    text = re.sub(r"```$", "", text).strip()

    def _try_parse(s: str) -> Optional[List[dict]]:
        try:
            obj = json.loads(s)
            return obj if isinstance(obj, list) else None
        except Exception:
            return None

    # Direct parse
    arr = _try_parse(text)
    if arr is not None:
        return arr

    # Fallback: find first array
    m = re.search(r"\[.*\]", text, flags=re.S)
    if not m:
        return None
    frag = m.group(0)

    arr = _try_parse(frag)
    if arr is not None:
        return arr

    # Last-chance: strip trailing commas before } or ]
    sanitized = re.sub(r",(\s*[}\]])", r"\1", frag)
    arr = _try_parse(sanitized)
    return arr


# ---------------- Provider calls ----------------


def call_openrouter(model: str, prompt: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key or not model:
        return None, "missing key or model"
    url = "https://openrouter.ai/api/v1/chat/completions"
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
        "max_tokens": 640,
    }
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "User-Agent": "SafeFix-K8s/1.0",
        "HTTP-Referer": "https://safefix.local",
    }
    js, err = _post_json(url, headers, body, provider="openrouter")
    if not js:
        return None, err or "no json"
    try:
        txt = js["choices"][0]["message"]["content"].strip()
        ops = _extract_json_array(txt)
        return ops, None if ops is not None else "parse-failed"
    except Exception as e:
        return None, f"extract-error {e}"


def call_groq(model: str, prompt: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    key = os.environ.get("GROQ_API_KEY")
    if not key or not model:
        return None, "missing key or model"
    url = "https://api.groq.com/openai/v1/chat/completions"
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
        "max_tokens": 1024,
    }
    js, err = _post_json(
        url,
        {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        body,
        provider="groq",
    )
    if not js:
        return None, err or "no json"
    try:
        txt = js["choices"][0]["message"]["content"].strip()
        ops = _extract_json_array(txt)
        return ops, None if ops is not None else "parse-failed"
    except Exception as e:
        return None, f"extract-error {e}"


def call_gemini(model: str, prompt: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    key = os.environ.get("GEMINI_API_KEY")
    if not key or not model:
        return None, "missing key or model"
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={key}"
    )
    body = {
        "contents": [{"parts": [{"text": SYSTEM_PROMPT + "\n\n" + prompt}]}],
        "generationConfig": {"temperature": 0.0},
    }
    js_err = None
    try:
        r = requests.post(url, json=body, timeout=90)
        if 200 <= r.status_code < 300:
            js = r.json()
            txt = js["candidates"][0]["content"]["parts"][0]["text"].strip()
            ops = _extract_json_array(txt)
            return ops, None if ops is not None else "parse-failed"
        js_err = f"{r.status_code} {r.text[:160]}"
    except Exception as e:
        js_err = f"network {e}"
    return None, js_err


def call_ollama(model: str, prompt: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    if not model or not base:
        return None, "missing base or model"
    url = f"{base.rstrip('/')}/api/chat"
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
    }
    try:
        r = requests.post(url, json=body, timeout=90)
        if 200 <= r.status_code < 300:
            js = r.json()
            txt = js.get("message", {}).get("content", "").strip()
            ops = _extract_json_array(txt)
            if ops is not None:
                return ops, None
    except Exception:
        pass
    # fallback endpoint
    try:
        url2 = f"{base.rstrip('/')}/api/generate"
        r2 = requests.post(
            url2,
            json={
                "model": model,
                "prompt": SYSTEM_PROMPT + "\n\n" + prompt,
                "stream": False,
            },
            timeout=90,
        )
        if 200 <= r2.status_code < 300:
            js2 = r2.json()
            txt2 = js2.get("response", "").strip()
            ops = _extract_json_array(txt2)
            return ops, None if ops is not None else "parse-failed"
        return None, f"{r2.status_code} {r2.text[:160]}"
    except Exception as e:
        return None, f"network {e}"


# ------------------ Voting & Application ------------------------


def sanitize_ops(ops: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(ops, list):
        return out
    for o in ops:
        if not isinstance(o, dict):
            continue
        op = o.get("op")
        path = o.get("path")
        if not isinstance(op, str) or not isinstance(path, str):
            continue
        if op not in ("add", "replace", "remove"):
            continue
        if op in ("add", "replace") and "value" not in o:
            continue

        # Drop clearly forbidden paths early (extra safety)
        if path in FORBIDDEN_EXACT:
            continue
        if any(path.startswith(pref) for pref in FORBIDDEN_PREFIXES):
            continue
        # Allow imagePullPolicy, but block direct /image fields and replicas
        if "/imagePullPolicy" not in path and any(seg in path for seg in FORBIDDEN_SEGMENTS):
            continue

        out.append({"op": op, "path": path, "value": o.get("value")})
    return out


def vote_merge(provider_ops: List[Tuple[str, List[Dict[str, Any]]]]) -> List[Dict[str, Any]]:
    priority = ["openrouter", "groq", "gemini", "ollama"]
    seen: Dict[str, Dict[str, Any]] = {}
    counts: Dict[str, int] = {}
    first_provider: Dict[str, str] = {}
    for provider, ops in provider_ops:
        for op in ops:
            key = json.dumps(op, sort_keys=True)
            counts[key] = counts.get(key, 0) + 1
            if key not in first_provider:
                first_provider[key] = provider
            if key not in seen:
                seen[key] = op
    if not counts:
        return []
    max_votes = max(counts.values())
    winners = [k for k, v in counts.items() if v == max_votes]
    winners.sort(
        key=lambda k: priority.index(first_provider.get(k, "ollama"))
        if first_provider.get(k, "ollama") in priority
        else 99
    )
    return [seen[k] for k in winners]


# ---- Category-aware single-provider fallback (resources / probes / seccomp) ----


def _is_safe_cat_path(
    op: Dict[str, Any],
    need_resources: bool,
    need_probes: bool,
    need_seccomp: bool,
) -> bool:
    if op.get("op") not in ("add", "replace"):
        return False
    path = op.get("path", "")

    # Normalize checks to handle both Pod and controller-style specs
    if need_resources and (
        "/containers/" in path and "/resources" in path
    ):
        return True

    if need_probes and (
        "/containers/" in path
        and ("/livenessProbe" in path or "/readinessProbe" in path)
    ):
        return True

    if need_seccomp and "securityContext/seccompProfile" in path:
        return True

    return False


def category_aware_single_provider_fallback(
    provider_ops: List[Tuple[str, List[Dict[str, Any]]]],
    categories: List[str],
) -> List[Dict[str, Any]]:
    """
    For some categories it's safe to take single-provider ops:
      - Resources/MissingLimits / Resources/MissingRequests
      - Probes/MissingReadinessLiveness
      - Policy/PodSecurityViolation  (seccompProfile)
    We pick at most ONE provider (by priority) and only accept ops on
    whitelisted JSON Pointer paths.
    """
    cats = set(categories)
    need_resources = any(c.startswith("Resources/") for c in cats)
    need_probes = any(c.startswith("Probes/") for c in cats)
    need_seccomp = "Policy/PodSecurityViolation" in cats

    if not (need_resources or need_probes or need_seccomp):
        return []

    priority = ["openrouter", "groq", "gemini", "ollama"]

    # Pick the first provider (by priority) that has at least one safe op
    for prov in priority:
        for name, ops in provider_ops:
            if name != prov:
                continue
            safe_ops = [
                o
                for o in ops
                if _is_safe_cat_path(o, need_resources, need_probes, need_seccomp)
            ]
            if safe_ops:
                return safe_ops

    return []


# ---- Security-aware fallback (privileged, allowPrivilegeEscalation, caps, runAsNonRoot) ----


def augment_with_security_fixes(
    auto_fix_categories: List[str],
    provider_ops: List[Tuple[str, List[Dict[str, Any]]]],
    final_ops: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    For security-related categories that still have no coverage after voting +
    non-security fallback, try to salvage safe, monotonic-hardening ops from
    a single strong provider on allowed paths:

      - Auth/RunAsRoot
      - Security/PrivilegedContainer
      - Security/AllowPrivilegeEscalation
      - Security/CapabilitiesNotDropped
    """
    if not auto_fix_categories or not provider_ops:
        return final_ops

    allowed_map = allowed_paths_for_categories(auto_fix_categories)
    categories_fixed, categories_unfixed = categorize_ops_against_categories(
        final_ops, auto_fix_categories
    )

    security_targets = {
        "Auth/RunAsRoot",
        "Security/AllowPrivilegeEscalation",
        "Security/CapabilitiesNotDropped",
        "Security/PrivilegedContainer",
    }

    # Only bother with security categories that are still uncovered
    uncovered_security = [c for c in categories_unfixed if c in security_targets]
    if not uncovered_security:
        return final_ops

    # Build quick index to avoid duplicate paths
    existing_paths = {
        op.get("path")
        for op in final_ops
        if isinstance(op.get("path"), str)
    }

    # Same provider priority as vote_merge
    provider_priority = ["openrouter", "groq", "gemini", "ollama"]

    for cat in uncovered_security:
        patterns = allowed_map.get(cat, [])
        if not patterns:
            continue

        for prov in provider_priority:
            # Find ops from this provider
            ops_for_provider = [
                ops for (name, ops) in provider_ops if name == prov
            ]
            if not ops_for_provider:
                continue
            ops = ops_for_provider[0]

            picked = False
            for op in ops:
                path = op.get("path", "")
                if not isinstance(path, str):
                    continue
                if path in existing_paths:
                    continue

                # Must match allowed path for this category
                if not any(ptr_matches(pat, path) for pat in patterns):
                    continue

                # Must be a monotonic-hardening op for that category
                if not is_safe_security_op(cat, op):
                    continue

                final_ops.append(op)
                existing_paths.add(path)
                picked = True
                break  # One safe op is enough to mark category as covered

            if picked:
                break  # Stop searching other providers for this category

    return final_ops


# --------- Local deterministic fallback for common raw categories ----------


def _fallback_ops_for_missing_selector(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Deterministic fix for Deployments missing spec.selector.

    Strategy:
    - Only for kind=Deployment, apps/v1-style.
    - If spec.selector is missing:
        * If template.metadata.labels exists and non-empty:
            -> set spec.selector.matchLabels = template.metadata.labels
        * Else:
            -> synthesize a label based on metadata.name (or 'app')
               and set BOTH:
                  - spec.template.metadata.labels
                  - spec.selector.matchLabels
    """
    if not isinstance(doc, dict):
        return []

    if doc.get("kind") != "Deployment":
        return []
    spec = doc.get("spec")
    if not isinstance(spec, dict):
        return []

    # If selector already exists, nothing to do.
    if "selector" in spec:
        return []

    ops: List[Dict[str, Any]] = []

    tmpl = (spec.get("template") or {})
    tmeta = (tmpl.get("metadata") or {})
    tlabels = (tmeta.get("labels") or {})

    # Case 1: template already has labels → reuse them for selector
    if tlabels:
        ops.append(
            {
                "op": "add",
                "path": "/spec/selector",
                "value": {"matchLabels": tlabels},
            }
        )
        return ops

    # Case 2: no labels at all → synthesize one and apply in both places
    md = doc.get("metadata") or {}
    name = md.get("name") or "app"
    synth_labels = {"app": name}

    # Add labels to template.metadata.labels
    if "metadata" not in tmpl:
        # If there was no metadata at all, we need to add it
        ops.append(
            {
                "op": "add",
                "path": "/spec/template/metadata",
                "value": {"labels": synth_labels},
            }
        )
    else:
        # metadata exists but labels may not
        if not tlabels:
            ops.append(
                {
                    "op": "add",
                    "path": "/spec/template/metadata/labels",
                    "value": synth_labels,
                }
            )

    # Add selector.matchLabels using the same labels
    ops.append(
        {
            "op": "add",
            "path": "/spec/selector",
            "value": {"matchLabels": synth_labels},
        }
    )

    return ops


def local_fallback_ops(categories: List[str], docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Local deterministic fallbacks for common structural issues.

    Currently supports:
    - Missing selector in Deployments (either via explicit MISSING_SELECTOR
      category or via Schema/InvalidManifest when spec.selector is absent).
    """
    ops: List[Dict[str, Any]] = []
    cats = set([c for c in categories if c])
    if not docs:
        return ops

    d0 = docs[0]

    # Treat both MISSING_SELECTOR and Schema/InvalidManifest as candidates
    # for auto-fixing missing spec.selector on Deployments.
    if "MISSING_SELECTOR" in cats or "Schema/InvalidManifest" in cats:
        ops += _fallback_ops_for_missing_selector(d0)

    # You can extend here for other deterministic schema fixes if needed.
    return ops


# ---------------- Payload normalizer ----------------


def normalize_payload_to_files(
    payload: Dict[str, Any]
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Supports:
    - Classic SafeFix payload: {"context": {...}, "files": [...]}
    - SafeFix normalizer v3.x payload:
        {"context": {...}, "files":[{"file":..., "findings":[{category, ...}]}]}
    - Raw tool payloads (e.g., raw-kubescape):
        {"version": "...", "items":[...]} -> grouped by file.
    """
    context = payload.get("context") or {}
    meta = payload.get("metadata") or {}

    # If context missing, synthesize from raw payload metadata
    if not context:
        context = {
            "source_tool": meta.get("source_tool") or payload.get("version") or "unknown",
            "generated_at": payload.get("generated_at") or "",
            "raw_findings_count": meta.get("raw_findings_count") or 0,
            "note": "Auto-derived context from raw payload.",
        }

    # Case 1: already a SafeFix-style payload with files[]
    files = payload.get("files")
    if isinstance(files, list) and files:
        normalized_files: List[Dict[str, Any]] = []
        for fe in files:
            f_findings = []
            for fd in fe.get("findings", []):
                fd = dict(fd)  # shallow copy
                fd.setdefault("snippet", "")
                fd.setdefault("patchHint", "")
                f_findings.append(fd)
            normalized_files.append({"file": fe.get("file"), "findings": f_findings})
        return context, normalized_files

    # Case 2: raw tool payload with items[]
    items = payload.get("items") or []
    if not isinstance(items, list) or not items:
        return context, []

    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for it in items:
        file_rel = it.get("file") or it.get("filename") or "UNKNOWN_FILE"
        finding = {
            "category": it.get("category") or it.get("rule") or "UNKNOWN",
            "severity": it.get("severity"),
            "message": it.get("message") or it.get("description"),
            "resourceRef": {
                "kind": it.get("kind", ""),
                "name": it.get("name", ""),
                "namespace": it.get("namespace", "") or "default",
            },
            "raw": {
                "tools": it.get("tools"),
                "rule_ids": it.get("rule_ids"),
                "examples": it.get("examples"),
                "line": it.get("line"),
            },
            "snippet": it.get("snippet", ""),
            "patchHint": it.get("patchHint", ""),
        }
        by_file.setdefault(file_rel, []).append(finding)

    files_list = [{"file": f, "findings": v} for f, v in sorted(by_file.items())]
    return context, files_list


# ------------ File resolution helper (handles basename search) -------------


def resolve_yaml_path(tests_dir: Path, file_rel: str) -> Path:
    """
    Try tests_dir / file_rel first.
    If it doesn't exist, search by basename under tests_dir.
    This helps when different tools normalize paths differently.
    """
    p = tests_dir / file_rel
    if p.exists():
        return p
    base = Path(file_rel).name
    candidates = list(tests_dir.rglob(base))
    if candidates:
        return candidates[0]
    # Fallback: return the original (non-existing) path; caller will see empty content.
    return p


# ---------------- Prompt builder (uses snippet + patchHint) ----------------


def build_prompt(
    context: Dict[str, Any],
    file_entry: Dict[str, Any],
    original_text: str,
) -> str:
    file_rel = file_entry.get("file", "")
    findings = file_entry.get("findings") or []

    if findings:
        rr = findings[0].get("resourceRef") or {}
        kind = rr.get("kind", "")
        name = rr.get("name", "")
        ns = rr.get("namespace", "") or "default"
    else:
        kind = name = ""
        ns = "default"

    # Categories list
    raw_cats = sorted(set(f.get("category") for f in findings if f.get("category")))
    auto_fix_cats = [c for c in raw_cats if c not in NON_AUTO_FIX_CATEGORIES]
    non_auto_fix_cats = [c for c in raw_cats if c in NON_AUTO_FIX_CATEGORIES]

    categories_block = "- " + "\n- ".join(auto_fix_cats) if auto_fix_cats else "- (none)"
    non_auto_fix_block = (
        "- " + "\n- ".join(non_auto_fix_cats)
        if non_auto_fix_cats
        else "- (none; all categories are auto-fixable)"
    )

    # Allowed paths block (for the LLM)
    allowed_paths_map = allowed_paths_for_categories(auto_fix_cats)
    if allowed_paths_map:
        lines = []
        for c in sorted(allowed_paths_map.keys()):
            paths = allowed_paths_map[c] or []
            if not paths:
                continue
            lines.append(f"- {c}:")
            for pth in paths:
                lines.append(f"    - {pth}")
        allowed_paths_block = "\n".join(lines)
    else:
        allowed_paths_block = "- (no explicit allowed paths; you must be extremely conservative)."

    forbidden_paths_block = (
        "- " + "\n- ".join(sorted(FORBIDDEN_EXACT | FORBIDDEN_PREFIXES))
        + "\n- (and any path containing '/image' or '/spec/replicas' except imagePullPolicy)"
    )

    # Prefer per-finding snippet if present; else use file content
    finding_snippets = [
        f.get("snippet", "").strip()
        for f in findings
        if isinstance(f.get("snippet"), str) and f.get("snippet", "").strip()
    ]
    if finding_snippets:
        unique_snips: List[str] = []
        for s in finding_snippets:
            if s not in unique_snips:
                unique_snips.append(s)
            if sum(len(x) for x in unique_snips) > 2000:
                break
        snippet = "\n---\n".join(unique_snips)[:2500]
    else:
        snippet = first_yaml_snippet(original_text)

    docs = yaml_load_all(original_text)
    hints = derive_hints_from_yaml(docs)

    # Collect patch hints from payload (SafeFix v3.5 normalizer)
    patch_hints = [
        f.get("patchHint", "").strip()
        for f in findings
        if isinstance(f.get("patchHint"), str) and f.get("patchHint", "").strip()
    ]
    patch_hints_block = (
        "- " + "\n- ".join(sorted(set(patch_hints)))
        if patch_hints
        else "- (no explicit patch hints provided)."
    )

    special = derive_special_guidance(raw_cats, patch_hints)

    return USER_PROMPT_TEMPLATE.format(
        context=json.dumps(
            {
                **context,
                "kind": kind,
                "name": name,
                "namespace": ns,
            },
            ensure_ascii=False,
            indent=2,
        ),
        file=file_rel,
        yaml_snippet=snippet,
        derived_hints=hints,
        categories=categories_block,
        non_auto_fix_categories=non_auto_fix_block,
        allowed_paths_block=allowed_paths_block,
        forbidden_paths_block=forbidden_paths_block,
        patch_hints=patch_hints_block,
        special_guidance=special,
    )


# ------------------------------ Main -----------------------------


def main():
    ap = argparse.ArgumentParser(
        description="Vote across multiple LLMs to fix payload categories and write secured YAMLs."
    )
    ap.add_argument(
        "--payload",
        required=True,
        help="Path to output_llm_payload.json OR raw tool payload (e.g., raw-kubeconform).",
    )
    ap.add_argument(
        "--tests-dir",
        required=True,
        help="Directory containing original YAML files (as referenced in payload)",
    )
    ap.add_argument("--out-dir", default="output/llm_fixes", help="Output directory")
    ap.add_argument(
        "--or-model",
        default=os.environ.get("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
    )
    ap.add_argument(
        "--groq-model",
        default=os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant"),
    )
    ap.add_argument(
        "--gemini-model",
        default=os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"),
    )
    ap.add_argument(
        "--ollama-model",
        default=os.environ.get("OLLAMA_MODEL", "meta-llama/llama-3-8b"),
    )
    args = ap.parse_args()

    payload = read_json(Path(args.payload))
    context, files = normalize_payload_to_files(payload)

    tests_dir = Path(args.tests_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    rows: List[Tuple[str, str, str, int, int]] = []  # file, provider, status, ops_applied, ops_skipped

    for f in files:
        file_rel = f.get("file")
        findings = f.get("findings") or []
        if not file_rel or not findings:
            continue

        file_path = resolve_yaml_path(tests_dir, file_rel)
        original = read_text(file_path)
        prompt = build_prompt(context, f, original)

        provider_ops: List[Tuple[str, List[Dict[str, Any]]]] = []
        provider_errs: Dict[str, str] = {}

        # space calls slightly (helps with bursty 429s)
        if os.environ.get("OPENROUTER_API_KEY"):
            ops, err = call_openrouter(args.or_model, prompt)
            time.sleep(1.1)
            provider_ops.append(("openrouter", sanitize_ops(ops or [])))
            if err:
                provider_errs["openrouter"] = err
        if os.environ.get("GROQ_API_KEY"):
            ops, err = call_groq(args.groq_model, prompt)
            time.sleep(1.1)
            provider_ops.append(("groq", sanitize_ops(ops or [])))
            if err:
                provider_errs["groq"] = err
        if os.environ.get("GEMINI_API_KEY"):
            ops, err = call_gemini(args.gemini_model, prompt)
            time.sleep(1.1)
            provider_ops.append(("gemini", sanitize_ops(ops or [])))
            if err:
                provider_errs["gemini"] = err
        if os.environ.get("OLLAMA_BASE_URL"):
            ops, err = call_ollama(args.ollama_model, prompt)
            time.sleep(1.1)
            provider_ops.append(("ollama", sanitize_ops(ops or [])))
            if err:
                provider_errs["ollama"] = err

        have_any = any(len(ops) > 0 for _, ops in provider_ops)
        merged: List[Dict[str, Any]] = []

        cats = sorted(set(ff.get("category") for ff in findings if ff.get("category")))
        auto_fix_cats = [c for c in cats if c not in NON_AUTO_FIX_CATEGORIES]
        non_auto_fix_cats = [c for c in cats if c in NON_AUTO_FIX_CATEGORIES]

        if have_any:
            # 1) Start with consensus (vote) ops
            merged = vote_merge(provider_ops)
        else:
            # 2) If no providers produced ops at all, try structural local fallback
            merged = local_fallback_ops(auto_fix_cats, yaml_load_all(original))

        # 3) For certain “safe” categories (resources / probes / seccomp),
        #    also allow single-provider ops on whitelisted paths.
        extra_safe_ops = category_aware_single_provider_fallback(provider_ops, auto_fix_cats)
        if extra_safe_ops:
            existing_keys = {json.dumps(o, sort_keys=True) for o in merged}
            for op in extra_safe_ops:
                key = json.dumps(op, sort_keys=True)
                if key not in existing_keys:
                    merged.append(op)
                    existing_keys.add(key)

        # 4) Security-aware fallback for uncovered security categories
        merged = augment_with_security_fixes(
            auto_fix_categories=auto_fix_cats,
            provider_ops=provider_ops,
            final_ops=merged,
        )

        # 5) Schema fallback: ensure spec.selector exists for Deployments
        #    when Schema/InvalidManifest is present but no /spec/selector patch is present.
        if "Schema/InvalidManifest" in auto_fix_cats:
            docs_for_fallback = yaml_load_all(original)
            if docs_for_fallback:
                has_selector_op = any(
                    isinstance(o.get("path"), str) and o["path"] == "/spec/selector"
                    for o in merged
                )
                if not has_selector_op:
                    selector_ops = local_fallback_ops(
                        ["Schema/InvalidManifest"],
                        docs_for_fallback,
                    )
                    if selector_ops:
                        existing_keys = {json.dumps(o, sort_keys=True) for o in merged}
                        for op in selector_ops:
                            key = json.dumps(op, sort_keys=True)
                            if key not in existing_keys:
                                merged.append(op)
                                existing_keys.add(key)

        applied: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        fixed = ""

        if merged:
            docs = yaml_load_all(original) if original else []
            if docs:
                # assign to likely target doc (first workload / podspec)
                def target_doc_index(path: str) -> int:
                    if re.search(r"/(spec|template)/", path):
                        for i, d in enumerate(docs):
                            if get_pod_spec(d):
                                return i
                    return 0

                for op in merged:
                    try:
                        idx = target_doc_index(op.get("path", ""))
                        docs[idx] = apply_json_patch(docs[idx], [op])
                        applied.append(op)
                    except Exception as e:
                        skipped.append({"op": op, "reason": f"apply error: {e}"})
                fixed = yaml_dump_all(docs)
            else:
                skipped = [
                    {"op": op, "reason": "original YAML not parseable"} for op in merged
                ]

        safe = file_rel.replace("\\", "_").replace("/", "_").replace("..", "")
        secured_path = out_dir / f"SECURED_{safe}"
        diff_path = out_dir / f"DIFF_{safe}.diff"
        report_path = out_dir / f"REPORT_{safe}.json"

        if fixed:
            write_text(secured_path, fixed)
            write_text(
                diff_path,
                unified_diff_text(
                    original,
                    fixed,
                    str(Path(args.tests_dir) / file_rel),
                    str(secured_path),
                ),
            )

        # Track per-provider summary
        for prov, ops in provider_ops:
            rows.append(
                (
                    file_rel,
                    prov,
                    "ok" if ops else "empty",
                    len(ops),
                    0,
                )
            )

        reason = None
        if not have_any and not merged:
            reason = "No provider produced valid JSON Patch ops (and no local fallback applicable)."
        elif not have_any and merged:
            reason = "Providers empty; used local deterministic fallback."

        # Compute per-category fix stats based on op paths
        categories_fixed, categories_unfixed = categorize_ops_against_categories(
            applied,
            auto_fix_cats,
        )

        summary = {
            "file": file_rel,
            # categories present in payload (ground truth)
            "categories_present": cats,
            # categories we ALLOW auto-fixing via LLM
            "categories_auto_fix": auto_fix_cats,
            # categories intentionally not auto-fixed (still vulnerable)
            "non_auto_fix_categories": non_auto_fix_cats,
            "providers": [{"name": n, "ops": ops} for n, ops in provider_ops],
            "provider_errors": provider_errs,
            "applied_ops_count": len(applied),
            "skipped_ops_count": len(skipped),
            "auto_fix_stats": {
                "auto_fix_count": len(auto_fix_cats),
                "categories_fixed": categories_fixed,
                "categories_unfixed": categories_unfixed,
            },
            "reason": reason,
            "notes": [
                "Prompt included YAML snippet (prefer payload snippets) and derived hints to increase JSON compliance.",
                "Ties resolved by provider priority: openrouter > groq > gemini > ollama.",
                "Local fallback currently covers MISSING_SELECTOR (Deployment).",
                "Understands SafeFix normalizer v3.5 payload (snippet + patchHint).",
                "Category-aware fallback may apply resources/probes/seccompProfile from a single strong provider on safe paths.",
                "Security-aware fallback may apply monotonic-hardening securityContext ops (runAsNonRoot, privileged=false, allowPrivilegeEscalation=false, capabilities.drop=[ALL]) on allowed paths when consensus is missing.",
                (
                    "The following categories were intentionally NOT auto-fixed; they remain vulnerable and "
                    "require manual/cluster-specific handling: "
                    + (", ".join(non_auto_fix_cats) if non_auto_fix_cats else "none")
                ),
            ],
        }
        write_text(report_path, json.dumps(summary, indent=2))

    csv_lines = ["file,provider,status,ops_applied,ops_skipped"]
    for file_rel, prov, status, a, s in rows:
        csv_lines.append(",".join([file_rel.replace(",", ";"), prov, status, str(a), str(s)]))
    write_text(out_dir / "REPORT_ALL.csv", "\n".join(csv_lines))

    print(f"[OK] Wrote secured files, diffs and reports to: {out_dir}")


# ---------------- Raw single-file runner (still available) ----------------


def run_llm_on_raw_file(raw_path: Path, tests_dir: Path, out_dir: Path):
    raw = read_json(raw_path)
    context, files = normalize_payload_to_files(raw)
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    for idx, fe in enumerate(files):
        file_rel = fe.get("file") or f"RAW_{idx}.yaml"
        file_path = resolve_yaml_path(Path(tests_dir), file_rel)
        original = read_text(file_path)
        prompt = build_prompt(
            context,
            {"file": file_rel, "findings": fe.get("findings") or []},
            original,
        )

        provider_ops: List[Tuple[str, List[Dict[str, Any]]]] = []
        provider_errs: Dict[str, str] = {}

        if os.environ.get("OPENROUTER_API_KEY"):
            ops, err = call_openrouter(
                os.environ.get("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
                prompt,
            )
            time.sleep(1.1)
            provider_ops.append(("openrouter", sanitize_ops(ops or [])))
            if err:
                provider_errs["openrouter"] = err
        if os.environ.get("GROQ_API_KEY"):
            ops, err = call_groq(
                os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant"), prompt
            )
            time.sleep(1.1)
            provider_ops.append(("groq", sanitize_ops(ops or [])))
            if err:
                provider_errs["groq"] = err
        if os.environ.get("GEMINI_API_KEY"):
            ops, err = call_gemini(
                os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"),
                prompt,
            )
            time.sleep(1.1)
            provider_ops.append(("gemini", sanitize_ops(ops or [])))
            if err:
                provider_errs["gemini"] = err
        if os.environ.get("OLLAMA_BASE_URL"):
            ops, err = call_ollama(
                os.environ.get("OLLAMA_MODEL", "meta-llama/llama-3-8b"),
                prompt,
            )
            time.sleep(1.1)
            provider_ops.append(("ollama", sanitize_ops(ops or [])))
            if err:
                provider_errs["ollama"] = err

        cats = sorted(
            set(ff.get("category") for ff in (fe.get("findings") or []) if ff.get("category"))
        )
        auto_fix_cats = [c for c in cats if c not in NON_AUTO_FIX_CATEGORIES]
        non_auto_fix_cats = [c for c in cats if c in NON_AUTO_FIX_CATEGORIES]

        if any(len(ops) > 0 for _, ops in provider_ops):
            merged = vote_merge(provider_ops)
        else:
            merged = local_fallback_ops(auto_fix_cats, yaml_load_all(original))

        extra_safe_ops = category_aware_single_provider_fallback(provider_ops, auto_fix_cats)
        if extra_safe_ops:
            existing_keys = {json.dumps(o, sort_keys=True) for o in merged}
            for op in extra_safe_ops:
                key = json.dumps(op, sort_keys=True)
                if key not in existing_keys:
                    merged.append(op)
                    existing_keys.add(key)

        # Security-aware fallback in raw runner as well
        merged = augment_with_security_fixes(
            auto_fix_categories=auto_fix_cats,
            provider_ops=provider_ops,
            final_ops=merged,
        )

        # Schema fallback: ensure spec.selector exists for Deployments
        if "Schema/InvalidManifest" in auto_fix_cats:
            docs_for_fallback = yaml_load_all(original)
            if docs_for_fallback:
                has_selector_op = any(
                    isinstance(o.get("path"), str) and o["path"] == "/spec/selector"
                    for o in merged
                )
                if not has_selector_op:
                    selector_ops = local_fallback_ops(
                        ["Schema/InvalidManifest"],
                        docs_for_fallback,
                    )
                    if selector_ops:
                        existing_keys = {json.dumps(o, sort_keys=True) for o in merged}
                        for op in selector_ops:
                            key = json.dumps(op, sort_keys=True)
                            if key not in existing_keys:
                                merged.append(op)
                                existing_keys.add(key)

        applied, skipped = [], []
        docs = yaml_load_all(original) if original else []
        if docs and merged:
            def target_doc_index(path: str) -> int:
                if re.search(r"/(spec|template)/", path):
                    for i, d in enumerate(docs):
                        if get_pod_spec(d):
                            return i
                return 0

            for op in merged:
                try:
                    idx = target_doc_index(op.get("path", ""))
                    docs[idx] = apply_json_patch(docs[idx], [op])
                    applied.append(op)
                except Exception as e:
                    skipped.append({"op": op, "reason": f"apply error: {e}"})
        fixed = yaml_dump_all(docs) if docs else ""

        categories_fixed, categories_unfixed = categorize_ops_against_categories(
            applied,
            auto_fix_cats,
        )

        sanitized_file = file_rel.replace("\\", "_").replace("/", "_").replace("..", "")
        safe = f"RAW_{idx}_{sanitized_file}"
        secured_path = out_dir / f"SECURED_{safe}"
        diff_path = out_dir / f"DIFF_{safe}.diff"
        report_path = out_dir / f"REPORT_{safe}.json"
        if fixed:
            write_text(secured_path, fixed)
            write_text(diff_path, unified_diff_text(original, fixed, str(file_path), str(secured_path)))
        write_text(
            report_path,
            json.dumps(
                {
                    "file": file_rel,
                    "categories_present": cats,
                    "categories_auto_fix": auto_fix_cats,
                    "non_auto_fix_categories": non_auto_fix_cats,
                    "providers": [{"name": n, "ops": ops} for n, ops in provider_ops],
                    "provider_errors": provider_errs,
                    "applied_ops_count": len(applied),
                    "skipped_ops_count": len(skipped),
                    "auto_fix_stats": {
                        "auto_fix_count": len(auto_fix_cats),
                        "categories_fixed": categories_fixed,
                        "categories_unfixed": categories_unfixed,
                    },
                    "notes": [
                        "Processed via raw runner with YAML context and tolerant JSON extraction.",
                        "Understands SafeFix normalizer payload fields (snippet + patchHint) if present.",
                        "Category-aware fallback may apply resources/probes/seccompProfile from a single strong provider on safe paths.",
                        "Security-aware fallback may apply monotonic-hardening securityContext ops (runAsNonRoot, privileged=false, allowPrivilegeEscalation=false, capabilities.drop=[ALL]) on allowed paths when consensus is missing.",
                        (
                            "The following categories were intentionally NOT auto-fixed; they remain vulnerable and "
                            "require manual/cluster-specific handling: "
                            + (", ".join(non_auto_fix_cats) if non_auto_fix_cats else "none")
                        ),
                    ],
                },
                indent=2,
            ),
        )


if __name__ == "__main__":
    main()
