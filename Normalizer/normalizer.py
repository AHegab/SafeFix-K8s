#!/usr/bin/env python3
"""
SafeFix-K8s Normalizer (v3.5, Raw-Only + High-Recall + No-Drop)

Goals
-----
1) Use ONLY evidence coming from raw detector outputs (no YAML atomic sweep).
2) High recall: every meaningful detector finding should become a normalized
   category, so the LLM sees *all* issues (within the priority band).
3) Never drop a mapped finding just because its category is unfamiliar:
   - If we can't map -> Misc/Unmapped.
   - If category not in registry -> auto-registered with default severity/priority.
4) Still provide severity/priority/status metadata so you can reason about FPs
   later, but payload shaping is recall-first (no pre-filtering by status).
"""

import argparse, base64, csv, json, re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml

# ---------------------- Registry / Priorities ----------------------

PRIORITY = ("CRITICAL", "HIGH", "MEDIUM", "LOW")  # order matters

# IMPORTANT: CRITICAL/HIGH are deployment-safety essentials
CATEGORY_META: Dict[str, Dict[str, Any]] = {
    # SCHEMA
    "Schema/InvalidManifest":            {"severity": "HIGH",   "priority": "HIGH"},
    # Security Context
    "Security/PrivilegedContainer":      {"severity": "HIGH",   "priority": "CRITICAL"},
    "Security/AllowPrivilegeEscalation": {"severity": "HIGH",   "priority": "HIGH"},
    "Security/CapabilitiesNotDropped":   {"severity": "MEDIUM", "priority": "HIGH"},
    "Security/HostPathMount":           {"severity": "HIGH",   "priority": "CRITICAL"},
    "Volume/DockerSocketMounted":       {
        "severity": "HIGH",
        "priority": "CRITICAL",
        "normalized_to": "Security/HostPathMount",
    },
    # RBAC
    "RBAC/WildcardVerbsOrResources":     {
        "severity": "HIGH",
        "priority": "HIGH",
        "strong_tools": {"rbacpolice"},
    },
    "RBAC/BindClusterAdmin":             {
        "severity": "HIGH",
        "priority": "HIGH",
        "strong_tools": {"rbacpolice"},
    },
    # Network
    "Network/MissingNetworkPolicy":      {"severity": "MEDIUM", "priority": "MEDIUM"},
    # Image / API
    "Image/TagNotPinned":                {"severity": "LOW",    "priority": "LOW"},
    "Image/DeprecatedAPI":               {
        "severity": "HIGH",
        "priority": "HIGH",
        "strong_tools": {"pluto"},
    },
    # Resources / Probes
    "Resources/MissingRequests":         {"severity": "MEDIUM", "priority": "HIGH"},
    "Resources/MissingLimits":           {"severity": "MEDIUM", "priority": "HIGH"},
    "Probes/MissingReadinessLiveness":   {"severity": "MEDIUM", "priority": "HIGH"},
    # Auth
    "Auth/RunAsRoot":                    {"severity": "MEDIUM", "priority": "HIGH"},
    # Secrets
    "Secrets/Hardcoded":                 {
        "severity": "HIGH",
        "priority": "HIGH",
        "strong_tools": {"gitleaks", "conftest"},
    },
    # PSS baseline / policy roll-up
    "Policy/PodSecurityViolation":       {"severity": "HIGH",   "priority": "HIGH"},
    # Style
    "Style/YamlLint":                    {
        "severity": "LOW",
        "priority": "LOW",
        "strong_tools": {"yamllint"},
    },
    # Catch-all for anything we can't classify precisely
    "Misc/Unmapped": {
        "severity": "MEDIUM",
        "priority": "LOW",  # still included when payload-min-priority=LOW
    },
}

# Simple tool weight hints for scoring (status metadata only)
WEIGHTS: Dict[str, Dict[str, float]] = {
    "Schema/InvalidManifest":            {"kubeconform": 1.0, "kubescape": 0.2, "conftest": 0.2, "kubeLinter": 0.2, "polaris": 0.1},
    "Security/PrivilegedContainer":      {"kubeaudit": 0.7, "trivy": 0.6, "polaris": 0.5, "kubescore": 0.3, "kubeLinter": 0.3, "kubescape": 0.3, "conftest": 0.2, "checkov": 0.5},
    "Security/AllowPrivilegeEscalation": {"kubeaudit": 0.7, "trivy": 0.6, "polaris": 0.5, "kubescore": 0.3, "kubeLinter": 0.3, "kubescape": 0.3, "conftest": 0.2, "checkov": 0.6},
    "Security/CapabilitiesNotDropped":   {"kubeaudit": 0.7, "trivy": 0.5, "kubescore": 0.4, "kubeLinter": 0.4, "polaris": 0.3, "kubescape": 0.2, "checkov": 0.4},
    "Security/HostPathMount":           {"kubeaudit": 0.7, "trivy": 0.6, "polaris": 0.5, "kubescore": 0.3, "kubescape": 0.3, "conftest": 0.2, "checkov": 0.4},
    "RBAC/WildcardVerbsOrResources":     {"rbacpolice": 1.0, "kubescape": 0.3, "conftest": 0.2},
    "RBAC/BindClusterAdmin":             {"rbacpolice": 1.0, "kubescape": 0.3, "conftest": 0.2},
    "Network/MissingNetworkPolicy":      {"kubescore": 0.6, "polaris": 0.6, "kubescape": 0.5, "kubeLinter": 0.3, "conftest": 0.2},
    "Image/TagNotPinned":                {"trivy": 0.5, "kubescore": 0.4, "kubeLinter": 0.4, "polaris": 0.3, "checkov": 0.4},
    "Image/DeprecatedAPI":               {"pluto": 1.0, "kubeconform": 0.4},
    "Resources/MissingRequests":         {"trivy": 0.4, "kubescore": 0.5, "polaris": 0.4, "kubeLinter": 0.4, "checkov": 0.4},
    "Resources/MissingLimits":           {"trivy": 0.4, "kubescore": 0.5, "polaris": 0.4, "kubeLinter": 0.4, "checkov": 0.4},
    "Probes/MissingReadinessLiveness":   {"kubescore": 0.5, "polaris": 0.5, "kubeLinter": 0.4, "checkov": 0.4},
    "Auth/RunAsRoot":                    {"kubeaudit": 0.6, "trivy": 0.5, "polaris": 0.4, "kubescore": 0.3, "kubeLinter": 0.3, "kubescape": 0.3, "checkov": 0.4},
    "Secrets/Hardcoded":                 {"gitleaks": 1.0, "conftest": 0.6, "kubescore": 0.2, "polaris": 0.2, "checkov": 0.5},
    "Policy/PodSecurityViolation":       {"kubescape": 0.7, "conftest": 0.6, "kubeaudit": 0.5, "trivy": 0.5, "polaris": 0.4, "checkov": 0.4},
    "Style/YamlLint":                    {"yamllint": 1.0},
}

KNOWN_TOOLS = [
    "gitleaks", "kubeaudit", "kubeconform", "kubeLinter", "kubescape", "kubescore", "polaris",
    "rbacpolice", "trivy", "yamllint", "pluto", "conftest", "checkov",
    "kube-linter", "kube-score",
]

# ---------------------- Patterns (mapping) ----------------------
# These are intentionally broad for high recall.
PATTERNS: Dict[str, List[str]] = {
    "Schema/InvalidManifest": [
        r"\bschema\b",
        r"invalid.*\b(schema|manifest)\b",
        r"missing (apiVersion|kind)\b",
        r"\bunknown field\b",
        r"failed to validate",
        r"invalid (type|value)",
    ],

    "Security/PrivilegedContainer": [
        r"privileged\s*:\s*true",
        r"\bprivileged container\b",
    ],

    "Security/AllowPrivilegeEscalation": [
        r"allowPrivilegeEscalation\s*:\s*true",
        r"\bCKV_K8S_20\b",
    ],

    "Security/CapabilitiesNotDropped": [
        r"capabilit(?:y|ies).*?(NET_ADMIN|SYS_ADMIN|NET_RAW|ALL)",
        r"add:\s*\[.*\bALL\b.*\]",
        r"\b(no|missing)\b.*\bdrop\b.*\bcapabilit",
        r"Minimize the admission of containers with (the )?NET_RAW capability",
        r"Minimize the admission of containers with capabilities assigned",
    ],

    "Security/HostPathMount": [
        r"\bhostPath\b",
        r"hostNetwork\s*:\s*true",
        r"hostPID\s*:\s*true",
        r"hostIPC\s*:\s*true",
    ],

    "Volume/DockerSocketMounted": [
        r"docker\.sock",
        r"containerd\.sock",
    ],

    "RBAC/WildcardVerbsOrResources": [
        r"verbs\s*:\s*\[.*\*.*\]",
        r"resources\s*:\s*\[.*\*.*\]",
        r"\bcluster-admin\b",
        r"\bsystem:masters\b",
    ],

    "RBAC/BindClusterAdmin": [
        r"\bClusterRoleBinding\b.*\bcluster-admin\b",
    ],

    "Network/MissingNetworkPolicy": [
        r"\bno networkpolic",
        r"lack an associated NetworkPolicy",
        r"Minimize the admission of pods which lack an associated NetworkPolicy",
    ],

    "Image/TagNotPinned": [
        r"image:\s*\S*:(latest|dev)\b",
        r"\bnot pinned\b",
        r"\bno digest\b",
        r"\bfloating tag\b",
        r"Image should use digest",
    ],

    "Image/DeprecatedAPI": [
        r"\bdeprecated api\b",
        r"apiVersion:\s*(apps/v1beta|extensions/v1beta|batch/v1beta)",
    ],

    "Resources/MissingRequests": [
        r"\bno (cpu|memory) request",
        r"(cpu|memory) requests? should be set",
        r"requests? (are|is) not set",
    ],

    "Resources/MissingLimits": [
        r"\bno (cpu|memory) limit",
        r"(cpu|memory) limits? should be set",
        r"limits? (are|is) not set",
    ],

    "Probes/MissingReadinessLiveness": [
        r"\bno liveness probe\b",
        r"\bno readiness probe\b",
        r"Liveness Probe Should be Configured",
        r"Readiness Probe Should be Configured",
        r"HEALTH_PROBES",
    ],

    "Auth/RunAsRoot": [
        r"runAsUser\s*:\s*0",
        r"\bruns?\s+as\s+root\b",
        r"Minimize the admission of root containers",
        r"RootContainers",
    ],

    "Policy/PodSecurityViolation": [
        r"\bpod security\b",
        r"\bpss\b",
        r"restricted.*policy",
        r"seccompProfile.*unconfined",
        r"Seccomp profile is missing",
        r"Seccomp profile should be added",
        r"Service Account Tokens are only mounted where necessary",
        r"Ensure that Service Account Tokens are only mounted where necessary",
        r"Default service account with token mounted",
        r"AppArmor annotation missing",
        r"Security Context not set",
        r"runAsNonRoot should be set to true",
    ],

    "Style/YamlLint": [
        r"trailing spaces",
        r"line too long",
        r"wrong indentation",
        r"missing document start",
    ],
}

# Secret FP gates
SECRET_PLACEHOLDER_RE = re.compile(
    r"(?i)(example|sample|test|dummy|placeholder|changeme|password123|your[-_ ]?token|xxxx+|abc123|lorem)"
)
SECRET_COMMENT_RE = re.compile(r"(?i)#\s*(api|secret|token|password)")
SECRET_KIND_RE = re.compile(r"\bkind:\s*Secret\b", re.I)
SECRET_DATA_LINE_RE = re.compile(r'^\s*[A-Za-z0-9_.-]+\s*:\s*("?)([^"\n]+)\1\s*$', re.M)


def _is_base64_like(s: str) -> bool:
    s = s.strip()
    if len(s) < 8:
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def _entropy(s: str) -> float:
    from math import log2

    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((cnt / n) * log2(cnt / n) for cnt in freq.values())


def _likely_secret_val(v: str) -> bool:
    return _entropy(v) >= 3.0 and not SECRET_PLACEHOLDER_RE.search(v)

# ---------------------- IO helpers / Anchoring ----------------------


def guess_tool_from_path(p: Path) -> Optional[str]:
    low = p.name.lower()
    for t in KNOWN_TOOLS:
        if t in low:
            return t.replace("kube-linter", "kubeLinter").replace("kube-score", "kubescore")
    for part in p.parts:
        pl = part.lower()
        for t in KNOWN_TOOLS:
            if t in pl:
                return t.replace("kube-linter", "kubeLinter").replace("kube-score", "kubescore")
    return None


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        try:
            return path.read_bytes().decode("utf-8", "ignore")
        except Exception:
            return ""


def _tail_after_tests(path_like: str) -> Optional[str]:
    if not isinstance(path_like, str) or not path_like.strip():
        return None
    norm = path_like.replace("\\", "/")
    if "tests/" in norm:
        return norm.split("tests/", 1)[-1]
    for cut in ("/scan/", "/workspace/", "/workdir/", "/project/", "/src/", "/out/", "/opt/work/"):
        if cut in norm:
            norm = norm.split(cut, 1)[-1]
            break
    if norm.startswith("/") or (":" in norm[:5]):
        try:
            return Path(norm).name
        except Exception:
            return norm.strip("/")
    return norm


def load_manifests(root: Path):
    """
    Only used to:
    - record file_text for snippets
    - build manifests_index for (kind, name) -> file anchoring
    """
    index: Dict[str, List[Dict[str, Any]]] = {}
    file_text: Dict[str, str] = {}
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}:
            rel = str(p.relative_to(root))
            txt = read_text(p)
            file_text[rel] = txt
            try:
                for doc in yaml.safe_load_all(txt):
                    if not isinstance(doc, dict) or not doc:
                        continue
                    md = doc.get("metadata") or {}
                    index.setdefault(rel, []).append(
                        {
                            "kind": str(doc.get("kind") or ""),
                            "apiVersion": str(doc.get("apiVersion") or ""),
                            "name": str(md.get("name") or ""),
                            "namespace": str(md.get("namespace") or "default"),
                            "raw": doc,
                        }
                    )
            except Exception:
                pass
    return index, file_text


def parse_detector_file(p: Path) -> List[Dict[str, Any]]:
    tool = guess_tool_from_path(p) or "unknown"
    b = p.read_bytes()
    t = b.decode("utf-8", "ignore")
    out: List[Dict[str, Any]] = []
    parsed = None

    try:
        parsed = json.loads(t)
    except Exception:
        try:
            lst = list(yaml.safe_load_all(t))
            parsed = lst if len(lst) != 1 else lst[0]
        except Exception:
            parsed = None

    # SPECIAL CASE: Checkov – one record per failed_check
    if isinstance(parsed, dict) and tool == "checkov" \
       and isinstance(parsed.get("results"), dict) \
       and isinstance(parsed["results"].get("failed_checks"), list):

        for fc in parsed["results"]["failed_checks"]:
            fc_text = json.dumps(fc, ensure_ascii=False)
            out.append({
                "tool": tool,
                "path": str(p),
                "raw": fc,
                "text": fc_text,
            })
        return out

    # Generic handling
    if isinstance(parsed, list):
        for item in parsed:
            out.append({"tool": tool, "path": str(p), "raw": item, "text": t})
    elif isinstance(parsed, dict):
        out.append({"tool": tool, "path": str(p), "raw": parsed, "text": t})
    else:
        out.append({"tool": tool, "path": str(p), "raw": None, "text": t})

    return out


_FILENAME_FIELD_CANDIDATES = (
    "repo_file_path",
    "file_path",
    "filename",
    "file",
    "manifest",
    "path",
    "filesPath",
)


def _pluck(*ds, keys: Tuple[str, ...]) -> Optional[str]:
    for d in ds:
        if not isinstance(d, dict):
            continue
        for k in keys:
            v = d.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return None


def _search_filename_in_text(txt: str) -> Optional[str]:
    for key in ("filename", "file_path", "repo_file_path", "manifest", "file", "path", "filesPath"):
        m = re.search(rf'"{key}"\s*:\s*"(.*?)"', txt)
        if m and m.group(1).strip():
            return m.group(1).strip()
    return None


def derive_resource_ref(raw: Optional[dict], text: str) -> Dict[str, Any]:
    ref = {"file": None, "kind": None, "name": None, "namespace": None}
    if isinstance(raw, dict):
        f = _pluck(raw, raw.get("metadata") or {}, raw.get("resource") or {}, keys=_FILENAME_FIELD_CANDIDATES)
        if not f:
            f = _search_filename_in_text(text or "")
        if f:
            tail = _tail_after_tests(f)
            ref["file"] = tail or f.replace("\\", "/")
        md = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
        if md:
            ref["kind"] = ref["kind"] or md.get("kind")
            ref["name"] = ref["name"] or md.get("name")
            ref["namespace"] = ref["namespace"] or md.get("namespace")
        for k in ("resource", "resourceRef", "object", "obj"):
            obj = raw.get(k)
            if isinstance(obj, dict):
                ref["kind"] = ref["kind"] or obj.get("kind")
                ref["name"] = ref["name"] or obj.get("name")
                ref["namespace"] = ref["namespace"] or obj.get("namespace")
        ref["kind"] = ref["kind"] or raw.get("kind")
        ref["name"] = ref["name"] or raw.get("name")
        ref["namespace"] = ref["namespace"] or raw.get("namespace")
        # Checkov compact form: "resource": "Deployment.default.nginx"
        if not ref["kind"] or not ref["name"]:
            res_s = str(raw.get("resource") or raw.get("resource_address") or "")
            m = re.search(r"([A-Za-z]+)\.[\w-]*\.([A-Za-z0-9._-]+)", res_s)
            if m:
                ref["kind"] = ref["kind"] or m.group(1)
                ref["name"] = ref["name"] or m.group(2)

    low = text or ""
    m = re.search(r"kind:\s*([A-Za-z0-9]+)", low)
    ref["kind"] = ref["kind"] or (m.group(1) if m else None)
    m = re.search(r"metadata:\s*.*?\bname:\s*([A-Za-z0-9._-]+)", low, re.S)
    ref["name"] = ref["name"] or (m.group(1) if m else None)
    m = re.search(r"\bnamespace:\s*([A-Za-z0-9._-]+)", low)
    ref["namespace"] = ref["namespace"] or (m.group(1) if m else None)
    return ref


def anchor_to_manifest(ref: Dict[str, Any], manifests_index: Dict[str, List[Dict[str, Any]]], tests_root: Path) -> Dict[str, Any]:
    """
    Try to anchor a finding to a real manifest under tests_root.
    If file path cannot be resolved AND we can't match by (kind, name),
    we mark file as UNKNOWN_FILE so it can be skipped later.
    """
    file_candidate = ref.get("file")

    # 1) Try by file path / basename
    if file_candidate:
        p = tests_root / file_candidate
        if p.exists():
            ref["file"] = str(p.relative_to(tests_root))
            return ref
        base = Path(file_candidate).name
        for cand in tests_root.rglob(base):
            ref["file"] = str(cand.relative_to(tests_root))
            return ref
        # we couldn't anchor by file path; clear it
        ref["file"] = None

    # 2) Try by (kind, name)
    k, n = ref.get("kind"), ref.get("name")
    if k and n:
        for f, docs in manifests_index.items():
            for d in docs:
                if d["kind"] == k and d["name"] == n:
                    ref["file"] = f
                    ref["namespace"] = ref.get("namespace") or d.get("namespace")
                    return ref

    # 3) If still not anchored, mark as UNKNOWN_FILE
    if not ref.get("file"):
        ref["file"] = "UNKNOWN_FILE"
    return ref

# ---------------------- Secret FP gate ----------------------


def secret_fp_gate(snippet: str, tools: Set[str]) -> Tuple[bool, str]:
    # Secret object with mostly base64 data? Probably fine.
    if SECRET_KIND_RE.search(snippet):
        vals = [m.group(2) for m in SECRET_DATA_LINE_RE.finditer(snippet)]
        if vals:
            b64ish = sum(1 for v in vals if _is_base64_like(v))
            if b64ish >= max(1, int(0.6 * len(vals))):
                return False, "Secret.data mostly base64-encoded"
    # Placeholder-style / comments-only
    if SECRET_PLACEHOLDER_RE.search(snippet) or SECRET_COMMENT_RE.search(snippet):
        return False, "Placeholder/comment"
    # Strong tools (gitleaks/conftest) are trusted
    if {"gitleaks", "conftest"} & tools:
        return True, "Secret corroborated by focused tool"
    # High-entropy value following a secret-like key
    for line in snippet.splitlines():
        if re.search(r"(?i)\b(password|secret|token|api[_-]?key)\s*:", line):
            val = line.split(":", 1)[-1].strip().strip('"')
            if _likely_secret_val(val):
                return True, "High-entropy secret-like value"
    return False, "No corroboration; likely FP"

# ---------------------- Mapping / Scoring ----------------------


def map_to_category(text: str, raw: Optional[dict], tool: str) -> Optional[str]:
    """
    High-recall mapping from raw detector output to canonical category.
    1) Special-case certain IDs.
    2) Regex patterns (PATTERNS).
    3) Fallback heuristics on keywords for common issues.
    """
    hay = (text or "") + " " + (json.dumps(raw, ensure_ascii=False) if isinstance(raw, dict) else "")
    low = hay.lower()

    # Special-case for well-known IDs
    if "ckv_k8s_20" in low:
        return "Security/AllowPrivilegeEscalation"

    # Pattern-based mapping
    for cat, regexes in PATTERNS.items():
        for pat in regexes:
            if re.search(pat, low, flags=re.IGNORECASE):
                alias = CATEGORY_META.get(cat, {}).get("normalized_to")
                return alias or cat

    # Pluto: deprecated API wording
    if tool == "pluto" and "deprecated" in low:
        return "Image/DeprecatedAPI"

    # --------- Fallback heuristics (recall-first) ---------
    # NetworkPolicy
    if "networkpolicy" in low and ("missing" in low or "no " in low or "must be covered" in low):
        return "Network/MissingNetworkPolicy"

    # Floating tag / tag not pinned
    if ("floating tag" in low or "tag not pinned" in low or "tag is not pinned" in low or
        ("image tag" in low and "latest" in low) or (":latest" in low and "image" in low)):
        return "Image/TagNotPinned"

    # Resource limits / requests
    if "resource limits" in low or "no limits" in low or "no cpu limits" in low or "no memory limits" in low:
        return "Resources/MissingLimits"
    if "resource requests" in low or "no requests" in low or "no cpu requests" in low or "no memory requests" in low:
        return "Resources/MissingRequests"

    # Probes
    if "liveness" in low or "readiness" in low:
        if "no " in low or "missing" in low or "not configured" in low:
            return "Probes/MissingReadinessLiveness"

    # Privileged / APE
    if "privileged" in low:
        return "Security/PrivilegedContainer"
    if "allowprivilegeescalation" in low:
        return "Security/AllowPrivilegeEscalation"

    # Run as root
    if "run as root" in low or "running as root" in low or "uid 0" in low:
        return "Auth/RunAsRoot"

    # HostPath / host* / docker.sock
    if "hostpath" in low or "hostnetwork" in low or "hostpid" in low or "hostipc" in low or "docker.sock" in low or "containerd.sock" in low:
        return "Security/HostPathMount"

    # Secrets / hardcoded credentials
    if any(k in low for k in ["password", "secret", "token", "apikey", "api key"]) and any(
        w in low for w in ["hardcoded", "plain", "plaintext", "in environment variable", "in env var", "embedded", "leak"]
    ):
        return "Secrets/Hardcoded"
    if tool in {"gitleaks"} and any(k in low for k in ["password", "secret", "token", "apikey", "api key"]):
        return "Secrets/Hardcoded"

    # PodSecurity / PSS
    if "pod security" in low or "podsecurity" in low or "pss" in low:
        return "Policy/PodSecurityViolation"

    # If still nothing, let caller treat as Misc/Unmapped
    return None


def bucket_key(ref: Dict[str, Any], category: str) -> Tuple[str, str, str, str, str]:
    return (
        ref.get("file") or "UNKNOWN_FILE",
        ref.get("kind") or "",
        ref.get("name") or "",
        ref.get("namespace") or "",
        category,
    )


def patch_hint(category: str) -> str:
    H = {
        "Security/PrivilegedContainer": "Set securityContext.privileged=false; also set allowPrivilegeEscalation=false; runAsNonRoot=true.",
        "Security/AllowPrivilegeEscalation": "Set securityContext.allowPrivilegeEscalation=false; ensure runAsNonRoot=true.",
        "Security/CapabilitiesNotDropped": "Add securityContext.capabilities.drop: ['ALL']; remove dangerous capAdd.",
        "Security/HostPathMount": "Remove hostPath/host*; use PVC/projected volumes; avoid docker/containerd sockets.",
        "RBAC/WildcardVerbsOrResources": "Replace '*' with minimal verbs/resources; avoid cluster-admin; scope to namespace.",
        "RBAC/BindClusterAdmin": "Replace cluster-admin with least-privilege Role/ClusterRole.",
        "Network/MissingNetworkPolicy": "Add default-deny NetworkPolicy and explicit allows.",
        "Image/TagNotPinned": "Pin to digest or fixed tag; avoid :latest; set IfNotPresent.",
        "Image/DeprecatedAPI": "Migrate apiVersion to a supported level (e.g., networking.k8s.io/v1).",
        "Resources/MissingRequests": "Add cpu/memory requests per container.",
        "Resources/MissingLimits": "Add cpu/memory limits per container.",
        "Probes/MissingReadinessLiveness": "Add readiness+liveness probes.",
        "Auth/RunAsRoot": "Set runAsNonRoot: true (and runAsUser to a non-zero UID).",
        "Secrets/Hardcoded": "Move inline secrets to a Secret and mount via envFrom/volume; avoid literals in manifests.",
        "Schema/InvalidManifest": "Fix schema/unknown fields according to the Kubernetes API for the target version.",
        "Style/YamlLint": "Fix formatting only (indentation, trailing spaces, etc.); no behavioral changes.",
        "Policy/PodSecurityViolation": "Adopt Pod Security Standards (restricted); set seccompProfile: RuntimeDefault, runAsNonRoot, drop caps, etc.",
        "Misc/Unmapped": "Carefully inspect this detector message and make the minimal safe change while preserving workload behavior.",
    }
    return H.get(category, "Apply minimal, schema-compliant, least-privilege changes.")


def llm_context() -> Dict[str, Any]:
    return {
        "goal": "Generate minimal JSON Patches that preserve workload behavior while fixing the findings.",
        "guardrails": [
            "Conform to kubeconform schema for the target cluster version.",
            "Meet Pod Security Standards (baseline/restricted) where applicable.",
            "Prefer least-privilege & immutable image refs; avoid hostPath/hostNetwork.",
            "Do not remove required fields (metadata.name/selectors/ports/args/command).",
            "Keep probes/resources sensible; avoid extreme limits.",
        ],
    }

# ---------------------- Normalization core ----------------------


def normalize(args):
    tests_root = Path(args.tests_dir)
    raw_root = Path(args.raw_dir)

    manifests_index, file_text = load_manifests(tests_root)

    # Parse raw detector outputs
    raw_findings: List[Dict[str, Any]] = []
    for p in raw_root.rglob("*"):
        if p.is_file():
            raw_findings.extend(parse_detector_file(p))

    # First pass: map raw findings into preliminary buckets
    prelim: List[Dict[str, Any]] = []
    for f in raw_findings:
        tool = f["tool"]
        txt = f.get("text", "")
        raw = f.get("raw")
        cat = map_to_category(txt, raw, tool)

        # If we couldn't map it, keep it but mark as generic.
        if not cat:
            cat = "Misc/Unmapped"

        # If it's some new category string we haven't put in CATEGORY_META yet,
        # give it a default severity/priority so it still flows through.
        if cat not in CATEGORY_META:
            CATEGORY_META.setdefault(cat, {
                "severity": "MEDIUM",
                "priority": "LOW",
            })

        # derive & anchor
        ref = derive_resource_ref(raw, txt)
        ref = anchor_to_manifest(ref, manifests_index, tests_root)

        # snippet (for context; does not influence mapping)
        file_rel = ref.get("file") or ""
        snippet_source = file_text.get(file_rel) or txt
        snippet = "\n".join(snippet_source.splitlines()[:120])

        prelim.append(
            {
                "tool": tool,
                "category": cat,
                "ref": ref,
                "snippet": snippet,
                "raw": raw,
                "text": txt,
            }
        )

    # Aggregate into buckets per (file, kind, name, namespace, category)
    buckets: Dict[Tuple[str, str, str, str, str], Dict[str, Any]] = {}
    for r in prelim:
        cat = r["category"]
        key = bucket_key(r["ref"], cat)
        if key not in buckets:
            buckets[key] = {
                "file": key[0],
                "kind": key[1],
                "name": key[2],
                "namespace": key[3],
                "category": cat,
                "severity": CATEGORY_META[cat]["severity"],
                "priority": CATEGORY_META[cat]["priority"],
                "tools": set(),
                "score": 0.0,
                "snippet": r["snippet"],
                "examples": [],
                "provenance": "tools",
            }
        b = buckets[key]
        tool = r["tool"]
        b["tools"].add(tool)
        b["examples"].append(r["raw"] if r["raw"] is not None else {"text": r["text"][:2000]})
        b["score"] += float(WEIGHTS.get(cat, {}).get(tool, 0.0))

    refined: Dict[Tuple[str, str, str, str, str], Dict[str, Any]] = {
        k: {
            **v,
            "tools": set(v["tools"]),
            "examples": list(v["examples"]),
        }
        for k, v in buckets.items()
    }

    # Post-process / status decision with gates (for metadata only)
    nonatomic_consensus = max(1, int(args.nonatomic_consensus))
    min_priority_idx = PRIORITY.index(args.payload_min_priority)

    normalized: List[Dict[str, Any]] = []
    for key, b in refined.items():
        # Skip findings that could not be anchored to a real test manifest
        if not b.get("file") or b["file"] == "UNKNOWN_FILE":
            continue

        cat = b["category"]
        meta = CATEGORY_META[cat]
        tools = set(b["tools"])
        score = b["score"]
        prov = b.get("provenance", "tools")
        priority = meta["priority"]

        # Decide status (Actual / NeedsCorroboration) – used for analysis only
        if cat == "Secrets/Hardcoded":
            ok, why = secret_fp_gate(b["snippet"], tools)
            status = "Actual" if ok else "NeedsCorroboration"
            reason = f"secrets-gate={why} | tools={sorted(tools)}"
        else:
            strong = set(meta.get("strong_tools", set())) & tools
            if strong:
                status = "Actual"
                reason = f"strong-tool={sorted(strong)}"
            else:
                if priority in ("LOW", "MEDIUM"):
                    status = "Actual" if (len(tools) >= nonatomic_consensus or score >= 0.9) else "NeedsCorroboration"
                else:
                    status = "Actual" if score >= 0.6 or len(tools) >= 1 else "NeedsCorroboration"
                reason = f"consensus={len(tools)} score={score:.2f}"

        normalized.append(
            {
                "file": b["file"],
                "category": cat,
                "severity": meta["severity"],
                "priority": priority,
                "status": status,
                "score": round(score, 3),
                "tools": sorted(tools),
                "resourceRef": {
                    "file": b["file"],
                    "kind": b["kind"],
                    "name": b["name"],
                    "namespace": b["namespace"],
                },
                "snippet": b["snippet"],
                "examples": b["examples"],
                "provenance": prov,
                "decisionReason": reason,
            }
        )

    # LLM payload shaping: recall-first
    # Include ALL findings (regardless of status) whose priority is at or above min_priority.
    def priority_idx(p: str) -> int:
        return PRIORITY.index(p)

    payload_candidates = [
        f for f in normalized if priority_idx(f["priority"]) <= min_priority_idx
    ]

    # sort by (priority, severity, category) to push deployment-critical first
    def sort_key(f):
        return (
            priority_idx(f["priority"]),
            {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f["severity"], 1),
            f["category"],
        )

    payload_candidates.sort(key=sort_key)

    llm_files: Dict[str, Any] = {}
    for fnd in payload_candidates:
        file_rel = fnd["file"]
        F = llm_files.setdefault(file_rel, {"file": file_rel, "findings": []})
        F["findings"].append(
            {
                "category": fnd["category"],
                "severity": fnd["severity"],
                "priority": fnd["priority"],
                "resourceRef": fnd["resourceRef"],
                "snippet": fnd["snippet"],
                "tools": fnd["tools"],
                "score": fnd["score"],
                "patchHint": patch_hint(fnd["category"]),
            }
        )

    # Write outputs
    Path(args.out_normalized).write_text(
        json.dumps(normalized, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    Path(args.out_llm_payload).write_text(
        json.dumps({"context": llm_context(), "files": list(llm_files.values())}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    if args.out_buckets_csv:
        with open(args.out_buckets_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(
                [
                    "file",
                    "kind",
                    "name",
                    "namespace",
                    "category",
                    "severity",
                    "priority",
                    "status",
                    "score",
                    "tools",
                    "provenance",
                    "reason",
                ]
            )
            for b in normalized:
                w.writerow(
                    [
                        b["file"],
                        b["resourceRef"]["kind"],
                        b["resourceRef"]["name"],
                        b["resourceRef"]["namespace"],
                        b["category"],
                        b["severity"],
                        b["priority"],
                        b["status"],
                        b["score"],
                        ";".join(b["tools"]),
                        b.get("provenance", "tools"),
                        b["decisionReason"],
                    ]
                )

    actual = sum(1 for x in normalized if x["status"] == "Actual")
    pending = sum(1 for x in normalized if x["status"] != "Actual")
    print(f"Wrote normalized findings -> {args.out_normalized}")
    print(f"Wrote LLM payload        -> {args.out_llm_payload}")
    if args.out_buckets_csv:
        print(f"Wrote weighted buckets   -> {args.out_buckets_csv}")
    print(f"Actual={actual} | NeedsCorroboration={pending} | Total={len(normalized)}")


# --------------------------- CLI ---------------------------


def main():
    ap = argparse.ArgumentParser(
        description="SafeFix-K8s priority-driven normalizer (raw-only, high-recall mapping, no YAML atomic sweep, no-drop for categories)"
    )
    ap.add_argument("--raw-dir", required=True)
    ap.add_argument("--tests-dir", required=True)
    ap.add_argument("--out-normalized", required=True)
    ap.add_argument("--out-llm-payload", required=True)
    ap.add_argument("--out-buckets-csv", default="")
    ap.add_argument(
        "--payload-min-priority",
        default="LOW",
        choices=list(PRIORITY),
        help="Only include findings at or above this priority in the payload (default LOW = include all).",
    )
    ap.add_argument(
        "--nonatomic-consensus",
        dest="nonatomic_consensus",
        type=int,
        default=2,
        help="For LOW/MEDIUM findings, number of tools needed to mark status=Actual (metadata only, default 2).",
    )
    args = ap.parse_args()
    normalize(args)


if __name__ == "__main__":
    main()
