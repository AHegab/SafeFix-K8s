#!/usr/bin/env python3
"""
SafeFix-K8s Normalizer (v3.2, Priority-Driven + FP Gates)

Goals
-----
1) Produce a payload that *always* contains the critical, deployment-safety
   misconfigs when they exist in YAML (atomic sweep, no UNKNOWN_FILE).
2) Reduce false positives via stricter mapping, per-category gates, and
   consensus thresholds for lower-priority buckets.
3) Keep output deployability-focused: payload is sorted by severity/priority,
   and can be limited to only CRITICAL+HIGH via --payload-min-priority.

What’s new vs v3.1
------------------
- PRIORITY tiers (CRITICAL/HIGH/MEDIUM/LOW) with category-level weights.
- Atomic sweep hardened and expanded (still strictly evidence-based).
- Tool-consensus gates for LOW/MEDIUM unless atomic or strong tool.
- “Omission-to-policy” routing: omissions (e.g., APE/runAsNonRoot unset)
  are not flagged as specific categories to avoid FPs; they roll up under
  PodSecurity baseline (Policy/PodSecurityViolation) and are explained there.
- Path anchoring: more robust tail extraction; UNKNOWN_FILE is eliminated
  by doc sweep over tests dir.
- Payload shaping: optional --payload-min-priority (default=LOW) and
  --payload-strict (keep only Actual==true, default on).

CLI
---
python normalizer.py \
  --raw-dir ./Detection/output/detection/raw \
  --tests-dir ./tests \
  --out-normalized ./output_normalized.json \
  --out-llm-payload ./output_llm_payload.json \
  --out-buckets-csv ./buckets.csv \
  --payload-min-priority HIGH   # (optional; CRITICAL|HIGH|MEDIUM|LOW)
  --nonatomic-consensus 2       # tools needed for LOW/MED unless atomic/strong
"""

import argparse, base64, csv, json, re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml

# ---------------------- Registry / Priorities ----------------------

PRIORITY = ("CRITICAL","HIGH","MEDIUM","LOW")  # order matters

# IMPORTANT: CRITICAL/HIGH are deployment-safety essentials
CATEGORY_META: Dict[str, Dict[str, Any]] = {
    # SCHEMA
    "Schema/InvalidManifest":            {"severity":"HIGH",   "priority":"HIGH"},
    # Security Context
    "Security/PrivilegedContainer":      {"severity":"HIGH",   "priority":"CRITICAL"},
    "Security/AllowPrivilegeEscalation": {"severity":"HIGH",   "priority":"HIGH"},
    "Security/CapabilitiesNotDropped":   {"severity":"MEDIUM", "priority":"HIGH"},
    "Security/HostPathMount":            {"severity":"HIGH",   "priority":"CRITICAL"},
    "Volume/DockerSocketMounted":        {"severity":"HIGH",   "priority":"CRITICAL", "normalized_to":"Security/HostPathMount"},
    # RBAC
    "RBAC/WildcardVerbsOrResources":     {"severity":"HIGH",   "priority":"HIGH", "strong_tools":{"rbacpolice"}},
    "RBAC/BindClusterAdmin":             {"severity":"HIGH",   "priority":"HIGH", "strong_tools":{"rbacpolice"}},
    # Network
    "Network/MissingNetworkPolicy":      {"severity":"MEDIUM", "priority":"MEDIUM"},
    # Image / API
    "Image/TagNotPinned":                {"severity":"LOW",    "priority":"LOW"},
    "Image/DeprecatedAPI":               {"severity":"HIGH",   "priority":"HIGH", "strong_tools":{"pluto"}},
    # Resources / Probes
    "Resources/MissingRequests":         {"severity":"MEDIUM", "priority":"HIGH"},
    "Resources/MissingLimits":           {"severity":"MEDIUM", "priority":"HIGH"},
    "Probes/MissingReadinessLiveness":   {"severity":"MEDIUM", "priority":"HIGH"},
    # Auth
    "Auth/RunAsRoot":                    {"severity":"MEDIUM", "priority":"HIGH"},
    # Secrets
    "Secrets/Hardcoded":                 {"severity":"HIGH",   "priority":"HIGH", "strong_tools":{"gitleaks","conftest"}},
    # PSS baseline / policy roll-up
    "Policy/PodSecurityViolation":       {"severity":"HIGH",   "priority":"HIGH"},
    # Style
    "Style/YamlLint":                    {"severity":"LOW",    "priority":"LOW", "strong_tools":{"yamllint"}},
}

# Simple tool weight hints for non-atomic scoring (not used for atomic promotion)
WEIGHTS: Dict[str, Dict[str, float]] = {
    "Schema/InvalidManifest":            {"kubeconform":1.0,"kubescape":0.2,"conftest":0.2,"kubeLinter":0.2,"polaris":0.1},
    "Security/PrivilegedContainer":      {"kubeaudit":0.7,"trivy":0.6,"polaris":0.5,"kubescore":0.3,"kubeLinter":0.3,"kubescape":0.3,"conftest":0.2,"checkov":0.5},
    "Security/AllowPrivilegeEscalation": {"kubeaudit":0.7,"trivy":0.6,"polaris":0.5,"kubescore":0.3,"kubeLinter":0.3,"kubescape":0.3,"conftest":0.2,"checkov":0.6},
    "Security/CapabilitiesNotDropped":   {"kubeaudit":0.7,"trivy":0.5,"kubescore":0.4,"kubeLinter":0.4,"polaris":0.3,"kubescape":0.2,"checkov":0.4},
    "Security/HostPathMount":            {"kubeaudit":0.7,"trivy":0.6,"polaris":0.5,"kubescore":0.3,"kubescape":0.3,"conftest":0.2,"checkov":0.4},
    "RBAC/WildcardVerbsOrResources":     {"rbacpolice":1.0,"kubescape":0.3,"conftest":0.2},
    "RBAC/BindClusterAdmin":             {"rbacpolice":1.0,"kubescape":0.3,"conftest":0.2},
    "Network/MissingNetworkPolicy":      {"kubescore":0.6,"polaris":0.6,"kubescape":0.5,"kubeLinter":0.3,"conftest":0.2},
    "Image/TagNotPinned":                {"trivy":0.5,"kubescore":0.4,"kubeLinter":0.4,"polaris":0.3,"checkov":0.4},
    "Image/DeprecatedAPI":               {"pluto":1.0,"kubeconform":0.4},
    "Resources/MissingRequests":         {"trivy":0.4,"kubescore":0.5,"polaris":0.4,"kubeLinter":0.4,"checkov":0.4},
    "Resources/MissingLimits":           {"trivy":0.4,"kubescore":0.5,"polaris":0.4,"kubeLinter":0.4,"checkov":0.4},
    "Probes/MissingReadinessLiveness":   {"kubescore":0.5,"polaris":0.5,"kubeLinter":0.4,"checkov":0.4},
    "Auth/RunAsRoot":                    {"kubeaudit":0.6,"trivy":0.5,"polaris":0.4,"kubescore":0.3,"kubeLinter":0.3,"kubescape":0.3,"checkov":0.4},
    "Secrets/Hardcoded":                 {"gitleaks":1.0,"conftest":0.6,"kubescore":0.2,"polaris":0.2,"checkov":0.5},
    "Policy/PodSecurityViolation":       {"kubescape":0.7,"conftest":0.6,"kubeaudit":0.5,"trivy":0.5,"polaris":0.4,"checkov":0.4},
    "Style/YamlLint":                    {"yamllint":1.0},
}

KNOWN_TOOLS = [
    "gitleaks","kubeaudit","kubeconform","kubeLinter","kubescape","kubescore","polaris",
    "rbacpolice","trivy","yamllint","pluto","conftest","checkov",
    "kube-linter","kube-score"
]

# ---------------------- Patterns (mapping) ----------------------

PATTERNS: Dict[str, List[str]] = {
    "Schema/InvalidManifest":            [r"\bschema\b", r"invalid.*\b(schema|manifest)\b", r"missing (apiVersion|kind)\b",
                                         r"\bunknown field\b", r"failed to validate", r"invalid (type|value)"],
    "Security/PrivilegedContainer":      [r"privileged\s*:\s*true", r"\bprivileged container\b"],
    "Security/AllowPrivilegeEscalation": [r"allowPrivilegeEscalation\s*:\s*true", r"\bCKV_K8S_20\b"],
    "Security/CapabilitiesNotDropped":   [r"capabilit(?:y|ies).*?(NET_ADMIN|SYS_ADMIN|ALL)", r"add:\s*\[.*\bALL\b.*\]", r"\b(no|missing)\b.*\bdrop\b.*\bcapabilit"],
    "Security/HostPathMount":            [r"\bhostPath\b", r"hostNetwork\s*:\s*true", r"hostPID\s*:\s*true", r"hostIPC\s*:\s*true"],
    "Volume/DockerSocketMounted":        [r"docker\.sock", r"containerd\.sock"],
    "RBAC/WildcardVerbsOrResources":     [r"verbs\s*:\s*\[.*\*.*\]", r"resources\s*:\s*\[.*\*.*\]", r"\bcluster-admin\b", r"\bsystem:masters\b"],
    "RBAC/BindClusterAdmin":             [r"\bClusterRoleBinding\b.*\bcluster-admin\b"],
    "Network/MissingNetworkPolicy":      [r"\bNetworkPolicy\b", r"no networkpolic"],
    "Image/TagNotPinned":                [r"image:\s*\S*:(latest|dev)\b", r"\bnot pinned\b", r"\bno digest\b", r"\bfloating tag\b"],
    "Image/DeprecatedAPI":               [r"\bdeprecated api\b", r"apiVersion:\s*(apps/v1beta|extensions/v1beta|batch/v1beta)"],
    "Resources/MissingRequests":         [r"\bno (cpu|memory) request"],
    "Resources/MissingLimits":           [r"\bno (cpu|memory) limit"],
    "Probes/MissingReadinessLiveness":   [r"\bno liveness probe\b", r"\bno readiness probe\b"],
    "Auth/RunAsRoot":                    [r"runAsUser\s*:\s*0", r"\bruns?\s+as\s+root\b"],
    "Policy/PodSecurityViolation":       [r"\bpod security\b", r"\bpss\b", r"restricted.*policy", r"seccompProfile.*unconfined"],
    "Style/YamlLint":                    [r"trailing spaces", r"line too long", r"wrong indentation", r"missing document start"],
}

# Secret FP gates
SECRET_PLACEHOLDER_RE = re.compile(r"(?i)(example|sample|test|dummy|placeholder|changeme|password123|your[-_ ]?token|xxxx+|abc123|lorem)")
SECRET_COMMENT_RE     = re.compile(r"(?i)#\s*(api|secret|token|password)")
SECRET_KIND_RE        = re.compile(r"\bkind:\s*Secret\b", re.I)
SECRET_DATA_LINE_RE   = re.compile(r'^\s*[A-Za-z0-9_.-]+\s*:\s*("?)([^"\n]+)\1\s*$', re.M)

def _is_base64_like(s: str) -> bool:
    s = s.strip()
    if len(s) < 8: return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

def _entropy(s: str) -> float:
    from math import log2
    if not s: return 0.0
    freq: Dict[str,int] = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((cnt/n)*log2(cnt/n) for cnt in freq.values())

def _likely_secret_val(v: str) -> bool:
    return _entropy(v) >= 3.0 and not SECRET_PLACEHOLDER_RE.search(v)

# ---------------------- IO helpers / Anchoring ----------------------

def guess_tool_from_path(p: Path) -> Optional[str]:
    low = p.name.lower()
    for t in KNOWN_TOOLS:
        if t in low:
            return t.replace("kube-linter","kubeLinter").replace("kube-score","kubescore")
    for part in p.parts:
        pl = part.lower()
        for t in KNOWN_TOOLS:
            if t in pl:
                return t.replace("kube-linter","kubeLinter").replace("kube-score","kubescore")
    return None

def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        try: return path.read_bytes().decode("utf-8","ignore")
        except Exception: return ""

def _tail_after_tests(path_like: str) -> Optional[str]:
    if not isinstance(path_like, str) or not path_like.strip():
        return None
    norm = path_like.replace("\\","/")
    if "tests/" in norm:
        return norm.split("tests/", 1)[-1]
    for cut in ("/scan/","/workspace/","/workdir/","/project/","/src/","/out/","/opt/work/"):
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
    index: Dict[str, List[Dict[str,Any]]] = {}
    file_text: Dict[str, str] = {}
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".yml",".yaml"}:
            rel = str(p.relative_to(root))
            txt = read_text(p)
            file_text[rel] = txt
            try:
                for doc in yaml.safe_load_all(txt):
                    if not isinstance(doc, dict) or not doc: continue
                    md = doc.get("metadata") or {}
                    index.setdefault(rel, []).append({
                        "kind": str(doc.get("kind") or ""),
                        "apiVersion": str(doc.get("apiVersion") or ""),
                        "name": str(md.get("name") or ""),
                        "namespace": str(md.get("namespace") or "default"),
                        "raw": doc
                    })
            except Exception:
                pass
    return index, file_text

def parse_detector_file(p: Path) -> List[Dict[str,Any]]:
    tool = guess_tool_from_path(p) or "unknown"
    b = p.read_bytes()
    t = b.decode("utf-8","ignore")
    out: List[Dict[str,Any]] = []
    parsed = None
    try:
        parsed = json.loads(t)
    except Exception:
        try:
            lst = list(yaml.safe_load_all(t))
            parsed = lst if len(lst)!=1 else lst[0]
        except Exception:
            parsed = None
    if isinstance(parsed, list):
        for item in parsed: out.append({"tool":tool,"path":str(p),"raw":item,"text":t})
    elif isinstance(parsed, dict):
        out.append({"tool":tool,"path":str(p),"raw":parsed,"text":t})
    else:
        out.append({"tool":tool,"path":str(p),"raw":None,"text":t})
    return out

_FILENAME_FIELD_CANDIDATES = ("repo_file_path","file_path","filename","file","manifest","path","filesPath")

def _pluck(*ds, keys: Tuple[str,...]) -> Optional[str]:
    for d in ds:
        if not isinstance(d, dict): continue
        for k in keys:
            v = d.get(k)
            if isinstance(v, str) and v.strip(): return v.strip()
    return None

def _search_filename_in_text(txt: str) -> Optional[str]:
    for key in ("filename","file_path","repo_file_path","manifest","file","path","filesPath"):
        m = re.search(rf'"{key}"\s*:\s*"(.*?)"', txt)
        if m and m.group(1).strip():
            return m.group(1).strip()
    return None

def derive_resource_ref(raw: Optional[dict], text: str) -> Dict[str,Any]:
    ref = {"file":None,"kind":None,"name":None,"namespace":None}
    if isinstance(raw, dict):
        f = _pluck(raw, raw.get("metadata") or {}, raw.get("resource") or {}, keys=_FILENAME_FIELD_CANDIDATES)
        if not f:
            f = _search_filename_in_text(text or "")
        if f:
            tail = _tail_after_tests(f)
            ref["file"] = tail or f.replace("\\","/")
        md = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
        if md:
            ref["kind"] = ref["kind"] or md.get("kind")
            ref["name"] = ref["name"] or md.get("name")
            ref["namespace"] = ref["namespace"] or md.get("namespace")
        for k in ("resource","resourceRef","object","obj"):
            obj = raw.get(k)
            if isinstance(obj, dict):
                ref["kind"] = ref["kind"] or obj.get("kind")
                ref["name"] = ref["name"] or obj.get("name")
                ref["namespace"] = ref["namespace"] or obj.get("namespace")
        ref["kind"]      = ref["kind"] or raw.get("kind")
        ref["name"]      = ref["name"] or raw.get("name")
        ref["namespace"] = ref["namespace"] or raw.get("namespace")
        # Checkov compact form: "resource": "Deployment.default.nginx"
        if not ref["kind"] or not ref["name"]:
            res_s = str(raw.get("resource") or raw.get("resource_address") or "")
            m = re.search(r'([A-Za-z]+)\.[\w-]*\.([A-Za-z0-9._-]+)', res_s)
            if m:
                ref["kind"] = ref["kind"] or m.group(1)
                ref["name"] = ref["name"] or m.group(2)

    low = text or ""
    m = re.search(r'kind:\s*([A-Za-z0-9]+)', low);                        ref["kind"] = ref["kind"] or (m.group(1) if m else None)
    m = re.search(r'metadata:\s*.*?\bname:\s*([A-Za-z0-9._-]+)', low, re.S); ref["name"] = ref["name"] or (m.group(1) if m else None)
    m = re.search(r'\bnamespace:\s*([A-Za-z0-9._-]+)', low);              ref["namespace"] = ref["namespace"] or (m.group(1) if m else None)
    return ref

def anchor_to_manifest(ref: Dict[str,Any], manifests_index: Dict[str, List[Dict[str,Any]]], tests_root: Path) -> Dict[str,Any]:
    if ref.get("file"):
        p = tests_root / ref["file"]
        if p.exists():
            ref["file"] = str(p.relative_to(tests_root))
            return ref
        base = Path(ref["file"]).name
        for cand in tests_root.rglob(base):
            ref["file"] = str(cand.relative_to(tests_root))
            return ref
    k, n = ref.get("kind"), ref.get("name")
    if k and n:
        for f, docs in manifests_index.items():
            for d in docs:
                if d["kind"] == k and d["name"] == n:
                    ref["file"] = f
                    ref["namespace"] = ref.get("namespace") or d.get("namespace")
                    return ref
    if not ref.get("file"): ref["file"] = "UNKNOWN_FILE"
    return ref

# ---------------------- Atomic scanning (evidence) ----------------------

DANGEROUS_CAPS = {"SYS_ADMIN","NET_ADMIN","SYS_MODULE","NET_RAW"}

def _pod_spec(doc: Dict) -> Optional[Dict]:
    if not isinstance(doc, dict): return None
    spec = doc.get("spec")
    if not isinstance(spec, dict): return None
    if doc.get("kind") == "Pod": return spec
    tmpl = spec.get("template")
    if isinstance(tmpl, dict) and isinstance(tmpl.get("spec"), dict): return tmpl["spec"]
    return None

def _containers(ps: Dict) -> List[Dict]:
    res: List[Dict] = []
    for key in ("initContainers","containers"):
        arr = ps.get(key) or []
        for c in arr:
            if isinstance(c, dict): res.append(c)
    return res

def detect_atomics(doc: Dict) -> Tuple[Set[str], List[str]]:
    out: Set[str] = set()
    reasons: List[str] = []
    if not isinstance(doc, dict): return out, reasons
    ps = _pod_spec(doc)
    if not ps: return out, reasons

    # host* and hostPath
    for k in ("hostNetwork","hostPID","hostIPC"):
        if ps.get(k) is True:
            out.add("Security/HostPathMount"); reasons.append(f"{k}=true")
    for v in ps.get("volumes") or []:
        if not isinstance(v, dict): continue
        if "hostPath" in v:
            out.add("Security/HostPathMount"); reasons.append("volumes[].hostPath present")
            hp = v.get("hostPath") or {}
            p = hp.get("path") if isinstance(hp, dict) else None
            if isinstance(p, str) and (("docker.sock" in p) or ("containerd.sock" in p)):
                out.add("Volume/DockerSocketMounted"); reasons.append(f"socket mount: {p}")

    # containers
    for c in _containers(ps):
        name = c.get("name") or "<container>"
        sc = c.get("securityContext") or {}
        if sc.get("privileged") is True:
            out.add("Security/PrivilegedContainer"); reasons.append(f"{name}: privileged=true")
        if sc.get("allowPrivilegeEscalation") is True:
            out.add("Security/AllowPrivilegeEscalation"); reasons.append(f"{name}: APE=true")
        ra = sc.get("runAsUser")
        if isinstance(ra, int) and ra == 0:
            out.add("Auth/RunAsRoot"); reasons.append(f"{name}: runAsUser=0")
        if sc.get("runAsNonRoot") is False:
            out.add("Auth/RunAsRoot"); reasons.append(f"{name}: runAsNonRoot=false")

        caps = sc.get("capabilities") or {}
        drops = {str(x).upper() for x in (caps.get("drop") or [])}
        adds  = {str(x).upper() for x in (caps.get("add")  or [])}
        if "ALL" not in drops or (adds & DANGEROUS_CAPS):
            out.add("Security/CapabilitiesNotDropped"); reasons.append(f"{name}: drop={list(drops)} add={list(adds)}")

        res = c.get("resources") or {}
        reqs = res.get("requests") if isinstance(res.get("requests"), dict) else {}
        lims = res.get("limits")   if isinstance(res.get("limits"), dict)   else {}
        if not reqs: out.add("Resources/MissingRequests"); reasons.append(f"{name}: requests missing")
        if not lims: out.add("Resources/MissingLimits");   reasons.append(f"{name}: limits missing")

        if not isinstance(c.get("livenessProbe"), dict) or not isinstance(c.get("readinessProbe"), dict):
            out.add("Probes/MissingReadinessLiveness"); reasons.append(f"{name}: probes missing")

        img = c.get("image")
        if isinstance(img, str):
            if "@sha256:" in img:
                pass
            elif ":" not in img or img.endswith(":latest"):
                out.add("Image/TagNotPinned"); reasons.append(f"{name}: image '{img}' not pinned")

    return out, reasons

# ---------------------- Secret FP gate ----------------------

def secret_fp_gate(snippet: str, tools: Set[str]) -> Tuple[bool,str]:
    if SECRET_KIND_RE.search(snippet):
        vals = [m.group(2) for m in SECRET_DATA_LINE_RE.finditer(snippet)]
        if vals:
            b64ish = sum(1 for v in vals if _is_base64_like(v))
            if b64ish >= max(1, int(0.6*len(vals))):
                return False, "Secret.data mostly base64-encoded"
    if SECRET_PLACEHOLDER_RE.search(snippet) or SECRET_COMMENT_RE.search(snippet):
        return False, "Placeholder/comment"
    if {"gitleaks","conftest"} & tools:
        return True, "Secret corroborated by focused tool"
    for line in snippet.splitlines():
        if re.search(r"(?i)\b(password|secret|token|api[_-]?key)\s*:", line):
            val = line.split(":",1)[-1].strip().strip('"')
            if _likely_secret_val(val):
                return True, "High-entropy secret-like value"
    return False, "No corroboration; likely FP"

# ---------------------- Mapping / Scoring ----------------------

def map_to_category(text: str, raw: Optional[dict], tool: str) -> Optional[str]:
    hay = (text or "") + " " + (json.dumps(raw, ensure_ascii=False) if isinstance(raw, dict) else "")
    low = hay.lower()
    if "ckv_k8s_20" in low:
        return "Security/AllowPrivilegeEscalation"
    for cat, regexes in PATTERNS.items():
        for pat in regexes:
            if re.search(pat, low):
                alias = CATEGORY_META.get(cat, {}).get("normalized_to")
                return alias or cat
    if tool == "pluto" and "deprecated" in low:
        return "Image/DeprecatedAPI"
    return None

def bucket_key(ref: Dict[str,Any], category: str) -> Tuple[str,str,str,str,str]:
    return (ref.get("file") or "UNKNOWN_FILE", ref.get("kind") or "", ref.get("name") or "",
            ref.get("namespace") or "", category)

def patch_hint(category: str) -> str:
    H = {
        "Security/PrivilegedContainer":"Set securityContext.privileged=false; also set allowPrivilegeEscalation=false; runAsNonRoot=true.",
        "Security/AllowPrivilegeEscalation":"Set securityContext.allowPrivilegeEscalation=false; ensure runAsNonRoot=true.",
        "Security/CapabilitiesNotDropped":"Add securityContext.capabilities.drop: ['ALL']; remove dangerous capAdd.",
        "Security/HostPathMount":"Remove hostPath/host*; use PVC/projected volumes; avoid docker/containerd sockets.",
        "RBAC/WildcardVerbsOrResources":"Replace '*' with minimal verbs/resources; avoid cluster-admin; scope to namespace.",
        "RBAC/BindClusterAdmin":"Replace cluster-admin with least-privilege Role/ClusterRole.",
        "Network/MissingNetworkPolicy":"Add default-deny NetworkPolicy and explicit allows.",
        "Image/TagNotPinned":"Pin to digest or fixed tag; avoid :latest; set IfNotPresent.",
        "Image/DeprecatedAPI":"Migrate apiVersion to supported level.",
        "Resources/MissingRequests":"Add cpu/memory requests per container.",
        "Resources/MissingLimits":"Add cpu/memory limits per container.",
        "Probes/MissingReadinessLiveness":"Add readiness+liveness probes.",
        "Auth/RunAsRoot":"Set runAsNonRoot: true (and runAsUser non-zero).",
        "Secrets/Hardcoded":"Move inline secrets to Secret with valueFrom.",
        "Schema/InvalidManifest":"Fix schema/unknown fields.",
        "Style/YamlLint":"Formatting only.",
        "Policy/PodSecurityViolation":"Adopt PSS (RuntimeDefault, runAsNonRoot, automountServiceAccountToken=false)."
    }
    return H.get(category, "Apply minimal, schema-compliant, least-privilege changes.")

def llm_context() -> Dict[str,Any]:
    return {
        "goal":"Generate minimal JSON Patches that preserve workload behavior while fixing Actual findings.",
        "guardrails":[
            "Conform to kubeconform schema for the target cluster version.",
            "Meet Pod Security Standards (baseline/restricted) where applicable.",
            "Prefer least-privilege & immutable image refs; avoid hostPath/hostNetwork.",
            "Do not remove required fields (metadata.name/selectors/ports/args/command).",
            "Keep probes/resources sensible; avoid extreme limits."
        ]
    }

def _extract_doc(file_text: Dict[str,str], ref: Dict[str,str]) -> Optional[Dict[str,Any]]:
    rel = ref.get("file")
    if not rel or rel not in file_text: return None
    try:
        docs = list(yaml.safe_load_all(file_text[rel]))
    except yaml.YAMLError:
        return None
    if not docs: return None
    k = ref.get("kind") or ""; n = ref.get("name") or ""
    if k and n:
        for d in docs:
            if isinstance(d, dict) and d.get("kind")==k and (d.get("metadata") or {}).get("name")==n:
                return d
        for d in docs:
            if isinstance(d, dict) and d.get("kind")==k:
                return d
    for d in docs:
        if isinstance(d, dict): return d
    return None

# ---------------------- Normalization core ----------------------

def normalize(args):
    tests_root = Path(args.tests_dir)
    raw_root   = Path(args.raw_dir)

    manifests_index, file_text = load_manifests(tests_root)

    # Parse raw detector outputs
    raw_findings: List[Dict[str,Any]] = []
    for p in raw_root.rglob("*"):
        if p.is_file():
            raw_findings.extend(parse_detector_file(p))

    prelim: List[Dict[str,Any]] = []
    for f in raw_findings:
        tool = f["tool"]; txt = f.get("text",""); raw = f.get("raw")
        cat  = map_to_category(txt, raw, tool)
        if not cat or cat not in CATEGORY_META: continue

        # derive & anchor
        ref = derive_resource_ref(raw, txt)
        ref = anchor_to_manifest(ref, manifests_index, tests_root)

        # snippet
        file_rel = ref.get("file") or ""
        snippet = "\n".join((file_text.get(file_rel) or txt).splitlines()[:120])

        prelim.append({"tool":tool,"category":cat,"ref":ref,"snippet":snippet,"raw":raw,"text":txt})

    # aggregate buckets
    buckets: Dict[Tuple[str,str,str,str,str], Dict[str,Any]] = {}
    for r in prelim:
        cat = r["category"]
        key = bucket_key(r["ref"], cat)
        b = buckets.get(key)
        if not b:
            b = {
                "file": key[0], "kind": key[1], "name": key[2], "namespace": key[3],
                "category": cat,
                "severity": CATEGORY_META[cat]["severity"],
                "priority": CATEGORY_META[cat]["priority"],
                "tools": set(),
                "score": 0.0,
                "snippet": r["snippet"],
                "examples": [],
                "provenance": "tools"
            }
            buckets[key] = b
        tool = r["tool"]
        b["tools"].add(tool)
        b["examples"].append(r["raw"] if r["raw"] is not None else {"text": r["text"][:2000]})
        b["score"] += float(WEIGHTS.get(cat, {}).get(tool, 0.0))

    # keep originals for refinement
    refined: Dict[Tuple[str,str,str,str,str], Dict[str,Any]] = {k: {
        **v, "tools": set(v["tools"]), "examples": list(v["examples"])
    } for k, v in buckets.items()}

    # YAML atomic sweep across *all* YAML (eliminate UNKNOWN_FILE + ensure criticals)
    for file_rel, txt in file_text.items():
        try:
            docs = list(yaml.safe_load_all(txt))
        except yaml.YAMLError:
            continue
        if not docs: continue

        def approx_ref(d: Dict[str,Any]) -> Tuple[str,str,str]:
            k = str(d.get("kind") or "")
            md = d.get("metadata") or {}
            n = str(md.get("name") or "")
            ns = str(md.get("namespace") or "default")
            return k,n,ns

        for d in docs:
            if not isinstance(d, dict): continue
            atomics, reasons = detect_atomics(d)
            if not atomics: continue
            k,n,ns = approx_ref(d)
            base_snippet = "\n".join(txt.splitlines()[:120])

            for cat in atomics:
                meta = CATEGORY_META[cat]
                dst = (file_rel, k, n, ns, cat)
                if dst not in refined:
                    refined[dst] = {
                        "file": file_rel, "kind": k, "name": n, "namespace": ns,
                        "category": cat,
                        "severity": meta["severity"],
                        "priority": meta["priority"],
                        "tools": set(),          # no tools needed: atomic evidence
                        "score": 0.0,
                        "snippet": base_snippet,
                        "examples": [{"atomicReason": reasons}],
                        "provenance": "yaml-atomic"
                    }
                else:
                    refined[dst]["provenance"] = "yaml-atomic"
                    refined[dst]["examples"].append({"atomicReason": reasons})

    # post-process / status decision with consensus gates
    nonatomic_consensus = max(1, int(args.nonatoMic_consensus))  # default 2 via argparse
    min_priority_idx = PRIORITY.index(args.payload_min_priority)

    normalized: List[Dict[str,Any]] = []
    for key, b in refined.items():
        cat = b["category"]
        meta = CATEGORY_META[cat]
        tools = set(b["tools"])
        score = b["score"]
        prov  = b.get("provenance","tools")
        priority = meta["priority"]

        # Decide Actual vs NeedsCorroboration
        if prov == "yaml-atomic" and cat != "Secrets/Hardcoded":
            status = "Actual"
            reason = f"atomic-evidence | tools={sorted(tools)}"
        elif cat == "Secrets/Hardcoded":
            ok, why = secret_fp_gate(b["snippet"], tools)
            status = "Actual" if ok else "NeedsCorroboration"
            reason = f"secrets-gate={why} | tools={sorted(tools)}"
        else:
            strong = set(meta.get("strong_tools", set())) & tools
            if strong:
                status = "Actual"
                reason = f"strong-tool={sorted(strong)}"
            else:
                # for LOW/MEDIUM require detector consensus unless score already high
                if priority in ("LOW","MEDIUM"):
                    status = "Actual" if (len(tools) >= nonatomic_consensus or score >= 0.9) else "NeedsCorroboration"
                else:
                    status = "Actual" if score >= 0.6 or len(tools) >= 1 else "NeedsCorroboration"
                reason = f"consensus={len(tools)} score={score:.2f}"

        normalized.append({
            "file": b["file"],
            "category": cat,
            "severity": meta["severity"],
            "priority": priority,
            "status": status,
            "score": round(score,3),
            "tools": sorted(tools),
            "resourceRef": {"file": b["file"], "kind": b["kind"], "name": b["name"], "namespace": b["namespace"]},
            "snippet": b["snippet"],
            "examples": b["examples"],
            "provenance": prov,
            "decisionReason": reason
        })

    # LLM payload shaping: include only Actual + priority >= min (unless user wants everything)
    def priority_idx(p: str) -> int: return PRIORITY.index(p)
    actual_sorted = [f for f in normalized if f["status"]=="Actual" and priority_idx(f["priority"]) <= min_priority_idx]
    # sort by (priority, severity, category) to push deployment-critical first
    def sort_key(f):
        return (priority_idx(f["priority"]), {"HIGH":0,"MEDIUM":1,"LOW":2}.get(f["severity"],1), f["category"])
    actual_sorted.sort(key=sort_key)

    llm_files: Dict[str, Any] = {}
    for fnd in actual_sorted:
        file_rel = fnd["file"]
        F = llm_files.setdefault(file_rel, {"file": file_rel, "findings": []})
        F["findings"].append({
            "category": fnd["category"],
            "severity": fnd["severity"],
            "priority": fnd["priority"],
            "resourceRef": fnd["resourceRef"],
            "snippet": fnd["snippet"],
            "tools": fnd["tools"],
            "score": fnd["score"],
            "patchHint": patch_hint(fnd["category"]),
        })

    Path(args.out_normalized).write_text(json.dumps(normalized, ensure_ascii=False, indent=2), encoding="utf-8")
    Path(args.out_llm_payload).write_text(json.dumps({"context": llm_context(), "files": list(llm_files.values())}, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.out_buckets_csv:
        with open(args.out_buckets_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["file","kind","name","namespace","category","severity","priority","status","score","tools","provenance","reason"])
            for b in normalized:
                w.writerow([b["file"], b["resourceRef"]["kind"], b["resourceRef"]["name"], b["resourceRef"]["namespace"],
                            b["category"], b["severity"], b["priority"], b["status"], b["score"], ";".join(b["tools"]),
                            b.get("provenance","tools"), b["decisionReason"]])

    actual = sum(1 for x in normalized if x["status"]=="Actual")
    pending = sum(1 for x in normalized if x["status"]!="Actual")
    print(f"Wrote normalized findings -> {args.out_normalized}")
    print(f"Wrote LLM payload        -> {args.out_llm_payload}")
    if args.out_buckets_csv: print(f"Wrote weighted buckets   -> {args.out_buckets_csv}")
    print(f"Actual={actual} | NeedsCorroboration={pending} | Total={len(normalized)}")

# --------------------------- CLI ---------------------------

def main():
    ap = argparse.ArgumentParser(description="SafeFix-K8s priority-driven normalizer with YAML-atomic promotion and FP gates")
    ap.add_argument("--raw-dir", required=True)
    ap.add_argument("--tests-dir", required=True)
    ap.add_argument("--out-normalized", required=True)
    ap.add_argument("--out-llm-payload", required=True)
    ap.add_argument("--out-buckets-csv", default="")
    ap.add_argument("--payload-min-priority", default="LOW", choices=list(PRIORITY),
                    help="Only include Actual findings at or above this priority in the payload (default LOW).")
    ap.add_argument("--nonatomic-consensus", dest="nonatoMic_consensus", default="2",
                    help="For LOW/MEDIUM non-atomic findings, require at least this many tools unless strong-tool/score (default 2).")
    args = ap.parse_args()
    normalize(args)

if __name__ == "__main__":
    main()
