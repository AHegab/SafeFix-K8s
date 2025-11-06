#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SafeFix-K8s LLM Payload Builder (v9.0 - PERFECT EDITION)

Enterprise-grade normalizer with comprehensive tool parsing, intelligent
categorization, and robust error handling.

Outputs (default ./output/normalization)
--------------------------
- llm_payload.json   (Primary LLM-ready output)
- normalized_findings.json (Optional debug output)

Usage
-----
python Normalizer/normalize.py --raw output/detection/raw --out output/normalization \
             [--min-support 1] [--only-security 1] [--emit-normalized 0]

Features
--------
- Universal tool parser with dedicated handlers for 13+ security tools
- Smart categorization with 16+ security/quality categories  
- Intelligent file resolution across workspace
- Precise snippet extraction with context-aware window
- JSONPath generation for pinpoint remediation
- Resource identity extraction (apiVersion, kind, metadata)
- Severity inference from rule IDs and control metadata
- UTF-8 BOM handling and relaxed JSON parsing
- Graceful degradation when PyYAML unavailable

Architecture
-----------
1. parse_raw_dir() -> Raw finding extraction per tool
2. aggregate() -> Deduplication and cross-tool correlation
3. build_llm_items() -> Context enrichment with snippets/jsonpath
4. main() -> CLI orchestration and output generation
"""

import argparse, json, re, sys, os
from pathlib import Path
from datetime import datetime

OUTPUT_ROOT = Path(os.getenv("SAFEFIX_OUTPUT_ROOT", "output")).resolve()
DEFAULT_RAW_DIR = os.getenv("SAFEFIX_DETECTION_RAW_DIR") or str(OUTPUT_ROOT / "detection" / "raw")
DEFAULT_OUT_DIR = os.getenv("SAFEFIX_NORMALIZATION_DIR") or str(OUTPUT_ROOT / "normalization")

# Optional YAML support
try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None

# ---------------- CLI ----------------
def parse_args():
    p = argparse.ArgumentParser("SafeFix-K8s LLM payload builder (v8.0)")
    p.add_argument("--raw", default=DEFAULT_RAW_DIR, help="Folder containing *raw* tool outputs (defaults to output/detection/raw)")
    p.add_argument("--out", default=DEFAULT_OUT_DIR, help="Folder to write outputs (llm_payload.json)")
    p.add_argument("--min-support", type=int, default=1, help="Minimum number of distinct tools to keep a (file,category)")
    p.add_argument("--only-security", type=int, default=1, help="If 1, exclude quality-only categories (probes/limits/schema/yaml)")
    p.add_argument("--emit-normalized", type=int, default=0, help="If 1, also emit normalized_findings.json for debugging")
    return p.parse_args()

# ---------------- Canonical Categories & Enhanced Regex ----------------
CANONICAL = {
    # CRITICAL Security Issues
    "PRIVILEGED":               [r"\bprivileged\s*:\s*true\b", r"\bPrivilegedTrue\b", r"\bprivileged-container\b", r"\bC-0057\b", r"\brule-privilege-escalation\b"],
    "PRIV_ESCALATION":          [r"\ballowPrivilegeEscalation\s*:\s*(true|nil)\b", r"\bAllowPrivilegeEscalation(True|Nil)\b", r"\bC-0016\b"],
    "CAP_SYS_ADMIN":            [r"\b(cap_sys_admin|SYS_ADMIN)\b", r"\bdrop-net-raw-capability\b", r"\bcapabilities\b", r"\bC-0046\b", r"\binsecure-capabilities\b"],
    "HOSTPATH":                 [r"\bhostPath\b", r"/var/run/docker\.sock", r"\bdocker-sock\b", r"\bC-0048\b", r"\bC-0045\b", r"\bC-0074\b"],
    
    # HIGH Security Issues  
    "RUN_AS_NONROOT_FALSE":     [r"\brunasnonroot\s*:\s*false\b", r"\brunasuser\s*:\s*0\b", r"\brun-as-non-root\b", r"\bC-0013\b", r"\bnon-root-containers\b"],
    "READONLY_ROOTFS_FALSE":    [r"\breadOnlyRootFilesystem\s*:\s*false\b", r"\bReadOnlyRootFilesystem(Nil|False)\b", r"\bC-0017\b", r"\bimmutable-container-filesystem\b"],
    "NO_SECCOMP":               [r"\bseccomp(Profile)?\b(?!.*RuntimeDefault)", r"\bSeccompProfileMissing\b", r"\bC-0055\b", r"\blinux-hardening\b"],
    "NO_APPARMOR":              [r"\bAppArmorAnnotationMissing\b", r"\bAppArmor\b.*(unconfined|missing)", r"\bC-0055\b"],
    "HARD_CODED_CREDS":         [r"\bGitleaks\b", r"\b(password|token|apikey|api[_-]?key|secret)\b.*(=|:|\"|\s)\w+", r"\bC-0012\b"],
    "PLAIN_SECRET":             [r"\bkind\s*:\s*Secret\b", r"\bOpaque\b", r"\bstringData\b", r"\bunencrypted", r"\bC-0207\b"],
    "SERVICEACCOUNT_TOKEN_AUTO":[r"\bAutomountServiceAccountToken(True|Nil)\b", r"\bdeprecated-service-account-field\b", r"\bC-0034\b"],
    "RBAC_OVER_PERMISSIVE":     [r"\bDangerousVerb\b", r"\bverbs\s*:\s*\[\s*\*\s*\]", r"\bwildcard", r"\bcluster-admin\b"],
    "NETWORK_POLICY_MISSING":   [r"\bnetwork\s*policy\b.*missing", r"\bC-0030\b", r"\bC-0260\b", r"\bingress.*egress\b"],
    
    # MEDIUM Security Issues
    "IMAGE_LATEST":             [r":[Ll]atest\b", r"\bno-latest-image\b", r"\bC-0075\b"],
    "HOST_NAMESPACE":           [r"\bhostPID\b", r"\bhostIPC\b", r"\bhostNetwork\b", r"\bC-0038\b", r"\bC-0041\b"],
    "CNI_EMBEDDED_PRIVILEGED":  [r"\bCNI config\b.*\bprivileged=true\b", r"\bcni\.conf\b.*\bprivileged\b.*\btrue\b"],
    "POD_DEFAULT_NAMESPACE":    [r"\bdefault\s+namespace\b", r"\bC-0061\b", r"\bpods-in-default-namespace\b"],
    
    # Quality/DevOps Issues (LOW priority)
    "NO_PROBES":                [r"\b(liveness|readiness|startup)Probe\b.*(missing|not set|absent|undefined)", r"\bno-(liveness|readiness)-probe\b", r"\bC-0056\b", r"\bC-0018\b"],
    "NO_RES_LIMITS":            [r"\b(resources|limits|requests)\b.*(missing|not set|unset|absent)", r"\b(memory|cpu)-(limit|request)\b", r"\bC-0270\b", r"\bC-0271\b"],
    "DEPRECATED_API":           [r"\bDeprecated apiVersion\b", r"\breplacement-api\b", r"\bremoved-in\b", r"\bPluto\b"],
    "SCHEMA_INVALID":           [r"\bSchema invalid\b", r"\bKubeConform\b", r"\bmissing property\b", r"\binvalid\s+schema\b"],
    "YAML_FORMATTING":          [r"\bYamllint\b", r"\bsyntax\s+error\b", r"\bindentation\b"],
}

# Severity mappings
QUALITY_ONLY = {"NO_PROBES", "NO_RES_LIMITS", "DEPRECATED_API", "SCHEMA_INVALID", "YAML_FORMATTING"}
CRITICAL_CATEGORIES = {"PRIVILEGED", "PRIV_ESCALATION", "CAP_SYS_ADMIN", "HOSTPATH"}
HIGH_CATEGORIES = {"RUN_AS_NONROOT_FALSE", "READONLY_ROOTFS_FALSE", "NO_SECCOMP", "NO_APPARMOR", "HARD_CODED_CREDS", "PLAIN_SECRET", "RBAC_OVER_PERMISSIVE"}
MEDIUM_CATEGORIES = {"IMAGE_LATEST", "HOST_NAMESPACE", "NETWORK_POLICY_MISSING", "SERVICEACCOUNT_TOKEN_AUTO", "CNI_EMBEDDED_PRIVILEGED", "POD_DEFAULT_NAMESPACE"}

TOOL_ALIASES = {
    "checkov":"Checkov","kubescape":"Kubescape","kubeaudit":"KubeAudit",
    "kubelinter":"KubeLinter","kube-linter":"KubeLinter","polaris":"Polaris",
    "trivy":"Trivy","trivy_config":"Trivy","kubescore":"KubeScore",
    "kubeconform":"KubeConform","pluto":"Pluto","rbacpolice":"RBACPolice",
    "gitleaks":"Gitleaks","yamllint":"Yamllint","conftest":"Conftest"
}
def norm_tool(name:str)->str:
    return TOOL_ALIASES.get((name or "").lower().replace(" ","_"), name or "?")

YAML_EXTS = (".yaml",".yml")
def now_iso(): return datetime.utcnow().isoformat(timespec="seconds")+"Z"
def read_text(p:Path)->str:
    try:
        return p.read_text(encoding="utf-8-sig", errors="ignore").replace("\ufeff","")
    except OSError:
        return ""
def is_yaml_path(s:str)->bool: return (s or "").strip().lower().endswith(YAML_EXTS)
def looks_like_yaml_in_text(s:str)->bool: return bool(re.search(r"\.(ya?ml)\b", s or "", re.I))
def extract_file_hint(s:str)->str:
    m = re.findall(r"((?:[^/\s\"']+/)*[^/\s\"']+\.(?:ya?ml))", s or "", re.I)
    return m[-1] if m else ""
def sanitize_path(s:str)->str:
    if not s: return "(unknown)"
    s = s.replace("\ufeff","").replace("\\","/")
    s = re.sub(r"/{2,}","/",s).strip("/")
    return s or "(unknown)"

def load_json_relaxed(p: Path):
    data = read_text(p)
    if not data.strip():
        return None
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        pass
    objs, chunk = [], ""
    for line in data.splitlines():
        s=line.strip()
        if not s: continue
        chunk += s
        if chunk.count("{") == chunk.count("}") and chunk.count("[") == chunk.count("]"):
            try:
                objs.append(json.loads(chunk))
            except json.JSONDecodeError:
                try:
                    objs.append(json.loads(s))
                except json.JSONDecodeError:
                    pass
            chunk=""
    if chunk:
        try:
            objs.append(json.loads(chunk))
        except json.JSONDecodeError:
            pass
    if len(objs)==1: return objs[0]
    return objs or None

# ---- Enhanced Parsers with Polaris & Kubescape Deep Parsing
def parse_polaris(data):
    """Parse Polaris Audit results with deep control extraction."""
    hits = []
    if not isinstance(data, dict):
        return hits
    
    results = data.get("Results", [])
    for item in results:
        if not isinstance(item, dict):
            continue
        
        name = item.get("Name", "")
        namespace = item.get("Namespace", "")
        kind = item.get("Kind", "")
        
        # Construct pseudo-file path from source if available
        file_hint = f"{namespace}/{kind}/{name}" if namespace else f"{kind}/{name}"
        
        # Parse Results (for ConfigMaps, Secrets, etc.)
        item_results = item.get("Results", {})
        if isinstance(item_results, dict):
            for check_id, check in item_results.items():
                if not isinstance(check, dict):
                    continue
                if check.get("Success") is False:  # Only failures
                    msg = check.get("Message", "")
                    severity = check.get("Severity", "warning")
                    category_hint = check.get("Category", "")
                    hits.append(make_finding("Polaris", file_hint, check_id, f"[{severity.upper()}] {msg} (Category: {category_hint})", check_id))
        
        # Parse PodResult (for Pods/Deployments/etc.)
        pod_result = item.get("PodResult", {})
        if isinstance(pod_result, dict):
            container_results = pod_result.get("ContainerResults", [])
            for container in container_results:
                if not isinstance(container, dict):
                    continue
                cname = container.get("Name", "")
                for check_id, check in container.get("Results", {}).items():
                    if not isinstance(check, dict):
                        continue
                    if check.get("Success") is False:
                        msg = check.get("Message", "")
                        severity = check.get("Severity", "warning")
                        hits.append(make_finding("Polaris", file_hint, check_id, f"[{severity.upper()}] Container '{cname}': {msg}", check_id))
    
    return hits

def parse_kubescape(data):
    """Parse Kubescape JSON with control-level detail extraction."""
    hits = []
    if not isinstance(data, dict):
        return hits
    
    results_list = data.get("results", [])
    for result in results_list:
        if not isinstance(result, dict):
            continue
        
        resource_id = result.get("resourceID", "")
        controls = result.get("controls", [])
        
        for control in controls:
            if not isinstance(control, dict):
                continue
            
            control_id = control.get("controlID", "")
            control_name = control.get("name", "")
            status = control.get("status", {})
            
            if isinstance(status, dict) and status.get("status") == "failed":
                rules = control.get("rules", [])
                for rule in rules:
                    if not isinstance(rule, dict):
                        continue
                    
                    rule_name = rule.get("name", "")
                    rule_status = rule.get("status", "")
                    
                    if rule_status == "failed":
                        paths = rule.get("paths", [])
                        msg = f"{control_name} ({control_id}) - Rule: {rule_name}"
                        
                        # Try to extract file path from resourceID
                        file_hint = resource_id.split("/")[-1] if "/" in resource_id else resource_id
                        
                        # Add path details if available
                        if paths and isinstance(paths, list) and len(paths) > 0:
                            fix_path = paths[0].get("fixPath", {})
                            if isinstance(fix_path, dict):
                                path_str = fix_path.get("path", "")
                                if path_str:
                                    msg += f" | Path: {path_str}"
                        
                        hits.append(make_finding("Kubescape", file_hint, control_id, msg, control_id))
    
    return hits
def make_finding(tool, file, title, message, rule_id=""):
    file = sanitize_path(file or extract_file_hint(message) or "")
    return {"tool": norm_tool(tool), "file": file or "(unknown)",
            "title": (title or "").strip(), "message": (message or "").strip(),
            "rule_id": (rule_id or "").strip()}

FILE_KEYS = {"file","file_path","repo_file_path","filename","manifest","target","Target","path","Path","Source","fileName","FileName","Manifest","Object","object","location","File"}
TITLE_KEYS= {"check_name","check","name","title","RuleID","ID","Type","auditResultName","rule","ruleID","controlID"}
MSG_KEYS  = {"description","diagnostic","message","Message","Title","Secret","Match","comment","text","details","detail","reason","result","msg","summary"}

def walk_json(obj, hits, prefer_file=""):
    if isinstance(obj, dict):
        f=t=m=rid=None
        for k,v in obj.items():
            lk=str(k)
            if lk in FILE_KEYS and isinstance(v,str) and not f: f=v
            if lk in TITLE_KEYS and isinstance(v,str) and not t: t=v
            if lk in MSG_KEYS   and isinstance(v,str) and not m: m=v
            if lk.lower() in {"id","ruleid","rule_id","check_id","policyid","controlid"} and isinstance(v,str) and not rid: rid=v
        if t or m: hits.append((f or prefer_file, t or "", m or "", rid or ""))
        for v in obj.values(): walk_json(v, hits, prefer_file=f or prefer_file)
    elif isinstance(obj, list):
        for it in obj: walk_json(it, hits, prefer_file=prefer_file)

def parse_by_name(name:str, parsed, hits):
    """Route parsing to specialized handlers based on tool name."""
    if parsed is None: 
        return
    
    n=name.lower()
    
    # Dedicated parsers for complex tools
    if "polaris" in n:
        hits.extend(parse_polaris(parsed))
        return
    if "kubescape" in n:
        hits.extend(parse_kubescape(parsed))
        return
    
    # Existing specialized parsers
    if   "kubeconform" in n:
        items = parsed if isinstance(parsed, list) else (parsed.get("resources") or [])
        for it in items:
            if str(it.get("status","")) .lower() != "invalid":
                continue
            filep = it.get("filePath") or it.get("filename") or it.get("path") or it.get("name") or ""
            errs = it.get("errors") or []
            msg = "; ".join([e.get("msg","") for e in errs]) if isinstance(errs, list) else str(errs)
            hits.append(make_finding("KubeConform", filep, "Schema invalid", msg, "KUBECONFORM_INVALID"))
        return
    if   "checkov" in n:
        if isinstance(parsed, dict):
            for it in parsed.get("results",{}).get("failed_checks",[]) or []:
                hits.append(make_finding("Checkov", it.get("file_path") or it.get("repo_file_path",""),
                                         it.get("check_name",""), it.get("description",""), it.get("check_id","")))
        return
    if   "trivy" in n:
        if isinstance(parsed, dict):
            for res in parsed.get("Results",[]) or []:
                tgt = res.get("Target","")
                for mc in res.get("Misconfigurations",[]) or []:
                    hits.append(make_finding("Trivy", tgt or mc.get("Target",""), mc.get("Title",""), mc.get("Message",""), mc.get("ID","")))
        return
    if   "kubeaudit" in n:
        if isinstance(parsed, list):
            for it in parsed:
                t = it.get("AuditResultName","") or it.get("auditResultName","")
                hits.append(make_finding("KubeAudit", it.get("file","") or it.get("File",""), t, it.get("msg",""), t))
        return
    if   "kubelinter" in n:
        if isinstance(parsed, dict):
            for it in parsed.get("reports",[]) or []:
                filep = it.get("object") or it.get("filename") or it.get("file","")
                hits.append(make_finding("KubeLinter", filep, it.get("check",""), it.get("diagnostic","")))
        return
    if   "pluto" in n:
        if isinstance(parsed, dict):
            for it in parsed.get("items",[]) or []:
                api = it.get("api",{}) or {}
                filep = it.get("filePath","") or it.get("filename","") or it.get("path","")
                title = f"{api.get('kind','')} {api.get('version','')}".strip()
                hits.append(make_finding("Pluto", filep, title, "Deprecated apiVersion", api.get("version","")))
        return
    if   "rbacpolice" in n:
        if isinstance(parsed, list):
            for it in parsed:
                hits.append(make_finding("RBACPolice", it.get("file",""), it.get("rule",""), it.get("message","")))
        return
    if   "gitleaks" in n:
        if isinstance(parsed, list):
            for it in parsed:
                hits.append(make_finding("Gitleaks", it.get("File","") or it.get("file",""), it.get("RuleID","") or "Gitleaks", it.get("Match",""), it.get("RuleID","")))
        return
    if   "conftest" in n:
        if isinstance(parsed, list):
            for it in parsed:
                filep = it.get("filename","") or it.get("file","")
                for f in it.get("failures",[]) or []:
                    hits.append(make_finding("Conftest", filep, "Conftest", f.get("msg","")))
        return
    
    # Fallback generic walk
    walk_hits=[]; walk_json(parsed, walk_hits)
    for f,t,m,rid in walk_hits:
        hits.append(make_finding(name, f,t,m, rid))

# ---- Categorization
COMPILED = {k:[re.compile(p, re.I) for p in pats] for k,pats in CANONICAL.items()}
# Enhanced rule ID mappings with Kubescape, Polaris, etc.
RULEID_MAP = {
    # Checkov
    "CKV_K8S_22": "PRIVILEGED", "CKV_K8S_26": "PRIV_ESCALATION", "CKV_K8S_37": "CAP_SYS_ADMIN",
    "CKV_K8S_8":  "NO_PROBES",  "CKV_K8S_10": "NO_RES_LIMITS",  "CKV_K8S_11": "NO_RES_LIMITS",
    "CKV_K8S_12": "NO_RES_LIMITS","CKV_K8S_13": "NO_RES_LIMITS","CKV_K8S_14": "IMAGE_LATEST",
    "CKV_K8S_16": "RUN_AS_NONROOT_FALSE", "CKV_K8S_23": "READONLY_ROOTFS_FALSE",
    "CKV_K8S_30": "NO_SECCOMP", "CKV_K8S_20": "SERVICEACCOUNT_TOKEN_AUTO",
    
    # Kubescape Controls
    "C-0057": "PRIVILEGED", "C-0016": "PRIV_ESCALATION", "C-0046": "CAP_SYS_ADMIN",
    "C-0013": "RUN_AS_NONROOT_FALSE", "C-0017": "READONLY_ROOTFS_FALSE",
    "C-0055": "NO_SECCOMP", "C-0048": "HOSTPATH", "C-0045": "HOSTPATH", "C-0074": "HOSTPATH",
    "C-0075": "IMAGE_LATEST", "C-0034": "SERVICEACCOUNT_TOKEN_AUTO",
    "C-0056": "NO_PROBES", "C-0018": "NO_PROBES",
    "C-0270": "NO_RES_LIMITS", "C-0271": "NO_RES_LIMITS",
    "C-0012": "HARD_CODED_CREDS", "C-0207": "PLAIN_SECRET",
    "C-0030": "NETWORK_POLICY_MISSING", "C-0260": "NETWORK_POLICY_MISSING",
    "C-0061": "POD_DEFAULT_NAMESPACE", "C-0038": "HOST_NAMESPACE", "C-0041": "HOST_NAMESPACE",
    
    # Polaris
    "hostIPCSet": "HOST_NAMESPACE", "hostPIDSet": "HOST_NAMESPACE", "hostNetworkSet": "HOST_NAMESPACE",
    "runAsRootAllowed": "RUN_AS_NONROOT_FALSE", "runAsPrivileged": "PRIVILEGED",
    "notReadOnlyRootFilesystem": "READONLY_ROOTFS_FALSE", "cpuLimitsMissing": "NO_RES_LIMITS",
    "memoryLimitsMissing": "NO_RES_LIMITS", "readinessProbeMissing": "NO_PROBES",
    "livenessProbeMissing": "NO_PROBES",
}

def get_severity(category: str) -> str:
    """Return severity level for a category."""
    if category in CRITICAL_CATEGORIES:
        return "CRITICAL"
    elif category in HIGH_CATEGORIES:
        return "HIGH"
    elif category in MEDIUM_CATEGORIES:
        return "MEDIUM"
    elif category in QUALITY_ONLY:
        return "LOW"
    return "MEDIUM"  # Default
def categorize(tool: str, title: str, message: str, rule_id: str):
    rid = (rule_id or "").strip().upper()
    if rid in RULEID_MAP: return RULEID_MAP[rid]
    if norm_tool(tool) == "Yamllint": return "YAML_FORMATTING"
    txt = f"{tool} {title} {message} {rule_id}"
    for cid, regs in COMPILED.items():
        if any(r.search(txt) for r in regs):
            return cid
    return None

def parse_raw_dir(raw_dir: Path):
    hits=[]
    for p in sorted(raw_dir.rglob("*")):
        if p.is_dir(): continue
        name = p.name
        if name.lower().endswith(".json"):
            parsed = load_json_relaxed(p)
            parse_by_name(name, parsed, hits)
        elif "yamllint" in name.lower():
            data = read_text(p)
            for line in data.splitlines():
                m = re.match(r"^([^:]+):(\d+):(\d+):\s*(warning|error):\s*([a-z0-9\-]+):\s*(.+)$", line.strip(), re.I)
                if not m: continue
                fpath, ln, col, level, rule, msg = m.groups()
                hits.append(make_finding("Yamllint", fpath, f"{level.upper()}:{rule}", f"L{ln}C{col} {msg}", rule))
    return hits

# ---- Enhanced Aggregation with Severity
def aggregate(hits):
    """Aggregate findings by (file, category) with tool correlation and severity."""
    by_key={}
    for h in hits:
        filep = sanitize_path(h.get("file",""))
        cat = categorize(h.get("tool",""), h.get("title",""), h.get("message",""), h.get("rule_id",""))
        if not cat: 
            continue
        k=(filep, cat)
        rec = by_key.setdefault(k, {
            "file":filep, 
            "category":cat, 
            "severity": get_severity(cat),
            "tools":set(), 
            "rule_ids":set(), 
            "examples":[], 
            "occ":0
        })
        rec["tools"].add(norm_tool(h.get("tool","")))
        if h.get("rule_id"): 
            rec["rule_ids"].add(h.get("rule_id",""))
        if len(rec["examples"])<3:
            ex = h.get("title") or h.get("message") or ""
            if ex and ex not in rec["examples"]:  # Avoid duplicates
                rec["examples"].append(ex)
        rec["occ"]+=1
    
    # Freeze and sort by severity then support
    out=[]
    for (f,c),r in by_key.items():
        out.append({
            "file": f, 
            "category": c, 
            "severity": r["severity"],
            "tools": sorted(r["tools"]),
            "support_count": len(r["tools"]), 
            "rule_ids": sorted([x for x in r["rule_ids"] if x]),
            "examples": r["examples"], 
            "occurrences": r["occ"],
        })
    
    # Sort: CRITICAL first, then by support count (descending)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    out.sort(key=lambda x: (severity_order.get(x["severity"], 99), -x["support_count"], x["file"], x["category"]))
    return out

# ---- Context extractors
CATEGORY_HINT_REGEX = {
    "PRIVILEGED": re.compile(r"\bprivileged\b", re.I),
    "PRIV_ESCALATION": re.compile(r"allowPrivilegeEscalation", re.I),
    "CAP_SYS_ADMIN": re.compile(r"capabilities|cap_sys_admin", re.I),
    "RUN_AS_NONROOT_FALSE": re.compile(r"runAsNonRoot|runAsUser", re.I),
    "READONLY_ROOTFS_FALSE": re.compile(r"readOnlyRootFilesystem", re.I),
    "NO_SECCOMP": re.compile(r"seccomp", re.I),
    "NO_APPARMOR": re.compile(r"apparmor", re.I),
    "HOSTPATH": re.compile(r"hostPath|docker\.sock", re.I),
    "IMAGE_LATEST": re.compile(r":latest\b", re.I),
    "NO_PROBES": re.compile(r"(liveness|readiness|startup)Probe", re.I),
    "NO_RES_LIMITS": re.compile(r"resources:|limits:|requests:", re.I),
    "RBAC_OVER_PERMISSIVE": re.compile(r"verbs:|\*", re.I),
    "DEPRECATED_API": re.compile(r"apiVersion|Ingress|extensions/v1beta1|networking.k8s.io/v1", re.I),
    "SCHEMA_INVALID": re.compile(r"(kind|apiVersion|metadata|spec|selector)", re.I),
}

def locate_file(repo_root: Path, rel_or_name: str) -> Path | None:
    if not rel_or_name or rel_or_name == "(unknown)":
        return None
    p = Path(rel_or_name)
    if p.is_absolute() and p.exists():
        return p
    # Try direct relative
    cand = (repo_root / rel_or_name)
    if cand.exists():
        return cand
    # Try under tests/
    tests = repo_root / "tests"
    if tests.exists():
        cand = tests / Path(rel_or_name).name
        if cand.exists():
            return cand
    # Last resort: search by name
    for base in [repo_root, tests]:
        if base and base.exists():
            m = list(base.rglob(Path(rel_or_name).name))
            if m: return m[0]
    return None

def extract_snippet(text: str, category: str, window: int = 16):
    regex = CATEGORY_HINT_REGEX.get(category)
    lines = text.splitlines()
    idx = None
    if regex:
        for i, line in enumerate(lines):
            if regex.search(line):
                idx = i; break
    if idx is None:
        # fallback to first non-empty
        for i, line in enumerate(lines):
            if line.strip(): idx = i; break
    if idx is None:
        return "", 1, 1
    start = max(0, idx - window//2)
    end = min(len(lines), start + window)
    snippet = "\n".join(lines[start:end])
    return snippet, start+1, end

def best_effort_jsonpath(doc: dict | list | None, category: str):
    if not isinstance(doc, dict):
        return ""
    kind = str(doc.get("kind",""))
    spec = doc.get("spec") if isinstance(doc.get("spec"), dict) else {}
    # locate first container and build a jsonpath to its securityContext when applicable
    def first_container_path():
        tpl = spec.get("template",{}).get("spec",{}) if kind.lower() in {"deployment","daemonset","statefulset","job","cronjob"} else spec
        containers = tpl.get("containers") if isinstance(tpl, dict) else None
        if isinstance(containers, list) and containers:
            name = containers[0].get("name") or ""
            if kind.lower() in {"deployment","daemonset","statefulset","job","cronjob"}:
                base = "$.spec.template.spec.containers"
            else:
                base = "$.spec.containers"
            if name:
                return f"{base}[?(@.name=='{name}')].securityContext"
            return f"{base}[0].securityContext"
        return ""
    if category in {"PRIVILEGED","PRIV_ESCALATION","NO_SECCOMP","RUN_AS_NONROOT_FALSE","READONLY_ROOTFS_FALSE","NO_PROBES","NO_RES_LIMITS","IMAGE_LATEST"}:
        return first_container_path()
    if category == "HOSTPATH":
        # volumes or volumeMounts
        base = "$.spec.template.spec" if kind.lower() in {"deployment","daemonset","statefulset","job","cronjob"} else "$.spec"
        return f"{base}.volumes"
    if category == "RBAC_OVER_PERMISSIVE":
        return "$.rules"
    return ""

def parse_yaml_doc(text: str):
    if not yaml:
        return None
    try:
        docs = list(yaml.safe_load_all(text))
        return docs[0] if docs else None
    except yaml.YAMLError:  # type: ignore[attr-defined]
        return None

def build_llm_items(repo_root: Path, agg, min_support: int, only_security: bool):
    """Build LLM payload with enhanced metadata, snippets, and remediation hints."""
    items=[]
    for r in agg:
        if not r["file"] or r["file"] == "(unknown)":
            continue
        if only_security and r["category"] in QUALITY_ONLY:
            continue
        if r["support_count"] < min_support:
            continue
        fpath = locate_file(repo_root, r["file"]) 
        if not fpath or not is_yaml_path(str(fpath)):
            continue
        text = read_text(fpath)
        snippet, sline, eline = extract_snippet(text, r["category"]) 
        doc = parse_yaml_doc(text)
        jsonpath = best_effort_jsonpath(doc, r["category"]) if doc else ""
        
        # Enhanced resource identity
        apiVersion = doc.get("apiVersion") if isinstance(doc, dict) else None
        kind = doc.get("kind") if isinstance(doc, dict) else None
        meta = doc.get("metadata") if isinstance(doc, dict) else {}
        res = {
            "apiVersion": apiVersion or "", 
            "kind": kind or "", 
            "metadata": {
                "name": (meta or {}).get("name",""), 
                "namespace": (meta or {}).get("namespace","")
            }
        }
        
        # Calculate relative path properly
        try:
            rel_path = str(fpath.relative_to(repo_root))
        except ValueError:
            rel_path = str(fpath)
        
        items.append({
            "file": rel_path,
            "category": r["category"],
            "severity": r["severity"],
            "tools": r["tools"],
            "support_count": r["support_count"],
            "rule_ids": r["rule_ids"],
            "hints": r["examples"],
            "policy": "least-privilege",  # Can be enhanced based on category
            "resource": res,
            "snippet": snippet,
            "span": {"start_line": sline, "end_line": eline},
            "jsonpath": jsonpath,
            "occurrences": r.get("occurrences", 1),
        })
    return items

def main():
    """Main execution with comprehensive error handling and statistics."""
    args = parse_args()
    repo_root = Path(os.getcwd()).resolve()
    raw_dir = Path(args.raw).resolve()
    
    # Back-compat fallback to old layout
    if not raw_dir.exists():
        candidates = [
            (repo_root / "output/detection/raw").resolve(),
            (repo_root / "Detection/output/raw").resolve(),
            (repo_root / "detection/output/raw").resolve()
        ]
        for legacy in candidates:
            if legacy.exists():
                print(f"[INFO] Using legacy path: {legacy}")
                raw_dir = legacy
                break
    
    out_dir = Path(args.out).resolve(); 
    out_dir.mkdir(parents=True, exist_ok=True)
    os.environ["SAFEFIX_NORMALIZATION_DIR"] = str(out_dir)
    
    if not raw_dir.exists():
        print(f"[ERROR] Raw directory not found: {raw_dir}", file=sys.stderr)
        sys.exit(1)
    
    print(f"[*] Parsing raw outputs from: {raw_dir}")
    hits = parse_raw_dir(raw_dir)
    print(f"[*] Extracted {len(hits)} raw findings")
    
    print(f"[*] Aggregating and correlating findings...")
    agg = aggregate(hits)
    print(f"[*] Aggregated to {len(agg)} unique (file, category) pairs")
    
    # Print severity distribution
    severity_counts = {}
    for item in agg:
        sev = item.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    print(f"[*] Severity distribution:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in severity_counts:
            print(f"    {sev}: {severity_counts[sev]}")
    
    print(f"[*] Building LLM payload (min_support={args.min_support}, only_security={bool(args.only_security)})...")
    items = build_llm_items(repo_root, agg, min_support=int(args.min_support), only_security=bool(args.only_security))
    
    payload = {
        "generated_at": now_iso(), 
        "version": "sfk-v9.0-perfect", 
        "metadata": {
            "raw_findings_count": len(hits),
            "aggregated_count": len(agg),
            "llm_items_count": len(items),
            "severity_distribution": severity_counts,
            "filters": {
                "min_support": int(args.min_support),
                "only_security": bool(args.only_security)
            }
        },
        "items": items
    }
    
    (out_dir/"llm_payload.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[OK] Wrote {out_dir/'llm_payload.json'} | LLM items={len(items)}")
    
    if int(args.emit_normalized):
        normalized = {
            "generated_at": now_iso(),
            "raw_findings": len(hits),
            "aggregate": agg
        }
        (out_dir/"normalized_findings.json").write_text(json.dumps(normalized, indent=2), encoding="utf-8")
        print(f"[OK] Wrote {out_dir/'normalized_findings.json'} (debug)")

if __name__ == "__main__":
    main()
