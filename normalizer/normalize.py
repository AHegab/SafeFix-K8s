#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SafeFix-K8s LLM Payload Builder (v8.0)

This copy lives under Normalizer/ and defaults to reading detector raw
outputs from Detection/output/raw. For backward compatibility, it will
fall back to detection/output/raw if the new path doesn't exist.

Outputs (default ./output)
--------------------------
- llm_payload.json   (ONLY; lean and LLM-ready)

Usage
-----
python Normalizer/normalize.py --raw Detection/output/raw --out output \
             [--min-support 1] [--only-security 1] [--emit-normalized 0]

Notes
-----
- PyYAML is optional. If missing, the builder still emits snippet/span
    using regex and omits jsonpath.
- We intentionally skip items whose file cannot be resolved to a YAML
    file under the workspace (e.g., "(unknown)" or pure resource IDs).
"""

import argparse, json, re, sys, os
from pathlib import Path
from datetime import datetime

# Optional YAML support
try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None

# ---------------- CLI ----------------
def parse_args():
    p = argparse.ArgumentParser("SafeFix-K8s LLM payload builder (v8.0)")
    p.add_argument("--raw", default="Detection/output/raw", help="Folder containing *raw* tool outputs (prefers Detection/output/raw; falls back to detection/output/raw)")
    p.add_argument("--out", default="output", help="Folder to write outputs (llm_payload.json)")
    p.add_argument("--min-support", type=int, default=1, help="Minimum number of distinct tools to keep a (file,category)")
    p.add_argument("--only-security", type=int, default=1, help="If 1, exclude quality-only categories (probes/limits/schema/yaml)")
    p.add_argument("--emit-normalized", type=int, default=0, help="If 1, also emit normalized_findings.json for debugging")
    return p.parse_args()

# ---------------- Canonical Categories & Regex ----------------
CANONICAL = {
    "PRIVILEGED":               [r"\bprivileged\s*:\s*true\b", r"\bPrivilegedTrue\b", r"\bprivileged-container\b"],
    "PRIV_ESCALATION":          [r"\ballowPrivilegeEscalation\s*:\s*(true|nil)\b", r"\bAllowPrivilegeEscalation(True|Nil)\b"],
    "CAP_SYS_ADMIN":            [r"\b(cap_sys_admin|SYS_ADMIN)\b", r"\bdrop-net-raw-capability\b", r"\bcapabilities\b"],
    "RUN_AS_NONROOT_FALSE":     [r"\brunasnonroot\s*:\s*false\b", r"\brunasuser\s*:\s*0\b", r"\brun-as-non-root\b"],
    "READONLY_ROOTFS_FALSE":    [r"\breadOnlyRootFilesystem\s*:\s*false\b", r"\bReadOnlyRootFilesystem(Nil|False)\b"],
    "NO_SECCOMP":               [r"\bseccomp(Profile)?\b(?!.*RuntimeDefault)", r"\bSeccompProfileMissing\b"],
    "NO_APPARMOR":              [r"\bAppArmorAnnotationMissing\b", r"\bAppArmor\b.*(unconfined|missing)"],
    "HOSTPATH":                 [r"\bhostPath\b", r"/var/run/docker\.sock", r"\bdocker-sock\b"],
    "IMAGE_LATEST":             [r":[Ll]atest\b", r"\bno-latest-image\b"],
    "HARD_CODED_CREDS":         [r"\bGitleaks\b", r"\b(password|token|apikey|api[_-]?key|secret)\b.*(=|:|\"|\s)\w+"],
    "PLAIN_SECRET":             [r"\bkind\s*:\s*Secret\b", r"\bOpaque\b", r"\bstringData\b"],
    "SERVICEACCOUNT_TOKEN_AUTO":[r"\bAutomountServiceAccountToken(True|Nil)\b", r"\bdeprecated-service-account-field\b"],
    "RBAC_OVER_PERMISSIVE":     [r"\bDangerousVerb\b|\bverbs\s*:\s*\[\s*\*\s*\]"],
    "DEPRECATED_API":           [r"\bDeprecated apiVersion\b|\breplacement-api\b|\bremoved-in\b"],
    "SCHEMA_INVALID":           [r"\bSchema invalid\b|\bKubeConform\b|\bmissing property\b"],
    "NO_PROBES":                [r"\b(liveness|readiness|startup)Probe\b.*(missing|not set|absent|undefined)|\bno-(liveness|readiness)-probe\b"],
    "NO_RES_LIMITS":            [r"\b(resources|limits|requests)\b.*(missing|not set|unset|absent)|\b(memory|cpu)-(limit|request)\b"],
    "CNI_EMBEDDED_PRIVILEGED":  [r"\bCNI config\b.*\bprivileged=true\b", r"\bcni\.conf\b.*\bprivileged\b.*\btrue\b"],
}
QUALITY_ONLY = {"NO_PROBES","NO_RES_LIMITS","DEPRECATED_API","SCHEMA_INVALID","YAML_FORMATTING"}

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

# ---- Parsers
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
    if parsed is None: return
    n=name.lower()
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
RULEID_MAP = {
    "CKV_K8S_22": "PRIVILEGED", "CKV_K8S_26": "PRIV_ESCALATION", "CKV_K8S_37": "CAP_SYS_ADMIN",
    "CKV_K8S_8":  "NO_PROBES",  "CKV_K8S_10": "NO_RES_LIMITS",  "CKV_K8S_11": "NO_RES_LIMITS",
    "CKV_K8S_12": "NO_RES_LIMITS","CKV_K8S_13": "NO_RES_LIMITS","CKV_K8S_14": "IMAGE_LATEST",
}
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

# ---- Aggregation to (file, category)
def aggregate(hits):
    by_key={}
    for h in hits:
        filep = sanitize_path(h.get("file",""))
        cat = categorize(h.get("tool",""), h.get("title",""), h.get("message",""), h.get("rule_id",""))
        if not cat: continue
        k=(filep, cat)
        rec = by_key.setdefault(k, {"file":filep, "category":cat, "tools":set(), "rule_ids":set(), "examples":[], "occ":0})
        rec["tools"].add(norm_tool(h.get("tool","")))
        if h.get("rule_id"): rec["rule_ids"].add(h.get("rule_id",""))
        if len(rec["examples"])<3:
            ex = h.get("title") or h.get("message") or ""
            if ex: rec["examples"].append(ex)
        rec["occ"]+=1
    # freeze
    out=[]
    for (f,c),r in by_key.items():
        out.append({
            "file": f, "category": c, "tools": sorted(r["tools"]),
            "support_count": len(r["tools"]), "rule_ids": sorted([x for x in r["rule_ids"] if x]),
            "examples": r["examples"], "occurrences": r["occ"],
        })
    return sorted(out, key=lambda x:(x["file"], x["category"]))

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
        # resource identity (best effort)
        apiVersion = doc.get("apiVersion") if isinstance(doc, dict) else None
        kind = doc.get("kind") if isinstance(doc, dict) else None
        meta = doc.get("metadata") if isinstance(doc, dict) else {}
        res = {"apiVersion": apiVersion or "", "kind": kind or "", "metadata": {"name": (meta or {}).get("name",""), "namespace": (meta or {}).get("namespace","")}}
        items.append({
            "file": str(fpath.relative_to(repo_root)) if str(fpath).startswith(str(repo_root)) else str(fpath),
            "category": r["category"],
            "tools": r["tools"],
            "support_count": r["support_count"],
            "rule_ids": r["rule_ids"],
            "hints": r["examples"],
            "policy": "least-privilege",
            "resource": res,
            "snippet": snippet,
            "span": {"start_line": sline, "end_line": eline},
            "jsonpath": jsonpath,
        })
    return items

def main():
    args = parse_args()
    repo_root = Path(os.getcwd()).resolve()
    raw_dir = Path(args.raw).resolve()
    # Back-compat fallback to old layout
    if not raw_dir.exists():
        legacy = (repo_root / "detection/output/raw").resolve()
        if legacy.exists():
            raw_dir = legacy
    out_dir = Path(args.out).resolve(); out_dir.mkdir(parents=True, exist_ok=True)
    if not raw_dir.exists():
        print(f"[!] Raw directory not found: {raw_dir}", file=sys.stderr)
    hits = parse_raw_dir(raw_dir)
    agg = aggregate(hits)
    items = build_llm_items(repo_root, agg, min_support=int(args.min_support), only_security=bool(args.only_security))
    payload = {"generated_at": now_iso(), "version": "sfk-v8.0-llm-payload", "items": items}
    (out_dir/"llm_payload.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"✅ Wrote {out_dir/'llm_payload.json'} | items={len(items)}")
    if int(args.emit_normalized):
        (out_dir/"normalized_findings.json").write_text(json.dumps({"aggregate": agg}, indent=2), encoding="utf-8")

if __name__ == "__main__":
    main()
