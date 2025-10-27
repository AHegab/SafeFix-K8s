#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SafeFix-K8s Normalizer (v7.0)

What it does
------------
• Reads raw outputs in detection/output/raw (original + *_embedded_raw.*).
• Parses all supported tools.
• Maps to canonical categories.
• Aggregates by (file, category) with merged tool support.
• Classifies per our study's rule:
    - ONLY {KubeScore} OR ONLY {Polaris}  -> "Needs corroboration" (advisory)
    - Otherwise                            -> "Actual (Correct)" (treat as True Positive)
• Adds source provenance (original | embedded), per-tool confidence, per-file rollup.

Outputs (default ./output)
--------------------------
- normalized_findings.json
- normalized_findings.csv
- summary.json
- llm_payload.json

Usage
-----
python normalize_v7.py --raw detection/output/raw --out output
"""

import argparse, json, re, csv, sys
from pathlib import Path
from datetime import datetime

# ---------------- CLI ----------------
def parse_args():
    p = argparse.ArgumentParser("SafeFix-K8s findings normalizer (v7.0)")
    p.add_argument("--raw", default="detection/output/raw", help="Folder containing *raw* tool outputs")
    p.add_argument("--out", default="output", help="Folder to write normalized outputs")
    return p.parse_args()

# ---------------- Canonical Categories ----------------
CANONICAL = {
    # Privilege / user / process
    "PRIVILEGED":               [r"\bprivileged\s*:\s*true\b", r"\bPrivileged container\b", r"\bPrivilegedTrue\b", r"\bprivileged-container\b"],
    "PRIV_ESCALATION":          [r"\ballowPrivilegeEscalation\s*:\s*true\b", r"\bAllowPrivilegeEscalation(Nil|True)\b", r"\ballow-privilege-escalation\b"],
    "CAP_SYS_ADMIN":            [r"\b(cap_sys_admin|SYS_ADMIN)\b", r"\bmust not add CAP_SYS_ADMIN\b", r"\bdrop-net-raw-capability\b", r"\bcapabilities\b"],
    "RUN_AS_NONROOT_FALSE":     [r"\brunasnonroot\s*:\s*false\b", r"\brunasuser\s*:\s*0\b", r"\bRunAsNonRoot\b", r"\brun-as-non-root\b"],
    "READONLY_ROOTFS_FALSE":    [r"\breadOnlyRootFilesystem\s*:\s*false\b", r"\bReadOnlyRootFilesystem(Nil|False)\b", r"\bread-only-root-filesystem\b"],

    "NO_SECCOMP":               [r"\bseccomp(Profile)?\b(?!.*RuntimeDefault)", r"\bSeccompProfileMissing\b", r"\bmust set seccompProfile"],
    "NO_APPARMOR":              [r"\bAppArmor\b.*(unconfined|missing)", r"\bAppArmorAnnotationMissing\b"],

    # Host access / node escape
    "HOSTPATH":                 [r"\bhostPath\b", r"\bVolumes? of type hostPath\b", r"\bSensitivePathsMounted\b", r"/var/run/docker\.sock", r"\bdocker-sock\b"],
    "HOSTNETWORK":              [r"\bhostNetwork\s*:\s*true\b"],
    "HOSTPID":                  [r"\bhostPID\s*:\s*true\b"],
    "HOSTIPC":                  [r"\bhostIPC\s*:\s*true\b"],

    # Image hygiene
    "IMAGE_LATEST":             [r":[Ll]atest\b", r"\bimage uses :latest\b", r"\bno-latest-image\b"],

    # Secrets / SA / misc
    "HARD_CODED_CREDS":         [r"\bGitleaks\b", r"\b(password|token|apikey|api[_-]?key|secret)\b.*(=|:|\"|\s)\w+"],
    "PLAIN_SECRET":             [r"\bkind\s*:\s*Secret\b", r"\bOpaque\b", r"\bstringData\b"],
    "SERVICEACCOUNT_TOKEN_AUTO":[r"\bAutomountServiceAccountToken(True|Nil)\b", r"\bDefault service account with token mounted\b", r"\bdefault-service-account\b", r"\bdeprecated-service-account-field\b"],
    "MISSING_SECURITY_CONTEXT": [r"\bCapabilityOrSecurityContextMissing\b", r"\bsecurityContext\b.*(missing|not set)"],

    # RBAC
    "RBAC_OVER_PERMISSIVE":     [r"\b(Cluster)?Role\b", r"\bverbs\s*:\s*\[\s*\*\s*\]", r"\bwildcard\b.*(verb|resource)", r"\bDangerousVerb\b", r"\bSensitiveResource\b", r"\bClusterAdmin\b"],

    # Network policy (generic)
    "NP_ALLOW_ALL":             [r"\bNetworkPolicy\b.*(0\.0\.0\.0/0|from:\s*\[\s*\])", r"\ballow all ingress\b"],
    "NP_MISSING":               [r"\bno networkpolicy defined\b|\bmissing networkpolicy\b"],

    # Services
    "SERVICE_NODEPORT":         [r"\bkind\s*:\s*Service\b.*\btype\s*:\s*NodePort\b", r"\bNodePort\b"],
    "SERVICE_LB_PUBLIC":        [r"\bService\b.*\btype\s*:\s*LoadBalancer\b", r"\bexternalIPs\b|\bexternalTrafficPolicy\b"],

    # Namespace / ports
    "DEFAULT_NAMESPACE":        [r"\bnamespace\b.*\bdefault\b"],
    "DYNAMIC_PORTS":            [r"\bdynamic/ephemeral ports\b|targetPort\b.*\bname\b"],

    # Embedded configs (CNI fix)
    "CNI_EMBEDDED_PRIVILEGED":  [r"\bCNI config\b.*\bprivileged=true\b", r"\bcni\.conf\b.*\bprivileged\b.*\btrue\b"],

    # Quality (kept visible)
    "NO_PROBES":                [r"\b(liveness|readiness|startup)Probe\b.*(missing|not set|absent|undefined)|\bno-(liveness|readiness)-probe\b"],
    "NO_RES_LIMITS":            [r"\b(resources|limits|requests)\b.*(missing|not set|unset|absent)|\b(memory|cpu)-(limit|request)\b"],
    "DEPRECATED_API":           [r"\bDeprecated apiVersion\b|\bPluto\b|\breplacement-api\b|\bremoved-in\b|\bdeprecated\b"],
    "SCHEMA_INVALID":           [r"\b(Schema invalid|KubeConform|statusInvalid|validation failed|missing property)\b"],
    "YAML_FORMATTING":          [r"\bYamllint\b|\bindentation\b|\btrailing spaces\b|\bline too long\b|\bduplicate-env-var\b"],
}
QUALITY_ONLY = {"NO_PROBES","NO_RES_LIMITS","DEPRECATED_API","SCHEMA_INVALID","YAML_FORMATTING"}

# Strength map (informational)
TOOL_WEIGHT = {
    "Checkov": 3, "KubeAudit": 3, "Trivy": 3, "KubeLinter": 2, "RBACPolice": 3,
    "KubeConform": 2, "Pluto": 2, "Gitleaks": 3, "Conftest": 3,
    "Polaris": 1, "KubeScore": 1, "Kubescape": 1, "Yamllint": 1
}

# Tool aliases
TOOL_ALIASES = {
    "checkov":"Checkov","kubescape":"Kubescape","kubeaudit":"KubeAudit",
    "kubelinter":"KubeLinter","kube-linter":"KubeLinter","polaris":"Polaris",
    "trivy":"Trivy","trivy_config":"Trivy","kubescore":"KubeScore",
    "kubeconform":"KubeConform","pluto":"Pluto","rbacpolice":"RBACPolice",
    "gitleaks":"Gitleaks","yamllint":"Yamllint","conftest":"Conftest"
}
def norm_tool(name:str)->str:
    return TOOL_ALIASES.get((name or "").lower().replace(" ","_"), name or "?")

# Some tools return Kind/Name instead of a file
TOOL_ALLOW_RESOURCE_IDS = {"Kubescape","KubeAudit","RBACPolice","Polaris","KubeLinter"}

# --------------- helpers ---------------
def now_iso(): return datetime.utcnow().isoformat(timespec="seconds")+"Z"
def read_text(p:Path)->str:
    if not p.exists(): return ""
    content = p.read_text(encoding="utf-8-sig", errors="ignore")
    return content.replace("\ufeff","")

YAML_EXTS = (".yaml",".yml")
def is_yaml_path(s:str)->bool: return (s or "").strip().lower().endswith(YAML_EXTS)
def looks_like_yaml_in_text(s:str)->bool: return bool(re.search(r"\.(ya?ml)\b", s or "", re.I))
def extract_file_hint(s:str)->str:
    m = re.findall(r"((?:[^/\s\"']+/)*[^/\s\"']+\.(?:ya?ml))", s or "", re.I)
    return m[-1] if m else ""
def sanitize_path(s:str)->str:
    if not s: return "(unknown)"
    s = s.replace("\ufeff","").replace("\\","/")
    s = re.sub(r"(^|[^A-Za-z])/?scan/","",s,flags=re.I)
    s = re.sub(r"/{2,}","/",s).strip("/")
    return s or "(unknown)"

def is_embedded_output(p: Path) -> bool:
    return p.stem.endswith("_embedded_raw")

def make_finding(tool, file, title, message, severity="", rule_id="", source="original"):
    file = sanitize_path(file or extract_file_hint(message) or "")
    return {
        "tool": norm_tool(tool),
        "file": file if file else "(unknown)",
        "title": (title or "").strip(),
        "message": (message or "").strip(),
        "severity": (severity or "").upper(),
        "rule_id": (rule_id or "").strip(),
        "source": source,   # "original" | "embedded"
    }

FILE_KEYS = {"file","file_path","repo_file_path","filename","manifest","target","Target",
             "path","Path","Source","fileName","FileName","Manifest","Object","object","location","File"}
TITLE_KEYS= {"check_name","check","name","title","RuleID","ID","Type","auditResultName","rule","ruleID","controlID"}
MSG_KEYS  = {"description","diagnostic","message","Message","Title","Secret","Match","comment","text","details",
             "detail","reason","result","msg","summary"}

def walk_json(obj, hits, prefer_file=""):
    if isinstance(obj, dict):
        if set(obj.keys()) <= {"tool","note","install","context"}:
            return
        f=t=m=rid=None
        for k,v in obj.items():
            lk=str(k)
            if lk in FILE_KEYS and isinstance(v,str) and not f: f=v
            if lk in TITLE_KEYS and isinstance(v,str) and not t: t=v
            if lk in MSG_KEYS   and isinstance(v,str) and not m: m=v
            if lk.lower() in {"id","ruleid","rule_id","check_id","policyid","controlid"} and isinstance(v,str) and not rid: rid=v
        if t or m: hits.append((f or prefer_file, t or "", m or "", rid or ""))
        for v in obj.values():
            walk_json(v, hits, prefer_file=f or prefer_file)
    elif isinstance(obj, list):
        for it in obj:
            walk_json(it, hits, prefer_file=prefer_file)

# ---------------- explicit parsers ----------------
def parse_kubelinter(parsed, findings, src):
    ok=False
    if isinstance(parsed, dict) and isinstance(parsed.get("reports"), list):
        for it in parsed["reports"]:
            filep = it.get("object") or it.get("filename") or it.get("file","")
            title = it.get("check","") or it.get("name","")
            msg   = it.get("diagnostic","") or it.get("message","") or it.get("details","")
            findings.append(make_finding("KubeLinter", filep, title, msg, source=src)); ok=True
    return ok

def parse_kubeaudit(parsed, findings, src):
    ok=False
    if isinstance(parsed, list):
        for it in parsed:
            title = it.get("AuditResultName","") or it.get("auditResultName","")
            msg   = it.get("msg","") or it.get("Message","") or ""
            filep = it.get("file","") or it.get("File","")
            findings.append(make_finding("KubeAudit", filep, title, msg, rule_id=title, source=src)); ok=True
    return ok

def parse_checkov(parsed, findings, src):
    ok=False
    if isinstance(parsed, dict) and "results" in parsed and isinstance(parsed["results"], dict):
        for it in parsed["results"].get("failed_checks", []) or []:
            findings.append(make_finding(
                "Checkov",
                it.get("file_path") or it.get("repo_file_path",""),
                it.get("check_name","") or it.get("resource",""),
                it.get("description","") or it.get("message",""),
                severity=it.get("severity",""),
                rule_id=it.get("check_id",""),
                source=src
            ))
            ok=True
    return ok

def parse_trivy(parsed, findings, src):
    ok=False
    if isinstance(parsed, dict) and isinstance(parsed.get("Results"), list):
        for res in parsed.get("Results", []):
            tgt = res.get("Target","")
            for mc in res.get("Misconfigurations", []) or []:
                findings.append(make_finding(
                    "Trivy",
                    tgt or mc.get("Target",""),
                    mc.get("Title","") or mc.get("ID",""),
                    mc.get("Message","") or mc.get("Description",""),
                    severity=mc.get("Severity",""),
                    rule_id=mc.get("ID",""),
                    source=src
                ))
                ok=True
    return ok

def parse_kubescore(parsed, findings, src):
    ok=False
    if isinstance(parsed, list):
        for item in parsed:
            filep = item.get("fileName","") or item.get("object_name","") or ""
            scored_objects = item.get("scoredObjects", []) or []
            if not scored_objects and "checks" in item:
                scored_objects = [item]
            for sobj in scored_objects:
                for chk in sobj.get("checks",[]) or []:
                    grade = chk.get("grade", 0)
                    comments = chk.get("comments") or []
                    if grade >= 10 and not comments:
                        continue
                    check_info = chk.get("check", {}) or {}
                    title = check_info.get("id","") or check_info.get("name","") or chk.get("checkID","") or chk.get("name","")
                    msg = chk.get("reason","") or chk.get("summary","") or check_info.get("comment","") or "Issue reported by KubeScore"
                    findings.append(make_finding("KubeScore", filep, title, msg, source=src)); ok=True
    return ok

def parse_polaris(parsed, findings, src):
    ok=False
    if isinstance(parsed, dict) and isinstance(parsed.get("Results"), list):
        for item in parsed["Results"]:
            name = item.get("Name","") or item.get("name","")
            kind = item.get("Kind","") or item.get("kind","")
            filep = f"{kind}/{name}" if kind and name else (name or kind)
            checks = item.get("Results",{}) or {}
            for check_id, chk in checks.items():
                if not isinstance(chk, dict): continue
                if chk.get("Success") or chk.get("success"):
                    continue
                title = chk.get("ID","") or check_id
                msg   = chk.get("Message","") or chk.get("message","") or "Issue reported by Polaris"
                sev   = chk.get("Severity","") or chk.get("severity","")
                findings.append(make_finding("Polaris", filep, title, msg, severity=sev, source=src)); ok=True
    return ok

def parse_pluto(parsed, findings, src):
    ok=False
    if isinstance(parsed, dict) and isinstance(parsed.get("items"), list):
        for it in parsed["items"]:
            fp = it.get("filePath","") or it.get("filename","") or it.get("path","")
            api = it.get("api",{}) or {}
            title = f"{api.get('kind','')} {api.get('version','')}".strip()
            msg   = "Deprecated apiVersion"
            details = []
            if api.get("removed-in"): details.append(f"removed-in {api['removed-in']}")
            if api.get("replacement-api"): details.append(f"replacement {api['replacement-api']}")
            if details: msg += f" ({', '.join(details)})"
            findings.append(make_finding("Pluto", fp, title, msg, rule_id=api.get("version",""), source=src)); ok=True
    return ok

def parse_rbacpolice(parsed, findings, src):
    ok=False
    if isinstance(parsed, list):
        for it in parsed:
            if not isinstance(it, dict): continue
            filep = it.get("file","") or ""
            title = it.get("rule","") or it.get("name","")
            msg   = it.get("message","") or it.get("details","") or it.get("reason","")
            sev   = it.get("severity","")
            findings.append(make_finding("RBACPolice", filep, title, msg, severity=sev, source=src)); ok=True
    elif isinstance(parsed, dict) and isinstance(parsed.get("findings"), list):
        for it in parsed["findings"]:
            obj = it.get("object",{}) or {}
            filep = obj.get("file","") or obj.get("name","") or obj.get("ref","")
            title = it.get("rule","") or it.get("name","")
            msg   = it.get("message","") or it.get("details","") or it.get("reason","")
            findings.append(make_finding("RBACPolice", filep, title, msg, source=src)); ok=True
    return ok

def parse_gitleaks(parsed, findings, src):
    ok=False
    if isinstance(parsed, list):
        for it in parsed:
            if not isinstance(it, dict): continue
            filep = it.get("File","") or it.get("file","") or it.get("path","")
            title = it.get("RuleID","") or it.get("Description","") or "Gitleaks"
            msg   = it.get("Match","") or it.get("Description","") or ""
            if not (filep or msg or title): continue
            findings.append(make_finding("Gitleaks", filep, title, msg, rule_id=it.get("RuleID",""), source=src)); ok=True
    return ok

def parse_conftest(parsed, findings, src):
    ok=False
    if isinstance(parsed, list):
        for it in parsed:
            filep = it.get("filename","") or it.get("file","")
            for f in it.get("failures",[]) or []:
                msg = f.get("msg","")
                # CNI embedded privilege upgrade → dedicated category later
                findings.append(make_finding("Conftest", filep, "Conftest", msg, source=src)); ok=True
    return ok

def parse_kubeconform(parsed, findings, src):
    ok=False
    items = []
    if isinstance(parsed, list):
        items = parsed
    elif isinstance(parsed, dict) and isinstance(parsed.get("resources"), list):
        items = parsed["resources"]
    for it in items:
        filep = it.get("filePath") or it.get("filename") or it.get("path") or it.get("name") or ""
        if str(it.get("status","")).lower() != "invalid":
            continue
        errs = it.get("errors") or []
        msg = "; ".join([e.get("msg","") for e in errs]) if isinstance(errs, list) else str(errs)
        findings.append(make_finding("KubeConform", filep, "Schema invalid", msg, rule_id="KUBECONFORM_INVALID", source=src)); ok=True
    return ok

# --------------- loader ---------------
def load_json_relaxed(p: Path):
    data = read_text(p)
    if not data.strip():
        return None
    # Try whole content
    try:
        return json.loads(data)
    except Exception:
        pass
    # Try scanning lines/chunks
    objs=[]
    chunk=""
    for line in data.splitlines():
        s=line.strip()
        if not s:
            continue
        # Some tools print adjacent JSON; try to buffer
        chunk += s
        if chunk.count("{") == chunk.count("}") and chunk.count("[") == chunk.count("]"):
            try:
                objs.append(json.loads(chunk))
            except Exception:
                try:
                    objs.append(json.loads(s))
                except Exception:
                    pass
            chunk=""
    if chunk:
        try:
            objs.append(json.loads(chunk))
        except Exception:
            pass
    if len(objs)==1:
        return objs[0]
    return objs or None

# --------------- categorization ---------------
COMPILED = {k:[re.compile(p, re.I) for p in pats] for k,pats in CANONICAL.items()}

RULEID_MAP = {
    # Checkov (ids most used in study)
    "CKV_K8S_22": "PRIVILEGED",
    "CKV_K8S_26": "PRIV_ESCALATION",
    "CKV_K8S_37": "CAP_SYS_ADMIN",
    "CKV_K8S_152":"RUN_AS_NONROOT_FALSE",
    "CKV_K8S_230":"NO_SECCOMP",
    "CKV_K8S_235":"NO_SECCOMP",

    # Checkov - quality
    "CKV_K8S_8":  "NO_PROBES", "CKV_K8S_10": "NO_RES_LIMITS", "CKV_K8S_11": "NO_RES_LIMITS",
    "CKV_K8S_12": "NO_RES_LIMITS","CKV_K8S_13": "NO_RES_LIMITS","CKV_K8S_14": "IMAGE_LATEST","CKV_K8S_15":"IMAGE_LATEST",
}

def categorize(tool: str, title: str, message: str, rule_id: str):
    tool_norm = norm_tool(tool)
    if tool_norm == "Yamllint":
        return "YAML_FORMATTING"
    # Conftest special (CNI)
    txt_l = f"{title} {message}".lower()
    if tool_norm == "Conftest" and ("cni config" in txt_l and "privileged=true" in txt_l):
        return "CNI_EMBEDDED_PRIVILEGED"

    rid = (rule_id or "").strip().upper()
    if rid in RULEID_MAP:
        return RULEID_MAP[rid]

    text = f"{tool} {title} {message} {rule_id}".strip()
    for cid, regs in COMPILED.items():
        if any(r.search(text) for r in regs):
            return cid
    return None

# --------------- parse raw dir ---------------
def parse_raw_dir(raw_dir: Path):
    findings=[]
    for p in sorted(raw_dir.rglob("*")):
        if p.is_dir(): continue
        name = p.name.lower()
        src = "embedded" if is_embedded_output(p) else "original"
        parsed = load_json_relaxed(p) if name.endswith(".json") else None
        data = read_text(p)

        # Yamllint plaintext
        if "yamllint" in name and not name.endswith(".json"):
            for line in data.splitlines():
                m = re.match(r"^([^:]+):(\d+):(\d+):\s*(warning|error):\s*([a-z0-9\-]+):\s*(.+)$", line.strip(), re.I)
                if not m: 
                    continue
                fpath, ln, col, level, rule, msg = m.groups()
                findings.append(make_finding("Yamllint", fpath, f"{level.upper()}:{rule}", f"L{ln}C{col} {msg}", severity=level.upper(), rule_id=rule, source=src))
            continue

        handled = False
        if   "kubelinter"   in name and parsed is not None: handled = parse_kubelinter(parsed, findings, src)
        elif "kubeaudit"    in name and parsed is not None: handled = parse_kubeaudit(parsed, findings, src)
        elif "checkov"      in name and parsed is not None: handled = parse_checkov(parsed, findings, src)
        elif "trivy"        in name and parsed is not None: handled = parse_trivy(parsed, findings, src)
        elif "kubescore"    in name and parsed is not None: handled = parse_kubescore(parsed, findings, src)
        elif "polaris"      in name and parsed is not None: handled = parse_polaris(parsed, findings, src)
        elif "pluto"        in name and parsed is not None: handled = parse_pluto(parsed, findings, src)
        elif "rbacpolice"   in name and parsed is not None: handled = parse_rbacpolice(parsed, findings, src)
        elif "gitleaks"     in name and parsed is not None: handled = parse_gitleaks(parsed, findings, src)
        elif "conftest"     in name and parsed is not None: handled = parse_conftest(parsed, findings, src)
        elif "kubeconform"  in name and parsed is not None: handled = parse_kubeconform(parsed, findings, src)

        if (not handled) and parsed is not None:
            # Generic fallback with best-effort tool guess
            tool_guess = (
                "Kubescape" if "kubescape" in name else
                "KubeAudit" if "kubeaudit" in name else
                "Polaris" if "polaris" in name else
                "KubeConform" if "kubeconform" in name else
                "Pluto" if "pluto" in name else
                "RBACPolice" if "rbacpolice" in name else
                "Gitleaks" if "gitleaks" in name else
                "Conftest" if "conftest" in name else
                "KubeLinter" if "kubelinter" in name else
                "Checkov" if "checkov" in name else
                "Trivy" if "trivy" in name else
                "Unknown"
            )
            hits=[]; walk_json(parsed, hits)
            for f,t,m,rid in hits:
                findings.append(make_finding(tool_guess, f,t,m, rule_id=rid, source=src))

    return findings

# --------------- classification ---------------
def classify_special(tools: set, is_quality: bool) -> str:
    """
    Our study rule:
      - If ONLY KubeScore OR ONLY Polaris reported (file, category) → 'Needs corroboration'
      - Otherwise                                                → 'Actual (Correct)'
    """
    if tools == {"KubeScore"} or tools == {"Polaris"}:
        return "Needs corroboration"
    return "Actual (Correct)"

def normalize(findings:list):
    by_key={}
    seen=set()

    for f in findings:
        cat = categorize(f["tool"], f["title"], f["message"], f.get("rule_id",""))
        if not cat:
            continue

        # de-dup by short signature
        fp = sanitize_path(f["file"])
        sig_msg = re.sub(r"\s+"," ", (f["title"] + " " + f["message"]).strip().lower())[:140]
        sig = (fp, cat, f["tool"], sig_msg, f["source"])
        if sig in seen: 
            continue
        seen.add(sig)

        # Attempt file repair / hints
        file_ok = False
        if is_yaml_path(fp) or looks_like_yaml_in_text(f["message"]) or looks_like_yaml_in_text(f["title"]):
            file_ok = True
        elif f["tool"] in TOOL_ALLOW_RESOURCE_IDS and fp:
            file_ok = looks_like_yaml_in_text(f["message"]) or looks_like_yaml_in_text(f["title"]) \
                      or bool(re.search(r"\b(kind|apiVersion|metadata\.name)\b", f["message"], re.I))
        elif fp == "(unknown)":
            hint = extract_file_hint(f["message"] + " " + f["title"])
            if hint:
                fp = sanitize_path(hint); file_ok = True
        else:
            file_ok = bool(fp)
        if not file_ok:
            fp = "(unknown)"

        key=(fp, cat)
        if key not in by_key:
            by_key[key] = {
                "file": fp, "category": cat,
                "is_security": cat not in QUALITY_ONLY,
                "tools": {f["tool"]},
                "examples": [(f["title"] or f["message"])][:3],
                "occurrences": 1,
                "rule_ids": set([f.get("rule_id","")]) if f.get("rule_id") else set(),
                "sources": set([f.get("source","original")]),
                "confidence": TOOL_WEIGHT.get(f["tool"], 1),
            }
        else:
            rec=by_key[key]
            rec["tools"].add(f["tool"])
            if len(rec["examples"])<3: rec["examples"].append(f["title"] or f["message"])
            rec["occurrences"]+=1
            if f.get("rule_id"): rec["rule_ids"].add(f["rule_id"])
            rec["sources"].add(f.get("source","original"))
            rec["confidence"] += TOOL_WEIGHT.get(f["tool"], 1)

    normalized=[]
    for rec in sorted(by_key.values(), key=lambda r:(r["file"], r["category"])):
        classification = classify_special(rec["tools"], not rec["is_security"])
        normalized.append({
            "file": rec["file"],
            "category": rec["category"],
            "is_security": rec["is_security"],
            "support_count": len(rec["tools"]),
            "tools": sorted(list(rec["tools"])),
            "rule_ids": sorted([r for r in rec["rule_ids"] if r]),
            "examples": rec["examples"],
            "occurrences": rec["occurrences"],
            "sources": sorted(list(rec["sources"])),
            "confidence": rec["confidence"],
            "suggested_classification": classification,
            "is_true_positive": (classification == "Actual (Correct)"),
        })
    return normalized

def build_llm_payload(normalized):
    tasks=[]
    for n in normalized:
        if n["suggested_classification"] != "Actual (Correct)":
            continue
        tasks.append({
            "file": n["file"], "category": n["category"],
            "tools": n["tools"], "support_count": n["support_count"],
            "rule_ids": n["rule_ids"], "hints": n["examples"],
            "policy": "least-privilege"
        })
    return {"generated_at": now_iso(), "version": "sfk-v7.0-llm-payload", "items": tasks}

# --------------- main ---------------
def main():
    args = parse_args()
    raw_dir = Path(args.raw).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not raw_dir.exists():
        print(f"[!] Raw directory not found: {raw_dir}", file=sys.stderr)

    findings = parse_raw_dir(raw_dir)
    tools_seen_sorted = sorted({f["tool"] for f in findings})
    counts = {t: sum(1 for f in findings if f["tool"] == t) for t in tools_seen_sorted}
    print("Parsed findings by tool:", counts)

    normalized = normalize(findings)

    # --- per-file rollup
    by_file = {}
    for n in normalized:
        by_file.setdefault(n["file"], []).append(n)
    per_file = []
    for f, items in sorted(by_file.items()):
        tps = sum(1 for it in items if it["is_true_positive"])
        nc  = sum(1 for it in items if it["suggested_classification"] == "Needs corroboration")
        per_file.append({
            "file": f,
            "normalized_findings": len(items),
            "true_positives": tps,
            "needs_corroboration": nc,
            "precision_assumed": 1.0,  # we do not emit FPs from the normalizer by policy
            "confidence_sum": sum(it.get("confidence", 0) for it in items),
            "tools": sorted({t for it in items for t in it["tools"]}),
            "sources": sorted({s for it in items for s in it.get("sources", ["original"])}),
        })

    # normalized_findings.json
    (out_dir/"normalized_findings.json").write_text(json.dumps({
        "generated_at": now_iso(), "source": str(raw_dir),
        "total_raw_findings": len(findings),
        "normalized_count": len(normalized),
        "findings": normalized,
    }, indent=2), encoding="utf-8")

    # normalized_findings.csv
    with (out_dir/"normalized_findings.csv").open("w", newline="", encoding="utf-8") as f:
        w=csv.writer(f)
        w.writerow(["File","Category","IsSecurity","SupportCount","Tools","SuggestedClassification","IsTruePositive","RuleIDs","Examples","Sources","Confidence"])
        for n in normalized:
            w.writerow([
                n["file"], n["category"], n["is_security"], n["support_count"],
                ",".join(n["tools"]), n["suggested_classification"], "yes" if n["is_true_positive"] else "no",
                ",".join(n["rule_ids"]), " | ".join(n["examples"]), ",".join(n["sources"]), n.get("confidence",0)
            ])

    # summary.json
    (out_dir/"summary.json").write_text(json.dumps({
        "generated_at": now_iso(), "source": str(raw_dir),
        "tools_seen": tools_seen_sorted, "total_raw_findings": len(findings),
        "normalized_findings": len(normalized),
        "by_classification": {
            "Actual(Correct)": sum(1 for n in normalized if n["suggested_classification"]=="Actual (Correct)"),
            "NeedsCorroboration": sum(1 for n in normalized if n["suggested_classification"]=="Needs corroboration"),
        },
        "per_file": per_file
    }, indent=2), encoding="utf-8")

    # llm_payload.json
    llm = build_llm_payload(normalized)
    (out_dir/"llm_payload.json").write_text(json.dumps(llm, indent=2), encoding="utf-8")

    print(f"✅ Wrote {out_dir/'normalized_findings.json'}")
    print(f"✅ Wrote {out_dir/'normalized_findings.csv'}")
    print(f"✅ Wrote {out_dir/'summary.json'}")
    print(f"✅ Wrote {out_dir/'llm_payload.json'}")

if __name__ == "__main__":
    main()
