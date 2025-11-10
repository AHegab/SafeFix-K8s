# Moved from Normalizer/normalize.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SafeFix-K8s Normalizer (v11) — tailored to your dataset

- Parses raw outputs from 13 detectors (JSON or text).
- Maps to canonical SafeFix categories.
- Aggregates by (file, misconfiguration) with tool votes.
- Emits: llm_payload.json, normalized_findings.json, matrix.xlsx (if pandas/xlsxwriter present).

Run:
  python normalize_v11.py --raw /path/to/raw.zip --yamls /path/to/yamls --out ./output/normalization
"""

import argparse, json, re, sys, os, zipfile
from pathlib import Path
from datetime import datetime

try:
    import yaml  # optional
except Exception:
    yaml = None

try:
    import pandas as pd  # optional
except Exception:
    pd = None

TOOL_ALIASES = {
    "trivy":"Trivy","checkov":"Checkov","kubeaudit":"KubeAudit","kubelinter":"KubeLinter","kube-linter":"KubeLinter",
    "polaris":"Polaris","kubescore":"KubeScore","kubescape":"Kubescape","conftest":"Conftest","kubeconform":"KubeConform",
    "rbacpolice":"RBAC-Police","rbac-police":"RBAC-Police","pluto":"Pluto","gitleaks":"Gitleaks","yamllint":"Yamllint"
}

QUALITY_ONLY = {"NO_PROBES","NO_RES_LIMITS","DEPRECATED_API","SCHEMA_INVALID","YAML_FORMATTING"}
CRITICAL = {"PRIVILEGED","PRIV_ESCALATION","CAP_SYS_ADMIN","HOSTPATH","DOCKER_SOCK"}
HIGH = {"RUN_AS_NONROOT_FALSE","READONLY_ROOTFS_FALSE","NO_SECCOMP","NO_APPARMOR","HARD_CODED_CREDS","PLAIN_SECRET","RBAC_OVER_PERMISSIVE"}
MEDIUM = {"IMAGE_LATEST","HOST_NAMESPACE","NETWORK_POLICY_MISSING","SERVICEACCOUNT_TOKEN_AUTO","POD_DEFAULT_NAMESPACE","MISSING_CAP_DROP"}

CANONICAL = {
    "PRIVILEGED":[r"\bprivileged\s*:\s*true\b"],
    "PRIV_ESCALATION":[r"allowPrivilegeEscalation\s*:\s*true"],
    "CAP_SYS_ADMIN":[r"CAP_SYS_ADMIN(?!.*drop)"],
    "MISSING_CAP_DROP":[r"capabilities.*drop|NET_RAW"],
    "HOSTPATH":[r"\bhostPath\b"],
    "DOCKER_SOCK":[r"/var/run/docker\.sock"],
    "RUN_AS_NONROOT_FALSE":[r"runAsUser\s*:\s*0\b", r"runAsNonRoot\s*:\s*false\b"],
    "READONLY_ROOTFS_FALSE":[r"readOnlyRootFilesystem\s*:\s*false\b"],
    "NO_SECCOMP":[r"seccomp(Profile)?.*(missing|absent|unset)|RuntimeDefault.*(not|missing)"],
    "NO_APPARMOR":[r"apparmor.*(unconfined|missing)|AppArmorAnnotationMissing"],
    "SERVICEACCOUNT_TOKEN_AUTO":[r"automountServiceAccountToken\s*:\s*(true|null|)$"],
    "POD_DEFAULT_NAMESPACE":[r"namespace:\s*default\b", r"pods-in-default-namespace"],
    "IMAGE_LATEST":[r":[Ll]atest\b", r"not pinned"],
    "HOST_NAMESPACE":[r"hostPID\s*:\s*true|hostIPC\s*:\s*true|hostNetwork\s*:\s*true"],
    "RBAC_OVER_PERMISSIVE":[r"verbs\s*:\s*\[\s*\*\s*\]"],
    "NETWORK_POLICY_MISSING":[r"no network policy|unrestricted communication"],
    "HARD_CODED_CREDS":[r"password|apikey|api[_-]?key|secret"],
    "PLAIN_SECRET":[r"kind:\s*Secret|stringData:"],
    "NO_PROBES":[r"(liveness|readiness|startup)Probe.*(missing|not set|unset)"],
    "NO_RES_LIMITS":[r"(resources|limits|requests).*(missing|not set|unset)"],
    "DEPRECATED_API":[r"Deprecated apiVersion|removed-in|extensions/v1beta1"],
    "SCHEMA_INVALID":[r"KubeConform|schema invalid|missing property|additionalProperties"],
    "YAML_FORMATTING":[r"yamllint|indentation|syntax error|line too long"],
}

RULEID_MAP = {
    # Checkov
    "CKV_K8S_22":"PRIVILEGED","CKV_K8S_26":"PRIV_ESCALATION","CKV_K8S_37":"CAP_SYS_ADMIN","CKV_K8S_28":"MISSING_CAP_DROP",
    "CKV_K8S_16":"RUN_AS_NONROOT_FALSE","CKV_K8S_23":"READONLY_ROOTFS_FALSE","CKV_K8S_30":"NO_SECCOMP",
    "CKV_K8S_20":"SERVICEACCOUNT_TOKEN_AUTO","CKV_K8S_21":"POD_DEFAULT_NAMESPACE","CKV_K8S_14":"IMAGE_LATEST",
    "CKV_K8S_8":"NO_PROBES","CKV_K8S_10":"NO_RES_LIMITS","CKV_K8S_11":"NO_RES_LIMITS","CKV_K8S_12":"NO_RES_LIMITS","CKV_K8S_13":"NO_RES_LIMITS",
    # Trivy
    "KSV001":"PRIVILEGED","KSV002":"PRIV_ESCALATION","KSV003":"MISSING_CAP_DROP","KSV004":"MISSING_CAP_DROP","KSV106":"MISSING_CAP_DROP",
    # Kubescape
    "C-0057":"PRIVILEGED","C-0016":"PRIV_ESCALATION","C-0046":"CAP_SYS_ADMIN","C-0048":"HOSTPATH","C-0045":"HOSTPATH","C-0074":"HOSTPATH",
    "C-0013":"RUN_AS_NONROOT_FALSE","C-0017":"READONLY_ROOTFS_FALSE","C-0055":"NO_SECCOMP","C-0075":"IMAGE_LATEST",
    "C-0034":"SERVICEACCOUNT_TOKEN_AUTO","C-0061":"POD_DEFAULT_NAMESPACE","C-0038":"HOST_NAMESPACE","C-0041":"HOST_NAMESPACE",
    "C-0012":"HARD_CODED_CREDS","C-0207":"PLAIN_SECRET","C-0030":"NETWORK_POLICY_MISSING","C-0260":"NETWORK_POLICY_MISSING",
    "C-0056":"NO_PROBES","C-0018":"NO_PROBES","C-0270":"NO_RES_LIMITS","C-0271":"NO_RES_LIMITS",
    # Polaris (common rule keys)
    "hostIPCSet":"HOST_NAMESPACE","hostPIDSet":"HOST_NAMESPACE","hostNetworkSet":"HOST_NAMESPACE",
    "runAsRootAllowed":"RUN_AS_NONROOT_FALSE","runAsPrivileged":"PRIVILEGED","notReadOnlyRootFilesystem":"READONLY_ROOTFS_FALSE",
    "cpuLimitsMissing":"NO_RES_LIMITS","memoryLimitsMissing":"NO_RES_LIMITS","readinessProbeMissing":"NO_PROBES","livenessProbeMissing":"NO_PROBES"
}

# ...existing code...
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SafeFix-K8s Normalizer (v11) — tailored to your dataset

- Parses raw outputs from 13 detectors (JSON or text).
- Maps to canonical SafeFix categories.
- Aggregates by (file, misconfiguration) with tool votes.
- Emits: llm_payload.json, normalized_findings.json, matrix.xlsx (if pandas/xlsxwriter present).

Run:
  python normalize_v11.py --raw /path/to/raw.zip --yamls /path/to/yamls --out ./output/normalization
"""

import argparse, json, re, sys, os, zipfile
from pathlib import Path
from datetime import datetime

try:
    import yaml  # optional
except Exception:
    yaml = None

try:
    import pandas as pd  # optional
except Exception:
    pd = None

TOOL_ALIASES = {
    "trivy":"Trivy","checkov":"Checkov","kubeaudit":"KubeAudit","kubelinter":"KubeLinter","kube-linter":"KubeLinter",
    "polaris":"Polaris","kubescore":"KubeScore","kubescape":"Kubescape","conftest":"Conftest","kubeconform":"KubeConform",
    "rbacpolice":"RBAC-Police","rbac-police":"RBAC-Police","pluto":"Pluto","gitleaks":"Gitleaks","yamllint":"Yamllint"
}

QUALITY_ONLY = {"NO_PROBES","NO_RES_LIMITS","DEPRECATED_API","SCHEMA_INVALID","YAML_FORMATTING"}
CRITICAL = {"PRIVILEGED","PRIV_ESCALATION","CAP_SYS_ADMIN","HOSTPATH","DOCKER_SOCK"}
HIGH = {"RUN_AS_NONROOT_FALSE","READONLY_ROOTFS_FALSE","NO_SECCOMP","NO_APPARMOR","HARD_CODED_CREDS","PLAIN_SECRET","RBAC_OVER_PERMISSIVE"}
MEDIUM = {"IMAGE_LATEST","HOST_NAMESPACE","NETWORK_POLICY_MISSING","SERVICEACCOUNT_TOKEN_AUTO","POD_DEFAULT_NAMESPACE","MISSING_CAP_DROP"}

CANONICAL = {
    "PRIVILEGED":[r"\bprivileged\s*:\s*true\b"],
    "PRIV_ESCALATION":[r"allowPrivilegeEscalation\s*:\s*true"],
    "CAP_SYS_ADMIN":[r"CAP_SYS_ADMIN(?!.*drop)"],
    "MISSING_CAP_DROP":[r"capabilities.*drop|NET_RAW"],
    "HOSTPATH":[r"\bhostPath\b"],
    "DOCKER_SOCK":[r"/var/run/docker\.sock"],
    "RUN_AS_NONROOT_FALSE":[r"runAsUser\s*:\s*0\b", r"runAsNonRoot\s*:\s*false\b"],
    "READONLY_ROOTFS_FALSE":[r"readOnlyRootFilesystem\s*:\s*false\b"],
    "NO_SECCOMP":[r"seccomp(Profile)?.*(missing|absent|unset)|RuntimeDefault.*(not|missing)"],
    "NO_APPARMOR":[r"apparmor.*(unconfined|missing)|AppArmorAnnotationMissing"],
    "SERVICEACCOUNT_TOKEN_AUTO":[r"automountServiceAccountToken\s*:\s*(true|null|)$"],
    "POD_DEFAULT_NAMESPACE":[r"namespace:\s*default\b", r"pods-in-default-namespace"],
    "IMAGE_LATEST":[r":[Ll]atest\b", r"not pinned"],
    "HOST_NAMESPACE":[r"hostPID\s*:\s*true|hostIPC\s*:\s*true|hostNetwork\s*:\s*true"],
    "RBAC_OVER_PERMISSIVE":[r"verbs\s*:\s*\[\s*\*\s*\]"],
    "NETWORK_POLICY_MISSING":[r"no network policy|unrestricted communication"],
    "HARD_CODED_CREDS":[r"password|apikey|api[_-]?key|secret"],
    "PLAIN_SECRET":[r"kind:\s*Secret|stringData:"],
    "NO_PROBES":[r"(liveness|readiness|startup)Probe.*(missing|not set|unset)"],
    "NO_RES_LIMITS":[r"(resources|limits|requests).*(missing|not set|unset)"],
    "DEPRECATED_API":[r"Deprecated apiVersion|removed-in|extensions/v1beta1"],
    "SCHEMA_INVALID":[r"KubeConform|schema invalid|missing property|additionalProperties"],
    "YAML_FORMATTING":[r"yamllint|indentation|syntax error|line too long"],
}

RULEID_MAP = {
    # Checkov
    "CKV_K8S_22":"PRIVILEGED","CKV_K8S_26":"PRIV_ESCALATION","CKV_K8S_37":"CAP_SYS_ADMIN","CKV_K8S_28":"MISSING_CAP_DROP",
    "CKV_K8S_16":"RUN_AS_NONROOT_FALSE","CKV_K8S_23":"READONLY_ROOTFS_FALSE","CKV_K8S_30":"NO_SECCOMP",
    "CKV_K8S_20":"SERVICEACCOUNT_TOKEN_AUTO","CKV_K8S_21":"POD_DEFAULT_NAMESPACE","CKV_K8S_14":"IMAGE_LATEST",
    "CKV_K8S_8":"NO_PROBES","CKV_K8S_10":"NO_RES_LIMITS","CKV_K8S_11":"NO_RES_LIMITS","CKV_K8S_12":"NO_RES_LIMITS","CKV_K8S_13":"NO_RES_LIMITS",
    # Trivy
    "KSV001":"PRIVILEGED","KSV002":"PRIV_ESCALATION","KSV003":"MISSING_CAP_DROP","KSV004":"MISSING_CAP_DROP","KSV106":"MISSING_CAP_DROP",
    # Kubescape
    "C-0057":"PRIVILEGED","C-0016":"PRIV_ESCALATION","C-0046":"CAP_SYS_ADMIN","C-0048":"HOSTPATH","C-0045":"HOSTPATH","C-0074":"HOSTPATH",
    "C-0013":"RUN_AS_NONROOT_FALSE","C-0017":"READONLY_ROOTFS_FALSE","C-0055":"NO_SECCOMP","C-0075":"IMAGE_LATEST",
    "C-0034":"SERVICEACCOUNT_TOKEN_AUTO","C-0061":"POD_DEFAULT_NAMESPACE","C-0038":"HOST_NAMESPACE","C-0041":"HOST_NAMESPACE",
    "C-0012":"HARD_CODED_CREDS","C-0207":"PLAIN_SECRET","C-0030":"NETWORK_POLICY_MISSING","C-0260":"NETWORK_POLICY_MISSING",
    "C-0056":"NO_PROBES","C-0018":"NO_PROBES","C-0270":"NO_RES_LIMITS","C-0271":"NO_RES_LIMITS",
    # Polaris (common rule keys)
    "hostIPCSet":"HOST_NAMESPACE","hostPIDSet":"HOST_NAMESPACE","hostNetworkSet":"HOST_NAMESPACE",
    "runAsRootAllowed":"RUN_AS_NONROOT_FALSE","runAsPrivileged":"PRIVILEGED","notReadOnlyRootFilesystem":"READONLY_ROOTFS_FALSE",
    "cpuLimitsMissing":"NO_RES_LIMITS","memoryLimitsMissing":"NO_RES_LIMITS","readinessProbeMissing":"NO_PROBES","livenessProbeMissing":"NO_PROBES"
}

def now_iso(): return datetime.utcnow().isoformat(timespec="seconds")+"Z"
def read_text(p:Path):
    try: return p.read_text(encoding="utf-8", errors="replace")
    except Exception: return ""

def norm_tool(name:str)->str:
    n=(name or "").lower().replace(" ","_")
    for k,v in TOOL_ALIASES.items():
        if k in n: return v
    return name or "Unknown"

def load_json_relaxed(text:str):
    try: return json.loads(text)
    except Exception: pass
    items=[]
    for line in text.splitlines():
        s=line.strip()
        if not s: continue
        try: items.append(json.loads(s))
        except Exception: continue
    return items if items else None

def parse_file(tool:str, text:str):
    hits=[]; low=tool.lower()
    def add(title,msg,rule_id="",file_path=""):
        hits.append({"tool":tool,"title":title or "","message":msg or "","rule_id":rule_id or "","file":file_path or ""})
    parsed=load_json_relaxed(text)
    if parsed is not None:
        if "trivy" in low and isinstance(parsed, dict):
            for res in parsed.get("Results",[]) or []:
                tgt=res.get("Target","")
                for mc in res.get("Misconfigurations",[]) or []:
                    add(mc.get("Title",""), mc.get("Message",""), mc.get("ID",""), tgt)
            return hits
        if "checkov" in low and isinstance(parsed, dict):
            for it in parsed.get("results",{}).get("failed_checks",[]) or []:
                add(it.get("check_name",""), it.get("description",""), it.get("check_id",""), it.get("file_path") or it.get("repo_file_path",""))
            return hits
        if "kubelinter" in low and isinstance(parsed, dict):
            for it in parsed.get("reports",[]) or []:
                add(it.get("check",""), it.get("diagnostic",""), "", it.get("object") or it.get("filename",""))
            return hits
        if "polaris" in low and isinstance(parsed, dict):
            for item in parsed.get("Results",[]) or []:
                kind=item.get("Kind",""); ns=item.get("Namespace",""); name=item.get("Name","")
                file_hint=f"{ns}/{kind}/{name}".strip("/")
                pod=item.get("PodResult",{})
                if isinstance(pod, dict):
                    for cres in pod.get("ContainerResults",[]) or []:
                        for cid,chk in (cres.get("Results",{}) or {}).items():
                            if isinstance(chk, dict) and chk.get("Success") is False:
                                add(cid, chk.get("Message",""), cid, file_hint)
                inner=item.get("Results",{})
                if isinstance(inner, dict):
                    for cid,chk in inner.items():
                        if isinstance(chk, dict) and chk.get("Success") is False:
                            add(cid, chk.get("Message",""), cid, file_hint)
            return hits
        if "kubescape" in low and isinstance(parsed, dict):
            for result in parsed.get("results",[]) or []:
                rid=result.get("resourceID","")
                for control in result.get("controls",[]) or []:
                    st=(control.get("status",{}) or {}).get("status"); 
                    if st!="failed": continue
                    cid=control.get("controlID",""); cname=control.get("name","")
                    for rule in control.get("rules",[]) or []:
                        if rule.get("status")=="failed":
                            add(cname, rule.get("name",""), cid, rid)
            return hits
        if "kubeconform" in low:
            items=parsed if isinstance(parsed, list) else (parsed.get("resources") or [])
            for it in items:
                if str(it.get("status","")).lower()!="invalid": 
                    continue
                fp=it.get("filePath") or it.get("filename") or it.get("path","")
                msg="; ".join([e.get("msg","") for e in it.get("errors",[])]) if isinstance(it.get("errors"), list) else str(it.get("errors",""))
                add("KubeConform", msg, "KUBECONFORM_INVALID", fp)
            return hits
        if "kubeaudit" in low and isinstance(parsed, list):
            for it in parsed: 
                t=it.get("auditResultName","") or it.get("AuditResultName","")
                add(t, it.get("msg",""), t, it.get("file",""))
            return hits
        if "pluto" in low and isinstance(parsed, dict):
            for it in parsed.get("items",[]) or []:
                api=it.get("api",{}) or {}
                fp=it.get("filePath","") or it.get("filename","") or it.get("path","")
                add(f"{api.get('kind','')} {api.get('version','')}", "Deprecated apiVersion", api.get("version",""), fp)
            return hits
        if "rbac-police" in low or "rbacpolice" in low:
            if isinstance(parsed, list):
                for it in parsed:
                    add(it.get("rule",""), it.get("message",""), "", it.get("file",""))
            return hits
        if "gitleaks" in low and isinstance(parsed, list):
            for it in parsed:
                add(it.get("RuleID","") or "Gitleaks", it.get("Match",""), it.get("RuleID",""), it.get("File","") or it.get("file",""))
            return hits
        if "conftest" in low and isinstance(parsed, list):
            for it in parsed:
                fp=it.get("filename","") or it.get("file","")
                for f in it.get("failures",[]) or []:
                    add("Conftest", f.get("msg",""), "", fp)
            return hits
    # text fallback
    if "yamllint" in low:
        for line in text.splitlines():
            m=re.match(r"^([^:]+):\d+:\d+:\s*(warning|error):\s*([a-z0-9\-]+):\s*(.+)$", line.strip(), re.I)
            if m:
                fp, level, rule, msg = m.group(1), m.group(2), m.group(3), m.group(4)
                add(f"{level.upper()}:{rule}", msg, rule, fp)
        return hits
    for line in text.splitlines():
        s=line.strip()
        if len(s)>8:
            add(tool, s, "", "")
    return hits

def categorize(title, message, rule_id, tool):
    rid=(rule_id or "").strip().upper()
    if rid in RULEID_MAP and RULEID_MAP[rid]:
        return RULEID_MAP[rid]
    txt=f"{tool} {title} {message} {rule_id}"
    def anymatch(cat):
        for pat in CANONICAL.get(cat, []):
            if re.search(pat, txt, re.I): return True
        return False
    for cat in CRITICAL:
        if anymatch(cat): return cat
    for cat in HIGH:
        if anymatch(cat): return cat
    for cat in MEDIUM:
        if anymatch(cat): return cat
    for cat in QUALITY_ONLY:
        if anymatch(cat): return cat
    return None

def severity_for(cat):
    if cat in CRITICAL: return "CRITICAL"
    if cat in HIGH: return "HIGH"
    if cat in MEDIUM: return "MEDIUM"
    if cat in QUALITY_ONLY: return "LOW"
    return "MEDIUM"

def aggregate(hits):
    by={}
    # Build test file lookup for improved mapping
    test_dir = Path("tests")
    test_files = {f.name: f for f in test_dir.glob("*.yaml")}
    def map_path(raw_path):
        # Direct match
        if raw_path in test_files:
            return str(test_files[raw_path])
        # Try basename match
        base = os.path.basename(raw_path)
        if base in test_files:
            return str(test_files[base])
        # Synthetic resource path mapping
        m = re.search(r"([A-Za-z0-9_.-]+)\.ya?ml", raw_path)
        if m and m.group(1)+".yaml" in test_files:
            return str(test_files[m.group(1)+".yaml"])
        # Try resource name/kind matching
        for fname, fpath in test_files.items():
            if fname.split(".")[0] in raw_path:
                return str(fpath)
        return raw_path

    for h in hits:
        cat=categorize(h.get("title",""), h.get("message",""), h.get("rule_id",""), h.get("tool",""))
        if not cat: continue
        f=h.get("file","") or "(unknown)"
        mapped_f = map_path(f)
        k=(mapped_f,cat)
        rec=by.setdefault(k, {"file":mapped_f,"category":cat,"severity":severity_for(cat),"tools":set(),"rule_ids":set(),"examples":[], "occ":0})
        rec["tools"].add(h.get("tool",""))
        rid=(h.get("rule_id","") or "").strip()
        if rid: rec["rule_ids"].add(rid)
        if len(rec["examples"])<3:
            ex=h.get("title") or h.get("message")
            if ex and ex not in rec["examples"]:
                rec["examples"].append(ex)
        rec["occ"]+=1
    out=[]
    for (f,c),r in by.items():
        out.append({"file":f,"category":c,"severity":r["severity"],"tools":sorted(r["tools"]),"support_count":len(r["tools"]),"rule_ids":sorted(r["rule_ids"]),"examples":r["examples"],"occurrences":r["occ"]})
    order={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    out.sort(key=lambda x:(order.get(x["severity"],9), -x["support_count"], x["file"], x["category"]))
    return out

def build_matrix(items, outdir:Path):
    if pd is None: return None
    tools = ["Trivy","Checkov","KubeAudit","KubeLinter","Polaris","KubeScore","Kubescape","Conftest","KubeConform","RBAC-Police","Pluto","Gitleaks","Yamllint"]
    rows=[]
    for it in items:
        if it["category"] in QUALITY_ONLY: 
            continue
        row={"File":it["file"],"Misconfiguration":it["category"]}
        for t in tools:
            row[t]="✔" if t in it["tools"] else ""
        rows.append(row)
    df=pd.DataFrame(rows, columns=["File","Misconfiguration"]+tools)
    p=outdir/"matrix.xlsx"
    with pd.ExcelWriter(p, engine="xlsxwriter") as w:
        df.to_excel(w, index=False, sheet_name="Detections")
        ws=w.sheets["Detections"]; ws.set_column(0,0,40); ws.set_column(1,1,44); ws.set_column(2,14,12); ws.freeze_panes(1,2)
    return str(p)

def ensure_raw_dir(raw_arg:str, workdir:Path)->Path:
    p=Path(raw_arg)
    if p.exists():
        if p.is_dir(): return p.resolve()
        if zipfile.is_zipfile(p):
            zdir=workdir/"raw_unpack"; zdir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(p,'r') as z: z.extractall(zdir)
            return zdir.resolve()
    return Path(raw_arg).resolve()

def parse_raw(root:Path):
    hits=[]
    for p in sorted(root.rglob("*")):
        if p.is_dir(): continue
        tool=norm_tool(p.name)
        text=read_text(p)
        if not text.strip(): continue
        hits.extend(parse_file(tool, text))
    return hits

