# normalizer/normalize_all.py
# Robust normalizer for SafeFixK8s outputs + Consensus (N tools agree)
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple, Optional, Set

# ------------------------
# defaults / constants
# ------------------------

ROOT    = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "detection" / "output" / "raw"
OUT_JSON= ROOT / "output" / "normalized_findings.json"
OUT_DIR = ROOT / "output"

SEV_ORDER = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

# ------------------------
# helpers
# ------------------------

def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="microseconds") + "Z"

def warn(msg: str) -> None:
    print(f"[WARN] {msg}", file=sys.stderr)

def note(msg: str) -> None:
    print(f"[info] {msg}")

def _hash_id(parts: Iterable[str]) -> str:
    h = hashlib.md5()
    for p in parts:
        if p is None:
            p = ""
        if not isinstance(p, str):
            p = json.dumps(p, sort_keys=True, ensure_ascii=False, default=str)
        h.update(p.encode("utf-8", errors="ignore"))
        h.update(b"|")
    return h.hexdigest()

def relpath_or_same(p: str) -> str:
    """Normalize file paths to be relative to repo root when possible."""
    try:
        if not p:
            return ""
        pp = Path(p)
        # If it's already relative, keep it
        if not pp.is_absolute():
            return str(pp.as_posix())
        # Try to make relative to ROOT
        return str(pp.relative_to(ROOT).as_posix())
    except Exception:
        return p.replace("\\", "/")

def load_json(p: Path) -> Any:
    """
    Robust loader:
    - UTF-8 with optional BOM
    - Accepts JSON arrays/objects
    - If JSONL, returns a list of decoded objects
    - If file is placeholder / not valid JSON, returns []
    """
    try:
        if not p.exists() or p.stat().st_size == 0:
            return []
        raw = p.read_bytes()
        # Strip UTF-8 BOM if present
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]

        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            return []

        # Skip obvious placeholders or docker error text
        low = text.lower()
        if ("placeholder" in low) or ("error response from daemon" in low):
            warn(f"Placeholder/diagnostic text in {p}; skipping.")
            return []

        # First try standard JSON
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try JSON Lines
            objs: List[Any] = []
            ok = True
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    objs.append(json.loads(line))
                except json.JSONDecodeError:
                    ok = False
                    break
            if ok and objs:
                return objs

            warn(f"Bad JSON in {p}: falling back to empty.")
            return []
    except Exception as e:
        warn(f"Failed to read {p}: {e}")
        return []

def iter_json_lines(p: Path) -> Iterable[Any]:
    """Yield JSON objects from a file that may contain JSON-lines with noise."""
    if not p.exists() or p.stat().st_size == 0:
        warn(f"Missing/empty: {p}")
        return
    with p.open("r", encoding="utf-8-sig", errors="ignore") as f:
        for ln in f:
            s = ln.strip()
            if not s:
                continue
            try:
                yield json.loads(s)
            except Exception:
                continue

def safe_text(p: Path) -> str:
    if not p.exists() or p.stat().st_size == 0:
        warn(f"Missing/empty: {p}")
        return ""
    try:
        return p.read_text(encoding="utf-8-sig", errors="ignore")
    except Exception as e:
        warn(f"Text read failed {p}: {e}")
        return ""

def sev_norm(s: Any, default="INFO") -> str:
    if s is None:
        return default
    s = str(s)
    su = s.upper()
    sl = s.lower()
    if su in SEV_ORDER:
        return su
    if sl == "critical": return "CRITICAL"
    if sl in {"warning","warn"}: return "MEDIUM"
    if sl in {"advice","ok","passed","bestpractice","best_practice","info"}: return "INFO"
    if su.startswith("WARN"): return "MEDIUM"
    if su.startswith("ERR"): return "HIGH"
    return default

def _norm_msg(msg: Any) -> str:
    if isinstance(msg, dict):
        for k in ("Message", "message", "summary", "text", "reason", "description"):
            v = msg.get(k)
            if isinstance(v, str):
                return v
        return json.dumps(msg, sort_keys=True, ensure_ascii=False, default=str)
    if msg is None:
        return ""
    return str(msg)

def _mk(
    tool: str,
    rule: str | None,
    severity: str | None,
    kind: str | None,
    name: str | None,
    message: Any,
    file: str | None = None,
    line: int | None = None,
    labels: Dict[str, Any] | None = None,
    namespace: Optional[str] = None,
    tool_version: Optional[str] = None,
    raw_file: Optional[str] = None,
) -> Dict[str, Any]:
    msg = _norm_msg(message)
    file = relpath_or_same(file or "")
    rid = _hash_id([tool, rule, kind, namespace or "", name, file, str(line or 0), msg])
    d = {
        "findingId": rid,
        "tool": tool,
        "ruleId": (rule or "unknown"),
        "severity": sev_norm(severity, default="INFO"),
        "resourceRef": {
            "kind": (kind or "Object"),
            "name": (name or "unknown"),
            "namespace": namespace or ""
        },
        "message": msg if isinstance(message, str) else message,
        "location": {"file": file, "line": line},
        "labels": labels or {}
    }
    if tool_version:
        d["toolVersion"] = tool_version
    if raw_file:
        d["rawFile"] = raw_file
    return d

def highest_severity(severities: Iterable[str]) -> str:
    top = "INFO"
    for s in severities:
        ss = sev_norm(s, "INFO")
        if SEV_ORDER[ss] > SEV_ORDER[top]:
            top = ss
    return top

# ------------------------
# loaders: existing tools
# ------------------------

def from_kubeaudit(p: Path) -> List[Dict]:
    data = load_json(p)
    findings: List[Dict] = []
    items = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
    for it in items:
        if not isinstance(it, dict):
            continue
        # kubeaudit outputs vary; normalize common fields
        rule = it.get("auditResultName") or it.get("name") or it.get("id") or "kubeaudit"
        sev_raw = it.get("severity") or it.get("level") or "MEDIUM"
        sev = sev_norm(sev_raw)
        obj = it.get("resource") or {}
        kind = obj.get("kind") or "Object"
        name = obj.get("name") or "unknown"
        ns = obj.get("namespace") or obj.get("ns")
        msg = it.get("message") or it.get("remediation") or rule
        findings.append(_mk("kubeaudit", rule, sev, kind, name, msg, labels={}, namespace=ns, raw_file=str(p)))
    return findings

def from_kubelinter(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings = []
    for it in data.get("Reports", []) or data.get("reports", []) or []:
        if not isinstance(it, dict):
            continue
        tool = "kubelinter"
        check_field = it.get("Check")
        if isinstance(check_field, dict):
            rule = check_field.get("name") or check_field.get("id")
        else:
            rule = check_field or it.get("check")
        diag = it.get("Diagnostic", {})
        if isinstance(diag, dict):
            msg = diag.get("Message") or diag.get("message")
        else:
            msg = it.get("Message") or it.get("message")
        sev  = it.get("Severity") or it.get("severity") or "MEDIUM"
        obj  = it.get("Object", {}) or it.get("object", {}) or {}
        k8s_obj = obj.get("K8sObject") or obj.get("k8sObject") or {}
        if isinstance(k8s_obj, dict):
            gvk = k8s_obj.get("GroupVersionKind") or {}
            kind = gvk.get("Kind") or k8s_obj.get("kind") or "Object"
            name = k8s_obj.get("Name") or k8s_obj.get("name") or "unknown"
            ns   = k8s_obj.get("Namespace") or k8s_obj.get("namespace")
        else:
            kind = obj.get("kind") or "Object"
            name = obj.get("name") or "unknown"
            ns   = obj.get("namespace")
        metadata = obj.get("Metadata") or obj.get("metadata") or {}
        file = metadata.get("FilePath") or metadata.get("filePath") or obj.get("file") or ""
        findings.append(_mk(tool, rule, sev, kind, name, {"Message": msg or rule}, file=file, namespace=ns, raw_file=str(p)))
    return findings

def from_polaris(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings = []
    for res in data.get("Results", []) or data.get("results", []):
        if not isinstance(res, dict):
            continue
        kind = res.get("Kind") or res.get("kind") or "Object"
        name = res.get("Name") or res.get("name") or "unknown"
        namespace = res.get("Namespace") or res.get("namespace") or ""
        file = res.get("FilePath") or res.get("filePath") or ""
        checks_dict = res.get("Results", {}) or res.get("results", {})
        if isinstance(checks_dict, dict):
            for check_id, check_data in checks_dict.items():
                if not isinstance(check_data, dict):
                    continue
                if check_data.get("Success", True):
                    continue
                rule = check_data.get("ID") or check_id
                sev = check_data.get("Severity") or check_data.get("severity") or "INFO"
                if str(sev).lower() == "danger":
                    sev = "HIGH"
                elif str(sev).lower() == "warning":
                    sev = "MEDIUM"
                msg = check_data.get("Message") or check_data.get("message") or rule
                findings.append(_mk("polaris", rule, sev, kind, name, msg, file=file, namespace=namespace, raw_file=str(p)))
        pod_result = res.get("PodResult") or res.get("podResult")
        if isinstance(pod_result, dict):
            pod_checks = pod_result.get("Results", {}) or pod_result.get("results", {})
            if isinstance(pod_checks, dict):
                for check_id, check_data in pod_checks.items():
                    if not isinstance(check_data, dict):
                        continue
                    if check_data.get("Success", True):
                        continue
                    rule = check_data.get("ID") or check_id
                    sev = check_data.get("Severity") or check_data.get("severity") or "INFO"
                    if str(sev).lower() == "danger":
                        sev = "HIGH"
                    elif str(sev).lower() == "warning":
                        sev = "MEDIUM"
                    msg = check_data.get("Message") or check_data.get("message") or rule
                    findings.append(_mk("polaris", rule, sev, kind, name, msg, file=file, namespace=namespace, raw_file=str(p)))
    return findings

def from_trivy_config(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings = []
    for r in data.get("Results", []) or data.get("results", []) or []:
        file = r.get("Target") or r.get("target") or ""
        for m in r.get("Misconfigurations", []) or r.get("misconfigurations", []) or []:
            rule = m.get("ID") or m.get("id") or "unknown"
            sev  = m.get("Severity") or m.get("severity") or "INFO"
            msg  = m.get("Message") or m.get("message") or rule
            kind = "Object"
            name = "unknown"
            ns   = None
            labels = {"url": m.get("PrimaryURL") or m.get("primaryURL")}
            findings.append(_mk("trivy-config", rule, sev, kind, name, msg, file=file, labels=labels, namespace=ns, raw_file=str(p)))
    return findings

def from_kubescore(p: Path) -> List[Dict]:
    data = load_json(p)
    findings: List[Dict] = []
    if not data:
        return findings
    items = data if isinstance(data, list) else [data]
    for item in items:
        objmeta = item.get("object", {}) if isinstance(item, dict) else {}
        kind = (objmeta.get("kind") or item.get("kind") or "Object") if isinstance(item, dict) else "Object"
        name = (objmeta.get("name") or item.get("name") or "unknown") if isinstance(item, dict) else "unknown"
        ns   = (objmeta.get("namespace") or item.get("namespace"))
        file = ""
        if isinstance(item, dict):
            file = item.get("fileName") or item.get("filename") or item.get("file") or ""
        checks = []
        if isinstance(item, dict) and isinstance(item.get("checks"), list):
            checks = item["checks"]
        elif isinstance(item, dict) and any(k in item for k in ("check","id","grade","severity","comment","comments","message")):
            checks = [item]
        for chk in checks:
            rule = (chk.get("check") or chk.get("id") or chk.get("name") or "unknown")
            raw_sev = (chk.get("grade") or chk.get("severity") or chk.get("type") or "MEDIUM")
            if str(raw_sev).lower() == "security":
                raw_sev = "HIGH"
            msg = (chk.get("comment") or chk.get("comments") or chk.get("message") or chk)
            findings.append(_mk("kube-score", rule, raw_sev, kind, name, msg, file=file, namespace=ns, raw_file=str(p)))
    return findings

_yamllint_re = re.compile(r"^(?P<file>.+):(?P<line>\d+):(?P<col>\d+):\s\[(?P<severity>\w+)\]\s(?P<message>.+)$")

def from_yamllint(p: Path) -> List[Dict]:
    txt = safe_text(p)
    findings = []
    for ln in txt.splitlines():
        m = _yamllint_re.match(ln.strip())
        if not m:
            continue
        d = m.groupdict()
        findings.append(_mk(
            "yamllint",
            rule="yaml-lint",
            severity=d.get("severity","LOW"),
            kind="YAML",
            name=Path(d["file"]).name,
            message=d["message"],
            file=d["file"],
            line=int(d["line"]),
            namespace=None,
            raw_file=str(p)
        ))
    return findings

# ------------------------
# loaders: optional/extra tools already scaffolded
# ------------------------

def from_checkov(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings: List[Dict] = []
    items: List[Dict] = []
    if isinstance(data, list):
        items = [d for d in data if isinstance(d, dict)]
    elif isinstance(data, dict):
        items = [data]
    for item in items:
        res = (item.get("results") or {}) if isinstance(item, dict) else {}
        for r in (res.get("failed_checks") or []):
            rule = r.get("check_id")
            sev  = r.get("severity") or "INFO"
            msg  = r.get("check_name") or r.get("description")
            addr = r.get("resource") or r.get("resource_address") or ""
            kind = "Object"
            name = addr or "unknown"
            file = r.get("file_path") or r.get("repo_file_path") or ""
            line = (r.get("file_line_range") or [None, None])[0]
            labels = {"guideline": r.get("guideline")}
            findings.append(_mk("checkov", rule, sev, kind, name, msg, file=file, line=line, labels=labels, raw_file=str(p)))
    return findings

def from_terrascan(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings = []
    for v in data.get("results", {}).get("violations", []):
        rule = v.get("rule_name") or v.get("rule_id") or v.get("violation_id")
        sev  = v.get("severity") or "MEDIUM"
        msg  = v.get("description") or v.get("category") or v.get("violation_message") or v
        kind = v.get("resource", {}).get("type") or "Object"
        name = v.get("resource", {}).get("name") or "unknown"
        file = v.get("file") or v.get("file_path") or ""
        line = v.get("line")
        findings.append(_mk("terrascan", rule, sev, kind, name, msg, file=file, line=line, raw_file=str(p)))
    return findings

def from_gitleaks(p: Path) -> List[Dict]:
    findings = []
    try:
        if not p.exists() or p.stat().st_size == 0:
            return findings
        raw_bytes = p.read_bytes()
        if raw_bytes.startswith(b"\xef\xbb\xbf"):
            raw_bytes = raw_bytes[3:]
        content = raw_bytes.decode("utf-8", errors="ignore")
        import re as _re
        match = _re.search(r'\n\[\s*\n\s*\{', content)
        if not match:
            return findings
        json_start = match.start() + 1
        json_part = content[json_start:].strip()
        data = json.loads(json_part)
        if not isinstance(data, list):
            data = [data]
        for item in data:
            if not isinstance(item, dict):
                continue
            rule_id = item.get("RuleID")
            if not rule_id:
                continue
            description = item.get("Description", "")
            file_path = item.get("File", "")
            start_line = item.get("StartLine", 0)
            file_name = Path(file_path).name if file_path else "unknown"
            severity = "HIGH"
            if "generic" in str(rule_id).lower():
                severity = "MEDIUM"
            message = description or "Secret detected"
            findings.append(_mk(
                "gitleaks",
                rule_id,
                severity,
                "Secret",
                file_name,
                message,
                file=file_path,
                line=int(start_line),
                raw_file=str(p)
            ))
    except Exception as e:
        warn(f"Failed to parse {p.name}: {e}")
    return findings

def from_trufflehog(p: Path) -> List[Dict]:
    findings = []
    for it in iter_json_lines(p):
        if not isinstance(it, dict):
            continue
        detector = it.get("DetectorName") or it.get("DetectorType") or it.get("rule")
        if not detector:
            continue
        sev = "HIGH"
        msg = "High-entropy or credential-like pattern"
        src = (((it.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
        file = src.get("file") or it.get("File") or ""
        line = src.get("line") or it.get("Line") or 0
        findings.append(_mk("trufflehog", detector, sev, "Repository", "\\", msg, file=file, line=int(line or 0), raw_file=str(p)))
    return findings

# ------------------------
# NEW loaders: kube-bench, rbac-police, pluto
# ------------------------

def from_kubebench(p: Path) -> List[Dict]:
    """
    kube-bench typical JSON structure:
    {
      "Controls": [
        {
          "id":"1 Master Node Security Configuration",
          "tests":[
            {
              "section":"1.1",
              "desc":"Ensure ...",
              "results":[{"test_number":"1.1.1","test_desc":"Ensure ...", "status":"FAIL"|"WARN"|"PASS", "audit":"...", "actual_value":"...", ...}]
            }
          ]
        }
      ],
      "node_name":"ip-10-0-0-1", "version":"..."
    }
    We emit only FAIL/WARN as findings.
    """
    data = load_json(p)
    if not data:
        return []
    
    findings: List[Dict] = []
    
    # Handle list or dict
    if isinstance(data, list):
        # If it's a list, it might be a list of result objects or placeholder
        if not data or not isinstance(data[0], dict):
            return []
        # Take first item if it looks like a kube-bench result
        if "Controls" in data[0] or "controls" in data[0]:
            data = data[0]
        else:
            # It's a list of placeholder objects, skip
            return []
    
    if not isinstance(data, dict):
        return []
    
    node = data.get("node_name") or data.get("nodeName") or "node"
    version = data.get("version") or data.get("kube-bench_version") or None
    ctrls = data.get("Controls") or data.get("controls") or []
    for ctrl in ctrls:
        tests = ctrl.get("tests") or []
        for t in tests:
            results = t.get("results") or []
            for r in results:
                status = str(r.get("status","")).upper()
                if status not in {"FAIL","WARN"}:
                    continue
                rule = r.get("test_number") or r.get("id") or t.get("section") or "kube-bench"
                msg  = r.get("test_desc") or r.get("desc") or "CIS benchmark finding"
                sev  = "HIGH" if status == "FAIL" else "MEDIUM"
                findings.append(_mk(
                    "kube-bench", rule, sev,
                    kind="Node", name=node, message=msg,
                    labels={"status": status, "control": ctrl.get("id") or ctrl.get("title")},
                    tool_version=version, raw_file=str(p)
                ))
    return findings

def from_rbacpolice(p: Path) -> List[Dict]:
    """
    rbac-police JSON varies by version/flags. General patterns include objects describing risky bindings/roles, with fields like:
      - kind/name/namespace of Role/ClusterRole/RoleBinding
      - verdict/risk/reason (overly permissive, wildcard verbs/resources)
      - subjects (serviceAccount, user, group)
    We capture high-level 'rule' from risk/reason and attach subject/role info in labels.
    """
    data = load_json(p)
    if not data:
        return []
    
    findings: List[Dict] = []
    
    # Ensure we have a list
    items = data if isinstance(data, list) else [data]
    for it in items:
        if not isinstance(it, dict):
            continue
        kind = it.get("kind") or it.get("objectKind") or "RBAC"
        name = it.get("name") or it.get("objectName") or "unknown"
        ns   = it.get("namespace") or ""
        verdict = str(it.get("verdict") or it.get("result") or "").lower()
        risk    = it.get("risk") or {}
        reason  = risk.get("reason") if isinstance(risk, dict) else it.get("reason")
        rule    = (risk.get("rule") if isinstance(risk, dict) else None) or "rbac-overly-permissive"
        sev     = "HIGH" if "critical" in str(risk).lower() or "admin" in str(reason).lower() else "MEDIUM"
        msg     = reason or verdict or "Overly permissive RBAC configuration"
        labels  = {}
        if isinstance(risk, dict):
            labels.update({k: v for k, v in risk.items() if k not in {"reason","rule"}})
        if it.get("subjects"):
            labels["subjects"] = it["subjects"]
        if it.get("roleRef"):
            labels["roleRef"] = it["roleRef"]
        findings.append(_mk("rbac-police", rule, sev, kind, name, msg, namespace=ns, labels=labels, raw_file=str(p)))
    return findings

def from_pluto(p: Path) -> List[Dict]:
    """
    Pluto JSON (detect) often returns a list of items like:
      {
        "name":"my-deploy",
        "namespace":"default",
        "kind":"Deployment",
        "api":"apps/v1beta1",
        "replacementApi":"apps/v1",
        "deprecated":"true",
        "removedIn":"1.16",
        "deprecatedIn":"1.9",
        "helmChart":"...", "file":"..."
      }
    We emit any deprecated/removed API as a finding.
    """
    data = load_json(p)
    if not data:
        return []
    
    findings: List[Dict] = []
    
    # Handle both dict (with "items" key) and direct list
    if isinstance(data, dict):
        # Pluto often wraps items in an "items" array
        items = data.get("items", [])
        if not items:
            # Maybe the dict itself is a single finding
            items = [data] if data.get("api") or data.get("kind") else []
    else:
        items = data if isinstance(data, list) else [data]
    for it in items:
        if not isinstance(it, dict):
            continue
        kind = it.get("kind") or "Object"
        name = it.get("name") or "unknown"
        ns   = it.get("namespace") or ""
        file = it.get("file") or it.get("manifest") or ""
        api  = it.get("api") or it.get("apiVersion") or ""
        repl = it.get("replacementApi") or it.get("replacedBy") or ""
        dep  = str(it.get("deprecated") or it.get("isDeprecated") or "true").lower() in {"true","yes","1"}
        removed_in = it.get("removedIn") or ""
        deprecated_in = it.get("deprecatedIn") or ""
        if not api:
            continue
        rule = f"deprecated-api:{api}"
        sev  = "HIGH" if removed_in else "MEDIUM"
        msg  = f"Deprecated API {api}. Use {repl or 'supported API'}"
        labels = {"replacementApi": repl, "removedIn": removed_in, "deprecatedIn": deprecated_in}
        findings.append(_mk("pluto", rule, sev, kind, name, msg, file=file, namespace=ns, labels=labels, raw_file=str(p)))
    return findings

# ------------------------
# collector & dedupe
# ------------------------

def _fingerprint(f: Dict) -> str:
    reduced = {
        "tool": f.get("tool", ""),
        "ruleId": f.get("ruleId", ""),
        "severity": f.get("severity", ""),
        "resourceKind": f.get("resourceRef", {}).get("kind", ""),
        "resourceName": f.get("resourceRef", {}).get("name", ""),
        "resourceNs": f.get("resourceRef", {}).get("namespace", ""),
        "file": f.get("location", {}).get("file", ""),
        "line": f.get("location", {}).get("line", ""),
        "message": str(f.get("message", ""))[:200],
    }
    blob = json.dumps(reduced, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()

def collect_all(raw_dir: Path) -> List[Dict]:
    f: List[Dict] = []
    # base 8
    f += from_kubelinter(raw_dir / "kubelinter_raw.json")
    f += from_kubeaudit(raw_dir / "kubeaudit_raw.json")
    f += from_polaris(raw_dir / "polaris_raw.json")
    f += from_trivy_config(raw_dir / "trivy_config_raw.json")
    f += from_kubescore(raw_dir / "kubescore_raw.json")
    f += from_yamllint(raw_dir / "yamllint_raw.txt")
    f += from_kubescape(raw_dir / "kubescape_raw.json")
    f += from_kubeconform(raw_dir / "kubeconform_raw.json")
    # optional extras (if present)
    f += from_checkov(raw_dir / "checkov_raw.json")
    f += from_terrascan(raw_dir / "terrascan_raw.json")
    f += from_gitleaks(raw_dir / "gitleaks_raw.json")
    f += from_trufflehog(raw_dir / "trufflehog_raw.json")
    # NEW 2 tools (rbac-police and pluto only, kube-bench removed)
    f += from_rbacpolice(raw_dir / "rbacpolice_raw.json")
    f += from_pluto(raw_dir / "pluto_raw.json")

    # dedupe
    seen: Set[str] = set()
    deduped: List[Dict] = []
    for item in f:
        key = _fingerprint(item)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped

# ------------------------
# missing loader stubs you already had
# ------------------------

def from_kubescape(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings: List[Dict] = []

    # Handle array form
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            results = entry.get("results") or []
            resources = entry.get("resources") or []
            rmap = {}
            for res in resources:
                rid = res.get("resourceID", "")
                if not rid: continue
                obj = res.get("object", {}) or {}
                src = res.get("source", {}) or {}
                meta = obj.get("metadata") or {}
                rmap[rid] = {
                    "kind": obj.get("kind",""),
                    "name": meta.get("name","") if isinstance(meta, dict) else "",
                    "ns": meta.get("namespace","") if isinstance(meta, dict) else "",
                    "file": src.get("relativePath",""),
                }
            for resu in results:
                rid = resu.get("resourceID","")
                meta = rmap.get(rid, {})
                for ctrl in resu.get("controls") or []:
                    status = (ctrl.get("status") or {}).get("status")
                    if status != "failed":
                        continue
                    cid = ctrl.get("controlID","")
                    cname = ctrl.get("name","")
                    msg = cname or cid or "Kubescape control failed"
                    findings.append(_mk(
                        "kubescape", cid or "unknown", "MEDIUM",
                        meta.get("kind","Resource"), meta.get("name","unknown"), msg,
                        file=meta.get("file",""), namespace=meta.get("ns",""), raw_file=str(p)
                    ))
        return findings

    # Single object schema
    resources_list = data.get("resources", []) or []
    resource_map = {}
    for res in resources_list:
        res_id = res.get("resourceID", "")
        if res_id:
            obj = res.get("object", {}) or {}
            meta = obj.get("metadata") or {}
            source = res.get("source", {}) or {}
            resource_map[res_id] = {
                "kind": obj.get("kind", ""),
                "name": meta.get("name", "") if isinstance(meta, dict) else "",
                "ns": meta.get("namespace", "") if isinstance(meta, dict) else "",
                "file": source.get("relativePath", "")
            }

    results = data.get("results", []) or []
    for result in results:
        resource_id = result.get("resourceID", "")
        controls = result.get("controls", []) or []
        res_meta = resource_map.get(resource_id, {})
        kind = res_meta.get("kind", "Resource")
        name = res_meta.get("name", "unknown")
        ns   = res_meta.get("ns", "")
        file = res_meta.get("file", "")
        for control in controls:
            status_info = control.get("status", {}) or {}
            if status_info.get("status") != "failed":
                continue
            control_id = control.get("controlID", "")
            control_name = control.get("name", "")
            sev = "MEDIUM"
            findings.append(_mk("kubescape", control_id, sev, kind, name, control_name or control_id, file=file, namespace=ns, raw_file=str(p)))
    return findings

def from_kubeconform(p: Path) -> List[Dict]:
    """
    kubeconform -output json -strict -summary -verbose
    The JSON contains per-file results with valid/invalid items; surface invalids and errors.
    """
    data = load_json(p) or {}
    findings: List[Dict] = []
    
    # kubeconform produces a dict with "resources" array
    resources = data.get("resources", [])
    
    for res in resources:
        if not isinstance(res, dict):
            continue
        
        status = res.get("status", "")
        
        # Only report invalid and error statuses
        if status not in ("statusInvalid", "statusError"):
            continue
        
        file = res.get("filename", "")
        kind = res.get("kind", "Object")
        name = res.get("name", "unknown")
        version = res.get("version", "")
        msg = res.get("msg", "")
        
        # Determine severity based on status
        sev = "HIGH" if status == "statusInvalid" else "MEDIUM"
        
        # Build rule ID
        if status == "statusInvalid":
            rule = "schema-validation-failed"
        else:
            rule = "schema-error"
        
        # Extract validation errors for more detail
        validation_errors = res.get("validationErrors", [])
        if validation_errors:
            for err in validation_errors:
                err_path = err.get("path", "")
                err_msg = err.get("msg", "")
                full_msg = f"{msg} - Path: {err_path}, Error: {err_msg}"
                findings.append(_mk(
                    "kubeconform", rule, sev, kind, name, full_msg,
                    file=file, namespace="", 
                    labels={"apiVersion": version, "status": status},
                    raw_file=str(p)
                ))
        else:
            findings.append(_mk(
                "kubeconform", rule, sev, kind, name, msg,
                file=file, namespace="",
                labels={"apiVersion": version, "status": status},
                raw_file=str(p)
            ))
    
    return findings

# ------------------------
# consensus / aggregation
# ------------------------

def group_key(f: Dict, strategy: str) -> Tuple[str, str, str, str]:
    """
    Return a grouping key for consensus counting.
    strategy in {"rule", "message", "rule_or_message"}
    """
    ref = f.get("resourceRef", {}) or {}
    ns  = ref.get("namespace","") or ""
    kind= ref.get("kind","") or ""
    name= ref.get("name","") or ""
    file= (f.get("location",{}) or {}).get("file","") or ""
    rule= str(f.get("ruleId","") or "").strip()
    msg = _norm_msg(f.get("message","") or "").strip()

    # Use namespace/kind/name primarily; fall back to file if name is unknown
    id_part = (ns, kind, name if name != "unknown" else f"{name}@{file}")

    if strategy == "rule":
        return (*id_part, rule or msg or "unknown")
    if strategy == "message":
        return (*id_part, msg or rule or "unknown")
    # rule_or_message
    return (*id_part, rule or msg or "unknown")

def compute_consensus(findings: List[Dict], threshold: int, strategy: str) -> Tuple[List[Dict], List[Dict]]:
    """
    Returns (annotated_findings, consensus_groups)
    consensus_groups is a list of grouped objects with tools, count, top severity, confirmed flag.
    """
    # map group -> {tools set, severities, sample, members idx}
    groups: Dict[Tuple[str,str,str,str], Dict[str, Any]] = {}
    for idx, f in enumerate(findings):
        gk = group_key(f, strategy)
        ent = groups.setdefault(gk, {"tools": set(), "severities": [], "members": [], "sample": f})
        ent["tools"].add(f.get("tool","unknown"))
        ent["severities"].append(f.get("severity","INFO"))
        ent["members"].append(idx)

    consensus_rows: List[Dict] = []
    for gk, ent in groups.items():
        tools = sorted(ent["tools"])
        count = len(tools)
        top_sev = highest_severity(ent["severities"])
        confirmed = (count >= threshold)
        # annotate members
        for i in ent["members"]:
            findings[i]["toolsAgreeCount"] = count
            findings[i]["confirmed"] = confirmed
        ns, kind, name_or_file, rule_or_msg = gk
        sample = ent["sample"]
        consensus_rows.append({
            "namespace": ns,
            "kind": kind,
            "name": sample.get("resourceRef",{}).get("name") or name_or_file,
            "file": (sample.get("location",{}) or {}).get("file",""),
            "groupKey": rule_or_msg,
            "tools": tools,
            "count": count,
            "severity": top_sev,
            "confirmed": confirmed
        })
    return findings, consensus_rows

# ------------------------
# Excel & CSV outputs
# ------------------------

def write_excel(findings: List[Dict], out_path: Path) -> None:
    try:
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    except ImportError:
        warn("openpyxl not installed. Run: pip install openpyxl")
        return

    # group resource -> vuln -> tools
    grouped = {}
    toolset: Set[str] = set()
    for f in findings:
        ref = f.get("resourceRef", {})
        loc = f.get("location", {})
        key = (ref.get("namespace",""), ref.get("kind","Object"), ref.get("name","unknown"), loc.get("file",""))
        vuln_key = f"{f.get('ruleId','unknown')} [{f.get('severity','INFO')}]"
        entry = grouped.setdefault(key, {})
        row = entry.setdefault(vuln_key, {"rule": f.get("ruleId","unknown"),
                                          "severity": f.get("severity","INFO"),
                                          "message": _norm_msg(f.get("message",""))[:200],
                                          "tools": set(),
                                          "toolsAgreeCount": f.get("toolsAgreeCount", 1),
                                          "confirmed": f.get("confirmed", False)})
        row["tools"].add(f.get("tool","unknown"))
        toolset.add(f.get("tool","unknown"))

    tools = sorted(toolset)
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Security Findings"

    header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
    header_font = Font(color="FFFFFF", bold=True)
    border = Border(left=Side(style='thin'), right=Side(style='thin'),
                    top=Side(style='thin'), bottom=Side(style='thin'))

    headers = ["Namespace", "Kind", "Name", "File", "Vulnerability", "Severity", "Message",
               "ToolsAgreeCount", "Confirmed"] + tools
    for c, h in enumerate(headers, 1):
        cell = ws.cell(row=1, column=c, value=h)
        cell.fill = header_fill; cell.font = header_font
        cell.alignment = Alignment(horizontal="center", vertical="center"); cell.border = border

    r = 2
    for (ns, kind, name, file), vulns in sorted(grouped.items()):
        for _, d in sorted(vulns.items(), key=lambda kv: (-SEV_ORDER.get(kv[1]["severity"],1), kv[0])):
            ws.cell(r,1, ns).border = border
            ws.cell(r,2, kind).border = border
            ws.cell(r,3, name).border = border
            ws.cell(r,4, file or "N/A").border = border
            ws.cell(r,5, d["rule"]).border = border

            sev_cell = ws.cell(r,6, d["severity"]); sev_cell.border = border
            if d["severity"] == "CRITICAL":
                sev_cell.fill = PatternFill(start_color="C00000", end_color="C00000", fill_type="solid"); sev_cell.font = Font(color="FFFFFF", bold=True)
            elif d["severity"] == "HIGH":
                sev_cell.fill = PatternFill(start_color="FF0000", end_color="FF0000", fill_type="solid"); sev_cell.font = Font(color="FFFFFF")
            elif d["severity"] == "MEDIUM":
                sev_cell.fill = PatternFill(start_color="FFC000", end_color="FFC000", fill_type="solid")
            elif d["severity"] == "LOW":
                sev_cell.fill = PatternFill(start_color="FFFF00", end_color="FFFF00", fill_type="solid")

            ws.cell(r,7, d["message"]).border = border
            ws.cell(r,8, d["toolsAgreeCount"]).border = border
            ws.cell(r,9, "Y" if d["confirmed"] else "N").border = border

            for c, t in enumerate(tools, 10):
                cell = ws.cell(r, c)
                if t in d["tools"]:
                    cell.value = "yes"
                    cell.fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
                else:
                    cell.value = "no"
                cell.border = border
            r += 1

    # widths
    widths = {"A":14, "B":14, "C":26, "D":36, "E":32, "F":12, "G":60, "H":16, "I":12}
    for col, w in widths.items():
        ws.column_dimensions[col].width = w
    for idx in range(10, 10+len(tools)):
        from openpyxl.utils import get_column_letter
        ws.column_dimensions[get_column_letter(idx)].width = 12
    ws.freeze_panes = "A2"

    out_xlsx = out_path
    out_xlsx.parent.mkdir(parents=True, exist_ok=True)
    wb.save(out_xlsx)
    note(f"wrote Excel: {out_xlsx}")

def write_csv(consensus_rows: List[Dict], out_csv: Path) -> None:
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Namespace","Kind","Name","File","GroupKey","ToolsAgreeCount","Confirmed","Severity","Tools"])
        for r in sorted(consensus_rows, key=lambda x:(-SEV_ORDER.get(x["severity"],1), x["namespace"], x["kind"], x["name"])):
            w.writerow([r["namespace"], r["kind"], r["name"], r["file"], r["groupKey"],
                        r["count"], "Y" if r["confirmed"] else "N", r["severity"], ",".join(r["tools"])])

# ------------------------
# CLI
# ------------------------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Normalize SafeFixK8s outputs & compute multi-tool consensus.")
    ap.add_argument("--raw-dir", default=str(RAW_DIR), help="Directory containing raw tool outputs.")
    ap.add_argument("--out-json", default=str(OUT_JSON), help="Path to write normalized JSON bundle.")
    ap.add_argument("--out-excel", default=str(OUT_DIR / "security_findings.xlsx"), help="Path to Excel report.")
    ap.add_argument("--out-csv", default=str(OUT_DIR / "consensus_findings.csv"), help="Path to consensus CSV.")
    ap.add_argument("--threshold", type=int, default=3, help="Minimum distinct tools that must agree to mark 'confirmed'.")
    ap.add_argument("--group-by", choices=["rule","message","rule_or_message"], default="rule",
                    help="How to group findings across tools when counting agreement.")
    ap.add_argument("--no-excel", action="store_true", help="Skip Excel generation.")
    ap.add_argument("--no-csv", action="store_true", help="Skip CSV consensus export.")
    return ap.parse_args()

# ------------------------
# main
# ------------------------

def main():
    args = parse_args()
    raw_dir = Path(args.raw_dir)
    out_json= Path(args.out_json)
    out_excel= Path(args.out_excel)
    out_csv = Path(args.out_csv)

    all_findings = collect_all(raw_dir)

    # consensus
    annotated, consensus_rows = compute_consensus(all_findings, threshold=args.threshold, strategy=args.group_by)

    bundle = {
        "version": "1.1",
        "generatedAt": now_iso(),
        "source": "SafeFixK8s/Normalizer",
        "threshold": args.threshold,
        "groupBy": args.group_by,
        "findings": annotated
    }
    out_json.parent.mkdir(parents=True, exist_ok=True)
    with out_json.open("w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2, default=str)
    note(f"wrote {out_json} with {len(annotated)} findings.")

    if not args.no_csv:
        write_csv(consensus_rows, out_csv)

    if not args.no_excel:
        write_excel(annotated, out_excel)

    note(f"Raw detection files preserved in: {raw_dir}")

# ------------------------
# entry
# ------------------------

if __name__ == "__main__":
    main()
