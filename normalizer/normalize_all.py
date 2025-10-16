# normalizer/normalize_all.py
# Robust normalizer for SafeFixK8s outputs

from __future__ import annotations
import json, hashlib, re, csv, sys
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Iterable, List
from collections import defaultdict

ROOT    = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "output" / "raw"
OUT     = ROOT / "output" / "normalized_findings.json"
MATRIX_CSV = ROOT / "output" / "tool_detection_matrix.csv"
MATRIX_JSON = ROOT / "output" / "tool_detection_matrix.json"
LOGS_DIR = ROOT / "output" / "logs"

# Ensure logs directory exists
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Setup logging
LOG_FILE = LOGS_DIR / f"normalizer_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.log"

def log(msg: str, level: str = "INFO") -> None:
    """Write to both console and log file."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] [{level}] {msg}"
    
    # Console output (with colors for errors/warnings)
    # Use ASCII-safe version for console to avoid Windows encoding issues
    console_msg = log_msg.replace("✓", "[OK]").replace("→", "->")
    
    try:
        if level == "ERROR":
            print(f"\033[91m{console_msg}\033[0m", file=sys.stderr)  # Red
        elif level == "WARN":
            print(f"\033[93m{console_msg}\033[0m")  # Yellow
        elif level == "INFO":
            print(console_msg)
        else:
            print(console_msg)
    except UnicodeEncodeError:
        # Fallback for really problematic consoles
        print(console_msg.encode('ascii', 'replace').decode('ascii'))
    
    # File output (keep Unicode for log files)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(log_msg + "\n")

# ------------------------
# helpers
# ------------------------

def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="microseconds") + "Z"

def warn(msg: str) -> None:
    log(msg, "WARN")

def _hash_id(parts: Iterable[str]) -> str:
    h = hashlib.md5()
    for p in parts:
        if p is None:
            p = ""
        if not isinstance(p, str):
            p = json.dumps(p, sort_keys=True, ensure_ascii=False)
        h.update(p.encode("utf-8", errors="ignore"))
        h.update(b"|")
    return h.hexdigest()

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
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            return []

        low = text.lower()
        if ("placeholder" in low) or ("error response from daemon" in low) or ("exec /kubeaudit" in low):
            warn(f"Placeholder/diagnostic text in {p}; skipping.")
            return []

        try:
            return json.loads(text)
        except json.JSONDecodeError:
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
    if su in {"LOW","MEDIUM","HIGH","CRITICAL","INFO","UNKNOWN"}:
        return su
    if sl == "critical": return "CRITICAL"
    if sl in {"warning","warn"}: return "MEDIUM"
    if sl in {"advice","info","ok","passed","bestpractice","best_practice"}: return "INFO"
    if su.startswith("WARN"): return "MEDIUM"
    if su.startswith("ERR"): return "HIGH"
    return default

def _norm_msg(msg: Any) -> str:
    if isinstance(msg, dict):
        for k in ("Message", "message", "summary", "text"):
            v = msg.get(k)
            if isinstance(v, str):
                return v
        return json.dumps(msg, sort_keys=True, ensure_ascii=False)
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
) -> Dict[str, Any]:
    # coerce ruleId to a clean string
    rid = rule
    if not isinstance(rid, str):
        try:
            rid = (rid.get("id") or rid.get("name")) if isinstance(rid, dict) else str(rid)
        except Exception:
            rid = "unknown"
    msg = _norm_msg(message)
    fid = _hash_id([tool, rid, kind, name, file, str(line or 0), msg])
    return {
        "findingId": fid,
        "tool": tool,
        "ruleId": rid or "unknown",
        "severity": sev_norm(severity, default="INFO"),
        "resourceRef": {"kind": kind or "Object", "name": name or "unknown"},
        "message": message,
        "location": {"file": file or "", "line": (int(line) if isinstance(line, int) or (isinstance(line, str) and line.isdigit()) else None)},
        "labels": labels or {}
    }

# ------------------------
# mappers
# ------------------------

def from_kubelinter(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings = []
    for it in data.get("Reports", []) or data.get("reports", []) or []:
        tool = "kubelinter"
        rule = it.get("Check", {}).get("name") or it.get("check") or it.get("Diagnostic", {}).get("check") or it.get("name")
        msg  = it.get("Message") or it.get("message") or it
        sev  = it.get("Severity") or it.get("severity") or "MEDIUM"
        obj  = it.get("Object", {}) or it.get("object", {}) or {}
        kind = obj.get("k8sObject", {}).get("kind") or obj.get("kind") or "Object"
        name = obj.get("k8sObject", {}).get("name") or obj.get("name") or "unknown"
        file = (obj.get("file") or "") if isinstance(obj, dict) else ""
        findings.append(_mk(tool, rule, sev, kind, name, {"Message": msg}, file=file))
    return findings

def from_polaris(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings = []
    for res in data.get("results", []):
        for check in res.get("checks", []):
            rule = check.get("id") or check.get("type")
            sev  = check.get("severity") or "INFO"
            msg  = check.get("message") or {}
            kind = res.get("kind") or "Object"
            name = res.get("name") or "unknown"
            file = res.get("filePath") or ""
            findings.append(_mk("polaris", rule, sev, kind, name, {"Message": msg}, file=file))
    return findings

def from_trivy_config(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings = []
    for r in data.get("Results", []) or data.get("results", []) or []:
        file = r.get("Target") or r.get("target") or ""
        for m in r.get("Misconfigurations", []) or r.get("misconfigurations", []) or []:
            rule = m.get("ID") or m.get("id")
            sev  = m.get("Severity") or m.get("severity")
            msg  = m.get("Message") or m.get("message")
            kind = "Object"
            name = "unknown"
            findings.append(_mk("trivy-config", rule, sev, kind, name, msg, file=file, labels={"url": m.get("PrimaryURL") or m.get("primaryURL")}))
    return findings

def from_kubescore(p: Path) -> List[Dict]:
    data = load_json(p)
    findings: List[Dict] = []
    if not data:
        return findings
    items = data if isinstance(data, list) else [data]

    def sev_from_grade(g):
        try:
            g = float(g)
            return "HIGH" if g < 5 else ("MEDIUM" if g < 7 else "INFO")
        except:
            return "INFO"

    for item in items:
        objmeta = item.get("object", {}) if isinstance(item, dict) else {}
        kind = objmeta.get("kind") or item.get("kind") or "Object"
        name = objmeta.get("name") or item.get("name") or "unknown"
        file = item.get("fileName") or item.get("filename") or item.get("file") or ""

        checks = []
        if isinstance(item, dict) and isinstance(item.get("checks"), list):
            checks = item["checks"]

        for chk in checks:
            chkmeta = chk.get("check") or {}
            rule = chkmeta.get("id") or chkmeta.get("name") or "unknown"
            raw_sev = sev_from_grade(chk.get("grade", 10))
            msg = chk.get("comment") or chk.get("comments") or chk.get("message") or chkmeta
            findings.append(_mk("kube-score", rule, raw_sev, kind, name, msg, file=file))
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
            line=int(d["line"])
        ))
    return findings

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
            findings.append(_mk("checkov", rule, sev, kind, name, msg, file=file, line=line, labels=labels))
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
        findings.append(_mk("terrascan", rule, sev, kind, name, msg, file=file, line=line))
    return findings

def from_gitleaks(p: Path) -> List[Dict]:
    findings = []
    for it in iter_json_lines(p):
        if not isinstance(it, dict):
            continue
        if "rule" not in it and "Description" not in it and "RuleID" not in it:
            continue
        rule = it.get("RuleID") or it.get("rule") or it.get("Description")
        sev  = "HIGH"
        msg  = it.get("Description") or it.get("Summary") or "Potential secret"
        file = it.get("File") or it.get("file") or it.get("Target") or ""
        line = it.get("StartLine") or it.get("line") or None
        findings.append(_mk("gitleaks", rule, sev, "Repository", "\\", msg, file=file, line=int(line or 0)))
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
        findings.append(_mk("trufflehog", detector, sev, "Repository", "\\", msg, file=file, line=int(line or 0)))
    return findings

def from_syft(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings = []
    for pkg in data.get("artifacts", []) or []:
        name = pkg.get("name")
        ver  = pkg.get("version")
        labels = {"type": (pkg.get("type") or pkg.get("packageType") or "").lower()}
        findings.append(_mk("syft","SBOM-PACKAGE","INFO","Image", f"{name}:{ver}", f"Package {name}:{ver} present", labels=labels))
    return findings

def from_grype(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings = []
    for m in data.get("matches", []) or []:
        vuln = (m.get("vulnerability") or {})
        art  = (m.get("artifact") or {})
        rule = vuln.get("id") or "unknown"
        sev  = vuln.get("severity") or "MEDIUM"
        pkg  = f"{art.get('name')} {art.get('version')}"
        img  = (data.get("source", {}) or {}).get("target", "") or "image"
        msg  = f"{pkg} vulnerable"
        findings.append(_mk("grype", rule, sev, "Image", img, msg))
    return findings

def from_kubescape(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings = []
    for ctrl in data.get("controls", []) or data.get("report", {}).get("controls", []) or []:
        rule = ctrl.get("controlID") or ctrl.get("id") or ctrl.get("name")
        sev  = ctrl.get("severity") or "MEDIUM"
        for res in ctrl.get("resources", []):
            kind = res.get("resourceKind") or res.get("kind") or "Object"
            name = res.get("resourceName") or res.get("name") or "unknown"
            file = res.get("filePath") or ""
            msg  = res.get("remediation") or ctrl.get("description") or ctrl.get("name") or "policy finding"
            findings.append(_mk("kubescape", rule, sev, kind, name, msg, file=file))
    return findings

def from_kubesec(p: Path) -> List[Dict]:
    data = load_json(p)
    findings = []
    items: List[Any] = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("results") or data.get("checks") or []
        if not isinstance(items, list):
            items = [items]
    for it in items:
        rule = (it.get("id") or it.get("selector") or "kubesec")
        sev  = it.get("severity") or "MEDIUM"
        file = (it.get("file") or it.get("target") or it.get("path") or "")
        kind = (it.get("object", {}) or {}).get("kind") or "Object"
        name = (it.get("object", {}) or {}).get("name") or "unknown"
        msg  = it.get("reason") or it.get("message") or it.get("recommendations") or it
        findings.append(_mk("kubesec", rule, sev, kind, name, msg, file=file))
    return findings

def from_kubeaudit(p: Path) -> List[Dict]:
    data = load_json(p)
    findings = []
    items = (data.get("results") if isinstance(data, dict) else data) or []
    for it in items:
        rule = it.get("auditResultName") or it.get("name") or "kubeaudit"
        sev  = it.get("severity") or it.get("level") or "MEDIUM"
        obj  = it.get("resource") or {}
        kind = obj.get("kind") or "Object"
        name = obj.get("name") or "unknown"
        file = it.get("file") or ""
        msg  = it.get("message") or it.get("remediation") or it
        findings.append(_mk("kubeaudit", rule, sev, kind, name, msg, file=file))
    return findings

def from_kyverno(p: Path) -> List[Dict]:
    data = load_json(p)
    findings: List[Dict] = []
    if not data:
        return findings
    # kyverno apply -o json outputs policy reports; normalize common shapes
    items = []
    if isinstance(data, dict) and "policyReport" in data:
        items = data["policyReport"].get("results", [])
    elif isinstance(data, dict) and "results" in data:
        items = data["results"]
    elif isinstance(data, list):
        items = data
    for it in items:
        rule = it.get("policy") or it.get("policyName") or it.get("rule") or "kyverno"
        sev  = it.get("severity") or it.get("priority") or "MEDIUM"
        res  = (it.get("resources") or [{}])[0] if isinstance(it.get("resources"), list) else (it.get("resource") or {})
        kind = res.get("kind") or "Object"
        name = res.get("name") or "unknown"
        file = (it.get("file") or "")
        msg  = it.get("message") or it.get("description") or it
        findings.append(_mk("kyverno", rule, sev, kind, name, msg, file=file))
    return findings

# ------------------------
# collector
# ------------------------

def _fingerprint(f: Dict) -> str:
    reduced = {
        "tool": f.get("tool", ""),
        "ruleId": f.get("ruleId", ""),
        "severity": f.get("severity", ""),
        "resourceKind": f.get("resourceRef", {}).get("kind", ""),
        "resourceName": f.get("resourceRef", {}).get("name", ""),
        "file": f.get("location", {}).get("file", ""),
        "line": f.get("location", {}).get("line", ""),
        "message": str(f.get("message", ""))[:200],
    }
    blob = json.dumps(reduced, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()

def _issue_key(f: Dict) -> str:
    """Generate a key for grouping similar issues (ignoring tool name)"""
    rr = f.get("resourceRef", {}) or {}
    loc = f.get("location", {}) or {}
    # Group by: ruleId + resource kind/name + file
    return f"{f.get('ruleId', 'unknown')}|{rr.get('kind', '')}|{rr.get('name', '')}|{loc.get('file', '')}"

def generate_detection_matrix(findings: List[Dict]) -> Dict[str, Any]:
    """
    Generate a matrix showing which tools detected which issues.
    Returns dict with matrix data and summary statistics.
    """
    # Group findings by issue key
    issue_groups = defaultdict(list)
    for f in findings:
        key = _issue_key(f)
        issue_groups[key].append(f)
    
    # Build matrix rows
    matrix_rows = []
    all_tools = set()
    
    for issue_key, group in issue_groups.items():
        # Get representative finding (first one)
        rep = group[0]
        rr = rep.get("resourceRef", {}) or {}
        loc = rep.get("location", {}) or {}
        
        # Collect which tools detected this issue
        tools_detected = sorted(set(f.get("tool", "unknown") for f in group))
        all_tools.update(tools_detected)
        
        # Get severity (use highest if multiple)
        severities = [f.get("severity", "INFO") for f in group]
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 0}
        max_sev = max(severities, key=lambda s: sev_order.get(s, 0))
        
        row = {
            "ruleId": rep.get("ruleId", "unknown"),
            "severity": max_sev,
            "resourceKind": rr.get("kind", ""),
            "resourceName": rr.get("name", ""),
            "file": loc.get("file", ""),
            "detectionCount": len(group),
            "toolsDetected": tools_detected,
            "toolCount": len(tools_detected)
        }
        matrix_rows.append(row)
    
    # Sort by detection count (descending), then by severity
    matrix_rows.sort(key=lambda r: (-r["detectionCount"], -sev_order.get(r["severity"], 0)))
    
    # Generate summary statistics
    all_tools_list = sorted(all_tools)
    tool_stats = {tool: {"total": 0, "unique": 0} for tool in all_tools_list}
    
    for row in matrix_rows:
        for tool in row["toolsDetected"]:
            tool_stats[tool]["total"] += 1
            if row["toolCount"] == 1:
                tool_stats[tool]["unique"] += 1
    
    return {
        "matrix": matrix_rows,
        "toolStats": tool_stats,
        "allTools": all_tools_list,
        "totalIssues": len(matrix_rows),
        "totalFindings": len(findings)
    }

def save_detection_matrix_csv(matrix_data: Dict[str, Any], output_path: Path):
    """Save detection matrix as CSV with tool columns"""
    log(f"Building CSV matrix with {len(matrix_data['matrix'])} rows", "INFO")
    all_tools = matrix_data["allTools"]
    
    try:
        with output_path.open("w", encoding="utf-8", newline="") as f:
            # Create headers
            headers = ["RuleID", "Severity", "ResourceKind", "ResourceName", "File", "DetectionCount", "ToolCount"]
            headers.extend(all_tools)  # Add a column for each tool
            
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            
            for row in matrix_data["matrix"]:
                csv_row = {
                    "RuleID": row["ruleId"],
                    "Severity": row["severity"],
                    "ResourceKind": row["resourceKind"],
                    "ResourceName": row["resourceName"],
                    "File": row["file"],
                    "DetectionCount": row["detectionCount"],
                    "ToolCount": row["toolCount"]
                }
                # Mark which tools detected this issue
                for tool in all_tools:
                    csv_row[tool] = "✓" if tool in row["toolsDetected"] else ""
                
                writer.writerow(csv_row)
        
        log(f"CSV matrix written successfully", "INFO")
    except Exception as e:
        log(f"Failed to write CSV matrix: {e}", "ERROR")
        raise

def collect_all() -> List[Dict]:
    log("Starting collection from all raw files", "INFO")
    findings: List[Dict] = []
    
    parsers = [
        ("kubelinter", RAW_DIR / "kubelinter_raw.json", from_kubelinter),
        ("polaris", RAW_DIR / "polaris_raw.json", from_polaris),
        ("trivy-config", RAW_DIR / "trivy_config_raw.json", from_trivy_config),
        ("kube-score", RAW_DIR / "kubescore_raw.json", from_kubescore),
        ("yamllint", RAW_DIR / "yamllint_raw.txt", from_yamllint),
        ("checkov", RAW_DIR / "checkov_raw.json", from_checkov),
        ("terrascan", RAW_DIR / "terrascan_raw.json", from_terrascan),
        ("gitleaks", RAW_DIR / "gitleaks_raw.json", from_gitleaks),
        ("trufflehog", RAW_DIR / "trufflehog_raw.json", from_trufflehog),
        ("kubescape", RAW_DIR / "kubescape_raw.json", from_kubescape),
        ("kubesec", RAW_DIR / "kubesec_raw.json", from_kubesec),
        ("kubeaudit", RAW_DIR / "kubeaudit_raw.json", from_kubeaudit),
        ("kyverno", RAW_DIR / "kyverno_raw.json", from_kyverno),
    ]
    
    for tool_name, file_path, parser_func in parsers:
        try:
            log(f"Parsing {tool_name} from {file_path.name}", "INFO")
            tool_findings = parser_func(file_path)
            findings.extend(tool_findings)
            log(f"  → {tool_name}: {len(tool_findings)} findings", "INFO")
        except Exception as e:
            log(f"  → {tool_name}: FAILED - {e}", "ERROR")
            # Continue processing other tools even if one fails

    log(f"Collection complete: {len(findings)} total findings", "INFO")
    return findings

def main():
    log("="*60, "INFO")
    log("SafeFixK8s Normalizer Starting", "INFO")
    log(f"Log file: {LOG_FILE}", "INFO")
    log("="*60, "INFO")
    
    try:
        findings = collect_all()
        
        log("Building normalized findings bundle", "INFO")
        bundle = {
            "version": "1.0",
            "generatedAt": now_iso(),
            "source": "SafeFixK8s/Normalizer",
            "findings": findings
        }
        
        log(f"Writing normalized findings to {OUT}", "INFO")
        OUT.parent.mkdir(parents=True, exist_ok=True)
        with OUT.open("w", encoding="utf-8") as f:
            json.dump(bundle, f, ensure_ascii=False, indent=2)
        log(f"✓ Wrote {OUT} with {len(bundle['findings'])} findings (with duplicates)", "INFO")
        
        # Generate detection matrix
        log("Generating detection matrix", "INFO")
        matrix_data = generate_detection_matrix(findings)
        
        # Save matrix as JSON
        log(f"Writing matrix JSON to {MATRIX_JSON}", "INFO")
        with MATRIX_JSON.open("w", encoding="utf-8") as f:
            json.dump(matrix_data, f, ensure_ascii=False, indent=2)
        log(f"✓ Matrix JSON saved to {MATRIX_JSON}", "INFO")
        
        # Save matrix as CSV
        log(f"Writing matrix CSV to {MATRIX_CSV}", "INFO")
        save_detection_matrix_csv(matrix_data, MATRIX_CSV)
        log(f"✓ Matrix CSV saved to {MATRIX_CSV}", "INFO")
        
        # Print summary
        log("", "INFO")
        log("="*60, "INFO")
        log("TOOL DETECTION SUMMARY", "INFO")
        log("="*60, "INFO")
        log(f"Total unique issues: {matrix_data['totalIssues']}", "INFO")
        log(f"Total findings (with duplicates): {matrix_data['totalFindings']}", "INFO")
        log("", "INFO")
        log("Per-Tool Statistics:", "INFO")
        log(f"{'Tool':<20} {'Total':<10} {'Unique':<10}", "INFO")
        log("-"*40, "INFO")
        for tool, stats in sorted(matrix_data["toolStats"].items()):
            log(f"{tool:<20} {stats['total']:<10} {stats['unique']:<10}", "INFO")
        log("="*60, "INFO")
        log("", "INFO")
        
        # Delete all raw files after successful normalization (keep logs/)
        log("Starting cleanup of raw files", "INFO")
        deleted_count = 0
        if RAW_DIR.exists():
            for raw_file in RAW_DIR.iterdir():
                if raw_file.is_file():
                    try:
                        raw_file.unlink()
                        deleted_count += 1
                        log(f"Deleted {raw_file.name}", "INFO")
                    except Exception as e:
                        log(f"Failed to delete {raw_file.name}: {e}", "ERROR")
        log(f"✓ Cleanup complete: removed {deleted_count} raw file(s)", "INFO")
        
        log("="*60, "INFO")
        log("Normalizer completed successfully", "INFO")
        log(f"Log saved to: {LOG_FILE}", "INFO")
        log("="*60, "INFO")
        
    except Exception as e:
        log(f"FATAL ERROR: {e}", "ERROR")
        import traceback
        log(traceback.format_exc(), "ERROR")
        sys.exit(1)

if __name__ == "__main__":
    main()
