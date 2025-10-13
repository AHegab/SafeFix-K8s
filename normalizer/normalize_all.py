# normalizer/normalize_all.py
# Robust normalizer for SafeFixK8s outputs
from __future__ import annotations
import json, hashlib, sys, re
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Iterable, List

ROOT    = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "output" / "raw"
OUT     = ROOT / "output" / "normalized_findings.json"

# ------------------------
# helpers
# ------------------------

def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="microseconds") + "Z"

def warn(msg: str) -> None:
    print(f"[WARN] {msg}")

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
        # Strip UTF-8 BOM if present
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]

        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            return []

        # Skip obvious placeholders or shell error text
        low = text.lower()
        if ("placeholder" in low) or ("error response from daemon" in low) or ("exec /kubeaudit" in low):
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
            # ignore Go log lines like {"level":"info-0",...} that *are* JSON too – still parse them
            try:
                yield json.loads(s)
            except Exception:
                # skip non-JSON garbage lines
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

def _dedupe_key(f: Dict[str, Any]) -> tuple:
    rr = f.get("resourceRef", {}) or {}
    loc = f.get("location", {}) or {}
    return (
        f.get("tool",""),
        f.get("ruleId",""),
        rr.get("kind",""),
        rr.get("name",""),
        loc.get("file",""),
        int(loc.get("line", 0) or 0),
        _norm_msg(f.get("message"))
    )

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
    msg = _norm_msg(message)
    fid = _hash_id([tool, rule, kind, name, file, str(line or 0), msg])
    return {
        "findingId": fid,
        "tool": tool,
        "ruleId": rule or "unknown",
        "severity": sev_norm(severity, default="INFO"),
        "resourceRef": {"kind": kind or "Object", "name": name or "unknown"},
        "message": msg if isinstance(message, str) else message,
        "location": {"file": file or "", "line": line},
        "labels": labels or {}
    }

# ------------------------
# mappers
# ------------------------

def from_kubelinter(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings = []
    for it in data.get("Reports", []) or data.get("reports", []) or []:
        # kube-linter JSON v2/v1 vary; try generic fields
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

    for item in items:
        objmeta = item.get("object", {}) if isinstance(item, dict) else {}
        kind = (objmeta.get("kind") or item.get("kind") or "Object") if isinstance(item, dict) else "Object"
        name = (objmeta.get("name") or item.get("name") or "unknown") if isinstance(item, dict) else "unknown"
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
            findings.append(_mk("kube-score", rule, raw_sev, kind, name, msg, file=file))

    return findings

_yamllint_re = re.compile(r"^(?P<file>.+):(?P<line>\d+):(?P<col>\d+):\s\[(?P<severity>\w+)\]\s(?P<message>.+)$")

def from_yamllint(p: Path) -> List[Dict]:
    txt = safe_text(p)
    findings = []
    for ln in txt.splitlines():
        m = _yamllint_re.match(ln.strip())
        if not m:
            # try braces warning line (tool sometimes prints different)
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
    findings = []
    for r in data.get("results", {}).get("failed_checks", []):
        rule = r.get("check_id")
        sev  = r.get("severity") or "INFO"
        msg  = r.get("check_name") or r.get("description")
        addr = r.get("resource") or r.get("resource_address") or ""
        kind = "Object"
        name = addr or "unknown"
        file = r.get("file_path") or r.get("repo_file_path") or ""
        line = r.get("file_line_range", [None, None])[0]
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
    # gitleaks default docker command emits JSON lines (one object per finding).
    findings = []
    for it in iter_json_lines(p):
        # filter out non-finding log events (they still parse)
        if not isinstance(it, dict):
            continue
        if "rule" not in it and "Description" not in it and "RuleID" not in it:
            # probably a log line from gitleaks itself
            continue
        rule = it.get("RuleID") or it.get("rule") or it.get("Description")
        sev  = "HIGH"
        msg  = it.get("Description") or it.get("Summary") or "Potential secret"
        file = it.get("File") or it.get("file") or it.get("Target") or ""
        line = it.get("StartLine") or it.get("line") or None
        findings.append(_mk("gitleaks", rule, sev, "Repository", "\\", msg, file=file, line=int(line or 0)))
    return findings

def from_trufflehog(p: Path) -> List[Dict]:
    # trufflehog docker emits a mix of logs (JSON) and results as JSON lines
    findings = []
    for it in iter_json_lines(p):
        if not isinstance(it, dict):
            continue
        # Known fields: "DetectorName" / "Raw", "Redacted", "SourceMetadata", "Verification"
        detector = it.get("DetectorName") or it.get("DetectorType") or it.get("rule")
        if not detector:
            # might be a log line like {"level":"info-0", ...}
            continue
        sev = "HIGH"
        msg = f"High-entropy or credential-like pattern"
        src = (((it.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
        file = src.get("file") or it.get("File") or ""
        line = src.get("line") or it.get("Line") or 0
        rule = detector
        findings.append(_mk("trufflehog", rule, sev, "Repository", "\\", msg, file=file, line=int(line or 0)))
    return findings

def from_syft(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings = []
    for pkg in data.get("artifacts", []) or data.get("artifactsByImage", []) or []:
        name = pkg.get("name")
        ver  = pkg.get("version")
        labels = {"type": (pkg.get("type") or pkg.get("packageType") or "").lower()}
        findings.append(_mk("syft","SBOM-PACKAGE","INFO","Image", f"{name}:{ver}", f"Package {name}:{ver} present", labels=labels))
    # some older syft formats:
    for img in data.get("artifacts", []) if isinstance(data.get("artifacts"), dict) else []:
        pass
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
    # v2 format: controls -> rules -> resources
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
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("results") or data.get("checks") or []
        if not isinstance(items, list):
            items = [items]
    else:
        items = []
    for it in items:
        rule = it.get("id") or it.get("selector") or "kubesec"
        sev  = it.get("severity") or "MEDIUM"
        file = (it.get("file") or it.get("target") or it.get("path") or "")
        kind = (it.get("object", {}) or {}).get("kind") or "Object"
        name = (it.get("object", {}) or {}).get("name") or "unknown"
        msg  = it.get("reason") or it.get("message") or it.get("recommendations") or it
        findings.append(_mk("kubesec", rule, sev, kind, name, msg, file=file))
    return findings

# ------------------------
# collector
# ------------------------

def _fingerprint(f: Dict) -> str:
    """
    Stable hash for deduping: based on sorted JSON of a reduced view
    so that dicts are never used as set keys.
    """
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

def collect_all() -> List[Dict]:
    findings: List[Dict] = []
    findings += from_kubelinter(RAW_DIR / "kubelinter_raw.json")
    findings += from_polaris(RAW_DIR / "polaris_raw.json")
    findings += from_trivy_config(RAW_DIR / "trivy_config_raw.json")
    findings += from_kubescore(RAW_DIR / "kubescore_raw.json")
    findings += from_yamllint(RAW_DIR / "yamllint_raw.txt")
    findings += from_checkov(RAW_DIR / "checkov_raw.json")
    findings += from_terrascan(RAW_DIR / "terrascan_raw.json")
    findings += from_gitleaks(RAW_DIR / "gitleaks_raw.json")
    findings += from_trufflehog(RAW_DIR / "trufflehog_raw.json")
    # Optional extras; load_json returns [] for bad placeholders, so these are safe:
    findings += from_kubescape(RAW_DIR / "kubescape_raw.json")
    findings += from_kubesec(RAW_DIR / "kubesec_raw.json")

    seen: set[str] = set()
    deduped: List[Dict] = []
    for f in findings:
        key = _fingerprint(f)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped

def main():
    bundle = {
        "version": "1.0",
        "generatedAt": now_iso(),
        "source": "SafeFixK8s/Normalizer",
        "findings": collect_all()
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
    print(f"[ok] wrote {OUT} with {len(bundle['findings'])} findings.")

if __name__ == "__main__":
    main()
