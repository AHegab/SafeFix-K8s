def run_llm_on_raw_file(tool: str, raw_file_path: str, models: str = "groq,openrouter,gemini", concurrency: int = 15, shard_models: bool = True, output: str = None) -> int:
    """
    Programmatically run the raw-to-LLM pipeline for a given tool and raw file.
    Returns the exit code from the orchestrator.
    """
    import subprocess, os, sys, shutil
    from pathlib import Path
    # Parse raw file
    parser_funcs = {
        "checkov": parse_checkov,
        "trivy": parse_trivy,
        "kubescape": parse_kubescape,
        "kubeaudit": parse_kubeaudit,
        "conftest": parse_conftest,
        "polaris": parse_polaris,
        "gitleaks": parse_gitleaks,
        "kubeconform": parse_kubeconform,
        "kubelinter": parse_kubelinter,
        "kubescore": parse_kubescore,
        "pluto": parse_pluto,
        "rbacpolice": parse_rbacpolice,
        "yamllint": parse_yamllint
    }
    raw_file = Path(raw_file_path)
    if not raw_file.exists():
        raise FileNotFoundError(f"Raw file not found: {raw_file}")
    items = parser_funcs[tool](raw_file)
    if not items:
        print("WARNING: No findings extracted from raw file")
        return 0
    payload = create_llm_payload(items, tool)
    output_dir = Path(output) if output else OUTPUT_ROOT / "llm"
    output_dir.mkdir(parents=True, exist_ok=True)
    temp_payload = output_dir / f"llm_payload_raw_{tool}.json"
    temp_payload.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    norm_payload = NORMALIZATION_DIR / "llm_payload.json"
    backup_payload = None
    if norm_payload.exists():
        backup_payload = NORMALIZATION_DIR / "llm_payload.json.backup"
        shutil.copy2(norm_payload, backup_payload)
    shutil.copy2(temp_payload, norm_payload)
    llm_script = Path(__file__).parent / "multi_llm_orchestrator.py"
    cmd = [
        sys.executable, str(llm_script),
        "--models", models,
        "--validate", "yaml",
        "--autofix",
        "--hygiene",
        "--concurrency", str(concurrency),
        "--timeout", "20",
        "--retries", "1"
    ]
    if shard_models:
        cmd.append("--shard-models")
    env = os.environ.copy()
    env["SAFEFIX_OUTPUT_ROOT"] = str(OUTPUT_ROOT)
    env["SAFEFIX_NORMALIZATION_DIR"] = str(NORMALIZATION_DIR)
    env["SAFEFIX_LLM_DIR"] = str(output_dir)
    result = subprocess.run(cmd, cwd=Path.cwd(), env=env, check=False)
    if backup_payload and backup_payload.exists():
        shutil.copy2(backup_payload, norm_payload)
    return result.returncode
#!/usr/bin/env python3
"""
Direct Raw-to-LLM Pipeline
Takes raw tool findings and sends them directly to LLM without normalization.

Usage:
    python LLMs/raw_to_llm.py --tool checkov --raw Detection/output/detection/raw/checkov_raw.json
    python LLMs/raw_to_llm.py --tool trivy --raw Detection/output/detection/raw/trivy_config_raw.json
    python LLMs/raw_to_llm.py --tool kubescape --raw Detection/output/detection/raw/kubescape_raw.json
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any
import subprocess

# --- Make printing safe on Windows consoles (no emoji crash) ---
try:
    # Python 3.7+: reconfigure IO to UTF-8 when possible
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except (AttributeError, ValueError, OSError):
    pass

def _utf8_ok() -> bool:
    enc = getattr(sys.stdout, "encoding", None)
    if isinstance(enc, str):
        enc = enc.upper()
    else:
        enc = ""
    return "UTF" in enc or "65001" in enc  # chcp 65001

def safe_fast_banner():
    # Use emoji only if the console supports it; otherwise ASCII fallback
    prefix = "⚡ " if _utf8_ok() else "[FAST] "
    print(prefix + "Fast mode: Model sharding enabled")

# Import from multi_llm_orchestrator
sys.path.insert(0, str(Path(__file__).parent))
try:
    from multi_llm_orchestrator import OUTPUT_ROOT, NORMALIZATION_DIR
except ImportError:
    OUTPUT_ROOT = Path(__file__).parent.parent / "output"
    NORMALIZATION_DIR = Path(__file__).parent.parent / "Normalizer"

def parse_checkov(raw_file: Path) -> List[Dict[str, Any]]:
    """Parse Checkov raw JSON output."""
    with open(raw_file, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    items = []
    failed_checks = data.get("results", {}).get("failed_checks", [])

    for check in failed_checks:
        file_path = check.get("file_path", "").lstrip("/")
        if file_path.startswith("scan/"):
            file_path = file_path[5:]  # Remove /scan/ prefix

        items.append({
            "file": file_path,
            "category": check.get("check_id", "UNKNOWN"),
            "severity": "HIGH",  # Checkov doesn't always provide severity
            "tools": ["Checkov"],
            "support_count": 1,
            "rule_ids": [check.get("check_id", "")],
            "examples": [check.get("check_name", "")],
            "occurrences": 1,
            "message": check.get("check_name", ""),
            "description": check.get("description") or check.get("check_name", ""),
            "line": check.get("file_line_range", [0, 0])[0] if check.get("file_line_range") else 0
        })

    return items


def parse_trivy(raw_file: Path) -> List[Dict[str, Any]]:
    """Parse Trivy config raw JSON output."""
    with open(raw_file, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    items = []
    results = data.get("Results", [])

    for result in results:
        target = result.get("Target", "")
        misconfigs = result.get("Misconfigurations", [])

        for misconf in misconfigs:
            if misconf.get("Status") != "FAIL":
                continue

            file_path = target
            if file_path.startswith("/scan/"):
                file_path = file_path[6:]  # Remove /scan/ prefix

            severity_map = {
                "CRITICAL": "CRITICAL",
                "HIGH": "HIGH",
                "MEDIUM": "MEDIUM",
                "LOW": "LOW"
            }

            severity = severity_map.get(misconf.get("Severity", "MEDIUM"), "MEDIUM")

            # Map Trivy IDs to categories
            trivy_id = misconf.get("ID", "")
            category = "UNKNOWN"
            if "KSV" in trivy_id:
                if "001" in trivy_id or "016" in trivy_id:
                    category = "PRIV_ESCALATION"
                elif "003" in trivy_id or "013" in trivy_id:
                    category = "RUN_AS_NONROOT_FALSE"
                elif "057" in trivy_id:
                    category = "PRIVILEGED"
                elif "017" in trivy_id:
                    category = "READONLY_ROOTFS_FALSE"
                elif "055" in trivy_id:
                    category = "NO_SECCOMP"

            cause_meta = misconf.get("CauseMetadata", {})
            line = cause_meta.get("StartLine", 0)

            items.append({
                "file": file_path,
                "category": category,
                "severity": severity,
                "tools": ["Trivy"],
                "support_count": 1,
                "rule_ids": [trivy_id],
                "examples": [misconf.get("Title", "")],
                "occurrences": 1,
                "message": misconf.get("Message", ""),
                "description": misconf.get("Description", ""),
                "line": line
            })

    return items


def parse_kubescape(raw_file: Path) -> List[Dict[str, Any]]:
    """Parse Kubescape raw JSON output."""
    with open(raw_file, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    items = []

    if isinstance(data, dict):
        # Kubescape format v2: summaryDetails.controls contains control results
        summary = data.get("summaryDetails", {})
        controls = summary.get("controls", {})
        resources = data.get("resources", [])

        # Create resource lookup by resourceID
        resource_lookup = {}
        for resource in resources:
            resource_id = resource.get("resourceID", "")
            source = resource.get("source", {})
            file_path = source.get("path", "").replace("\\", "/")
            if file_path.startswith("/scan/"):
                file_path = file_path[6:]
            resource_lookup[resource_id] = file_path

        # Process failed controls
        for control_id, control_data in controls.items():
            status = control_data.get("status", "")
            if status != "failed":
                continue

            # Get failed resources for this control
            resource_ids = control_data.get("resourceIDs", {})
            failed_resources = resource_ids.get("failed", [])

            control_name = control_data.get("name", control_id)

            for resource_id in failed_resources:
                file_path = resource_lookup.get(resource_id, "")
                if not file_path:
                    continue

                # Map control ID to category
                category = control_id
                if "C-0057" in control_id or "C-0034" in control_id:
                    category = "PRIVILEGED"
                elif "C-0016" in control_id:
                    category = "PRIV_ESCALATION"
                elif "C-0013" in control_id:
                    category = "RUN_AS_NONROOT_FALSE"
                elif "C-0017" in control_id:
                    category = "READONLY_ROOTFS_FALSE"
                elif "C-0055" in control_id:
                    category = "NO_SECCOMP"
                elif "C-0048" in control_id:
                    category = "HOSTPATH"

                items.append({
                    "file": file_path,
                    "category": category,
                    "severity": "HIGH",
                    "tools": ["Kubescape"],
                    "support_count": 1,
                    "rule_ids": [control_id],
                    "examples": [control_name],
                    "occurrences": 1,
                    "message": control_name,
                    "description": control_name,
                    "line": 0
                })

    return items


def parse_kubeaudit(raw_file: Path) -> List[Dict[str, Any]]:
    """Parse KubeAudit raw JSON output."""
    with open(raw_file, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    items = []
    if not isinstance(data, list):
        return items

    for finding in data:
        file_path = finding.get("file", "").replace("\\", "/")
        if file_path.startswith("/scan/"):
            file_path = file_path[6:]

        audit_result_name = finding.get("AuditResultName", "")
        msg = finding.get("msg", "")

        # Map KubeAudit audit result names to categories
        category = "UNKNOWN"
        if "Privileged" in audit_result_name:
            category = "PRIVILEGED"
        elif "AllowPrivilegeEscalation" in audit_result_name:
            category = "PRIV_ESCALATION"
        elif "RunAsNonRoot" in audit_result_name:
            category = "RUN_AS_NONROOT_FALSE"
        elif "ReadOnlyRootFilesystem" in audit_result_name:
            category = "READONLY_ROOTFS_FALSE"
        elif "Seccomp" in audit_result_name:
            category = "NO_SECCOMP"
        elif "AppArmor" in audit_result_name:
            category = "NO_APPARMOR"
        elif "HostPath" in audit_result_name:
            category = "HOSTPATH"
        elif "AutomountServiceAccountToken" in audit_result_name:
            category = "SERVICEACCOUNT_TOKEN_AUTO"
        elif "Capability" in audit_result_name:
            category = "MISSING_CAP_DROP"

        items.append({
            "file": file_path,
            "category": category,
            "severity": "HIGH",
            "tools": ["KubeAudit"],
            "support_count": 1,
            "rule_ids": [audit_result_name],
            "examples": [msg],
            "occurrences": 1,
            "message": msg,
            "description": msg,
            "line": 0
        })

    return items


def parse_conftest(raw_file: Path) -> List[Dict[str, Any]]:
    """Parse Conftest raw JSON output."""
    with open(raw_file, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    items = []
    if not isinstance(data, list):
        return items

    for result in data:
        file_path = result.get("filename", "").replace("\\", "/")
        # Handle Windows paths
        if "\\" in file_path:
            # Extract just the filename if full path
            file_path = Path(file_path).name
        if file_path.startswith("/scan/"):
            file_path = file_path[6:]

        failures = result.get("failures", [])
        for failure in failures:
            msg = failure.get("msg", "")
            # Extract rule ID from message (usually first word before colon)
            rule_id = msg.split(":")[0] if ":" in msg else msg.split()[0] if msg else "OPA_VIOLATION"

            # Map common OPA rule IDs to categories
            category = "OPA_VIOLATION"
            if "KSV" in rule_id or "PRIVILEGED" in msg.upper():
                if "PRIVILEGED" in msg.upper() or "C-0057" in msg:
                    category = "PRIVILEGED"
                elif "PRIV_ESC" in msg.upper() or "C-0016" in msg:
                    category = "PRIV_ESCALATION"
                elif "NONROOT" in msg.upper() or "C-0013" in msg:
                    category = "RUN_AS_NONROOT_FALSE"
                elif "READONLY" in msg.upper() or "C-0017" in msg:
                    category = "READONLY_ROOTFS_FALSE"
                elif "SECCOMP" in msg.upper() or "C-0055" in msg:
                    category = "NO_SECCOMP"
                elif "HOSTPATH" in msg.upper() or "C-0048" in msg:
                    category = "HOSTPATH"
                elif "NAMESPACE" in msg.upper() or "DEFAULT" in msg.upper():
                    category = "POD_DEFAULT_NAMESPACE"

            items.append({
                "file": file_path,
                "category": category,
                "severity": "HIGH",
                "tools": ["Conftest"],
                "support_count": 1,
                "rule_ids": [rule_id],
                "examples": [msg],
                "occurrences": 1,
                "message": msg,
                "description": msg,
                "line": 0
            })

    return items


def parse_gitleaks(raw_file: Path) -> List[Dict[str, Any]]:
    """Parse GitLeaks raw JSON output."""
    with open(raw_file, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    items = []
    if not isinstance(data, list):
        return items

    for finding in data:
        file_path = finding.get("File", "").replace("\\", "/")
        if file_path.startswith("/scan/"):
            file_path = file_path[6:]
        # Extract just filename if full path
        if "\\" in file_path or "/" in file_path:
            file_path = Path(file_path).name

        rule_id = finding.get("RuleID", "")
        description = finding.get("Description", "")
        line = finding.get("StartLine", 0)

        # Map GitLeaks rules to categories
        category = "HARDCODED_SECRET"
        if "password" in rule_id.lower() or "password" in description.lower():
            category = "HARDCODED_PASSWORD"
        elif "api" in rule_id.lower() or "key" in rule_id.lower():
            category = "HARDCODED_API_KEY"
        elif "token" in rule_id.lower():
            category = "HARDCODED_TOKEN"

        items.append({
            "file": file_path,
            "category": category,
            "severity": "CRITICAL",  # Secrets are always critical
            "tools": ["GitLeaks"],
            "support_count": 1,
            "rule_ids": [rule_id],
            "examples": [description],
            "occurrences": 1,
            "message": description,
            "description": description,
            "line": line
        })

    return items


def parse_kubeconform(raw_file: Path) -> List[Dict[str, Any]]:
    """Parse Kubeconform raw JSON output."""
    with open(raw_file, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    items = []
    resources = data.get("resources", [])

    for resource in resources:
        status = resource.get("status", "")
        if status not in ["statusError", "statusInvalid"]:
            continue

        file_path = resource.get("filename", "").replace("\\", "/")
        if file_path.startswith("/scan/"):
            file_path = file_path[6:]

        msg = resource.get("msg", "")
        kind = resource.get("kind", "")

        # Map validation errors to categories
        category = "SCHEMA_VALIDATION_ERROR"
        if "missing" in msg.lower():
            if "selector" in msg.lower():
                category = "MISSING_SELECTOR"
            elif "apiVersion" in msg.lower():
                category = "MISSING_API_VERSION"
            elif "kind" in msg.lower():
                category = "MISSING_KIND"
        elif "invalid" in msg.lower() or "validation" in msg.lower():
            category = "INVALID_SCHEMA"

        items.append({
            "file": file_path,
            "category": category,
            "severity": "HIGH",
            "tools": ["Kubeconform"],
            "support_count": 1,
            "rule_ids": [status],
            "examples": [msg],
            "occurrences": 1,
            "message": msg,
            "description": f"{kind}: {msg}",
            "line": 0
        })

    return items


def parse_kubelinter(raw_file: Path) -> List[Dict[str, Any]]:
    """Parse Kube-Linter raw JSON output."""
    with open(raw_file, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    items = []
    reports = data.get("Reports", [])

    for report in reports:
        diagnostic = report.get("Diagnostic", {})
        check = report.get("Check", "")
        obj = report.get("Object", {})
        metadata = obj.get("Metadata", {})

        file_path = metadata.get("FilePath", "").replace("\\", "/")
        if file_path.startswith("/scan/"):
            file_path = file_path[6:]

        message = diagnostic.get("Message", "")
        remediation = report.get("Remediation", "")

        # Map Kube-Linter checks to categories
        category = check.upper().replace("-", "_")
        if "privileged" in check.lower():
            category = "PRIVILEGED"
        elif "privilege-escalation" in check.lower():
            category = "PRIV_ESCALATION"
        elif "run-as-non-root" in check.lower():
            category = "RUN_AS_NONROOT_FALSE"
        elif "read-only-root" in check.lower() or "readonly" in check.lower():
            category = "READONLY_ROOTFS_FALSE"
        elif "host-" in check.lower():
            if "network" in check.lower():
                category = "HOST_NAMESPACE"
            elif "pid" in check.lower():
                category = "HOST_NAMESPACE"
            elif "ipc" in check.lower():
                category = "HOST_NAMESPACE"
        elif "cpu-requirements" in check.lower() or "memory-requirements" in check.lower():
            category = "NO_RES_LIMITS"
        elif "latest-tag" in check.lower():
            category = "LATEST_TAG"

        items.append({
            "file": file_path,
            "category": category,
            "severity": "HIGH",
            "tools": ["Kube-Linter"],
            "support_count": 1,
            "rule_ids": [check],
            "examples": [message],
            "occurrences": 1,
            "message": message,
            "description": f"{message}. {remediation}",
            "line": 0
        })

    return items


def parse_kubescore(raw_file: Path) -> List[Dict[str, Any]]:
    """Parse Kube-Score raw JSON output."""
    with open(raw_file, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    items = []
    if not isinstance(data, list):
        return items

    for result in data:
        file_path = result.get("file_name", "").replace("\\", "/")
        if file_path.startswith("/scan/"):
            file_path = file_path[6:]

        checks = result.get("checks", [])
        for check in checks:
            grade = check.get("grade", 10)
            if grade >= 10:  # Only report failures (grade < 10)
                continue

            check_info = check.get("check", {})
            check_id = check_info.get("id", "")
            check_name = check_info.get("name", "")
            comments = check.get("comments", [])

            # Get first comment as message
            message = check_name
            if comments and isinstance(comments, list) and len(comments) > 0:
                first_comment = comments[0]
                if isinstance(first_comment, dict):
                    message = first_comment.get("summary", check_name)
                    description = first_comment.get("description", "")
                else:
                    message = str(first_comment)
                    description = ""
            else:
                description = check_info.get("comment", "")

            # Map Kube-Score checks to categories
            category = check_id.upper().replace("-", "_")
            if "service-type" in check_id.lower():
                category = "NODEPORT_SERVICE"
            elif "stable-version" in check_id.lower():
                category = "DEPRECATED_API_VERSION"
            elif "service-targets-pod" in check_id.lower():
                category = "DANGLING_SERVICE"

            items.append({
                "file": file_path,
                "category": category,
                "severity": "MEDIUM" if grade >= 5 else "HIGH",
                "tools": ["Kube-Score"],
                "support_count": 1,
                "rule_ids": [check_id],
                "examples": [message],
                "occurrences": 1,
                "message": message,
                "description": description or message,
                "line": result.get("file_row", 0)
            })

    return items


def parse_pluto(raw_file: Path) -> List[Dict[str, Any]]:
    """Parse Pluto raw JSON output."""
    with open(raw_file, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    items = []
    # Pluto typically outputs version info, not findings
    # If there are actual findings, they would be in a different format
    # For now, return empty as Pluto is mainly for deprecation detection

    if isinstance(data, dict):
        return items
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                file_path = item.get("file", "").replace("\\", "/")
                if file_path.startswith("/scan/"):
                    file_path = file_path[6:]

                message = item.get("message", "") or item.get("description", "")
                if message:
                    items.append({
                        "file": file_path,
                        "category": "DEPRECATED_API_VERSION",
                        "severity": "MEDIUM",
                        "tools": ["Pluto"],
                        "support_count": 1,
                        "rule_ids": [item.get("rule", "deprecated")],
                        "examples": [message],
                        "occurrences": 1,
                        "message": message,
                        "description": message,
                        "line": 0
                    })

    return items


def parse_rbacpolice(raw_file: Path) -> List[Dict[str, Any]]:
    """Parse RBAC-Police raw JSON output."""
    with open(raw_file, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    items = []
    if not isinstance(data, list):
        return items

    for finding in data:
        file_path = finding.get("file", "").replace("\\", "/")
        if file_path.startswith("/scan/"):
            file_path = file_path[6:]

        rule = finding.get("rule", "")
        severity = finding.get("severity", "MEDIUM")
        message = finding.get("message", "")
        category_field = finding.get("category", "")

        # Map RBAC-Police categories
        category = category_field.upper().replace(" ", "_") if category_field else "RBAC_VIOLATION"
        if "excessive" in category_field.lower() or "cluster-admin" in rule.lower():
            category = "EXCESSIVE_PERMISSIONS"
        elif "dangerous" in category_field.lower():
            category = "DANGEROUS_VERB"

        severity_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW"
        }
        mapped_severity = severity_map.get(severity.upper(), "HIGH")

        items.append({
            "file": file_path,
            "category": category,
            "severity": mapped_severity,
            "tools": ["RBAC-Police"],
            "support_count": 1,
            "rule_ids": [rule],
            "examples": [message],
            "occurrences": 1,
            "message": message,
            "description": message,
            "line": 0
        })

    return items


def parse_yamllint(raw_file: Path) -> List[Dict[str, Any]]:
    """Parse YAMLlint raw text output."""
    items = []

    try:
        content = raw_file.read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError):
        return items

    lines = content.strip().split('\n')

    for line in lines:
        if not line.strip():
            continue
        # Format: file:line:col: [level] message (rule-id)
        # Example: /scan/13.deployment.yaml:10:7: [error] wrong indentation (indentation)
        parts = line.split(':', 3)
        if len(parts) < 4:
            continue
        file_path = parts[0].replace('\\', '/')
        if file_path.startswith('/scan/'):
            file_path = file_path[6:]
        try:
            line_num = int(parts[1])
        except (ValueError, IndexError):
            line_num = 0
        rest = parts[3] if len(parts) > 3 else ""
        # Extract level and message
        level = "error"
        message = rest.strip()
        if "[warning]" in rest:
            level = "warning"
            message = rest.split('[warning]')[-1].strip()
        elif "[error]" in rest:
            level = "error"
            message = rest.split('[error]')[-1].strip()
        # Extract rule ID from parentheses if present
        rule_id = "yamllint-rule"
        if "(" in message and ")" in message:
            rule_id = message.split("(")[-1].split(")")[0]
            message = message.split("(")[0].strip()
        # Map YAMLlint rules to categories
        category = "YAML_FORMAT_ERROR"
        if "indentation" in rule_id.lower():
            category = "YAML_INDENTATION_ERROR"
        elif "line-length" in rule_id.lower():
            category = "YAML_LINE_LENGTH"
        elif "document-start" in rule_id.lower():
            category = "YAML_DOCUMENT_START"
        elif "new-line" in rule_id.lower():
            category = "YAML_NEWLINE_ERROR"
        elif "trailing" in rule_id.lower():
            category = "YAML_TRAILING_SPACES"
        severity = "MEDIUM" if level == "warning" else "HIGH"
        items.append({
            "file": file_path,
            "category": category,
            "severity": severity,
            "tools": ["YAMLlint"],
            "support_count": 1,
            "rule_ids": [rule_id],
            "examples": [message],
            "occurrences": 1,
            "message": message,
            "description": message,
            "line": line_num
        })

    return items


def parse_polaris(raw_file: Path) -> List[Dict[str, Any]]:
    """Parse Polaris raw JSON output."""
    with open(raw_file, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    items = []
    results = data.get("Results", [])

    for result in results:
        # Polaris doesn't always have Filename, need to extract from PodResult or use Name
        pod_result = result.get("PodResult")
        if pod_result:
            # PodResult has YamlContent or we can use Name/Namespace
            name = result.get("Name", "")
            namespace = result.get("Namespace", "")
            kind = result.get("Kind", "")

            # Try to construct file path (Polaris doesn't always provide it)
            file_path = f"{kind.lower()}_{name}.yaml"
            if namespace and namespace != "default":
                file_path = f"{namespace}/{file_path}"

            checks = pod_result.get("Checks", {})
            for check_id, check_data in checks.items():
                if check_data.get("Success", True):  # Skip successful checks
                    continue

                message = check_data.get("Message", check_id)
                severity = check_data.get("Severity", "warning")

                # Map Polaris checks to categories
                category = check_id.upper().replace(" ", "_")
                if "privileged" in check_id.lower():
                    category = "PRIVILEGED"
                elif "readOnlyRootFilesystem" in check_id or "readOnlyRoot" in check_id:
                    category = "READONLY_ROOTFS_FALSE"
                elif "runAsNonRoot" in check_id or "runAsRoot" in check_id:
                    category = "RUN_AS_NONROOT_FALSE"
                elif "allowPrivilegeEscalation" in check_id:
                    category = "PRIV_ESCALATION"
                elif "cpuLimitsMissing" in check_id or "memoryLimitsMissing" in check_id:
                    category = "NO_RES_LIMITS"
                elif "hostNetworkSet" in check_id:
                    category = "HOST_NAMESPACE"

                severity_map = {
                    "danger": "CRITICAL",
                    "warning": "HIGH",
                    "info": "MEDIUM"
                }
                mapped_severity = severity_map.get(severity.lower(), "MEDIUM")

                items.append({
                    "file": file_path,
                    "category": category,
                    "severity": mapped_severity,
                    "tools": ["Polaris"],
                    "support_count": 1,
                    "rule_ids": [check_id],
                    "examples": [message],
                    "occurrences": 1,
                    "message": message,
                    "description": message,
                    "line": 0
                })
        else:
            # Fallback: check Results directly
            checks = result.get("Results", {})
            for check_id, check_data in checks.items():
                if check_data.get("Success", True):
                    continue

                name = result.get("Name", "")
                file_path = f"{result.get('Kind', 'Resource').lower()}_{name}.yaml"

                items.append({
                    "file": file_path,
                    "category": check_id.upper().replace(" ", "_"),
                    "severity": "MEDIUM",
                    "tools": ["Polaris"],
                    "support_count": 1,
                    "rule_ids": [check_id],
                    "examples": [check_data.get("Message", "")],
                    "occurrences": 1,
                    "message": check_data.get("Message", ""),
                    "description": check_data.get("Message", ""),
                    "line": 0
                })

    return items


def create_llm_payload(items: List[Dict[str, Any]], tool_name: str) -> Dict[str, Any]:
    """Create LLM payload from parsed items."""
    return {
        "generated_at": __import__("datetime").datetime.now().isoformat() + "Z",
        "version": f"raw-{tool_name.lower()}",
        "metadata": {
            "raw_findings_count": len(items),
            "aggregated_count": len(items),
            "llm_items_count": len(items),
            "source_tool": tool_name,
            "normalized": False
        },
        "items": items
    }


def main():
    parser = argparse.ArgumentParser(
        description="Send raw tool findings directly to LLM (bypasses normalization)"
    )
    parser.add_argument("--tool", required=True,
                       choices=["checkov", "trivy", "kubescape", "kubeaudit", "conftest", "polaris",
                               "gitleaks", "kubeconform", "kubelinter", "kubescore", "pluto", "rbacpolice", "yamllint"],
                       help="Tool name")
    parser.add_argument("--raw", required=True, type=str,
                       help="Path to raw tool output file")
    parser.add_argument("--models", type=str, default="groq,openrouter,gemini",
                       help="Comma-separated LLM providers")
    parser.add_argument("--concurrency", type=int, default=15,
                       help="Number of items to process in parallel")
    parser.add_argument("--shard-models", action="store_true", default=True,
                       help="Use model sharding (round-robin) for speed")
    parser.add_argument("--output", type=str, default=None,
                       help="Output directory (default: output/llm)")

    args = parser.parse_args()

    # Parse raw file (with yamllint .txt fallback if needed)
    raw_file = Path(args.raw)
    if not raw_file.exists() and args.tool == "yamllint" and raw_file.suffix.lower() == ".json":
        alt = raw_file.with_suffix(".txt")
        if alt.exists():
            raw_file = alt

    if not raw_file.exists():
        print(f"ERROR: Raw file not found: {raw_file}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"Raw-to-LLM Pipeline: {args.tool.upper()}")
    print(f"{'='*60}")
    print(f"Raw file: {raw_file}")
    print(f"Parsing {args.tool} format...")

    # Parse based on tool
    parser_funcs = {
        "checkov": parse_checkov,
        "trivy": parse_trivy,
        "kubescape": parse_kubescape,
        "kubeaudit": parse_kubeaudit,
        "conftest": parse_conftest,
        "polaris": parse_polaris,
        "gitleaks": parse_gitleaks,
        "kubeconform": parse_kubeconform,
        "kubelinter": parse_kubelinter,
        "kubescore": parse_kubescore,
        "pluto": parse_pluto,
        "rbacpolice": parse_rbacpolice,
        "yamllint": parse_yamllint
    }

    try:
        items = parser_funcs[args.tool](raw_file)
        print("Parsed {} findings".format(len(items)))
    except (json.JSONDecodeError, KeyError, ValueError, OSError) as e:
        print(f"ERROR: Failed to parse {args.tool} file: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    if not items:
        print("WARNING: No findings extracted from raw file")
        sys.exit(0)

    # Create LLM payload
    payload = create_llm_payload(items, args.tool)

    # Write temporary payload file
    output_dir = Path(args.output) if args.output else OUTPUT_ROOT / "llm"
    output_dir.mkdir(parents=True, exist_ok=True)

    temp_payload = output_dir / f"llm_payload_raw_{args.tool}.json"
    temp_payload.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Created LLM payload: {temp_payload}")

    # Temporarily replace normalization payload
    norm_payload = NORMALIZATION_DIR / "llm_payload.json"
    backup_payload = None
    if norm_payload.exists():
        backup_payload = NORMALIZATION_DIR / "llm_payload.json.backup"
        import shutil
        shutil.copy2(norm_payload, backup_payload)
    print(f"Backed up existing payload to {backup_payload}")

    # Copy temp payload to normalization dir (LLM orchestrator expects it there)
    import shutil
    shutil.copy2(temp_payload, norm_payload)
    print(f"Set {norm_payload} for LLM processing")

    # Run LLM orchestrator
    print(f"\n{'='*60}")
    print("Running LLM Fix Generation...")
    print(f"{'='*60}")

    llm_script = Path(__file__).parent / "multi_llm_orchestrator.py"
    cmd = [
        sys.executable, str(llm_script),
        "--models", args.models,
        "--validate", "yaml",
        "--autofix",
        "--hygiene",
        "--concurrency", str(args.concurrency),
        "--timeout", "20",
        "--retries", "1"
    ]

    if args.shard_models:
        cmd.append("--shard-models")
        safe_fast_banner()

    env = os.environ.copy()
    env["SAFEFIX_OUTPUT_ROOT"] = str(OUTPUT_ROOT)
    env["SAFEFIX_NORMALIZATION_DIR"] = str(NORMALIZATION_DIR)
    env["SAFEFIX_LLM_DIR"] = str(output_dir)

    result = subprocess.run(cmd, cwd=Path.cwd(), env=env, check=False)

    # Restore backup if it existed
    if backup_payload and backup_payload.exists():
        shutil.copy2(backup_payload, norm_payload)
    print("Restored original payload from backup")

    if result.returncode != 0:
        print(f"\nERROR: LLM processing failed with exit code {result.returncode}")
        sys.exit(result.returncode)

    print("\n" + "="*60)
    print("LLM Processing Complete!")
    print("="*60)
    print(f"Decisions saved to: {output_dir / 'llm_decisions.json'}")
    print("\nNext step: Combine fixes")
    print("  python LLMs/combine_yaml_files.py --file <target_file>")


if __name__ == "__main__":
    main()
