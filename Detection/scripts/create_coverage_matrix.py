#!/usr/bin/env python3
"""
Create Excel coverage matrix from detection tool outputs.
Format matches the provided CSV example exactly.
"""

import json
import os
from pathlib import Path
from collections import defaultdict
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment

# Paths
SCRIPT_DIR = Path(__file__).parent
RAW_DIR = SCRIPT_DIR / "output" / "raw"
OUTPUT_FILE = SCRIPT_DIR / "output" / "Coverage_Matrix.xlsx"

# Tool columns (all detection tools)
TOOL_COLUMNS = [
    "Trivy",
    "Checkov",
    "KubeAudit",
    "KubeLinter",
    "Polaris",
    "KubeScore",
    "Kubescape",
    "Conftest\n(Hegab's)",
    "KubeConform",
    "RBAC-Police",
    "Yamllint",
    "Gitleaks",
    "Pluto"
]


def normalize_filename(filepath):
    """Extract clean filename from path"""
    if not filepath:
        return ""
    return os.path.basename(filepath).replace("/scan/", "").replace("\\scan\\", "")


def parse_checkov():
    """Parse Checkov output"""
    findings = defaultdict(lambda: defaultdict(set))
    filepath = RAW_DIR / "checkov_raw.json"
    
    vuln_map = {
        "CKV_K8S_21": "Default namespace",
        "CKV_K8S_28": "Default capabilities not dropped",
        "CKV_K8S_37": "Default capabilities not dropped",
        "CKV_K8S_29": "No security context",
        "CKV_K8S_8": "No CPU limit",
        "CKV_K8S_11": "No CPU request",
        "CKV_K8S_9": "No memory limit",
        "CKV_K8S_10": "No memory request",
        "CKV_K8S_14": "Image not pinned by digest",
        "CKV_K8S_13": "ImagePullPolicy not Always",
        "CKV_K8S_15": "ImagePullPolicy not Always",
        "CKV_K8S_22": "Filesystem not read-only",
        "CKV_K8S_23": "No livenessProbe",
        "CKV_K8S_24": "No readinessProbe",
        "CKV_K8S_25": "Privilege escalation allowed",
        "CKV_K8S_20": "Privilege escalation allowed",
        "CKV_K8S_16": "Privileged container",
        "CKV_K8S_17": "Privileged container",
        "CKV_K8S_40": "Runs as root user",
        "CKV_K8S_43": "Using latest tag",
        "CKV_K8S_35": "No seccomp profile",
        "CKV_K8S_38": "No seccomp profile",
        "CKV_K8S_30": "No seccomp profile",
        "CKV_K8S_27": "Default service account token mounted",
        "CKV_K8S_41": "Default service account token mounted",
        "CKV_K8S_106": "No network policy",
        "CKV2_K8S_6": "No network policy",
        "CKV_K8S_31": "No AppArmor profile",
    }
    
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        for check in data.get("results", {}).get("failed_checks", []):
            file = normalize_filename(check.get("file_path", ""))
            check_id = check.get("check_id", "")
            if check_id in vuln_map:
                findings[file][vuln_map[check_id]].add("Checkov")
    except Exception as e:
        print(f"⚠️  Error parsing Checkov: {e}")
    
    return findings


def parse_trivy():
    """Parse Trivy output"""
    findings = defaultdict(lambda: defaultdict(set))
    filepath = RAW_DIR / "trivy_config_raw.json"
    
    vuln_map = {
        "KSV001": "Privileged container",
        "KSV003": "Default capabilities not dropped",
        "KSV005": "Default capabilities not dropped",
        "KSV006": "Docker socket mounted",
        "KSV011": "No CPU limit",
        "KSV012": "Runs as root user",
        "KSV013": "Using latest tag",
        "KSV014": "Filesystem not read-only",
        "KSV015": "No CPU request",
        "KSV016": "No memory request",
        "KSV017": "Privilege escalation allowed",
        "KSV018": "No memory limit",
        "KSV020": "Privilege escalation allowed",
        "KSV021": "Default namespace",
        "KSV025": "No seccomp profile",
        "KSV030": "No seccomp profile",
        "KSV104": "No seccomp profile",
        "KSV110": "Default namespace",
        "KSV111": "Runs as root user",
        "KSV116": "Runs as root user",
    }
    
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        for result in data.get("Results", []):
            file = normalize_filename(result.get("Target", ""))
            for misconfig in result.get("Misconfigurations", []):
                check_id = misconfig.get("ID", "")
                if check_id in vuln_map:
                    findings[file][vuln_map[check_id]].add("Trivy")
    except Exception as e:
        print(f"⚠️  Error parsing Trivy: {e}")
    
    return findings


def parse_kubeaudit():
    """Parse KubeAudit output"""
    findings = defaultdict(lambda: defaultdict(set))
    filepath = RAW_DIR / "kubeaudit_raw.json"
    
    vuln_map = {
        "AppArmorAnnotationMissing": "No AppArmor profile",
        "AutomountServiceAccountTokenTrueAndDefaultSA": "Default service account token mounted",
        "CapabilityOrSecurityContextMissing": "Default capabilities not dropped",
        "CapabilityNotDropped": "Default capabilities not dropped",
        "SensitivePathsMounted": "Docker socket mounted",
        "RunAsNonRootPSCNilCSCNil": "Runs as root user",
        "RunAsNonRootCSCFalse": "Runs as root user",
        "AllowPrivilegeEscalationNil": "Privilege escalation allowed",
        "AllowPrivilegeEscalationTrue": "Privilege escalation allowed",
        "ReadOnlyRootFilesystemNil": "Filesystem not read-only",
        "ReadOnlyRootFilesystemFalse": "Filesystem not read-only",
        "SeccompProfileMissing": "No seccomp profile",
        "PrivilegedTrue": "Privileged container",
    }
    
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        for item in data:
            file = normalize_filename(item.get("file", ""))
            audit_type = item.get("AuditResultName", "")
            if audit_type in vuln_map:
                findings[file][vuln_map[audit_type]].add("KubeAudit")
    except Exception as e:
        print(f"⚠️  Error parsing KubeAudit: {e}")
    
    return findings


def parse_kubelinter():
    """Parse KubeLinter output"""
    findings = defaultdict(lambda: defaultdict(set))
    filepath = RAW_DIR / "kubelinter_raw.json"
    
    vuln_map = {
        "docker-sock": "Docker socket mounted",
        "latest-tag": "Using latest tag",
        "no-read-only-root-fs": "Filesystem not read-only",
        "run-as-non-root": "Runs as root user",
        "unset-cpu-requirements": "No CPU request",
        "unset-memory-requirements": "No memory limit",
        "privilege-escalation-container": "Privilege escalation allowed",
        "privileged-container": "Privileged container",
        "mismatching-selector": "Deployment selector missing",
        "no-anti-affinity": "Single replica (non-HA)",
        "no-extensions-v1beta": "Using deprecated API",
    }
    
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        for report in data.get("Reports", []):
            file = normalize_filename(report.get("Object", {}).get("Metadata", {}).get("FilePath", ""))
            check_name = report.get("Check", "")
            if check_name in vuln_map:
                findings[file][vuln_map[check_name]].add("KubeLinter")
    except Exception as e:
        print(f"⚠️  Error parsing KubeLinter: {e}")
    
    return findings


def parse_polaris():
    """Parse Polaris output"""
    findings = defaultdict(lambda: defaultdict(set))
    filepath = RAW_DIR / "polaris_raw.json"
    
    vuln_map = {
        "cpuRequestsMissing": "No CPU request",
        "cpuLimitsMissing": "No CPU limit",
        "memoryRequestsMissing": "No memory request",
        "memoryLimitsMissing": "No memory limit",
        "readinessProbeMissing": "No readinessProbe",
        "livenessProbeMissing": "No livenessProbe",
        "runAsRootAllowed": "Runs as root user",
        "runAsPrivileged": "Privileged container",
        "notReadOnlyRootFilesystem": "Filesystem not read-only",
        "privilegeEscalationAllowed": "Privilege escalation allowed",
        "tagNotSpecified": "Using latest tag",
        "pullPolicyNotAlways": "ImagePullPolicy not Always",
        "insecureCapabilities": "Default capabilities not dropped",
        "dangerousCapabilities": "Dangerous capabilities",
        "tlsSettingsMissing": "No TLS configured (Ingress)",
    }
    
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        for result in data.get("results", []):
            file = normalize_filename(result.get("file", ""))
            pod_result = result.get("podResult", {})
            container_results = result.get("containerResults", [])
            
            # Check pod-level results
            for check_id, check_data in pod_result.get("results", {}).items():
                if not check_data.get("success", True):
                    if check_id in vuln_map:
                        findings[file][vuln_map[check_id]].add("Polaris")
            
            # Check container-level results
            for container in container_results:
                for check_id, check_data in container.get("results", {}).items():
                    if not check_data.get("success", True):
                        if check_id in vuln_map:
                            findings[file][vuln_map[check_id]].add("Polaris")
    except Exception as e:
        print(f"⚠️  Error parsing Polaris: {e}")
    
    return findings


def parse_kubescape():
    """Parse Kubescape output"""
    findings = defaultdict(lambda: defaultdict(set))
    filepath = RAW_DIR / "kubescape_raw.json"
    
    vuln_map = {
        "C-0016": "Privilege escalation allowed",
        "C-0017": "Privileged container",
        "C-0018": "Default capabilities not dropped",
        "C-0030": "No network policy",
        "C-0034": "Default namespace",
        "C-0044": "No security context",
        "C-0046": "No seccomp profile",
        "C-0048": "Host path mounted",
        "C-0050": "No CPU limit",
        "C-0051": "No CPU request",
        "C-0052": "No memory limit",
        "C-0053": "No memory request",
        "C-0055": "No livenessProbe",
        "C-0056": "No readinessProbe",
        "C-0057": "Runs as root user",
        "C-0074": "Standalone Pod",
        "C-0078": "Image not pinned by digest",
    }
    
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        for result in data.get("results", []):
            for resource in result.get("resourcesResult", []):
                file = ""
                res_id = resource.get("resourceID", "")
                # Extract filename from resourceID
                if "/" in res_id:
                    parts = res_id.split("/")
                    for part in parts:
                        if part.endswith(".yaml") or part.endswith(".yml"):
                            file = part
                            break
                
                for control in resource.get("controls", []):
                    if control.get("status", {}).get("status") == "failed":
                        control_id = control.get("controlID", "")
                        if control_id in vuln_map:
                            if file:
                                findings[file][vuln_map[control_id]].add("Kubescape")
    except Exception as e:
        print(f"⚠️  Error parsing Kubescape: {e}")
    
    return findings


def parse_kubescore():
    """Parse KubeScore output"""
    findings = defaultdict(lambda: defaultdict(set))
    filepath = RAW_DIR / "kubescore_raw.json"
    
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        for item in data:
            file = normalize_filename(item.get("file_name", ""))
            for check in item.get("checks", []):
                grade = check.get("grade", 10)
                if grade < 7:  # Failed or warning
                    comment = check.get("comment", "")
                    # Map based on comment/check name
                    if "network" in comment.lower() and "policy" in comment.lower():
                        findings[file]["No network policy"].add("KubeScore")
                    elif "liveness" in comment.lower():
                        findings[file]["No livenessProbe"].add("KubeScore")
                    elif "readiness" in comment.lower():
                        findings[file]["No readinessProbe"].add("KubeScore")
                    elif "cpu" in comment.lower() and "request" in comment.lower():
                        findings[file]["No CPU request"].add("KubeScore")
                    elif "cpu" in comment.lower() and "limit" in comment.lower():
                        findings[file]["No CPU limit"].add("KubeScore")
                    elif "memory" in comment.lower() and "request" in comment.lower():
                        findings[file]["No memory request"].add("KubeScore")
                    elif "memory" in comment.lower() and "limit" in comment.lower():
                        findings[file]["No memory limit"].add("KubeScore")
                    elif "standalone" in comment.lower() or "pod" in comment.lower():
                        findings[file]["Standalone Pod"].add("KubeScore")
    except Exception as e:
        print(f"⚠️  Error parsing KubeScore: {e}")
    
    return findings


def parse_conftest():
    """Parse Conftest output"""
    findings = defaultdict(lambda: defaultdict(set))
    filepath = RAW_DIR / "conftest_raw.json"
    
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        for result in data:
            if isinstance(result, dict):
                file = normalize_filename(result.get("filename", ""))
                
                for failure in result.get("failures", []):
                    msg = failure.get("msg", "").lower()
                    
                    # Map based on message content
                    if "privileged" in msg and "cni" in msg:
                        findings[file]["Privileged CNI plugin config"].add("Conftest\n(Hegab's)")
                    elif "privileged" in msg:
                        findings[file]["Privileged container"].add("Conftest\n(Hegab's)")
                    elif "secret" in msg and "unencrypted" in msg:
                        findings[file]["Unencrypted Secret"].add("Conftest\n(Hegab's)")
                    elif "capabilities" in msg or "drop" in msg:
                        findings[file]["Default capabilities not dropped"].add("Conftest\n(Hegab's)")
                    elif "root" in msg:
                        findings[file]["Runs as root user"].add("Conftest\n(Hegab's)")
                    elif "namespace" in msg and "default" in msg:
                        findings[file]["Default namespace"].add("Conftest\n(Hegab's)")
                    elif "escalation" in msg or "privilege" in msg:
                        findings[file]["Privilege escalation allowed"].add("Conftest\n(Hegab's)")
                    elif "seccomp" in msg:
                        findings[file]["No seccomp profile"].add("Conftest\n(Hegab's)")
    except Exception as e:
        print(f"⚠️  Error parsing Conftest: {e}")
    
    return findings


def parse_kubeconform():
    """Parse KubeConform output"""
    findings = defaultdict(lambda: defaultdict(set))
    filepath = RAW_DIR / "kubeconform_raw.json"
    
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        # Handle both formats: newline-delimited and standard JSON
        if isinstance(data, dict) and "resources" in data:
            # Standard JSON format
            for resource in data.get("resources", []):
                if resource.get("status") == "statusInvalid":
                    file = normalize_filename(resource.get("filename", ""))
                    findings[file]["Deployment selector missing"].add("KubeConform")
        else:
            # Newline-delimited JSON
            content = open(filepath, 'r', encoding='utf-8-sig').read()
            for line in content.strip().split('\n'):
                if line:
                    item = json.loads(line)
                    if item.get("status") == "statusInvalid":
                        file = normalize_filename(item.get("filename", ""))
                        findings[file]["Deployment selector missing"].add("KubeConform")
    except Exception as e:
        print(f"⚠️  Error parsing KubeConform: {e}")
    
    return findings


def parse_rbacpolice():
    """Parse RBAC Police output"""
    findings = defaultdict(lambda: defaultdict(set))
    filepath = RAW_DIR / "rbacpolice_raw.json"
    
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        for item in data:
            if isinstance(item, dict) and "rule" in item:
                file = normalize_filename(item.get("file", ""))
                findings[file]["Overly permissive Role"].add("RBAC-Police")
    except Exception as e:
        print(f"⚠️  Error parsing RBAC Police: {e}")
    
    return findings


def parse_yamllint():
    """Parse Yamllint text output"""
    findings = defaultdict(lambda: defaultdict(set))
    filepath = RAW_DIR / "yamllint_raw.txt"
    
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    # Format: /scan/filename.yaml:line:col: [error/warning] message
                    parts = line.split(':')
                    if len(parts) >= 4:
                        file = normalize_filename(parts[0])
                        # Extract the issue type from the message
                        if '[error]' in line or '[warning]' in line:
                            msg = ':'.join(parts[3:]).strip()
                            if 'syntax' in msg.lower():
                                findings[file]["YAML syntax error"].add("Yamllint")
                            elif 'indentation' in msg.lower():
                                findings[file]["YAML indentation error"].add("Yamllint")
                            elif 'line length' in msg.lower():
                                findings[file]["YAML line too long"].add("Yamllint")
                            elif 'trailing' in msg.lower():
                                findings[file]["YAML trailing spaces"].add("Yamllint")
                            else:
                                findings[file]["YAML formatting issue"].add("Yamllint")
    except Exception as e:
        print(f"⚠️  Error parsing Yamllint: {e}")
    
    return findings


def parse_gitleaks():
    """Parse Gitleaks JSON output"""
    findings = defaultdict(lambda: defaultdict(set))
    filepath = RAW_DIR / "gitleaks_raw.json"
    
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "File" in item:
                    file = normalize_filename(item.get("File", ""))
                    secret_type = item.get("RuleID", "Secret")
                    description = item.get("Description", "Hardcoded secret detected")
                    
                    # Create a readable vulnerability name
                    if "password" in secret_type.lower():
                        vuln = "Hardcoded password"
                    elif "token" in secret_type.lower():
                        vuln = "Hardcoded token"
                    elif "key" in secret_type.lower():
                        vuln = "Hardcoded API key"
                    elif "credential" in secret_type.lower():
                        vuln = "Hardcoded credentials"
                    else:
                        vuln = f"Hardcoded secret ({secret_type})"
                    
                    findings[file][vuln].add("Gitleaks")
    except Exception as e:
        print(f"⚠️  Error parsing Gitleaks: {e}")
    
    return findings


def parse_pluto():
    """Parse Pluto JSON output"""
    findings = defaultdict(lambda: defaultdict(set))
    filepath = RAW_DIR / "pluto_raw.json"
    
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        # Pluto format: {"items": [...], "target-versions": {...}}
        items = data.get("items", [])
        for item in items:
            file = normalize_filename(item.get("file", ""))
            api_version = item.get("api-version", "")
            kind = item.get("kind", "")
            deprecated = item.get("deprecated", False)
            removed = item.get("removed", False)
            
            if removed:
                vuln = f"Removed API: {api_version} {kind}"
            elif deprecated:
                vuln = f"Deprecated API: {api_version} {kind}"
            else:
                vuln = f"API version issue: {api_version} {kind}"
            
            findings[file][vuln].add("Pluto")
    except Exception as e:
        print(f"⚠️  Error parsing Pluto: {e}")
    
    return findings


def merge_findings(*finding_dicts):
    """Merge multiple finding dictionaries"""
    merged = defaultdict(lambda: defaultdict(set))
    for finding_dict in finding_dicts:
        for file, vulns in finding_dict.items():
            for vuln, tools in vulns.items():
                merged[file][vuln].update(tools)
    return merged


def create_excel(findings, output_path):
    """Create Excel coverage matrix matching the exact format"""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Coverage"
    
    # Write header row
    ws["A1"] = "File"
    ws["B1"] = "Vulns"
    for idx, tool in enumerate(TOOL_COLUMNS, start=3):
        ws.cell(row=1, column=idx, value=tool)
    
    # Sort files
    sorted_files = sorted(findings.keys())
    
    row = 2
    for file in sorted_files:
        vulns = findings[file]
        sorted_vulns = sorted(vulns.keys())
        
        if not sorted_vulns:
            # No vulnerabilities
            ws.cell(row=row, column=1, value=file)
            ws.cell(row=row, column=2, value="No issues detected by the configured tools.")
            row += 1
            ws.cell(row=row, column=1, value="")  # Empty separator
            row += 1
            continue
        
        # Write file name in first row
        start_row = row
        for vuln in sorted_vulns:
            ws.cell(row=row, column=2, value=vuln)
            detected_tools = vulns[vuln]
            
            # Mark tool columns with checkmarks
            for idx, tool in enumerate(TOOL_COLUMNS, start=3):
                if tool in detected_tools:
                    ws.cell(row=row, column=idx, value="✔")
            
            row += 1
        
        # Set file name in first column (spanning all vuln rows)
        ws.cell(row=start_row, column=1, value=file)
        
        # Add empty separator row
        ws.cell(row=row, column=1, value="")
        row += 1
    
    # Adjust column widths
    ws.column_dimensions['A'].width = 45
    ws.column_dimensions['B'].width = 50
    for col_idx in range(3, 3 + len(TOOL_COLUMNS)):
        ws.column_dimensions[openpyxl.utils.get_column_letter(col_idx)].width = 13
    
    # Save
    wb.save(output_path)
    print(f"\n✅ Coverage matrix created: {output_path}")


def main():
    """Main execution"""
    print("=" * 70)
    print("  Creating Detection Coverage Matrix")
    print("=" * 70)
    
    # Parse all tools
    print("\n📊 Parsing detection outputs...")
    trivy_findings = parse_trivy()
    checkov_findings = parse_checkov()
    kubeaudit_findings = parse_kubeaudit()
    kubelinter_findings = parse_kubelinter()
    polaris_findings = parse_polaris()
    kubescore_findings = parse_kubescore()
    kubescape_findings = parse_kubescape()
    conftest_findings = parse_conftest()
    kubeconform_findings = parse_kubeconform()
    rbacpolice_findings = parse_rbacpolice()
    yamllint_findings = parse_yamllint()
    gitleaks_findings = parse_gitleaks()
    pluto_findings = parse_pluto()
    
    # Merge all findings
    all_findings = merge_findings(
        trivy_findings, checkov_findings, kubeaudit_findings,
        kubelinter_findings, polaris_findings, kubescore_findings,
        kubescape_findings, conftest_findings, kubeconform_findings,
        rbacpolice_findings, yamllint_findings, gitleaks_findings,
        pluto_findings
    )
    
    print(f"   Files analyzed: {len(all_findings)}")
    total_vulns = sum(len(vulns) for vulns in all_findings.values())
    print(f"   Total findings: {total_vulns}")
    
    # Create Excel
    print("\n📄 Generating Excel coverage matrix...")
    create_excel(all_findings, OUTPUT_FILE)
    
    print("\n" + "=" * 70)
    print("✅ Done!")
    print("=" * 70)


if __name__ == "__main__":
    main()
