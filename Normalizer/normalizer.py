#!/usr/bin/env python3
"""
SafeFix-K8s Normalizer - FIXED VERSION

Fixes:
1. Better file extraction from Polaris (use resource name matching)
2. Proper bucket merging (UNKNOWN_FILE findings merge with known files)
3. Filter RBAC false positives (when no RBAC manifests exist)
4. Fix category mapping for KSV0125 (untrusted registry)
5. Better yamllint handling (only actual YAML issues)
6. Category families + strong tool mapping to match thesis taxonomy
"""

import argparse
import json
import csv
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple
from collections import defaultdict

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


# ============================================================================
# CATEGORY METADATA REGISTRY (UPDATED WITH FAMILIES + STRONG TOOLS)
# ============================================================================

CATEGORY_META = {
    # -------------------- Schema / Style --------------------
    "Schema/InvalidManifest": {
        "severity": "HIGH",
        "priority": "HIGH",
        "family": "Schema",
    },

    "Style/YamlLint": {
        "severity": "LOW",
        "priority": "LOW",
        "family": "Style",
        "strong_tools": {"yamllint"},
    },

    # -------------------- Privilege & Host-Namespace --------------------
    # Family tools: Conftest + Checkov + Trivy + Polaris + Kubescape (+ Kubeaudit)
    "Security/PrivilegedContainer": {
        "severity": "HIGH",
        "priority": "CRITICAL",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"conftest", "checkov", "trivy", "polaris", "kubescape", "kubeaudit"},
    },
    "Security/AllowPrivilegeEscalation": {
        "severity": "HIGH",
        "priority": "HIGH",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"conftest", "checkov", "trivy", "polaris", "kubescape", "kubeaudit"},
    },
    "Security/CapabilitiesNotDropped": {
        "severity": "MEDIUM",
        "priority": "HIGH",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"conftest", "checkov", "trivy", "polaris", "kubescape", "kubeaudit"},
    },
    "Security/HostPathMount": {
        "severity": "HIGH",
        "priority": "CRITICAL",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"conftest", "checkov", "trivy", "polaris", "kubescape", "kubeaudit"},
    },
    "Volume/DockerSocketMounted": {
        "severity": "HIGH",
        "priority": "CRITICAL",
        "family": "PrivilegeHostNamespace",
        "normalized_to": "Security/HostPathMount",
        "strong_tools": {"conftest", "checkov", "trivy", "polaris", "kubescape", "kubeaudit"},
    },
    "Security/MissingSeccompProfile": {
        "severity": "MEDIUM",
        "priority": "HIGH",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"conftest", "checkov", "trivy", "polaris", "kubescape", "kubeaudit"},
    },
    "Security/MissingAppArmorProfile": {
        "severity": "MEDIUM",
        "priority": "MEDIUM",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"kubeaudit"},
    },
    "Security/ReadOnlyRootFSFalse": {
        "severity": "MEDIUM",
        "priority": "HIGH",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"conftest", "checkov", "trivy", "polaris", "kubescape", "kubeaudit"},
    },
    "Security/HostPID": {
        "severity": "HIGH",
        "priority": "CRITICAL",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"conftest", "checkov", "trivy", "polaris", "kubescape"},
    },
    "Security/HostNetwork": {
        "severity": "HIGH",
        "priority": "CRITICAL",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"conftest", "checkov", "trivy", "polaris", "kubescape"},
    },
    "Security/HostIPC": {
        "severity": "HIGH",
        "priority": "CRITICAL",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"conftest", "checkov", "trivy", "polaris", "kubescape"},
    },

    # Auth / SA / Namespace – privilege surface
    "Auth/RunAsRoot": {
        "severity": "MEDIUM",
        "priority": "HIGH",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"conftest", "checkov", "trivy", "polaris", "kubescape", "kubeaudit"},
    },
    "Auth/RunAsNonRootUnset": {
        "severity": "MEDIUM",
        "priority": "HIGH",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"conftest", "checkov", "trivy", "polaris", "kubescape"},
    },
    "Auth/DefaultNamespace": {
        "severity": "LOW",
        "priority": "LOW",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"checkov", "trivy", "kubescape"},
    },
    "Auth/DefaultServiceAccount": {
        "severity": "MEDIUM",
        "priority": "MEDIUM",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"kubeaudit", "conftest", "checkov"},
    },
    "Auth/AutomountServiceAccountToken": {
        "severity": "MEDIUM",
        "priority": "MEDIUM",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"conftest", "checkov", "trivy", "kubescape"},
    },

    "Policy/PodSecurityViolation": {
        "severity": "HIGH",
        "priority": "HIGH",
        "family": "PrivilegeHostNamespace",
        "strong_tools": {"conftest", "kubescape", "checkov"},
    },

    # -------------------- Resource Configuration & DoS Risk --------------------
    # Tools: Conftest, Checkov, Polaris, KubeScore (+ Trivy, Kubescape, KubeLinter)
    "Resources/MissingRequests": {
        "severity": "MEDIUM",
        "priority": "HIGH",
        "family": "ResourceConfigDoS",
        "strong_tools": {"conftest", "checkov", "polaris", "kubescore"},
    },
    "Resources/MissingLimits": {
        "severity": "MEDIUM",
        "priority": "HIGH",
        "family": "ResourceConfigDoS",
        "strong_tools": {"conftest", "checkov", "polaris", "kubescore"},
    },
    "Probes/MissingReadinessLiveness": {
        "severity": "MEDIUM",
        "priority": "HIGH",
        "family": "ResourceConfigDoS",
        "strong_tools": {"conftest", "checkov", "polaris", "kubescore"},
    },
    "HA/SingleReplica": {
        "severity": "MEDIUM",
        "priority": "MEDIUM",
        "family": "ResourceConfigDoS",
        "strong_tools": {"conftest", "checkov", "polaris"},
    },

    # -------------------- Image Security & Supply Chain --------------------
    # Tools: Checkov + Conftest + Trivy + Polaris (+ KubeScore)
    "Image/TagNotPinned": {
        "severity": "LOW",
        "priority": "LOW",
        "family": "ImageSupplyChain",
        "strong_tools": {"checkov", "conftest", "trivy", "polaris", "kubescore"},
    },
    "Image/PullPolicyNotAlways": {
        "severity": "MEDIUM",
        "priority": "MEDIUM",
        "family": "ImageSupplyChain",
        "strong_tools": {"checkov", "conftest", "trivy", "polaris", "kubescore"},
    },
    "Image/UntrustedRegistry": {
        "severity": "MEDIUM",
        "priority": "MEDIUM",
        "family": "ImageSupplyChain",
        "strong_tools": {"trivy", "conftest"},
    },

    # -------------------- Secrets & Credentials Exposure --------------------
    # Tools: Gitleaks + Conftest + Trivy (+ Kubescape, KubeLinter)
    "Secrets/Hardcoded": {
        "severity": "HIGH",
        "priority": "HIGH",
        "family": "SecretsExposure",
        "strong_tools": {"gitleaks", "conftest", "trivy"},
    },

    # -------------------- RBAC Misconfigurations --------------------
    # Tools: RBAC-Police + Conftest + Trivy (+ Checkov)
    "RBAC/WildcardVerbsOrResources": {
        "severity": "HIGH",
        "priority": "HIGH",
        "family": "RBAC",
        "strong_tools": {"rbacpolice", "conftest", "trivy", "checkov"},
    },
    "RBAC/BindClusterAdmin": {
        "severity": "HIGH",
        "priority": "HIGH",
        "family": "RBAC",
        "strong_tools": {"rbacpolice", "conftest", "trivy", "checkov"},
    },
    "RBAC/ExcessivePermissions": {
        "severity": "HIGH",
        "priority": "HIGH",
        "family": "RBAC",
        "strong_tools": {"rbacpolice", "conftest", "trivy", "checkov"},
    },

    # -------------------- Network Exposure, Policies & TLS --------------------
    # Tools: Conftest + Checkov + Kubescape + KubeScore (+ Trivy)
    "Network/MissingNetworkPolicy": {
        "severity": "MEDIUM",
        "priority": "MEDIUM",
        "family": "NetworkExposureTLS",
        "strong_tools": {"conftest", "checkov", "kubescape", "kubescore", "trivy"},
    },

    # -------------------- Deprecated APIs & Ingress Hardening --------------------
    # Tools: Pluto + KubeLinter
    "Image/DeprecatedAPI": {
        "severity": "HIGH",
        "priority": "HIGH",
        "family": "DeprecatedAPIIngress",
        "strong_tools": {"pluto", "kubelinter"},
    },

    # -------------------- Catch-all --------------------
    "Misc/Unmapped": {
        "severity": "MEDIUM",
        "priority": "LOW",
        "family": "Misc",
    },
}


# Tool weights for scoring (higher = more trusted for their domain)
WEIGHTS = {
    "conftest": 0.25,
    "checkov": 0.20,
    "kubeaudit": 0.20,
    "kubescape": 0.18,
    "polaris": 0.18,
    "trivy": 0.15,
    "kubelinter": 0.12,
    "kubescore": 0.12,
    "pluto": 0.30,
    "kubeconform": 0.20,
    "yamllint": 0.25,
    "gitleaks": 0.30,
    "rbacpolice": 0.30,
}

PRIORITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


# ============================================================================
# CHECKOV ID MAPPINGS
# ============================================================================

CHECKOV_MAPPINGS = {
    "CKV_K8S_16": "Security/PrivilegedContainer",
    "CKV_K8S_20": "Security/AllowPrivilegeEscalation",
    "CKV_K8S_28": "Security/CapabilitiesNotDropped",
    "CKV_K8S_37": "Security/CapabilitiesNotDropped",
    "CKV_K8S_10": "Resources/MissingRequests",
    "CKV_K8S_11": "Resources/MissingLimits",
    "CKV_K8S_12": "Resources/MissingRequests",
    "CKV_K8S_13": "Resources/MissingLimits",
    "CKV_K8S_8": "Probes/MissingReadinessLiveness",
    "CKV_K8S_9": "Probes/MissingReadinessLiveness",
    "CKV_K8S_43": "Image/TagNotPinned",
    "CKV_K8S_15": "Image/PullPolicyNotAlways",
    "CKV_K8S_21": "Auth/DefaultNamespace",
    "CKV_K8S_23": "Auth/RunAsRoot",
    "CKV_K8S_40": "Auth/RunAsRoot",
    "CKV_K8S_29": "Policy/PodSecurityViolation",
    "CKV_K8S_31": "Security/MissingSeccompProfile",
    "CKV_K8S_38": "Auth/AutomountServiceAccountToken",
    "CKV2_K8S_6": "Network/MissingNetworkPolicy",
    "CKV_K8S_14": "Security/ReadOnlyRootFSFalse",
    "CKV_K8S_27": "Security/HostPathMount",
    "CKV_K8S_17": "Security/HostPID",
    "CKV_K8S_18": "Security/HostIPC",
    "CKV_K8S_19": "Security/HostNetwork",
    "CKV_K8S_25": "Security/CapabilitiesNotDropped",
    "CKV_K8S_22": "Security/ReadOnlyRootFSFalse",
    "CKV_K8S_30": "Security/MissingSeccompProfile",
    "CKV_K8S_35": "Auth/DefaultServiceAccount",
    "CKV_K8S_41": "Auth/AutomountServiceAccountToken",
    "CKV_K8S_34": "Auth/RunAsNonRootUnset",
}


# ============================================================================
# REGEX PATTERNS FOR CATEGORY MAPPING
# ============================================================================

CATEGORY_PATTERNS = [
    # Security - Privileged
    (r"privileged[:=\s]+true|privileged container|running.*privileged|is privileged", "Security/PrivilegedContainer"),

    # Security - Privilege Escalation
    (r"allowPrivilegeEscalation[:=\s]+true|privilege escalation", "Security/AllowPrivilegeEscalation"),

    # Security - Capabilities
    (r"NET_RAW|SYS_ADMIN|SYS_MODULE|capabilities.*drop|drop.*ALL|must drop ALL", "Security/CapabilitiesNotDropped"),

    # Security - HostPath / Docker Socket
    (r"hostPath|/var/run/docker\.sock|/var/run/containerd|docker socket", "Security/HostPathMount"),

    # Security - Host namespaces
    (r"hostPID[:=\s]+true|shares host.*PID|host process namespace", "Security/HostPID"),
    (r"hostNetwork[:=\s]+true|shares host.*network|host network namespace", "Security/HostNetwork"),
    (r"hostIPC[:=\s]+true|shares host.*IPC|host IPC namespace", "Security/HostIPC"),

    # Security - Seccomp / AppArmor
    (r"seccomp|seccompProfile|no seccomp", "Security/MissingSeccompProfile"),
    (r"apparmor|AppArmor", "Security/MissingAppArmorProfile"),

    # Security - Read-only root FS
    (r"readOnlyRootFilesystem|read-only root|root filesystem|read only", "Security/ReadOnlyRootFSFalse"),

    # Image - Untrusted Registry (NEW)
    (r"untrusted registry|trusted registr", "Image/UntrustedRegistry"),

    # Network Policy
    (r"NetworkPolicy|network policy|pods which lack.*NetworkPolicy", "Network/MissingNetworkPolicy"),

    # Image
    (r"imagePullPolicy.*IfNotPresent|imagePullPolicy.*Never|Image Pull Policy.*Always", "Image/PullPolicyNotAlways"),
    (r":latest|floating tag|tag.*not pinned|no digest|image tag", "Image/TagNotPinned"),
    (r"deprecated.*API|extensions/v1beta1|apps/v1beta", "Image/DeprecatedAPI"),

    # Resources
    (r"memory.*request|cpu.*request|resource.*request|missing.*request", "Resources/MissingRequests"),
    (r"memory.*limit|cpu.*limit|resource.*limit|missing.*limit", "Resources/MissingLimits"),

    # Probes
    (r"liveness|readiness|probe", "Probes/MissingReadinessLiveness"),

    # Auth - Root
    (r"runs as root|runAsUser[:=\s]+0|root user|runAsNonRoot|run as root", "Auth/RunAsRoot"),
    (r"runAsNonRoot.*should be set|runAsNonRoot.*unset", "Auth/RunAsNonRootUnset"),

    # Auth - Namespace / SA (order matters)
    (r"default service account|uses default.*account|serviceAccountName.*default|non-default service account|serviceAccountName to non-default|KSV_DEFAULT_SA",
     "Auth/DefaultServiceAccount"),
    (r"default namespace|deployed to default namespace|namespace:\s*default", "Auth/DefaultNamespace"),
    (r"automountServiceAccountToken|auto.*mount.*token", "Auth/AutomountServiceAccountToken"),

    # RBAC
    (r"wildcard|resources:.*\*|verbs:.*\*|excessive.*permission|RBAC", "RBAC/WildcardVerbsOrResources"),
    (r"cluster-admin|ClusterRole.*admin|bind.*admin", "RBAC/BindClusterAdmin"),

    # Secrets
    (r"hardcoded.*secret|hardcoded.*password|hardcoded.*credential|plaintext.*secret", "Secrets/Hardcoded"),

    # Policy
    (r"Pod security|PSS|restricted policy|baseline policy", "Policy/PodSecurityViolation"),

    # HA
    (r"single replica|replicas[:=\s]+1|replica.*count", "HA/SingleReplica"),

    # Schema
    (r"invalid|schema|validation.*failed", "Schema/InvalidManifest"),

    # Style - YAML lint (actual formatting issues only)
    (r"missing document start|no new line character|line too long|trailing spaces", "Style/YamlLint"),
]


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def normalize_path(path: str) -> str:
    """Normalize file path to relative path under tests/"""
    if not path:
        return ""

    # Convert to forward slashes first
    path = path.replace("\\", "/")

    # Strip leading slashes
    path = path.lstrip("/")

    # Handle absolute paths with "tests/" (case-insensitive for Windows)
    path_lower = path.lower()
    if "tests/" in path_lower:
        idx = path_lower.find("tests/")
        # Extract just the filename after tests/
        path = path[idx + 6:]  # Skip "tests/"

    # Handle kubegoat paths
    if "kubegoat/" in path_lower:
        idx = path_lower.find("kubegoat/")
        path = path[idx + 9:]  # Skip "kubegoat/"

    # Return basename (just filename, no directory)
    return Path(path).name


def extract_filename_from_raw(raw: Dict, text: str) -> Optional[str]:
    """Extract filename from raw finding or text"""
    candidates = [
        "repo_file_path", "file_path", "filename", "file", "File",  # Added "File" for gitleaks
        "manifest", "path", "filesPath", "resource", "target",
        "relativePath", "file_name", "sourcePath"
    ]

    def strip_line_number(path_val: str) -> str:
        """Strip line number suffix like :123 but preserve Windows drive letters like C:"""
        if not path_val:
            return path_val

        # Check if this looks like path:line_number (e.g., "file.yaml:123")
        # Pattern: ends with :<digits> and has .yaml/.yml before the colon
        match = re.match(r'^(.+\.ya?ml):(\d+)$', path_val, re.IGNORECASE)
        if match:
            return match.group(1)

        # Otherwise return as-is (preserves Windows paths like C:\path\file.yaml)
        return path_val

    # Try raw dict
    if raw and isinstance(raw, dict):
        for key in candidates:
            if key in raw and raw[key]:
                path_val = str(raw[key])
                path_val = strip_line_number(path_val)
                if path_val and ('.yaml' in path_val.lower() or '.yml' in path_val.lower()):
                    return normalize_path(path_val)

        # Check nested structures
        if "resource" in raw and isinstance(raw["resource"], dict):
            for key in candidates:
                if key in raw["resource"]:
                    path_val = str(raw["resource"][key])
                    path_val = strip_line_number(path_val)
                    if path_val and ('.yaml' in path_val.lower() or '.yml' in path_val.lower()):
                        return normalize_path(path_val)

        # Check source
        if "source" in raw and isinstance(raw["source"], dict):
            for key in candidates:
                if key in raw["source"]:
                    path_val = str(raw["source"][key])
                    path_val = strip_line_number(path_val)
                    if path_val and ('.yaml' in path_val.lower() or '.yml' in path_val.lower()):
                        return normalize_path(path_val)

        # Check object metadata (KubeLinter)
        if "Metadata" in raw and isinstance(raw["Metadata"], dict):
            file_path_val = raw["Metadata"].get("FilePath", "")
            if file_path_val:
                return normalize_path(file_path_val)

    # Try extracting from text
    if text:
        # Look for file path patterns
        match = re.search(r'(?:file|path)[:=]\s*([^\s,]+\.ya?ml)', text, re.IGNORECASE)
        if match:
            return normalize_path(match.group(1))

        # Look for filename at start of line
        match = re.search(r'^([^\s]+\.ya?ml)', text, re.MULTILINE)
        if match:
            return normalize_path(match.group(1))

        # Look for Target: filename pattern (Trivy)
        match = re.search(r'Target[:\s]+([^\s]+\.ya?ml)', text, re.IGNORECASE)
        if match:
            return normalize_path(match.group(1))

    return None


def extract_resource_info(raw: Any, text: str) -> Tuple[str, str, str]:
    """Extract kind, name, namespace from raw or text"""
    kind = ""
    name = ""
    namespace = ""

    # Handle case where raw is a list
    if isinstance(raw, list):
        if raw:  # If list is not empty, try first element
            raw = raw[0] if isinstance(raw[0], dict) else {}
        else:
            raw = {}

    # Ensure raw is a dict before proceeding
    if not isinstance(raw, dict):
        raw = {}

    # Try raw dict
    if raw:
        # Direct fields
        kind = raw.get("kind", "")

        # Metadata
        if "metadata" in raw and isinstance(raw["metadata"], dict):
            name = raw["metadata"].get("name", "")
            namespace = raw["metadata"].get("namespace", "")

        # Resource field
        if "resource" in raw and isinstance(raw["resource"], dict):
            kind = kind or raw["resource"].get("kind", "")
            if "metadata" in raw["resource"]:
                meta = raw["resource"]["metadata"]
                name = name or meta.get("name", "")
                namespace = namespace or meta.get("namespace", "")

        # Object field
        if "object" in raw and isinstance(raw["object"], dict):
            kind = kind or raw["object"].get("kind", "")
            if "metadata" in raw["object"]:
                meta = raw["object"]["metadata"]
                name = name or meta.get("name", "")
                namespace = namespace or meta.get("namespace", "")

        # K8sObject field (KubeLinter)
        if "K8sObject" in raw and isinstance(raw["K8sObject"], dict):
            k8s_obj = raw["K8sObject"]
            kind = kind or k8s_obj.get("Kind", "")
            name = name or k8s_obj.get("Name", "")
            namespace = namespace or k8s_obj.get("Namespace", "")

    # Try text with regex
    if text and not kind:
        match = re.search(r'kind:\s*(\w+)', text)
        if match:
            kind = match.group(1)

    if text and not name:
        match = re.search(r'(?:metadata:.*)?name:\s*([^\s\n]+)', text, re.DOTALL)
        if match:
            name = match.group(1)

    if text and not namespace:
        match = re.search(r'namespace:\s*([^\s\n]+)', text)
        if match:
            namespace = match.group(1)

    # Extract from conftest-style messages like "Pod 'efs-plugin'" or "Container 'name' in Pod 'pod-name'"
    if text and not kind:
        match = re.search(
            r'\b(Pod|Deployment|StatefulSet|DaemonSet|Service|Ingress|ConfigMap|Secret|ServiceAccount|Role|RoleBinding|ClusterRole|ClusterRoleBinding|NetworkPolicy)\b',
            text
        )
        if match:
            kind = match.group(1)

    if text and not name:
        # Try to extract from patterns like "Pod 'name'" or "in Pod 'name'"
        match = re.search(r"(?:Pod|Deployment|StatefulSet|DaemonSet|Service)\s+'([^']+)'", text)
        if match:
            name = match.group(1)

    return kind, name, namespace


def load_manifests(tests_dir: Path) -> Dict[str, Any]:
    """Load all YAML manifests from tests directory"""
    manifests = {}

    for yaml_file in tests_dir.rglob("*.yaml"):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                content = f.read()
                docs = list(yaml.safe_load_all(content))

                rel_path = str(yaml_file.relative_to(tests_dir.parent)).replace("\\", "/")

                resources = []
                for doc in docs:
                    if doc and isinstance(doc, dict):
                        resources.append({
                            "kind": doc.get("kind", ""),
                            "apiVersion": doc.get("apiVersion", ""),
                            "name": doc.get("metadata", {}).get("name", "") if "metadata" in doc else "",
                            "namespace": doc.get("metadata", {}).get("namespace", "") if "metadata" in doc else "",
                            "raw": doc
                        })

                manifests[rel_path] = {
                    "path": rel_path,
                    "content": content,
                    "resources": resources
                }
        except Exception as e:
            print(f"Warning: Failed to load {yaml_file}: {e}", file=sys.stderr)

    # Also try .yml extension
    for yaml_file in tests_dir.rglob("*.yml"):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                content = f.read()
                docs = list(yaml.safe_load_all(content))

                rel_path = str(yaml_file.relative_to(tests_dir.parent)).replace("\\", "/")

                resources = []
                for doc in docs:
                    if doc and isinstance(doc, dict):
                        resources.append({
                            "kind": doc.get("kind", ""),
                            "apiVersion": doc.get("apiVersion", ""),
                            "name": doc.get("metadata", {}).get("name", "") if "metadata" in doc else "",
                            "namespace": doc.get("metadata", {}).get("namespace", "") if "metadata" in doc else "",
                            "raw": doc
                        })

                manifests[rel_path] = {
                    "path": rel_path,
                    "content": content,
                    "resources": resources
                }
        except Exception as e:
            print(f"Warning: Failed to load {yaml_file}: {e}", file=sys.stderr)

    return manifests


def parse_checkov(file_path: Path) -> List[Dict]:
    """Parse Checkov JSON output"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)

        failed = data.get("results", {}).get("failed_checks", [])
        for check in failed:
            text = f"{check.get('check_name', 'Unknown')}: {check.get('description', '')}"
            findings.append({
                "tool": "checkov",
                "path": str(file_path),
                "raw": check,
                "text": text
            })
    except Exception as e:
        print(f"Warning: Failed to parse Checkov output {file_path}: {e}", file=sys.stderr)

    return findings


def parse_conftest(file_path: Path) -> List[Dict]:
    """Parse Conftest JSON output"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)

        if isinstance(data, list):
            for item in data:
                filename = item.get("filename", "")
                namespace = item.get("namespace", "")
                failures = item.get("failures", [])

                for failure in failures:
                    findings.append({
                        "tool": "conftest",
                        "path": str(file_path),
                        "raw": {
                            "filename": filename,
                            "namespace": namespace,
                            "failure": failure
                        },
                        "text": failure.get("msg", str(failure))
                    })
    except Exception as e:
        print(f"Warning: Failed to parse Conftest output {file_path}: {e}", file=sys.stderr)

    return findings


def parse_kubeconform(file_path: Path) -> List[Dict]:
    """Parse Kubeconform JSON output"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)

            # Check if it's the line-delimited format or dict format
            if isinstance(data, dict):
                resources = data.get("resources", [])
                for item in resources:
                    status = item.get("status", "")
                    # Only emit invalid resources
                    if status != "statusValid":
                        text = f"{status}: {item.get('msg', '')}"
                        findings.append({
                            "tool": "kubeconform",
                            "path": str(file_path),
                            "raw": item,
                            "text": text
                        })
    except json.JSONDecodeError:
        # Try line-delimited JSON
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                        status = item.get("status", "")

                        # Only emit invalid resources
                        if status == "invalid":
                            text = f"{status}: {item.get('msg', '')}"
                            findings.append({
                                "tool": "kubeconform",
                                "path": str(file_path),
                                "raw": item,
                                "text": text
                            })
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Warning: Failed to parse Kubeconform output {file_path}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Warning: Failed to parse Kubeconform output {file_path}: {e}", file=sys.stderr)

    return findings


def parse_trivy(file_path: Path) -> List[Dict]:
    """Parse Trivy config scan output"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)

        results = data.get("Results", [])
        for result in results:
            target = result.get("Target", "")
            misconfigs = result.get("Misconfigurations", [])

            for misconfig in misconfigs:
                text = f"{misconfig.get('ID', 'Unknown')}: {misconfig.get('Title', '')} - {misconfig.get('Message', '')}"
                findings.append({
                    "tool": "trivy",
                    "path": str(file_path),
                    "raw": {
                        "target": target,
                        "misconfig": misconfig,
                        "file_path": target,
                        "ID": misconfig.get("ID", "")
                    },
                    "text": text
                })
    except Exception as e:
        print(f"Warning: Failed to parse Trivy output {file_path}: {e}", file=sys.stderr)

    return findings


def parse_kubescape(file_path: Path) -> List[Dict]:
    """Parse Kubescape JSON output"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)

        # Get file path from resources array
        resources = data.get("resources", [])
        file_mapping = {}
        for resource in resources:
            resource_id = resource.get("resourceID", "")
            source = resource.get("source", {})
            rel_path = source.get("relativePath", "")
            if rel_path and resource_id:
                file_mapping[resource_id] = rel_path

        # Parse results
        results = data.get("results", [])
        for result in results:
            resource_id = result.get("resourceID", "")
            controls = result.get("controls", [])

            # Get file path for this resource
            file_ref = file_mapping.get(resource_id, "")

            for control in controls:
                if control.get("status", {}).get("status") == "failed":
                    control_id = control.get("controlID", "")
                    control_name = control.get("name", "")

                    text = f"{control_id}: {control_name}"

                    findings.append({
                        "tool": "kubescape",
                        "path": str(file_path),
                        "raw": {
                            "resourceID": resource_id,
                            "control": control,
                            "controlID": control_id,
                            "name": control_name,
                            "file_path": file_ref
                        },
                        "text": text
                    })

    except Exception as e:
        print(f"Warning: Failed to parse Kubescape output {file_path}: {e}", file=sys.stderr)

    return findings


def parse_polaris(file_path: Path) -> List[Dict]:
    """Parse Polaris JSON output"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)

        results = data.get("Results", [])
        for result in results:
            name = result.get("Name", "")
            kind = result.get("Kind", "")

            # Pod-level results
            pod_result = result.get("PodResult", {})
            pod_results = pod_result.get("Results", {})

            for check_id, check_result in pod_results.items():
                if not check_result.get("Success", True):
                    text = f"{check_id}: {check_result.get('Message', '')}"
                    findings.append({
                        "tool": "polaris",
                        "path": str(file_path),
                        "raw": {
                            "name": name,
                            "kind": kind,
                            "check": check_result
                        },
                        "text": text
                    })

            # Container-level results
            container_results = pod_result.get("ContainerResults", [])
            for container in container_results:
                container_name = container.get("Name", "")
                container_checks = container.get("Results", {})

                for check_id, check_result in container_checks.items():
                    if not check_result.get("Success", True):
                        text = f"{check_id}: {check_result.get('Message', '')} (container: {container_name})"
                        findings.append({
                            "tool": "polaris",
                            "path": str(file_path),
                            "raw": {
                                "name": name,
                                "kind": kind,
                                "container": container_name,
                                "check": check_result
                            },
                            "text": text
                        })

    except Exception as e:
        print(f"Warning: Failed to parse Polaris output {file_path}: {e}", file=sys.stderr)

    return findings


def parse_kubeaudit(file_path: Path) -> List[Dict]:
    """Parse Kubeaudit JSON output"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)

        if isinstance(data, list):
            for item in data:
                audit_result = item.get("AuditResultName", "")
                msg = item.get("msg", "")
                file_ref = item.get("file", "")

                findings.append({
                    "tool": "kubeaudit",
                    "path": str(file_path),
                    "raw": {
                        **item,
                        "file_path": file_ref
                    },
                    "text": f"{audit_result}: {msg}"
                })
    except Exception as e:
        print(f"Warning: Failed to parse Kubeaudit output {file_path}: {e}", file=sys.stderr)

    return findings


def parse_kubescore(file_path: Path) -> List[Dict]:
    """Parse Kubescore JSON output"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)

        if isinstance(data, list):
            for item in data:
                object_name = item.get("object_name", "")
                file_name = item.get("file_name", "")
                checks = item.get("checks", [])

                for check in checks:
                    grade = check.get("grade", 10)
                    skipped = check.get("skipped", False)

                    # Only report failures (grade < 10 and not skipped)
                    if grade < 10 and not skipped:
                        check_info = check.get("check", {})
                        check_name = check_info.get("name", "")
                        comments = check.get("comments", [])

                        comment_text = "; ".join([c.get("summary", "") for c in comments if c.get("summary")])
                        text = f"{check_name}: {comment_text}"

                        findings.append({
                            "tool": "kubescore",
                            "path": str(file_path),
                            "raw": {
                                "object_name": object_name,
                                "file_name": file_name,
                                "check": check
                            },
                            "text": text
                        })
    except Exception as e:
        print(f"Warning: Failed to parse Kubescore output {file_path}: {e}", file=sys.stderr)

    return findings


def parse_kubelinter(file_path: Path) -> List[Dict]:
    """Parse KubeLinter JSON output"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)

        reports = data.get("Reports", [])
        for report in reports:
            check = report.get("Check", "")
            diagnostic = report.get("Diagnostic", {})
            message = diagnostic.get("Message", "")
            obj = report.get("Object", {})
            metadata = obj.get("Metadata", {})
            file_path_ref = metadata.get("FilePath", "")

            findings.append({
                "tool": "kubelinter",
                "path": str(file_path),
                "raw": {
                    **report,
                    "file_path": file_path_ref
                },
                "text": f"{check}: {message}"
            })
    except Exception as e:
        print(f"Warning: Failed to parse KubeLinter output {file_path}: {e}", file=sys.stderr)

    return findings


def parse_pluto(file_path: Path) -> List[Dict]:
    """Parse Pluto JSON output"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)

        # Pluto reports deprecated APIs
        # If there are no deprecated APIs, it returns just target-versions
        if "items" in data or "outputs" in data:
            items = data.get("items", data.get("outputs", []))
            for item in items:
                api_version = item.get("apiVersion", "")
                kind = item.get("kind", "")
                deprecated = item.get("deprecated", False)

                if deprecated:
                    text = f"Deprecated API: {api_version} {kind}"
                    findings.append({
                        "tool": "pluto",
                        "path": str(file_path),
                        "raw": item,
                        "text": text
                    })
    except Exception as e:
        print(f"Warning: Failed to parse Pluto output {file_path}: {e}", file=sys.stderr)

    return findings


def parse_gitleaks(file_path: Path) -> List[Dict]:
    """Parse GitLeaks JSON output"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)

        # GitLeaks returns an array of secret findings
        if isinstance(data, list):
            for item in data:
                rule_id = item.get("RuleID", "")
                description = item.get("Description", "")
                match = item.get("Match", "")
                file_ref = item.get("File", "")
                start_line = item.get("StartLine", 0)

                text = f"{rule_id}: {description} - {match}"
                findings.append({
                    "tool": "gitleaks",
                    "path": str(file_path),
                    "raw": {
                        **item,
                        "file_path": file_ref  # Add for easier extraction
                    },
                    "text": text
                })
    except Exception as e:
        print(f"Warning: Failed to parse GitLeaks output {file_path}: {e}", file=sys.stderr)

    return findings


def parse_generic_json(file_path: Path, tool: str) -> List[Dict]:
    """Parse generic JSON output"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)

        # Check for RBAC-police "no manifests" message
        if tool == "rbacpolice" and isinstance(data, list):
            if any("No RBAC manifests found" in str(item) for item in data):
                # Don't create a finding for this - it's not a security issue
                return findings

        # Only create a generic finding if data seems relevant
        # Skip if it's just a config or empty structure
        if data and (not isinstance(data, dict) or (isinstance(data, dict) and len(data) > 2)):
            findings.append({
                "tool": tool,
                "path": str(file_path),
                "raw": data,
                "text": json.dumps(data, indent=2)[:1000]  # Truncate for safety
            })
    except Exception as e:
        print(f"Warning: Failed to parse {tool} output {file_path}: {e}", file=sys.stderr)

    return findings


def parse_text_file(file_path: Path, tool: str) -> List[Dict]:
    """Parse plain text output"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        if content.strip():
            # For yamllint, parse each line as a separate finding
            if tool == "yamllint":
                for line in content.strip().split('\n'):
                    if line.strip():
                        findings.append({
                            "tool": tool,
                            "path": str(file_path),
                            "raw": {},
                            "text": line.strip()
                        })
            else:
                findings.append({
                    "tool": tool,
                    "path": str(file_path),
                    "raw": {},
                    "text": content
                })
    except Exception as e:
        print(f"Warning: Failed to parse text file {file_path}: {e}", file=sys.stderr)

    return findings


def parse_detector_file(file_path: Path) -> List[Dict]:
    """Parse a single detector output file"""
    filename = file_path.name.lower()

    # Detect tool and use specific parser
    if "checkov" in filename:
        return parse_checkov(file_path)
    elif "conftest" in filename:
        return parse_conftest(file_path)
    elif "trivy" in filename:
        return parse_trivy(file_path)
    elif "kubescape" in filename:
        return parse_kubescape(file_path)
    elif "polaris" in filename:
        return parse_polaris(file_path)
    elif "kubeaudit" in filename:
        return parse_kubeaudit(file_path)
    elif "kubescore" in filename:
        return parse_kubescore(file_path)
    elif "kubelinter" in filename or "kube-linter" in filename:
        return parse_kubelinter(file_path)
    elif "pluto" in filename:
        return parse_pluto(file_path)
    elif "kubeconform" in filename:
        return parse_kubeconform(file_path)
    elif "yamllint" in filename:
        return parse_text_file(file_path, "yamllint")
    elif "gitleaks" in filename:
        return parse_gitleaks(file_path)
    elif "rbacpolice" in filename or "rbac-police" in filename:
        tool = "rbacpolice"
        if file_path.suffix == '.json':
            return parse_generic_json(file_path, tool)
        return parse_text_file(file_path, tool)

    # Generic fallback
    tool = "unknown"
    if file_path.suffix in ['.json', '.jsonl']:
        return parse_generic_json(file_path, tool)
    else:
        return parse_text_file(file_path, tool)


def map_to_category(text: str, raw: Optional[Dict], tool: str) -> Optional[str]:
    """Map a raw finding to a canonical category"""

    # Ensure raw is a dict
    if not isinstance(raw, dict):
        raw = {}

    # Check Trivy IDs first (for KSV0125)
    if raw and "ID" in raw:
        trivy_id = raw.get("ID", "")
        if trivy_id == "KSV0125":
            return "Image/UntrustedRegistry"

        trivy_mappings = {
            "KSV001": "Security/AllowPrivilegeEscalation",
            "KSV003": "Security/CapabilitiesNotDropped",
            "KSV004": "Security/CapabilitiesNotDropped",
            "KSV011": "Resources/MissingLimits",
            "KSV012": "Auth/RunAsRoot",
            "KSV014": "Security/ReadOnlyRootFSFalse",
            "KSV015": "Resources/MissingRequests",
            "KSV016": "Resources/MissingRequests",
            "KSV017": "Security/PrivilegedContainer",
            "KSV018": "Resources/MissingLimits",
            "KSV020": "Auth/RunAsRoot",
            "KSV021": "Auth/RunAsRoot",
            "KSV030": "Security/MissingSeccompProfile",
            "KSV104": "Security/MissingSeccompProfile",
            "KSV106": "Security/CapabilitiesNotDropped",
            "KSV110": "Auth/DefaultNamespace",
            "KSV118": "Policy/PodSecurityViolation",
        }
        if trivy_id in trivy_mappings:
            return trivy_mappings[trivy_id]

    # Check Checkov ID mappings
    if raw and "check_id" in raw:
        check_id = raw["check_id"]
        if check_id in CHECKOV_MAPPINGS:
            return CHECKOV_MAPPINGS[check_id]

    # Check Kubescape control IDs
    if raw and "controlID" in raw:
        control_id = raw["controlID"]
        control_mappings = {
            "C-0057": "Security/PrivilegedContainer",
            "C-0016": "Security/AllowPrivilegeEscalation",
            "C-0055": "Security/MissingSeccompProfile",
            "C-0017": "Security/ReadOnlyRootFSFalse",
            "C-0048": "Security/HostPathMount",
            "C-0074": "Security/HostPathMount",
            "C-0038": "Security/HostPID",
            "C-0041": "Security/HostNetwork",
            "C-0013": "Auth/RunAsRoot",
            "C-0270": "Resources/MissingLimits",
            "C-0271": "Resources/MissingLimits",
            "C-0056": "Probes/MissingReadinessLiveness",
            "C-0018": "Probes/MissingReadinessLiveness",
            "C-0260": "Network/MissingNetworkPolicy",
            "C-0030": "Network/MissingNetworkPolicy",
            "C-0061": "Auth/DefaultNamespace",
            "C-0034": "Auth/AutomountServiceAccountToken",
        }
        if control_id in control_mappings:
            return control_mappings[control_id]

    # Check Polaris check IDs
    if raw and "check" in raw and isinstance(raw["check"], dict):
        check_id = raw["check"].get("ID", "")
        polaris_mappings = {
            "runAsPrivileged": "Security/PrivilegedContainer",
            "privilegeEscalationAllowed": "Security/AllowPrivilegeEscalation",
            "notReadOnlyRootFilesystem": "Security/ReadOnlyRootFSFalse",
            "cpuLimitsMissing": "Resources/MissingLimits",
            "memoryLimitsMissing": "Resources/MissingLimits",
            "cpuRequestsMissing": "Resources/MissingRequests",
            "memoryRequestsMissing": "Resources/MissingRequests",
            "livenessProbeMissing": "Probes/MissingReadinessLiveness",
            "readinessProbeMissing": "Probes/MissingReadinessLiveness",
            "runAsRootAllowed": "Auth/RunAsRoot",
            "pullPolicyNotAlways": "Image/PullPolicyNotAlways",
            "hostNetworkSet": "Security/HostNetwork",
            "hostPIDSet": "Security/HostPID",
            "hostIPCSet": "Security/HostIPC",
            "hostPathSet": "Security/HostPathMount",
            "automountServiceAccountToken": "Auth/AutomountServiceAccountToken",
            "missingNetworkPolicy": "Network/MissingNetworkPolicy",
            "insecureCapabilities": "Security/CapabilitiesNotDropped",
            "dangerousCapabilities": "Security/CapabilitiesNotDropped",
            "linuxHardening": "Security/MissingSeccompProfile",
        }
        if check_id in polaris_mappings:
            return polaris_mappings[check_id]

    # Check KubeAudit result names
    if raw and "AuditResultName" in raw:
        audit_result = raw["AuditResultName"]
        kubeaudit_mappings = {
            "PrivilegedTrue": "Security/PrivilegedContainer",
            "AllowPrivilegeEscalationNil": "Security/AllowPrivilegeEscalation",
            "ReadOnlyRootFilesystemNil": "Security/ReadOnlyRootFSFalse",
            "RunAsNonRootPSCNilCSCNil": "Auth/RunAsRoot",
            "AutomountServiceAccountTokenTrueAndDefaultSA": "Auth/DefaultServiceAccount",
            "CapabilityOrSecurityContextMissing": "Security/CapabilitiesNotDropped",
            "SeccompProfileMissing": "Security/MissingSeccompProfile",
            "AppArmorAnnotationMissing": "Security/MissingAppArmorProfile",
        }
        if audit_result in kubeaudit_mappings:
            return kubeaudit_mappings[audit_result]

    # Check Kubescore check names
    if raw and "check" in raw and isinstance(raw["check"], dict):
        check_name = raw["check"].get("name", "")
        if "Privileged" in check_name and "Container" in check_name:
            return "Security/PrivilegedContainer"
        elif "ReadOnlyRootFilesystem" in check_name:
            return "Security/ReadOnlyRootFSFalse"
        elif "CPU" in check_name and "limit" in check_name.lower():
            return "Resources/MissingLimits"
        elif "Memory" in check_name and "limit" in check_name.lower():
            return "Resources/MissingLimits"
        elif "CPU" in check_name and "request" in check_name.lower():
            return "Resources/MissingRequests"
        elif "Memory" in check_name and "request" in check_name.lower():
            return "Resources/MissingRequests"
        elif "NetworkPolicy" in check_name:
            return "Network/MissingNetworkPolicy"
        elif "Image Pull Policy" in check_name:
            return "Image/PullPolicyNotAlways"
        elif "User Group ID" in check_name:
            return "Auth/RunAsRoot"

    # Check KubeLinter check names
    if raw and "Check" in raw:
        check = raw["Check"]
        kubelinter_mappings = {
            "privileged-container": "Security/PrivilegedContainer",
            "privilege-escalation-container": "Security/AllowPrivilegeEscalation",
            "no-read-only-root-fs": "Security/ReadOnlyRootFSFalse",
            "run-as-non-root": "Auth/RunAsRoot",
            "unset-cpu-requirements": "Resources/MissingRequests",
            "unset-memory-requirements": "Resources/MissingLimits",
            "docker-sock": "Security/HostPathMount",
            "sensitive-host-mounts": "Security/HostPathMount",
            "host-network": "Security/HostNetwork",
            "host-pid": "Security/HostPID",
            "host-ipc": "Security/HostIPC",
            "drop-net-raw-capability": "Security/CapabilitiesNotDropped",
        }
        if check in kubelinter_mappings:
            return kubelinter_mappings[check]

    # Check regex patterns
    combined = f"{text} {json.dumps(raw) if raw else ''}"
    for pattern, category in CATEGORY_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return category

    # Tool-specific heuristics
    if tool == "pluto":
        return "Image/DeprecatedAPI"

    if tool == "yamllint":
        return "Style/YamlLint"

    if tool == "gitleaks":
        return "Secrets/Hardcoded"

    if tool == "rbacpolice":
        return "RBAC/ExcessivePermissions"

    if tool == "kubeconform":
        return "Schema/InvalidManifest"

    # Default to unmapped
    return "Misc/Unmapped"


def derive_resource_ref(raw_finding: Dict, manifests: Dict) -> Dict:
    """Derive resource reference from raw finding"""

    raw = raw_finding.get("raw", {})
    text = raw_finding.get("text", "")

    # Extract filename
    file = extract_filename_from_raw(raw, text)

    # Extract resource info
    kind, name, namespace = extract_resource_info(raw, text)

    # Try to match against manifests if file unknown
    if not file and kind and name:
        for manifest_path, manifest_data in manifests.items():
            for resource in manifest_data["resources"]:
                if resource["kind"] == kind and resource["name"] == name:
                    file = manifest_path
                    break
            if file:
                break

    # If still no file, try basename matching
    if not file:
        extracted = extract_filename_from_raw(raw, text)
        if extracted:
            basename = Path(extracted).name
            for manifest_path in manifests.keys():
                if Path(manifest_path).name == basename:
                    file = manifest_path
                    break

    return {
        "file": file or None,
        "kind": kind,
        "name": name,
        "namespace": namespace
    }


def get_snippet(manifest_file: str, manifests: Dict, text: str, max_lines: int = 80) -> str:
    """Get a snippet of the relevant manifest (slightly trimmed to save tokens)"""

    if manifest_file and manifest_file in manifests:
        content = manifests[manifest_file]["content"]
        lines = content.split('\n')
        if len(lines) <= max_lines:
            return content
        return '\n'.join(lines[:max_lines]) + "\n..."

    # Fallback to text
    if text:
        lines = text.split('\n')
        if len(lines) <= max_lines:
            return text
        return '\n'.join(lines[:max_lines]) + "..."

    return ""


def secret_fp_gate(raw_finding: Dict, resource_ref: Dict) -> bool:
    """Determine if a secret finding is confirmed (not FP)"""

    tool = raw_finding.get("tool", "")

    # Trust gitleaks and conftest
    if tool in ["gitleaks", "conftest"]:
        return True

    text = raw_finding.get("text", "").lower()
    raw = raw_finding.get("raw", {})

    # Check for placeholder patterns
    placeholders = [
        "example", "changeme", "password123", "test", "dummy",
        "placeholder", "your-", "my-", "<", ">"
    ]

    for placeholder in placeholders:
        if placeholder in text:
            return False

    # If it's a K8s Secret kind and values are base64, likely not a leak
    kind = resource_ref.get("kind", "")
    if kind == "Secret":
        # Base64 pattern check
        if re.search(r'[A-Za-z0-9+/=]{20,}', text):
            # Check if it looks like encoded data
            if "data:" in text and not any(word in text for word in ["password", "token", "key", "secret"]):
                return False

    return True


def redact_secrets_from_snippet(snippet: str) -> str:
    """Redact secret values from snippet"""

    lines = snippet.split('\n')
    redacted_lines = []

    for line in lines:
        # Look for key: value patterns
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0]
                value = parts[1].strip()

                # Check if this looks like a secret
                secret_keywords = ["password", "token", "key", "secret", "credential", "apikey"]
                if any(kw in key.lower() for kw in secret_keywords):
                    if value and not value.startswith('#'):
                        redacted_lines.append(f"{key}: <REDACTED_SECRET>")
                        continue

        redacted_lines.append(line)

    return '\n'.join(redacted_lines)


def patch_hint(category: str) -> str:
    """Generate patch hint for a category"""

    hints = {
        "Security/PrivilegedContainer": "Set securityContext.privileged=false; also set allowPrivilegeEscalation=false; runAsNonRoot=true.",
        "Security/AllowPrivilegeEscalation": "Set securityContext.allowPrivilegeEscalation=false.",
        "Security/CapabilitiesNotDropped": "Add securityContext.capabilities.drop: ['ALL'] and only add back required capabilities.",
        "Security/HostPathMount": "Remove hostPath volumes or use more restricted volume types. Avoid mounting sensitive paths like /var/run/docker.sock.",
        "Security/HostPID": "Set hostPID=false in pod spec.",
        "Security/HostNetwork": "Set hostNetwork=false in pod spec.",
        "Security/HostIPC": "Set hostIPC=false in pod spec.",
        "Security/MissingSeccompProfile": "Add securityContext.seccompProfile with type: RuntimeDefault or Localhost.",
        "Security/ReadOnlyRootFSFalse": "Set securityContext.readOnlyRootFilesystem=true.",
        "RBAC/WildcardVerbsOrResources": "Replace wildcard (*) with specific verbs and resources needed for the role.",
        "RBAC/BindClusterAdmin": "Use a less privileged role instead of cluster-admin. Create custom roles with minimal permissions.",
        "RBAC/ExcessivePermissions": "Review and reduce permissions to minimum required. Remove unnecessary verbs like delete.",
        "Network/MissingNetworkPolicy": "Add default-deny NetworkPolicy and explicit allows for required traffic.",
        "Image/TagNotPinned": "Pin image to specific tag or digest (e.g., image:v1.2.3@sha256:...).",
        "Image/PullPolicyNotAlways": "Set imagePullPolicy: Always to ensure latest image is pulled.",
        "Image/DeprecatedAPI": "Migrate to current stable API version (e.g., networking.k8s.io/v1 for Ingress).",
        "Image/UntrustedRegistry": "Use images from trusted registries only (e.g., official registries, company registry).",
        "Resources/MissingRequests": "Add cpu/memory requests per container (e.g., requests: {cpu: 100m, memory: 128Mi}).",
        "Resources/MissingLimits": "Add cpu/memory limits per container (e.g., limits: {cpu: 500m, memory: 512Mi}).",
        "Probes/MissingReadinessLiveness": "Add livenessProbe and readinessProbe to containers.",
        "Auth/RunAsRoot": "Set securityContext.runAsUser to non-zero UID (e.g., 1000) and runAsNonRoot=true.",
        "Auth/RunAsNonRootUnset": "Set securityContext.runAsNonRoot=true.",
        "Auth/DefaultNamespace": "Specify explicit namespace in metadata.namespace.",
        "Auth/DefaultServiceAccount": "Create and specify custom ServiceAccount in spec.serviceAccountName.",
        "Auth/AutomountServiceAccountToken": "Set automountServiceAccountToken=false if not needed.",
        "Secrets/Hardcoded": "Remove hardcoded secrets; use Kubernetes Secret resources or external secret management.",
        "Policy/PodSecurityViolation": "Update pod security context to meet PSS baseline or restricted standards.",
        "HA/SingleReplica": "Increase replicas to at least 3 for high availability.",
        "Schema/InvalidManifest": "Fix YAML schema validation errors per Kubernetes API specification.",
        "Style/YamlLint": "Fix YAML formatting issues (indentation, line length, etc.).",
        "Misc/Unmapped": "Review and fix the identified issue based on the original tool's recommendation.",
    }

    return hints.get(category, "Review and fix the identified issue.")


def compute_status(bucket: Dict, nonatomic_consensus: int) -> Tuple[str, str]:
    """Compute status and decision reason for a bucket"""

    category = bucket["category"]
    tools = bucket["tools"]
    score = bucket["score"]
    priority = bucket["priority"]

    # Check for strong tools
    strong_tools = CATEGORY_META.get(category, {}).get("strong_tools", set())
    if strong_tools:
        if any(tool in tools for tool in strong_tools):
            return "Actual", f"strong-tool={strong_tools & tools}"

    # Special handling for secrets
    if category == "Secrets/Hardcoded":
        # Already filtered by secret_fp_gate, so if we're here it's confirmed
        return "Actual", "secret-gate=confirmed"

    # Priority-based heuristics
    if priority in ["CRITICAL", "HIGH"]:
        # More tolerant for high priority
        if len(tools) >= 1 and score >= 0.15:
            return "Actual", f"high-priority-tools={len(tools)}"
        return "NeedsCorroboration", f"insufficient-evidence-tools={len(tools)}"

    # For MEDIUM/LOW, use consensus
    if len(tools) >= nonatomic_consensus and score >= 0.20:
        return "Actual", f"consensus={len(tools)}>={nonatomic_consensus}"

    return "NeedsCorroboration", f"below-consensus-tools={len(tools)}<{nonatomic_consensus}"


def merge_unknown_file_buckets(buckets: Dict) -> Dict:
    """Merge UNKNOWN_FILE buckets with known file buckets based on kind/name/category"""

    # Step 1: Group buckets by (kind, name, category) to find resource-level matches
    resource_groups = defaultdict(list)

    for bucket_key, bucket in buckets.items():
        file, kind, name, namespace, category = bucket_key

        # Group by resource identity (kind, name, category)
        # We use kind/name if available, otherwise just category
        if kind and name:
            resource_key = (kind, name, category)
        else:
            # For buckets without kind/name, group by category only
            resource_key = (None, None, category)

        resource_groups[resource_key].append((bucket_key, bucket))

    # Step 2: For each resource group, merge UNKNOWN_FILE into known file
    merged_buckets = {}
    processed_keys = set()

    for resource_key, bucket_list in resource_groups.items():
        kind, name, category = resource_key

        # Separate buckets with known files vs UNKNOWN_FILE
        known_file_buckets = []
        unknown_file_buckets = []

        for bucket_key, bucket in bucket_list:
            file = bucket_key[0]
            if file and file != "UNKNOWN_FILE" and file != "":
                known_file_buckets.append((bucket_key, bucket))
            else:
                unknown_file_buckets.append((bucket_key, bucket))

        # If we have both known and unknown, merge them
        if known_file_buckets and unknown_file_buckets:
            # Use the first known file bucket as target
            target_key, target_bucket = known_file_buckets[0]

            # Merge all unknown buckets into target
            for unknown_key, unknown_bucket in unknown_file_buckets:
                target_bucket["tools"] |= unknown_bucket["tools"]
                target_bucket["score"] += unknown_bucket["score"]
                target_bucket["raw_findings"].extend(unknown_bucket["raw_findings"])

                # Merge examples
                for example in unknown_bucket["examples"]:
                    if len(target_bucket["examples"]) < 5:
                        target_bucket["examples"].append(example)

                processed_keys.add(unknown_key)

            # If there are multiple known file buckets, merge them too
            for i in range(1, len(known_file_buckets)):
                extra_key, extra_bucket = known_file_buckets[i]
                target_bucket["tools"] |= extra_bucket["tools"]
                target_bucket["score"] += extra_bucket["score"]
                target_bucket["raw_findings"].extend(extra_bucket["raw_findings"])

                for example in extra_bucket["examples"]:
                    if len(target_bucket["examples"]) < 5:
                        target_bucket["examples"].append(example)

                processed_keys.add(extra_key)

            merged_buckets[target_key] = target_bucket
            processed_keys.add(target_key)

        elif known_file_buckets:
            # Just keep the known buckets
            for bucket_key, bucket in known_file_buckets:
                if bucket_key not in processed_keys:
                    merged_buckets[bucket_key] = bucket
                    processed_keys.add(bucket_key)

        elif unknown_file_buckets:
            # No known file found - keep just one UNKNOWN_FILE bucket per category
            target_key, target_bucket = unknown_file_buckets[0]

            for i in range(1, len(unknown_file_buckets)):
                extra_key, extra_bucket = unknown_file_buckets[i]
                target_bucket["tools"] |= extra_bucket["tools"]
                target_bucket["score"] += extra_bucket["score"]
                target_bucket["raw_findings"].extend(extra_bucket["raw_findings"])

                for example in extra_bucket["examples"]:
                    if len(target_bucket["examples"]) < 5:
                        target_bucket["examples"].append(example)

                processed_keys.add(extra_key)

            merged_buckets[target_key] = target_bucket
            processed_keys.add(target_key)

    # Step 3: Add any buckets that weren't processed (safety check)
    for bucket_key, bucket in buckets.items():
        if bucket_key not in processed_keys:
            merged_buckets[bucket_key] = bucket

    return merged_buckets


def normalize(args) -> Tuple[List[Dict], Dict]:
    """Main normalization logic"""

    raw_dir = Path(args.raw_dir)
    tests_dir = Path(args.tests_dir)

    # Load manifests
    print(f"Loading manifests from {tests_dir}...")
    manifests = load_manifests(tests_dir)
    print(f"Loaded {len(manifests)} manifest files")

    # Parse all detector outputs
    print(f"Parsing detector outputs from {raw_dir}...")
    raw_findings = []
    for raw_file in raw_dir.rglob("*"):
        if raw_file.is_file():
            findings = parse_detector_file(raw_file)
            raw_findings.extend(findings)
    print(f"Parsed {len(raw_findings)} raw findings")

    # Aggregate into buckets
    print("Aggregating findings into buckets...")
    buckets = defaultdict(lambda: {
        "file": None,
        "kind": "",
        "name": "",
        "namespace": "",
        "category": "",
        "severity": "MEDIUM",
        "priority": "LOW",
        "tools": set(),
        "score": 0.0,
        "snippet": "",
        "examples": [],
        "provenance": "tools",
        "raw_findings": []
    })

    for raw_finding in raw_findings:
        # Map to category
        category = map_to_category(
            raw_finding.get("text", ""),
            raw_finding.get("raw"),
            raw_finding.get("tool", "")
        )

        if not category:
            category = "Misc/Unmapped"

        # Auto-register category if not in metadata
        if category not in CATEGORY_META:
            CATEGORY_META[category] = {"severity": "MEDIUM", "priority": "LOW", "family": "Misc"}

        # Check for normalization (normalized_to)
        normalized_to = CATEGORY_META[category].get("normalized_to")
        if normalized_to:
            category = normalized_to

        # Derive resource ref
        resource_ref = derive_resource_ref(raw_finding, manifests)

        # Special handling for secrets
        if category == "Secrets/Hardcoded":
            if not secret_fp_gate(raw_finding, resource_ref):
                continue  # Skip false positive secrets

        # Skip RBAC findings from rbacpolice when no RBAC manifests exist
        if raw_finding.get("tool") == "rbacpolice":
            raw_data = raw_finding.get("raw", {})
            if isinstance(raw_data, list):
                if any("No RBAC manifests found" in str(item) for item in raw_data):
                    continue  # Skip this finding

        # Create bucket key
        file = resource_ref["file"] or ""
        kind = resource_ref["kind"]
        name = resource_ref["name"]
        namespace = resource_ref["namespace"]

        bucket_key = (file, kind, name, namespace, category)
        bucket = buckets[bucket_key]

        # Update bucket
        bucket["file"] = file if file else None
        bucket["kind"] = kind
        bucket["name"] = name
        bucket["namespace"] = namespace
        bucket["category"] = category
        bucket["severity"] = CATEGORY_META[category]["severity"]
        bucket["priority"] = CATEGORY_META[category]["priority"]

        tool = raw_finding.get("tool", "unknown")
        bucket["tools"].add(tool)
        bucket["score"] += WEIGHTS.get(tool, 0.10)
        bucket["raw_findings"].append(raw_finding)

        # Add example
        if len(bucket["examples"]) < 3:
            bucket["examples"].append({
                "tool": tool,
                "text": raw_finding.get("text", "")[:200],
                "raw": raw_finding.get("raw", {})
            })

    print(f"Created {len(buckets)} unique buckets")

    # Merge UNKNOWN_FILE buckets
    print("Merging UNKNOWN_FILE buckets with known files...")
    buckets = merge_unknown_file_buckets(dict(buckets))
    print(f"After merging: {len(buckets)} buckets")

    # Convert buckets to list and compute status
    print("Computing status for each bucket...")
    normalized_findings = []

    for bucket_key, bucket in buckets.items():
        file = bucket["file"]
        category = bucket["category"]

        # Get snippet
        snippet = get_snippet(
            file if file else "",
            manifests,
            bucket["examples"][0]["text"] if bucket["examples"] else "",
            max_lines=80
        )

        # Redact secrets if needed
        if category == "Secrets/Hardcoded":
            snippet = redact_secrets_from_snippet(snippet)

        bucket["snippet"] = snippet

        # Compute status
        status, reason = compute_status(bucket, args.nonatomic_consensus)
        bucket["status"] = status
        bucket["decisionReason"] = reason

        # Convert tools set to list
        bucket["tools"] = sorted(list(bucket["tools"]))

        # Create final finding
        finding = {
            "file": file or "UNKNOWN_FILE",
            "category": category,
            "severity": bucket["severity"],
            "priority": bucket["priority"],
            "status": status,
            "score": round(bucket["score"], 2),
            "tools": bucket["tools"],
            "resourceRef": {
                "file": file,
                "kind": bucket["kind"],
                "name": bucket["name"],
                "namespace": bucket["namespace"]
            },
            "snippet": snippet,
            "examples": bucket["examples"],
            "provenance": bucket["provenance"],
            "decisionReason": reason
        }

        normalized_findings.append(finding)

    # Sort by priority then file
    def priority_key(f):
        try:
            return (PRIORITY_ORDER.index(f["priority"]), f["file"])
        except (ValueError, KeyError):
            return (99, f["file"])

    normalized_findings.sort(key=priority_key)

    # Build LLM payload
    print("Building LLM payload...")
    llm_payload = build_llm_payload(normalized_findings, args.payload_min_priority)

    return normalized_findings, llm_payload


def build_llm_payload(normalized_findings: List[Dict], min_priority: str) -> Dict:
    """Build LLM payload from normalized findings"""

    # Filter by priority
    priority_idx = PRIORITY_ORDER.index(min_priority) if min_priority in PRIORITY_ORDER else 3

    filtered = []
    for finding in normalized_findings:
        try:
            finding_idx = PRIORITY_ORDER.index(finding["priority"])
            if finding_idx <= priority_idx:
                # For UNKNOWN_FILE findings, only include if:
                # 1. They're CRITICAL or HIGH priority, OR
                # 2. They're confirmed "Actual" status (from strong tools)
                if finding["file"] == "UNKNOWN_FILE":
                    if finding["priority"] in ["CRITICAL", "HIGH"] and finding["status"] == "Actual":
                        filtered.append(finding)
                    # Otherwise skip UNKNOWN_FILE findings
                else:
                    # Include all findings with known files
                    filtered.append(finding)
        except (ValueError, KeyError):
            continue

    # Group by file
    files_dict = defaultdict(list)
    for finding in filtered:
        file = finding["file"]
        if file and file != "UNKNOWN_FILE":
            files_dict[file].append(finding)
        else:
            # UNKNOWN_FILE findings that made it through filtering
            # Group them together in a special UNKNOWN_FILE entry
            files_dict["UNKNOWN_FILE"].append(finding)

    # Build payload structure
    payload = {
        "context": {
            "goal": "Generate minimal JSON Patches that preserve workload behavior while fixing the findings.",
            "guardrails": [
                "Conform to kubeconform schema for the target cluster version.",
                "Meet Pod Security Standards (baseline/restricted) where applicable.",
                "Prefer least-privilege & immutable image refs; avoid hostPath/hostNetwork.",
                "Do not remove required fields (metadata.name/selectors/ports/args/command).",
                "Keep probes/resources sensible; avoid extreme limits."
            ]
        },
        "files": []
    }

    for file, findings in sorted(files_dict.items()):
        file_entry = {
            "file": Path(file).name,  # Use basename for LLM
            "findings": []
        }

        for finding in findings:
            file_entry["findings"].append({
                "category": finding["category"],
                "severity": finding["severity"],
                "priority": finding["priority"],
                "resourceRef": finding["resourceRef"],
                "snippet": finding["snippet"],
                "tools": finding["tools"],
                "score": finding["score"],
                "patchHint": patch_hint(finding["category"])
            })

        payload["files"].append(file_entry)

    return payload


def write_csv(normalized_findings: List[Dict], csv_path: Path):
    """Write CSV summary"""

    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            "file", "kind", "name", "namespace", "category",
            "severity", "priority", "status", "score", "tools",
            "provenance", "reason"
        ])

        for finding in normalized_findings:
            ref = finding["resourceRef"]
            writer.writerow([
                finding["file"],
                ref.get("kind", ""),
                ref.get("name", ""),
                ref.get("namespace", ""),
                finding["category"],
                finding["severity"],
                finding["priority"],
                finding["status"],
                finding["score"],
                ";".join(finding["tools"]),
                finding["provenance"],
                finding["decisionReason"]
            ])


def main():
    parser = argparse.ArgumentParser(
        description="SafeFix-K8s Normalizer - High-recall misconfiguration normalizer"
    )
    parser.add_argument("--raw-dir", required=True, help="Directory containing raw detector outputs")
    parser.add_argument("--tests-dir", required=True, help="Directory containing test YAML manifests")
    parser.add_argument("--out-normalized", required=True, help="Output path for normalized findings JSON")
    parser.add_argument("--out-llm-payload", required=True, help="Output path for LLM payload JSON")
    parser.add_argument("--out-buckets-csv", default="", help="Optional output path for buckets CSV")
    parser.add_argument("--payload-min-priority", default="LOW",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Minimum priority for LLM payload")
    parser.add_argument("--nonatomic-consensus", type=int, default=2,
                        help="Minimum tool count for consensus on MEDIUM/LOW findings")

    args = parser.parse_args()

    # Run normalization
    normalized_findings, llm_payload = normalize(args)

    # Write outputs
    print(f"Writing normalized findings to {args.out_normalized}...")
    with open(args.out_normalized, 'w', encoding='utf-8') as f:
        json.dump(normalized_findings, f, indent=2)

    print(f"Writing LLM payload to {args.out_llm_payload}...")
    with open(args.out_llm_payload, 'w', encoding='utf-8') as f:
        json.dump(llm_payload, f, indent=2)

    if args.out_buckets_csv:
        print(f"Writing CSV summary to {args.out_buckets_csv}...")
        write_csv(normalized_findings, Path(args.out_buckets_csv))

    # Print summary
    actual_count = sum(1 for f in normalized_findings if f["status"] == "Actual")
    corroboration_count = sum(1 for f in normalized_findings if f["status"] == "NeedsCorroboration")

    print("\n" + "=" * 60)
    print("NORMALIZATION COMPLETE")
    print("=" * 60)
    print(f"Total findings: {len(normalized_findings)}")
    print(f"  Actual: {actual_count}")
    print(f"  NeedsCorroboration: {corroboration_count}")
    print(f"\nLLM payload files: {len(llm_payload['files'])}")
    print(f"LLM payload findings: {sum(len(f['findings']) for f in llm_payload['files'])}")
    print("=" * 60)


if __name__ == "__main__":
    main()
