#!/usr/bin/env python3
"""
validation_gates_improved.py — SafeFix-K8s Enhanced Validation System
-----------------------------------------------------------------------

A comprehensive, production-ready validation system with:
- Complete coverage of all security categories
- Detailed failure reporting with actionable insights
- Configurable validation rules and severity levels
- Parallel validation support
- Diff analysis between original and secured manifests
- Type-safe implementation
- Comprehensive logging

PASS IF:
    - YAML is valid after optional schema auto-fix
    - All required auto-fix categories pass validation
    - No dangerous misconfigurations introduced
    - All severity-appropriate checks pass

NEEDS_REVIEW IF:
    - Schema validation warnings (kubeconform)
    - Medium severity issues in strict mode

FAIL IF:
    - YAML cannot be parsed
    - Required auto-fix categories fail
    - Critical/High severity violations detected
"""

import argparse
import csv
import json
import logging
import shutil
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

import yaml

# ============================================================================
# CONFIGURATION & LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class Severity(Enum):
    """Validation finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class ValidationConfig:
    """Validation configuration loaded from YAML."""
    dangerous_fields: List[Dict[str, Any]] = field(default_factory=list)
    forbidden_capabilities: List[str] = field(default_factory=list)
    trusted_registries: List[str] = field(default_factory=list)
    non_auto_fix_categories: Set[str] = field(default_factory=set)
    validation_rules: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    enable_kubeconform: bool = True
    enable_schema_autofix: bool = True
    enable_parallel_validation: bool = True
    max_workers: int = 4
    fail_on_needs_review: bool = False
    strict_mode: bool = False

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> 'ValidationConfig':
        """Load configuration from YAML file."""
        if config_path is None:
            config_path = Path(__file__).parent / "validation_config.yaml"

        if not config_path.exists():
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return cls()

        try:
            with config_path.open('r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            return cls(
                dangerous_fields=data.get('dangerous_fields', []),
                forbidden_capabilities=data.get('forbidden_capabilities', []),
                trusted_registries=data.get('trusted_registries', []),
                non_auto_fix_categories=set(data.get('non_auto_fix_categories', [])),
                validation_rules=data.get('validation_rules', {}),
                enable_kubeconform=data.get('validation_settings', {}).get('enable_kubeconform', True),
                enable_schema_autofix=data.get('validation_settings', {}).get('enable_schema_autofix', True),
                enable_parallel_validation=data.get('validation_settings', {}).get('enable_parallel_validation', True),
                max_workers=data.get('validation_settings', {}).get('max_workers', 4),
                fail_on_needs_review=data.get('validation_settings', {}).get('fail_on_needs_review', False),
                strict_mode=data.get('validation_settings', {}).get('strict_mode', False),
            )
        except Exception as e:
            logger.error(f"Failed to load config from {config_path}: {e}")
            return cls()


@dataclass
class ValidationFinding:
    """A single validation finding with context."""
    category: str
    severity: Severity
    passed: bool
    message: str
    container: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


@dataclass
class ValidationResult:
    """Complete validation result for a single manifest."""
    file: str
    status: str  # PASS, NEEDS_REVIEW, FAIL
    categories: List[str]
    auto_fix_categories: List[str]
    findings: List[ValidationFinding] = field(default_factory=list)
    dangerous: List[str] = field(default_factory=list)
    schema_fixed: bool = False
    schema_changes: List[str] = field(default_factory=list)
    diff_summary: Optional[Dict[str, Any]] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "file": self.file,
            "status": self.status,
            "categories": self.categories,
            "auto_fix_categories": self.auto_fix_categories,
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity.value,
                    "passed": f.passed,
                    "message": f.message,
                    "container": f.container,
                    "details": f.details
                }
                for f in self.findings
            ],
            "dangerous": self.dangerous,
            "schema_fixed": self.schema_fixed,
            "schema_changes": self.schema_changes,
            "diff_summary": self.diff_summary,
            "notes": self.notes
        }


# ============================================================================
# YAML UTILITIES
# ============================================================================

def load_yaml(path: Path) -> List[Dict[str, Any]]:
    """Load multi-document YAML safely."""
    try:
        txt = path.read_text(encoding="utf-8")
        docs = [doc for doc in yaml.safe_load_all(txt) if isinstance(doc, dict)]
        if not docs:
            raise ValueError("No valid YAML documents found")
        return docs
    except Exception as e:
        raise RuntimeError(f"Failed to parse YAML {path}: {e}")


def dump_yaml(path: Path, docs: List[Dict[str, Any]]) -> None:
    """Write multi-document YAML."""
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump_all(docs, f, sort_keys=False, default_flow_style=False)


# ============================================================================
# SCHEMA AUTO-FIX ENGINE
# ============================================================================

def autofix_schema_one(doc: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Repair common schema errors for Kubernetes resources.
    Returns: (fixed_doc, list_of_changes)
    """
    changes: List[str] = []
    kind = doc.get("kind", "")
    spec = doc.setdefault("spec", {})

    # Missing metadata.name
    if "metadata" not in doc:
        doc["metadata"] = {"name": "autofixed"}
        changes.append("Added missing metadata.name='autofixed'")
    elif "name" not in doc["metadata"]:
        doc["metadata"]["name"] = "autofixed"
        changes.append("Added missing metadata.name='autofixed'")

    # Deployment-specific fixes
    if kind == "Deployment":
        tmpl = spec.setdefault("template", {})
        tmpl_meta = tmpl.setdefault("metadata", {})
        tmpl_labels = tmpl_meta.setdefault("labels", {"app": "autofixed"})

        if tmpl_labels == {"app": "autofixed"}:
            changes.append("Added default template labels")

        sel = spec.setdefault("selector", {})
        if "matchLabels" not in sel:
            sel["matchLabels"] = tmpl_labels
            changes.append("Added selector.matchLabels from template labels")

    # Pod/Deployment/Job restartPolicy
    if kind in ("Pod", "Deployment", "Job"):
        tmpl = spec.get("template", {})
        pspec = tmpl.get("spec", spec)
        if "restartPolicy" not in pspec:
            default_policy = "Never" if kind == "Job" else "Always"
            pspec["restartPolicy"] = default_policy
            changes.append(f"Added restartPolicy='{default_policy}'")

    # Ingress API version upgrade
    if kind == "Ingress":
        api = doc.get("apiVersion", "")
        if api in ("extensions/v1beta1", "networking.k8s.io/v1beta1"):
            doc["apiVersion"] = "networking.k8s.io/v1"
            changes.append(f"Upgraded apiVersion from {api} to networking.k8s.io/v1")
            spec.setdefault("rules", [])
            if "ingressClassName" not in spec:
                spec["ingressClassName"] = "nginx"
                changes.append("Added default ingressClassName='nginx'")

    # Service port type fix
    if kind == "Service":
        ports = spec.setdefault("ports", [])
        for p in ports:
            if "port" in p:
                try:
                    old_port = p["port"]
                    p["port"] = int(p["port"])
                    if old_port != p["port"]:
                        changes.append(f"Fixed Service port type: {old_port} -> {p['port']}")
                except (ValueError, TypeError):
                    p["port"] = 80
                    changes.append("Fixed invalid Service port, defaulted to 80")

    return doc, changes


def autofix_schema_all(docs: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Apply schema auto-fix to all documents."""
    fixed_docs: List[Dict[str, Any]] = []
    all_changes: List[str] = []

    for i, doc in enumerate(docs):
        try:
            fixed_doc, changes = autofix_schema_one(doc)
            fixed_docs.append(fixed_doc)
            if changes:
                all_changes.extend([f"Doc {i}: {c}" for c in changes])
        except Exception as e:
            logger.warning(f"Schema autofix failed for doc {i}: {e}")
            fixed_docs.append(doc)

    return fixed_docs, all_changes


# ============================================================================
# SECURITY CONTEXT UTILITIES
# ============================================================================

def get_pod_spec(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Extract pod spec from various resource types."""
    spec = doc.get("spec", {})

    # For Deployment, StatefulSet, DaemonSet, Job, CronJob
    if "template" in spec:
        return spec["template"].get("spec", {})

    # For Pod
    return spec


def iter_containers(doc: Dict[str, Any]) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """Iterate over all containers (regular + init) with their names."""
    pod_spec = get_pod_spec(doc)

    for container in pod_spec.get("containers", []):
        yield (container.get("name", "unnamed"), container)

    for container in pod_spec.get("initContainers", []):
        yield (f"init:{container.get('name', 'unnamed')}", container)


def iter_effective_security_contexts(doc: Dict[str, Any]) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """
    Yield (container_name, effective_security_context) for each container.

    The effective security context merges pod-level and container-level settings.
    Container-level settings override pod-level, EXCEPT for capabilities which
    only exist at container level.
    """
    pod_spec = get_pod_spec(doc)
    pod_sc = pod_spec.get("securityContext", {}) or {}

    for container_name, container in iter_containers(doc):
        container_sc = container.get("securityContext", {}) or {}

        # Merge: container overrides pod, but capabilities only exist in container
        effective = {**pod_sc, **container_sc}

        # Ensure capabilities come from container only (not merged)
        if "capabilities" in container_sc:
            effective["capabilities"] = container_sc["capabilities"]
        elif "capabilities" in effective:
            # Remove if it somehow came from pod (shouldn't happen)
            del effective["capabilities"]

        yield (container_name, effective)


# ============================================================================
# DANGEROUS MISCONFIGURATION CHECK
# ============================================================================

def check_dangerous(doc: Dict[str, Any], config: ValidationConfig) -> List[str]:
    """Check for dangerous security misconfigurations."""
    dangerous: List[str] = []

    # Check security contexts
    for container_name, sc in iter_effective_security_contexts(doc):
        # Check dangerous fields
        for field_config in config.dangerous_fields:
            field = field_config['field']
            bad_value = field_config['value']

            if sc.get(field) == bad_value:
                msg = f"[{container_name}] {field}={bad_value}: {field_config.get('message', 'dangerous setting')}"
                dangerous.append(msg)

        # Check forbidden capabilities
        caps_add = sc.get("capabilities", {}).get("add", []) or []
        for cap in caps_add:
            if cap in config.forbidden_capabilities:
                dangerous.append(
                    f"[{container_name}] Forbidden capability added: {cap}"
                )

    # Check hostPath volumes
    pod_spec = get_pod_spec(doc)
    for volume in pod_spec.get("volumes", []):
        if "hostPath" in volume:
            vol_name = volume.get("name", "unnamed")
            path = volume["hostPath"].get("path", "unknown")
            dangerous.append(f"hostPath volume '{vol_name}' mounted: {path}")

    return dangerous


# ============================================================================
# CATEGORY VALIDATORS
# ============================================================================

class CategoryValidator:
    """Validation logic for different categories."""

    def __init__(self, config: ValidationConfig):
        self.config = config

    def validate_privileged_false(self, sc: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate privileged=false."""
        is_privileged = sc.get("privileged", False)
        if is_privileged:
            return False, f"privileged={is_privileged} (must be false)"
        return True, "privileged=false"

    def validate_allow_privilege_escalation_false(self, sc: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate allowPrivilegeEscalation=false."""
        allow_esc = sc.get("allowPrivilegeEscalation")
        if allow_esc is True:
            return False, f"allowPrivilegeEscalation={allow_esc} (must be false)"
        # If not set, it's acceptable (defaults to false with proper admission control)
        return True, f"allowPrivilegeEscalation={allow_esc or 'false'}"

    def validate_capabilities_drop_all(self, sc: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate that ALL capabilities are dropped."""
        caps = sc.get("capabilities", {})
        drop = caps.get("drop", []) or []
        add = caps.get("add", []) or []

        if "ALL" not in drop:
            return False, f"capabilities.drop missing 'ALL' (found: {drop})"

        if add:
            return True, f"capabilities.drop=['ALL'], add={add} (selective re-add allowed)"

        return True, "capabilities.drop=['ALL']"

    def validate_seccomp_profile_present(self, sc: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate seccomp profile is configured."""
        seccomp = sc.get("seccompProfile")
        if not seccomp:
            return False, "seccompProfile not configured"

        profile_type = seccomp.get("type", "")
        if profile_type == "Unconfined":
            return False, f"seccompProfile type is Unconfined (insecure)"

        return True, f"seccompProfile.type={profile_type}"

    def validate_readonly_root_filesystem(self, sc: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate readOnlyRootFilesystem=true."""
        readonly = sc.get("readOnlyRootFilesystem", False)
        if not readonly:
            return False, f"readOnlyRootFilesystem={readonly} (must be true)"
        return True, "readOnlyRootFilesystem=true"

    def validate_run_as_non_root(self, sc: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate runAsNonRoot=true."""
        run_as_non_root = sc.get("runAsNonRoot", False)
        if not run_as_non_root:
            return False, f"runAsNonRoot={run_as_non_root} (must be true)"
        return True, "runAsNonRoot=true"

    def validate_apparmor_profile_present(self, doc: Dict[str, Any], container_name: str) -> Tuple[bool, str]:
        """Validate AppArmor annotation is present."""
        annotations = doc.get("metadata", {}).get("annotations", {})

        # Check for container-specific annotation
        apparmor_key = f"container.apparmor.security.beta.kubernetes.io/{container_name}"
        if apparmor_key in annotations:
            profile = annotations[apparmor_key]
            if profile == "unconfined":
                return False, f"AppArmor profile is 'unconfined' for {container_name}"
            return True, f"AppArmor profile: {profile}"

        return False, f"AppArmor annotation missing for {container_name}"

    def validate_automount_sa_token_false(self, doc: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate automountServiceAccountToken=false."""
        pod_spec = get_pod_spec(doc)
        automount = pod_spec.get("automountServiceAccountToken")

        if automount is None or automount is True:
            return False, f"automountServiceAccountToken={automount} (should be false)"

        return True, "automountServiceAccountToken=false"

    def validate_non_default_service_account(self, doc: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate non-default service account is used."""
        pod_spec = get_pod_spec(doc)
        sa_name = pod_spec.get("serviceAccountName", "default")

        if sa_name == "default":
            return False, "serviceAccountName='default' (should be non-default)"

        return True, f"serviceAccountName='{sa_name}'"

    def validate_non_default_namespace(self, doc: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate resource is not in default namespace."""
        namespace = doc.get("metadata", {}).get("namespace", "default")

        if namespace == "default":
            return False, "namespace='default' (should be non-default)"

        return True, f"namespace='{namespace}'"

    def validate_resources_requests_present(self, container: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate resource requests are defined."""
        resources = container.get("resources", {})
        requests = resources.get("requests", {})

        if not requests:
            return False, "resources.requests not defined"

        has_cpu = "cpu" in requests
        has_memory = "memory" in requests

        if not has_cpu and not has_memory:
            return False, "resources.requests defined but empty"

        return True, f"resources.requests: {requests}"

    def validate_resources_limits_present(self, container: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate resource limits are defined."""
        resources = container.get("resources", {})
        limits = resources.get("limits", {})

        if not limits:
            return False, "resources.limits not defined"

        has_cpu = "cpu" in limits
        has_memory = "memory" in limits

        if not has_cpu and not has_memory:
            return False, "resources.limits defined but empty"

        return True, f"resources.limits: {limits}"

    def validate_probes_present(self, container: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate liveness or readiness probe is configured."""
        has_liveness = "livenessProbe" in container
        has_readiness = "readinessProbe" in container

        if not has_liveness and not has_readiness:
            return False, "Neither livenessProbe nor readinessProbe defined"

        probes = []
        if has_liveness:
            probes.append("livenessProbe")
        if has_readiness:
            probes.append("readinessProbe")

        return True, f"Probes configured: {', '.join(probes)}"

    def validate_image_tag_pinned(self, container: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate image tag is pinned (not 'latest' or missing)."""
        image = container.get("image", "")

        if not image:
            return False, "image not specified"

        # Check if tag is present
        if ":" not in image:
            return False, f"image '{image}' has no tag (implicitly 'latest')"

        # Extract tag
        tag = image.split(":")[-1]

        if tag == "latest":
            return False, f"image '{image}' uses 'latest' tag (should be pinned)"

        # Check for digest (most secure)
        if "@sha256:" in image:
            return True, f"image pinned with digest: {image}"

        return True, f"image tag pinned: {tag}"

    def validate_trusted_registry(self, container: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate image comes from trusted registry."""
        image = container.get("image", "")

        if not image:
            return False, "image not specified"

        # Extract registry
        parts = image.split("/")

        # docker.io/library/nginx or just nginx
        if len(parts) == 1:
            registry = "docker.io/library"
        elif len(parts) == 2 and "." not in parts[0]:
            registry = "docker.io"
        else:
            registry = parts[0]

        # Check against trusted registries
        for trusted in self.config.trusted_registries:
            if registry.startswith(trusted) or trusted.startswith(registry):
                return True, f"image from trusted registry: {registry}"

        return False, f"image from untrusted registry: {registry}"

    def validate_pod_security_standards(self, doc: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate against Pod Security Standards baseline."""
        # This is a composite check of critical security settings
        issues: List[str] = []

        pod_spec = get_pod_spec(doc)

        # Check for privileged
        for container_name, sc in iter_effective_security_contexts(doc):
            if sc.get("privileged"):
                issues.append(f"{container_name}: privileged=true")

            if sc.get("allowPrivilegeEscalation"):
                issues.append(f"{container_name}: allowPrivilegeEscalation=true")

        # Check hostPath, hostNetwork, hostPID, hostIPC
        if pod_spec.get("hostNetwork"):
            issues.append("hostNetwork=true")
        if pod_spec.get("hostPID"):
            issues.append("hostPID=true")
        if pod_spec.get("hostIPC"):
            issues.append("hostIPC=true")

        for volume in pod_spec.get("volumes", []):
            if "hostPath" in volume:
                issues.append(f"hostPath volume: {volume.get('name')}")

        if issues:
            return False, f"Pod Security Standards violations: {'; '.join(issues)}"

        return True, "Pod Security Standards baseline compliance"


# ============================================================================
# CATEGORY VALIDATION
# ============================================================================

def validate_category(
    doc: Dict[str, Any],
    category: str,
    config: ValidationConfig,
    validator: CategoryValidator
) -> List[ValidationFinding]:
    """
    Validate a specific category and return detailed findings.
    """
    findings: List[ValidationFinding] = []

    # Skip non-auto-fix categories
    if category in config.non_auto_fix_categories:
        return findings

    # Get rule configuration
    rule = config.validation_rules.get(category)
    if not rule:
        logger.debug(f"No validation rule defined for category: {category}")
        return findings

    check_type = rule.get("check_type", "")
    validator_name = rule.get("validator", "")
    severity_str = rule.get("severity", "MEDIUM")
    severity = Severity[severity_str]
    description = rule.get("description", category)

    # Get validator method
    validator_method = getattr(validator, f"validate_{validator_name}", None)
    if not validator_method:
        logger.warning(f"Validator method not found: validate_{validator_name}")
        return findings

    # Execute validation based on check type
    if check_type == "security_context":
        # Check each container's effective security context
        for container_name, sc in iter_effective_security_contexts(doc):
            passed, message = validator_method(sc)
            findings.append(ValidationFinding(
                category=category,
                severity=severity,
                passed=passed,
                message=message,
                container=container_name,
                details={"security_context": sc}
            ))

    elif check_type == "container":
        # Check each container
        for container_name, container in iter_containers(doc):
            passed, message = validator_method(container)
            findings.append(ValidationFinding(
                category=category,
                severity=severity,
                passed=passed,
                message=message,
                container=container_name
            ))

    elif check_type == "pod_spec":
        # Check pod-level configuration
        passed, message = validator_method(doc)
        findings.append(ValidationFinding(
            category=category,
            severity=severity,
            passed=passed,
            message=message
        ))

    elif check_type == "metadata":
        # Check metadata
        passed, message = validator_method(doc)
        findings.append(ValidationFinding(
            category=category,
            severity=severity,
            passed=passed,
            message=message
        ))

    elif check_type == "annotation":
        # Special handling for AppArmor which needs container name
        for container_name, _ in iter_containers(doc):
            passed, message = validator_method(doc, container_name)
            findings.append(ValidationFinding(
                category=category,
                severity=severity,
                passed=passed,
                message=message,
                container=container_name
            ))

    return findings


# ============================================================================
# KUBECONFORM VALIDATION
# ============================================================================

def run_kubeconform(path: Path) -> Tuple[bool, Optional[str]]:
    """Run kubeconform for schema validation. Returns (success, error_message)."""
    if shutil.which("kubeconform") is None:
        logger.debug("kubeconform not installed, skipping schema validation")
        return True, None

    try:
        result = subprocess.run(
            ["kubeconform", "-summary", "-output", "json", str(path)],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            return True, None
        else:
            return False, result.stderr or result.stdout

    except subprocess.TimeoutExpired:
        return False, "kubeconform validation timed out"
    except Exception as e:
        return False, f"kubeconform validation failed: {e}"


# ============================================================================
# DIFF ANALYSIS
# ============================================================================

def analyze_diff(original_docs: List[Dict[str, Any]], secured_docs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze differences between original and secured manifests."""

    def get_security_relevant_fields(doc: Dict[str, Any]) -> Dict[str, Any]:
        """Extract security-relevant fields for comparison."""
        pod_spec = get_pod_spec(doc)

        return {
            "securityContext": pod_spec.get("securityContext"),
            "serviceAccountName": pod_spec.get("serviceAccountName"),
            "automountServiceAccountToken": pod_spec.get("automountServiceAccountToken"),
            "hostNetwork": pod_spec.get("hostNetwork"),
            "hostPID": pod_spec.get("hostPID"),
            "hostIPC": pod_spec.get("hostIPC"),
            "containers": [
                {
                    "name": c.get("name"),
                    "securityContext": c.get("securityContext"),
                    "resources": c.get("resources"),
                    "livenessProbe": c.get("livenessProbe", {}).get("__type__") if c.get("livenessProbe") else None,
                    "readinessProbe": c.get("readinessProbe", {}).get("__type__") if c.get("readinessProbe") else None,
                }
                for c in pod_spec.get("containers", [])
            ]
        }

    changes = {
        "security_fields_added": [],
        "security_fields_modified": [],
        "resources_added": [],
        "probes_added": []
    }

    # Simple field-level comparison
    for orig, secured in zip(original_docs, secured_docs):
        orig_fields = get_security_relevant_fields(orig)
        secured_fields = get_security_relevant_fields(secured)

        # Check for added/modified security contexts
        if not orig_fields.get("securityContext") and secured_fields.get("securityContext"):
            changes["security_fields_added"].append("Pod-level securityContext")

        # Check containers
        for orig_c, sec_c in zip(orig_fields["containers"], secured_fields["containers"]):
            c_name = sec_c["name"]

            if not orig_c.get("securityContext") and sec_c.get("securityContext"):
                changes["security_fields_added"].append(f"Container '{c_name}' securityContext")

            if not orig_c.get("resources") and sec_c.get("resources"):
                changes["resources_added"].append(f"Container '{c_name}' resources")

            if not orig_c.get("livenessProbe") and sec_c.get("livenessProbe"):
                changes["probes_added"].append(f"Container '{c_name}' livenessProbe")

            if not orig_c.get("readinessProbe") and sec_c.get("readinessProbe"):
                changes["probes_added"].append(f"Container '{c_name}' readinessProbe")

    return changes


# ============================================================================
# MAIN VALIDATION FUNCTION
# ============================================================================

def validate_one(
    original_path: Path,
    secured_path: Path,
    categories: List[str],
    config: ValidationConfig
) -> ValidationResult:
    """
    Validate a single manifest file.

    Returns a ValidationResult with complete findings and status.
    """
    result = ValidationResult(
        file=original_path.name,
        status="PASS",
        categories=categories,
        auto_fix_categories=[c for c in categories if c not in config.non_auto_fix_categories]
    )

    validator = CategoryValidator(config)

    # =========================================================================
    # STEP 1: Load YAML
    # =========================================================================
    try:
        original_docs = load_yaml(original_path)
        secured_docs = load_yaml(secured_path)
    except Exception as e:
        result.status = "FAIL"
        result.notes.append(f"Failed to parse YAML: {e}")
        logger.error(f"[{original_path.name}] YAML parsing failed: {e}")
        return result

    # =========================================================================
    # STEP 2: Schema Auto-Fix (optional, in-memory)
    # =========================================================================
    if config.enable_schema_autofix:
        fixed_docs, schema_changes = autofix_schema_all(secured_docs)

        if schema_changes:
            result.schema_fixed = True
            result.schema_changes = schema_changes

            # Write fixed version
            try:
                dump_yaml(secured_path, fixed_docs)
                secured_docs = fixed_docs
                logger.info(f"[{original_path.name}] Applied {len(schema_changes)} schema fixes")
            except Exception as e:
                result.status = "FAIL"
                result.notes.append(f"Failed to write schema fixes: {e}")
                return result

    # =========================================================================
    # STEP 3: Check for Dangerous Misconfigurations
    # =========================================================================
    for doc in secured_docs:
        dangerous = check_dangerous(doc, config)
        if dangerous:
            result.dangerous.extend(dangerous)

    if result.dangerous:
        result.status = "FAIL"
        result.notes.extend(result.dangerous)
        logger.error(f"[{original_path.name}] DANGEROUS MISCONFIGURATIONS: {len(result.dangerous)}")
        return result

    # =========================================================================
    # STEP 4: Validate All Categories
    # =========================================================================
    for doc in secured_docs:
        for category in result.auto_fix_categories:
            findings = validate_category(doc, category, config, validator)
            result.findings.extend(findings)

    # =========================================================================
    # STEP 5: Determine Status Based on Findings
    # =========================================================================
    critical_failures = [f for f in result.findings if not f.passed and f.severity == Severity.CRITICAL]
    high_failures = [f for f in result.findings if not f.passed and f.severity == Severity.HIGH]
    medium_failures = [f for f in result.findings if not f.passed and f.severity == Severity.MEDIUM]
    low_failures = [f for f in result.findings if not f.passed and f.severity == Severity.LOW]

    if critical_failures or high_failures:
        result.status = "FAIL"

        failure_summary = []
        if critical_failures:
            failure_summary.append(f"{len(critical_failures)} CRITICAL")
        if high_failures:
            failure_summary.append(f"{len(high_failures)} HIGH")

        result.notes.append(f"Security validation failures: {', '.join(failure_summary)}")

        # Add detailed failure messages
        for finding in (critical_failures + high_failures):
            msg = f"[{finding.severity.value}] {finding.category}"
            if finding.container:
                msg += f" ({finding.container})"
            msg += f": {finding.message}"
            result.notes.append(msg)

        logger.error(f"[{original_path.name}] FAILED validation: {', '.join(failure_summary)}")
        return result

    if medium_failures and config.strict_mode:
        result.status = "NEEDS_REVIEW"
        result.notes.append(f"{len(medium_failures)} MEDIUM severity issues in strict mode")

    # =========================================================================
    # STEP 6: Kubeconform Schema Validation (optional)
    # =========================================================================
    if config.enable_kubeconform:
        kube_ok, kube_error = run_kubeconform(secured_path)
        if not kube_ok:
            if config.fail_on_needs_review:
                result.status = "FAIL"
            else:
                result.status = "NEEDS_REVIEW"
            result.notes.append(f"Schema validation warnings: {kube_error}")

    # =========================================================================
    # STEP 7: Diff Analysis
    # =========================================================================
    try:
        result.diff_summary = analyze_diff(original_docs, secured_docs)
    except Exception as e:
        logger.warning(f"[{original_path.name}] Diff analysis failed: {e}")

    # =========================================================================
    # STEP 8: Final Status Notes
    # =========================================================================
    if result.status == "PASS":
        passed_count = len([f for f in result.findings if f.passed])
        result.notes.append(f"All validations passed ({passed_count} checks)")

        if result.schema_fixed:
            result.notes.append(f"Schema auto-fixed ({len(result.schema_changes)} changes)")

        logger.info(f"[{original_path.name}] PASSED validation")

    return result


# ============================================================================
# PARALLEL VALIDATION
# ============================================================================

def validate_parallel(
    file_map: Dict[str, List[str]],
    tests_dir: Path,
    fixed_dir: Path,
    config: ValidationConfig
) -> List[ValidationResult]:
    """Validate multiple files in parallel."""

    tasks = []
    for rel_path, categories in file_map.items():
        original_path = tests_dir / rel_path
        secured_path = fixed_dir / f"SECURED_{rel_path.replace('/', '_')}"

        if not original_path.exists():
            logger.warning(f"Original file not found: {original_path}")
            continue

        if not secured_path.exists():
            logger.warning(f"Secured file not found: {secured_path}")
            continue

        tasks.append((original_path, secured_path, categories))

    results: List[ValidationResult] = []

    if config.enable_parallel_validation and len(tasks) > 1:
        logger.info(f"Validating {len(tasks)} files in parallel (max_workers={config.max_workers})")

        with ProcessPoolExecutor(max_workers=config.max_workers) as executor:
            futures = {
                executor.submit(validate_one, orig, sec, cats, config): orig
                for orig, sec, cats in tasks
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    orig_path = futures[future]
                    logger.error(f"Validation failed for {orig_path}: {e}")
                    results.append(ValidationResult(
                        file=orig_path.name,
                        status="FAIL",
                        categories=[],
                        auto_fix_categories=[],
                        notes=[f"Validation crashed: {e}"]
                    ))
    else:
        # Sequential validation
        logger.info(f"Validating {len(tasks)} files sequentially")

        for original_path, secured_path, categories in tasks:
            try:
                result = validate_one(original_path, secured_path, categories, config)
                results.append(result)
            except Exception as e:
                logger.error(f"Validation failed for {original_path}: {e}")
                results.append(ValidationResult(
                    file=original_path.name,
                    status="FAIL",
                    categories=[],
                    auto_fix_categories=[],
                    notes=[f"Validation crashed: {e}"]
                ))

    return results


# ============================================================================
# SUMMARY REPORTING
# ============================================================================

def write_summary(out_dir: Path, results: List[ValidationResult]) -> None:
    """Write validation summary CSV."""
    summary_path = out_dir / "SUMMARY_VALIDATION.csv"

    with summary_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Header
        writer.writerow([
            "file",
            "status",
            "total_checks",
            "passed_checks",
            "failed_checks",
            "critical_failures",
            "high_failures",
            "medium_failures",
            "low_failures",
            "dangerous_configs",
            "schema_fixed",
            "notes"
        ])

        # Data rows
        for r in results:
            total_checks = len(r.findings)
            passed_checks = len([f for f in r.findings if f.passed])
            failed_checks = total_checks - passed_checks

            critical = len([f for f in r.findings if not f.passed and f.severity == Severity.CRITICAL])
            high = len([f for f in r.findings if not f.passed and f.severity == Severity.HIGH])
            medium = len([f for f in r.findings if not f.passed and f.severity == Severity.MEDIUM])
            low = len([f for f in r.findings if not f.passed and f.severity == Severity.LOW])

            writer.writerow([
                r.file,
                r.status,
                total_checks,
                passed_checks,
                failed_checks,
                critical,
                high,
                medium,
                low,
                len(r.dangerous),
                r.schema_fixed,
                "; ".join(r.notes)
            ])

    logger.info(f"Summary written to: {summary_path}")


def write_detailed_reports(out_dir: Path, results: List[ValidationResult]) -> None:
    """Write detailed JSON reports for each validation."""
    for result in results:
        report_name = f"REPORT_VALIDATE_{result.file.replace('/', '_')}.json"
        report_path = out_dir / report_name

        try:
            report_path.write_text(
                json.dumps(result.to_dict(), indent=2),
                encoding="utf-8"
            )
        except Exception as e:
            logger.error(f"Failed to write report {report_name}: {e}")


def print_summary_stats(results: List[ValidationResult]) -> None:
    """Print validation summary statistics."""
    total = len(results)
    passed = len([r for r in results if r.status == "PASS"])
    needs_review = len([r for r in results if r.status == "NEEDS_REVIEW"])
    failed = len([r for r in results if r.status == "FAIL"])

    logger.info("=" * 70)
    logger.info("VALIDATION SUMMARY")
    logger.info("=" * 70)
    logger.info(f"Total files validated: {total}")
    logger.info(f"  PASS:         {passed:3d} ({passed/total*100:.1f}%)")
    logger.info(f"  NEEDS_REVIEW: {needs_review:3d} ({needs_review/total*100:.1f}%)")
    logger.info(f"  FAIL:         {failed:3d} ({failed/total*100:.1f}%)")
    logger.info("=" * 70)


# ============================================================================
# MAIN CLI
# ============================================================================

def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SafeFix-K8s Enhanced Validation System",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("--tests-dir", required=True, help="Directory containing original test files")
    parser.add_argument("--fixed-dir", required=True, help="Directory containing secured/fixed files")
    parser.add_argument("--payload", required=True, help="JSON payload with detection findings")
    parser.add_argument("--out-dir", required=True, help="Output directory for validation reports")
    parser.add_argument("--config", help="Path to validation config YAML (default: validation_config.yaml)")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")
    parser.add_argument("--strict-mode", action="store_true", help="Enable strict validation mode")
    parser.add_argument("--no-parallel", action="store_true", help="Disable parallel validation")

    args = parser.parse_args()

    # Configure logging
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    # Load configuration
    config_path = Path(args.config) if args.config else None
    config = ValidationConfig.load(config_path)

    if args.strict_mode:
        config.strict_mode = True

    if args.no_parallel:
        config.enable_parallel_validation = False

    # Setup paths
    tests_dir = Path(args.tests_dir)
    fixed_dir = Path(args.fixed_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"SafeFix-K8s Enhanced Validation System")
    logger.info(f"Tests directory: {tests_dir}")
    logger.info(f"Fixed directory: {fixed_dir}")
    logger.info(f"Output directory: {out_dir}")
    logger.info(f"Strict mode: {config.strict_mode}")
    logger.info(f"Parallel validation: {config.enable_parallel_validation}")

    # Load payload
    try:
        payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))
    except Exception as e:
        logger.error(f"Failed to load payload: {e}")
        return 1

    # Build file map
    file_map: Dict[str, List[str]] = {}

    if "files" in payload:
        for file_entry in payload["files"]:
            file_map[file_entry["file"]] = [f["category"] for f in file_entry["findings"]]
    elif "items" in payload:
        for item in payload["items"]:
            file_map.setdefault(item["file"], []).append(item["category"])

    if not file_map:
        logger.error("No files found in payload")
        return 1

    logger.info(f"Found {len(file_map)} files to validate")

    # Validate files
    results = validate_parallel(file_map, tests_dir, fixed_dir, config)

    # Write reports
    write_detailed_reports(out_dir, results)
    write_summary(out_dir, results)

    # Print summary
    print_summary_stats(results)

    # Determine exit code
    worst_status = "PASS"
    status_order = {"PASS": 0, "NEEDS_REVIEW": 1, "FAIL": 2}

    for result in results:
        if status_order[result.status] > status_order[worst_status]:
            worst_status = result.status

    if worst_status == "FAIL":
        logger.error("Validation FAILED")
        return 1
    elif worst_status == "NEEDS_REVIEW":
        if config.fail_on_needs_review:
            logger.warning("Validation NEEDS_REVIEW (failing due to configuration)")
            return 1
        else:
            logger.warning("Validation NEEDS_REVIEW")
            return 0
    else:
        logger.info("Validation PASSED")
        return 0


if __name__ == "__main__":
    sys.exit(main())
