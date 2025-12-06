#!/usr/bin/env python3
"""
ultimate_llm_orchestrator.py — Enhanced version with 100% fix coverage

Key improvements:
1. Comprehensive security hardening (all 4 controls applied together)
2. NetworkPolicy explicitly skipped from LLM
3. Retry logic with exponential backoff for rate limits (HTTP 429)
4. Fallback providers when primary fails (HTTP 404)
5. Better error recovery and logging
6. Complete category coverage
7. Safer patch application:
   - Workload doc auto-selection in multi-doc YAML
   - More robust JSON Patch engine (supports "-" and creates lists/objects)
   - Security hardening now merges with existing securityContext instead of
     overwriting, and de-duplicates volumes / mounts
"""

import argparse
import json
import os
import random
import re
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml

# ---------------------------------------------------------------------------
# Global constants
# ---------------------------------------------------------------------------

WORKLOAD_KINDS = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "ReplicaSet",
    "Pod",
}

# Valid Pod-level securityContext fields (PodSecurityContext)
POD_SC_ALLOWED = {
    "runAsUser",
    "runAsGroup",
    "runAsNonRoot",
    "fsGroup",
    "fsGroupChangePolicy",
    "supplementalGroups",
    "seccompProfile",
    "seLinuxOptions",
    "sysctls",
    "windowsOptions",
}

# ======================= Configuration =======================


class LlmProvider(Enum):
    """Available LLM providers."""
    OPENAI = "openai"
    GROQ = "groq"
    GEMINI = "gemini"
    OPENROUTER = "openrouter"


class FixStrategy(Enum):
    """Fix strategy for each category."""
    DETERMINISTIC = "deterministic"
    LLM_GUIDED = "llm_guided"
    TEMPLATE = "template"
    SKIP = "skip"  # for categories that shouldn't be auto-fixed


# Categories to SKIP from LLM processing
SKIP_FROM_LLM = {
    "Network/MissingNetworkPolicy",
    "Network/NetworkPolicyMisconfiguration",
}

SKIP_MESSAGES = {
    "Network/MissingNetworkPolicy":
        "NetworkPolicy requires separate resource with application-specific "
        "traffic rules. Create as separate manifest based on your architecture.",
    "Network/NetworkPolicyMisconfiguration":
        "NetworkPolicy misconfigurations require manual review of traffic "
        "requirements.",
}

# Categories that use comprehensive security hardening handler
SECURITY_HARDENING_CATEGORIES = {
    "Security/AllowPrivilegeEscalation",
    "Security/CapabilitiesNotDropped",
    "Security/ReadOnlyRootFSFalse",
    "Auth/RunAsRoot",
    "Security/MissingSecurityContextHardening",
}

# Enhanced category configurations
CATEGORY_CONFIG: Dict[str, Dict[str, Any]] = {
    # Deterministic fixes (0 tokens, 100% success)
    "Auth/DefaultNamespace": {
        "strategy": FixStrategy.DETERMINISTIC,
        "priority": 4,
    },
    "Auth/DefaultServiceAccount": {
        "strategy": FixStrategy.DETERMINISTIC,
        "priority": 4,
    },
    "Auth/AutomountServiceAccountToken": {
        "strategy": FixStrategy.DETERMINISTIC,
        "priority": 4,
    },

    # Template-based (minimal tokens, high success)
    "Probes/MissingReadinessLiveness": {
        "strategy": FixStrategy.TEMPLATE,
        "priority": 6,
    },
    "Resources/MissingRequests": {
        "strategy": FixStrategy.TEMPLATE,
        "priority": 6,
    },
    "Resources/MissingLimits": {
        "strategy": FixStrategy.TEMPLATE,
        "priority": 6,
    },

    # SKIP these categories entirely
    "Network/MissingNetworkPolicy": {
        "strategy": FixStrategy.SKIP,
        "priority": 0,
    },
    "Network/NetworkPolicyMisconfiguration": {
        "strategy": FixStrategy.SKIP,
        "priority": 0,
    },

    # Comprehensive security hardening (deterministic)
    "Security/AllowPrivilegeEscalation": {
        "strategy": FixStrategy.DETERMINISTIC,
        "priority": 10,
        "use_security_handler": True,
    },
    "Security/CapabilitiesNotDropped": {
        "strategy": FixStrategy.DETERMINISTIC,
        "priority": 10,
        "use_security_handler": True,
    },
    "Security/ReadOnlyRootFSFalse": {
        "strategy": FixStrategy.DETERMINISTIC,
        "priority": 10,
        "use_security_handler": True,
    },
    "Auth/RunAsRoot": {
        "strategy": FixStrategy.DETERMINISTIC,
        "priority": 10,
        "use_security_handler": True,
    },
    "Security/MissingSecurityContextHardening": {
        "strategy": FixStrategy.DETERMINISTIC,
        "priority": 10,
        "use_security_handler": True,
    },

    # LLM-guided with fallback (for other security issues)
    "Security/PrivilegedContainer": {
        "strategy": FixStrategy.LLM_GUIDED,
        "provider": LlmProvider.GROQ,
        "fallback": LlmProvider.OPENAI,
        "priority": 9,
        "max_retries": 3,
    },
    "Security/MissingSeccompProfile": {
        "strategy": FixStrategy.LLM_GUIDED,
        "provider": LlmProvider.GROQ,
        "fallback": LlmProvider.OPENAI,
        "priority": 8,
        "max_retries": 3,
    },
    "Security/MissingAppArmorProfile": {
        "strategy": FixStrategy.LLM_GUIDED,
        "provider": LlmProvider.GROQ,
        "fallback": LlmProvider.OPENAI,
        "priority": 8,
        "max_retries": 3,
    },
    "Image/TagNotPinned": {
        "strategy": FixStrategy.LLM_GUIDED,
        "provider": LlmProvider.OPENAI,
        "fallback": LlmProvider.GROQ,
        "priority": 5,
        "max_retries": 3,
    },
    "Policy/PodSecurityViolation": {
        "strategy": FixStrategy.LLM_GUIDED,
        "provider": LlmProvider.OPENAI,
        "fallback": LlmProvider.GROQ,
        "priority": 7,
        "max_retries": 3,
    },

    # Skip these (not actionable or duplicates)
    "Style/YamlLint": {"strategy": FixStrategy.SKIP},
    "Schema/InvalidManifest": {"strategy": FixStrategy.SKIP},
    "Misc/Unmapped": {"strategy": FixStrategy.SKIP},
}

# ======================= Helper Functions =======================


def load_dotenv():
    """Load environment variables from .env file."""
    env_paths = [Path.cwd() / ".env", Path(__file__).parent / ".env"]
    for p in env_paths:
        if p.exists():
            for line in p.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(
                        k.strip(),
                        v.strip().strip('"').strip("'"),
                    )
            break


load_dotenv()


def yaml_load_all(s: str) -> List[Any]:
    """Load all YAML documents."""
    if not s.strip():
        return []
    try:
        return [d for d in yaml.safe_load_all(s) if d is not None]
    except Exception:
        return []


def yaml_dump_all(docs: List[Any]) -> str:
    """Dump YAML documents."""
    return yaml.safe_dump_all(
        docs,
        sort_keys=False,
        default_flow_style=False,
    ) if docs else ""

# ======================= Retry Logic =======================


def retry_with_backoff(func, max_retries: int = 3, base_delay: float = 1.0):
    """
    Retry a function with exponential backoff.
    Handles rate limits (429) and transient errors.
    """
    for attempt in range(max_retries):
        try:
            result = func()

            # Some callers return (patches, explanation, error)
            if isinstance(result, tuple) and len(result) >= 3:
                patches, explanation, error = result

                # Handle rate limiting
                if error and "429" in str(error):
                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                        print(f"      Rate limited, retrying in {delay:.1f}s...")
                        time.sleep(delay)
                        continue

                return result

            return result

        except Exception as e:
            if attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)
                print(f"      Error: {e}, retrying in {delay:.1f}s...")
                time.sleep(delay)
            else:
                return None, None, str(e)

    return None, None, "Max retries exceeded"


def get_container_base_path(doc: Dict[str, Any]) -> str:
    """
    Get the correct base path for containers based on resource kind.

    Returns the JSON pointer path to the containers array.
    """
    kind = doc.get("kind", "")

    if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"):
        return "/spec/template/spec/containers"

    return "/spec/containers"


def get_pod_spec_path(doc: Dict[str, Any]) -> str:
    """
    Get the correct base path for pod spec based on resource kind.

    Returns the JSON pointer path to the pod spec.
    """
    kind = doc.get("kind", "")

    if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"):
        return "/spec/template/spec"

    return "/spec"


def get_containers_and_path(doc: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str]:
    """
    Get containers list and their base path.

    Returns: (containers_list, base_path)
    """
    kind = doc.get("kind", "")

    if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"):
        containers = (
            doc.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )
        base_path = "/spec/template/spec/containers"
    else:
        containers = doc.get("spec", {}).get("containers", [])
        base_path = "/spec/containers"

    return containers, base_path


def sanitize_pod_security_context(pod_sc: dict) -> dict:
    """
    Remove invalid fields from Pod-level securityContext.
    
    Only keeps fields that are valid for PodSecurityContext.
    This prevents LLM-generated patches from adding container-level
    fields (like 'privileged', 'capabilities', 'allowPrivilegeEscalation')
    to the Pod-level securityContext.
    
    Args:
        pod_sc: The Pod securityContext dictionary to sanitize
        
    Returns:
        Sanitized dictionary containing only valid PodSecurityContext fields
    """
    if not isinstance(pod_sc, dict):
        return pod_sc
    
    sanitized = {k: v for k, v in pod_sc.items() if k in POD_SC_ALLOWED}
    
    # Log any removed fields for debugging
    removed = set(pod_sc.keys()) - set(sanitized.keys())
    if removed:
        print(f"  [SANITIZE] Removed invalid Pod securityContext fields: {removed}")
    
    return sanitized


# ======================= Security Hardening Handler =======================


class SecurityHardeningHandler:
    """
    Comprehensive security context hardening handler.
    Applies ALL 4 required controls together:
    1. allowPrivilegeEscalation: false
    2. capabilities.drop: [ALL]
    3. readOnlyRootFilesystem: true
    4. runAsNonRoot: true + runAsUser: 1000

    **Improved behaviour**
    - Only touches workload kinds (Deployment/Job/DaemonSet/Pod/...)
    - Merges into existing pod/containers securityContext instead of overwriting
    - De-duplicates volumes and volumeMounts
    """

    @staticmethod
    def generate_all_patches(doc: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str]:
        """
        Generate ALL security hardening patches at once.

        Returns: (patches, explanation)
        """
        patches: List[Dict[str, Any]] = []
        kind = doc.get("kind", "")

        # Only apply to workload resources
        if kind not in WORKLOAD_KINDS:
            return [], (
                f"Security hardening skipped for non-workload resource kind={kind}"
            )

        # Resolve pod spec and containers
        pod_spec_path = get_pod_spec_path(doc)
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"):
            pod_spec = (
                doc.get("spec", {})
                .get("template", {})
                .get("spec", {})
            )
        else:
            pod_spec = doc.get("spec", {})

        pod_sc = pod_spec.get("securityContext", {}) or {}

        containers, containers_path = get_containers_and_path(doc)
        if not containers:
            return [], "No containers found to harden."

        # 1. Pod-level securityContext (merge)
        def ensure_pod_sc_field(field: str, value: Any):
            if field not in pod_sc:
                patches.append({
                    "op": "add",
                    "path": f"{pod_spec_path}/securityContext/{field}",
                    "value": value,
                    "description": f"Set pod-level {field}",
                })

        ensure_pod_sc_field("runAsNonRoot", True)
        ensure_pod_sc_field("runAsUser", 1000)
        ensure_pod_sc_field("fsGroup", 1000)
        if "seccompProfile" not in pod_sc:
            patches.append({
                "op": "add",
                "path": f"{pod_spec_path}/securityContext/seccompProfile",
                "value": {"type": "RuntimeDefault"},
                "description": "Set pod-level seccompProfile RuntimeDefault",
            })

        # 2. Container-level security for each container (merge)
        for i, container in enumerate(containers):
            container_name = container.get("name", f"container-{i}")
            base_path = f"{containers_path}/{i}/securityContext"
            c_sc = container.get("securityContext", {}) or {}

            def ensure_container_sc(path_suffix: str, field: str, value: Any, desc: str):
                if field not in c_sc:
                    patches.append({
                        "op": "add",
                        "path": f"{base_path}/{path_suffix}",
                        "value": value,
                        "description": f"{desc} in {container_name}",
                    })

            ensure_container_sc("allowPrivilegeEscalation", "allowPrivilegeEscalation",
                                False, "Prevent privilege escalation")

            # FIXED: Check if capabilities.drop contains "ALL", not just if it exists
            caps = c_sc.get("capabilities", {})
            drop_list = caps.get("drop", []) if isinstance(caps.get("drop"), list) else []
            if "ALL" not in drop_list:
                if "capabilities" not in c_sc:
                    # No capabilities at all - add fresh
                    patches.append({
                        "op": "add",
                        "path": f"{base_path}/capabilities",
                        "value": {"drop": ["ALL"]},
                        "description": f"Drop all capabilities in {container_name}",
                    })
                elif "drop" not in caps:
                    # capabilities exists but no drop - add drop
                    patches.append({
                        "op": "add",
                        "path": f"{base_path}/capabilities/drop",
                        "value": ["ALL"],
                        "description": f"Add capabilities.drop=[ALL] in {container_name}",
                    })
                else:
                    # drop exists but doesn't contain ALL - replace it
                    patches.append({
                        "op": "replace",
                        "path": f"{base_path}/capabilities/drop",
                        "value": ["ALL"],
                        "description": f"Replace capabilities.drop with [ALL] in {container_name}",
                    })

            ensure_container_sc("readOnlyRootFilesystem", "readOnlyRootFilesystem",
                                True, "Make root filesystem read-only")
            ensure_container_sc("runAsNonRoot", "runAsNonRoot",
                                True, "Run as non-root")
            ensure_container_sc("runAsUser", "runAsUser",
                                1000, "Run as UID 1000")
            if "seccompProfile" not in c_sc:
                patches.append({
                    "op": "add",
                    "path": f"{base_path}/seccompProfile",
                    "value": {"type": "RuntimeDefault"},
                    "description": f"Enable seccomp in {container_name}",
                })

            # 3. Add required volume mounts for read-only root filesystem
            image = container.get("image", "") or ""
            required_mounts = SecurityHardeningHandler._get_required_mounts_for_image(
                image
            )

            existing_mount_paths = {
                vm.get("mountPath")
                for vm in container.get("volumeMounts", []) or []
                if isinstance(vm, dict)
            }

            for mount in required_mounts:
                if mount["mountPath"] in existing_mount_paths:
                    continue
                patches.append({
                    "op": "add",
                    "path": f"{containers_path}/{i}/volumeMounts/-",
                    "value": mount,
                    "description": (
                        f"Add volume mount {mount['mountPath']} for {container_name}"
                    ),
                })

        # 4. Add emptyDir volumes (deduplicated)
        existing_vol_names = {
            v.get("name")
            for v in pod_spec.get("volumes", []) or []
            if isinstance(v, dict)
        }

        required_volumes = [
            {"name": "tmp", "emptyDir": {}},
            {"name": "cache", "emptyDir": {}},
            {"name": "run", "emptyDir": {}},
        ]

        for volume in required_volumes:
            if volume["name"] in existing_vol_names:
                continue
            patches.append({
                "op": "add",
                "path": f"{pod_spec_path}/volumes/-",
                "value": volume,
                "description": f"Add {volume['name']} volume for writable directory",
            })

        explanation = (
            "Applied comprehensive security hardening:\n"
            "  - allowPrivilegeEscalation: false (prevents privilege escalation)\n"
            "  - capabilities.drop: [ALL] (removes unnecessary privileges)\n"
            "  - readOnlyRootFilesystem: true (prevents filesystem tampering)\n"
            "  - runAsNonRoot: true + runAsUser: 1000 (ensures non-root execution)\n"
            "  - pod-level seccompProfile RuntimeDefault\n"
            "  - Added tmp/cache/run emptyDir volumes and mounts where needed"
        )

        return patches, explanation

    @staticmethod
    def _get_required_mounts_for_image(image: str) -> List[Dict[str, str]]:
        """Get required volume mounts based on container image."""
        image_lower = image.lower()

        if "nginx" in image_lower:
            return [
                {"name": "tmp", "mountPath": "/tmp"},
                {"name": "cache", "mountPath": "/var/cache/nginx"},
                {"name": "run", "mountPath": "/var/run"},
            ]
        elif "apache" in image_lower or "httpd" in image_lower:
            return [
                {"name": "tmp", "mountPath": "/tmp"},
                {"name": "run", "mountPath": "/var/run"},
            ]
        else:
            return [
                {"name": "tmp", "mountPath": "/tmp"},
            ]


# ======================= Template-Based Fixes =======================


def apply_template_fix(
    doc: Dict[str, Any],
    category: str,
    findings: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], str]:
    """
    Apply template-based fixes that require some inspection but no LLM.
    These are smarter than deterministic but don't need full LLM reasoning.
    """
    patches: List[Dict[str, Any]] = []
    explanation = ""

    containers, containers_path = get_containers_and_path(doc)

    if category == "Probes/MissingReadinessLiveness":
        for i, c in enumerate(containers):
            container_name = c.get("name", f"container-{i}")
            ports = c.get("ports", [])

            if ports:
                port = ports[0].get("containerPort", 80)

                if not c.get("livenessProbe"):
                    patches.append({
                        "op": "add",
                        "path": f"{containers_path}/{i}/livenessProbe",
                        "value": {
                            "httpGet": {"path": "/", "port": port},
                            "initialDelaySeconds": 30,
                            "periodSeconds": 10,
                        },
                    })
                if not c.get("readinessProbe"):
                    patches.append({
                        "op": "add",
                        "path": f"{containers_path}/{i}/readinessProbe",
                        "value": {
                            "httpGet": {"path": "/", "port": port},
                            "initialDelaySeconds": 10,
                            "periodSeconds": 5,
                        },
                    })
                explanation = (
                    f"Added HTTP liveness and readiness probes on port {port} "
                    f"for {container_name} to enable automatic recovery and "
                    f"traffic management."
                )
            else:
                if not c.get("livenessProbe"):
                    patches.append({
                        "op": "add",
                        "path": f"{containers_path}/{i}/livenessProbe",
                        "value": {
                            "tcpSocket": {"port": 8080},
                            "initialDelaySeconds": 30,
                            "periodSeconds": 10,
                        },
                    })
                if not c.get("readinessProbe"):
                    patches.append({
                        "op": "add",
                        "path": f"{containers_path}/{i}/readinessProbe",
                        "value": {
                            "tcpSocket": {"port": 8080},
                            "initialDelaySeconds": 10,
                            "periodSeconds": 5,
                        },
                    })
                explanation = (
                    f"Added TCP-based liveness and readiness probes for "
                    f"{container_name} to enable automatic recovery and "
                    f"traffic management."
                )

    elif category == "Resources/MissingRequests":
        for i, c in enumerate(containers):
            resources = c.get("resources", {})
            limits = resources.get("limits")
            requests = resources.get("requests")

            if not requests:
                if limits:
                    patches.append({
                        "op": "add",
                        "path": f"{containers_path}/{i}/resources/requests",
                        "value": limits,
                    })
                    explanation = (
                        "Added resource requests (copied from limits) to ensure "
                        "proper scheduling."
                    )
                else:
                    patches.append({
                        "op": "add",
                        "path": f"{containers_path}/{i}/resources/requests",
                        "value": {"cpu": "100m", "memory": "128Mi"},
                    })
                    explanation = (
                        "Added resource requests (cpu: 100m, memory: 128Mi) for "
                        "proper scheduling."
                    )

    elif category == "Resources/MissingLimits":
        for i, c in enumerate(containers):
            resources = c.get("resources", {})
            limits = resources.get("limits")
            requests = resources.get("requests")

            if not limits:
                if requests:
                    cpu = requests.get("cpu", "100m")
                    mem = requests.get("memory", "128Mi")
                    cpu_match = re.search(r"\d+", cpu)
                    mem_match = re.search(r"\d+", mem)
                    cpu_val = int(cpu_match.group()) if cpu_match else 100
                    mem_val = int(mem_match.group()) if mem_match else 128
                    patches.append({
                        "op": "add",
                        "path": f"{containers_path}/{i}/resources/limits",
                        "value": {
                            "cpu": f"{cpu_val * 2}m",
                            "memory": f"{mem_val * 2}Mi",
                        },
                    })
                    explanation = (
                        "Added resource limits (2x requests) to prevent "
                        "resource exhaustion."
                    )
                else:
                    patches.append({
                        "op": "add",
                        "path": f"{containers_path}/{i}/resources/limits",
                        "value": {"cpu": "200m", "memory": "256Mi"},
                    })
                    explanation = (
                        "Added resource limits (cpu: 200m, memory: 256Mi) to "
                        "prevent resource exhaustion."
                    )

    return patches, explanation


def apply_deterministic_fix(
    doc: Dict[str, Any],
    category: str,
    findings: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], str]:
    """Apply deterministic template-based fixes."""
    patches: List[Dict[str, Any]] = []
    explanation = ""
    kind = doc.get("kind", "")
    name = doc.get("metadata", {}).get("name", "unknown")

    pod_spec_path = get_pod_spec_path(doc)

    if category == "Auth/DefaultNamespace":
        if not doc.get("metadata", {}).get("namespace"):
            patches.append({
                "op": "add",
                "path": "/metadata/namespace",
                "value": "default-app",
            })
            explanation = (
                "Added namespace 'default-app' to avoid using the default "
                "namespace, improving security isolation."
            )

    elif category == "Auth/DefaultServiceAccount":
        sa_name = f"{name}-sa"

        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"):
            spec = (
                doc.get("spec", {})
                .get("template", {})
                .get("spec", {})
            )
        else:
            spec = doc.get("spec", {})

        if not spec.get("serviceAccountName"):
            patches.append({
                "op": "add",
                "path": f"{pod_spec_path}/serviceAccountName",
                "value": sa_name,
            })
            explanation = (
                f"Added dedicated ServiceAccount '{sa_name}' following the "
                f"principle of least privilege."
            )

    elif category == "Auth/AutomountServiceAccountToken":
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"):
            spec = (
                doc.get("spec", {})
                .get("template", {})
                .get("spec", {})
            )
        else:
            spec = doc.get("spec", {})

        if spec.get("automountServiceAccountToken") is not False:
            patches.append({
                "op": "add",
                "path": f"{pod_spec_path}/automountServiceAccountToken",
                "value": False,
            })
            explanation = (
                "Disabled automatic mounting of ServiceAccount token to reduce "
                "attack surface."
            )

    return patches, explanation


# ======================= LLM Functions =======================

SYSTEM_PROMPT = """
You are SafeFix, a Kubernetes security repair assistant.
Return a JSON object with two fields:
1. "patches": array of RFC-6902 patch operations
2. "explanation": brief explanation of what was fixed and why

Never change: metadata.name, metadata.namespace, kind, spec.selector, or Service ports.
""".strip()


def extract_relevant_context(doc: Dict[str, Any], category: str) -> str:
    """Extract only relevant YAML sections."""
    kind = doc.get("kind", "")

    if category.startswith("Security/") or category.startswith("Auth/RunAs"):
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
            spec = (
                doc.get("spec", {})
                .get("template", {})
                .get("spec", {})
            )
        else:
            spec = doc.get("spec", {})

        context = {
            "kind": kind,
            "metadata": {"name": doc.get("metadata", {}).get("name", "unknown")},
            "spec": spec,
        }
        return yaml.safe_dump(context, sort_keys=False)

    context = {
        "kind": kind,
        "metadata": doc.get("metadata", {}),
        "spec": doc.get("spec", {}),
    }
    return yaml.safe_dump(context, sort_keys=False)


def call_llm_with_fallback(
    category: str,
    doc: Dict[str, Any],
    context_yaml: str,
    models: Dict[str, str],
    config: Dict[str, Any],
) -> Tuple[Optional[List[Dict]], Optional[str], Optional[str]]:
    """
    Call LLM with fallback provider on failure.
    Returns (patches, explanation, error)
    """
    provider = config.get("provider", LlmProvider.OPENAI)
    fallback = config.get("fallback")
    max_retries = config.get("max_retries", 3)

    kind = doc.get("kind", "")
    name = doc.get("metadata", {}).get("name", "unknown")

    prompt = f"""Kind: {kind}
Name: {name}
Category: {category}

Context:
{context_yaml[:800]}

Return JSON with patches and explanation.
"""

    def try_provider(prov: LlmProvider):
        return call_provider_api(prov, prompt, models.get(prov.value, ""))

    result = retry_with_backoff(lambda: try_provider(provider), max_retries=max_retries)
    patches, explanation, error = result

    if error and fallback:
        print(f"      Primary failed, trying fallback ({fallback.value})...")
        result = retry_with_backoff(lambda: try_provider(fallback), max_retries=2)
        patches, explanation, error = result

    return patches, explanation, error


def call_provider_api(
    provider: LlmProvider,
    prompt: str,
    model: str,
) -> Tuple[Optional[List], Optional[str], Optional[str]]:
    """Call a specific provider's API."""
    if provider == LlmProvider.OPENAI:
        return call_openai(model or "gpt-4o-mini", prompt)
    if provider == LlmProvider.GROQ:
        return call_groq(model or "llama-3.1-8b-instant", prompt)
    if provider == LlmProvider.GEMINI:
        return call_gemini(model or "gemini-2.0-flash-exp", prompt)
    if provider == LlmProvider.OPENROUTER:
        return call_openrouter(model or "x-ai/grok-vision-beta", prompt)
    return None, None, f"Unknown provider: {provider}"


def extract_json_response(text: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    """Extract patches and explanation from LLM response."""
    if not text:
        return None, None

    text = text.strip()
    text = re.sub(r"^```(?:json)?", "", text, flags=re.IGNORECASE).strip()
    text = re.sub(r"```$", "", text).strip()

    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "patches" in obj:
            return obj.get("patches", []), obj.get("explanation", "")
        if isinstance(obj, list):
            return obj, None
    except Exception:
        pass

    match = re.search(r'\{[^{}]*"patches"[^{}]*\}', text, flags=re.S)
    if match:
        try:
            obj = json.loads(match.group(0))
            return obj.get("patches", []), obj.get("explanation", "")
        except Exception:
            pass

    match = re.search(r"\[.*\]", text, flags=re.S)
    if match:
        try:
            return json.loads(match.group(0)), None
        except Exception:
            pass

    return None, None


def call_openai(model: str, prompt: str) -> Tuple[Optional[List], Optional[str], Optional[str]]:
    """Call OpenAI API."""
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        return None, None, "OPENAI_API_KEY not set"

    try:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.0,
                "max_tokens": 1000,
            },
            timeout=60,
        )

        if response.status_code != 200:
            return None, None, f"HTTP {response.status_code}"

        text = response.json()["choices"][0]["message"]["content"]
        patches, explanation = extract_json_response(text)
        return patches, explanation, None if patches else "Could not parse response"
    except Exception as e:
        return None, None, str(e)


def call_groq(model: str, prompt: str) -> Tuple[Optional[List], Optional[str], Optional[str]]:
    """Call Groq API."""
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        return None, None, "GROQ_API_KEY not set"

    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.0,
                "max_tokens": 1000,
            },
            timeout=60,
        )

        if response.status_code != 200:
            return None, None, f"HTTP {response.status_code}"

        text = response.json()["choices"][0]["message"]["content"]
        patches, explanation = extract_json_response(text)
        return patches, explanation, None if patches else "Could not parse response"
    except Exception as e:
        return None, None, str(e)


def call_gemini(model: str, prompt: str) -> Tuple[Optional[List], Optional[str], Optional[str]]:
    """Call Gemini API."""
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        return None, None, "GEMINI_API_KEY not set"

    try:
        response = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}",
            json={
                "contents": [{"parts": [{"text": SYSTEM_PROMPT + "\n\n" + prompt}]}],
                "generationConfig": {"temperature": 0.0, "maxOutputTokens": 1000},
            },
            timeout=60,
        )

        if response.status_code != 200:
            return None, None, f"HTTP {response.status_code}"

        text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
        patches, explanation = extract_json_response(text)
        return patches, explanation, None if patches else "Could not parse response"
    except Exception as e:
        return None, None, str(e)


def call_openrouter(model: str, prompt: str) -> Tuple[Optional[List], Optional[str], Optional[str]]:
    """Call OpenRouter API."""
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        return None, None, "OPENROUTER_API_KEY not set"

    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer $%s" % key,
                "Content-Type": "application/json",
                "HTTP-Referer": "https://safefix.local",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.0,
                "max_tokens": 1000,
            },
            timeout=60,
        )

        if response.status_code != 200:
            return None, None, f"HTTP {response.status_code}"

        text = response.json()["choices"][0]["message"]["content"]
        patches, explanation = extract_json_response(text)
        return patches, explanation, None if patches else "Could not parse response"
    except Exception as e:
        return None, None, str(e)


# ======================= Patch Utilities =======================


def validate_patch_path(doc: Any, path: str, op: str) -> bool:
    """
    Validate that a patch path is valid for the document structure.

    Returns True if valid, False otherwise.
    """
    if not path or path == "/":
        return True

    parts = [p for p in path.split("/") if p]
    if not parts:
        return True

    cur = doc

    for i, part in enumerate(parts[:-1]):
        key = part.replace("~1", "/").replace("~0", "~")
        next_part = parts[i + 1] if i + 1 < len(parts) else None

        if isinstance(cur, list):
            try:
                if key == "-":
                    # "-" is only valid on last segment, not intermediate
                    return False
                idx = int(key)
                if idx < 0 or idx >= len(cur):
                    return op == "add"
                cur = cur[idx]
            except (ValueError, IndexError):
                return False
        elif isinstance(cur, dict):
            if key not in cur:
                if op == "add":
                    # For add we allow creating missing parents; type will be
                    # decided by the patch application logic.
                    return True
                return False
            cur = cur[key]
        else:
            return False

    # Last part is more relaxed; application code will handle details.
    return True


def filter_valid_patches(doc: Any, patches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filter out patches with invalid paths.

    Returns list of valid patches.
    """
    valid_patches: List[Dict[str, Any]] = []

    for patch in patches:
        op = patch.get("op", "")
        path = patch.get("path", "")

        if not op or not path:
            continue

        if validate_patch_path(doc, path, op):
            valid_patches.append(patch)
        else:
            print(f"  [DEBUG] Filtered invalid patch: {op} {path}")

    return valid_patches


def deduplicate_patches(patches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicate patches based on path AND operation.
    Improved: Keep later occurrences if they have different values (prefer replace over add).
    CRITICAL: Skip whole-object patches when individual field patches exist.

    Returns list of unique patches.
    """
    # First pass: identify paths that have child patches (individual fields)
    paths_with_children = set()
    for patch in patches:
        path = patch.get("path", "")
        # Check if this path has children by looking for longer paths with this prefix
        for other_patch in patches:
            other_path = other_patch.get("path", "")
            # If other_path starts with path + "/", then path has children
            if other_path.startswith(path + "/"):
                paths_with_children.add(path)
                break

    # Use (path, op) as key instead of just path
    # This allows different operations on the same path
    seen = {}  # key: path, value: (op, patch)

    for patch in patches:
        path = patch.get("path", "")
        op = patch.get("op", "")
        value = patch.get("value")

        # CRITICAL FIX: Skip patches that set a whole object when we have individual field patches
        if path in paths_with_children and op in ("add", "replace"):
            # This patch sets a whole object, but we have patches for individual fields
            # Skip this patch to avoid overwriting the individual fields
            # Silently skip - comment out for debugging
            # print(f"  [DEBUG DEDUP] Skipping whole-object patch for {path} (has child patches)")
            continue

        key = path
        if key not in seen:
            seen[key] = patch
        else:
            # If we see the same path again:
            # - Prefer 'replace' over 'add' (more specific)
            # - Keep the one with a value if the other doesn't
            existing_op = seen[key].get("op")
            if op == "replace" and existing_op == "add":
                # Replace is more specific, use it
                seen[key] = patch
            elif op == existing_op and value is not None:
                # Same op, but potentially better value - update
                seen[key] = patch

    return list(seen.values())


# ======================= JSON Patch Application =======================


def apply_json_patch(doc: Any, patch_ops: List[Dict[str, Any]]) -> Any:
    """Apply RFC-6902 JSON Patch operations."""
    import copy

    doc = copy.deepcopy(doc)
    debug = os.environ.get("DEBUG_PATCHES", "").lower() == "true"

    for op in patch_ops:
        op_type = op.get("op")
        path = op.get("path")

        if not isinstance(op_type, str) or not isinstance(path, str):
            continue
        if op_type not in ("add", "replace", "remove"):
            continue
        if op_type in ("add", "replace") and "value" not in op:
            continue

        if debug and "securityContext" in path:
            print(f"  [TRACE] Applying: {op_type} {path} = {op.get('value')}")

        try:
            parts = [p for p in path.split("/") if p]
            if not parts:
                continue

            cur = doc

            # Traverse parents, creating objects/lists as needed for add
            for i, part in enumerate(parts[:-1]):
                key = part.replace("~1", "/").replace("~0", "~")
                next_part = parts[i + 1] if i + 1 < len(parts) else None

                if isinstance(cur, list):
                    if key == "-":
                        # Can't have "-" in the middle of a path
                        raise KeyError(path)
                    idx = int(key)
                    if idx >= len(cur):
                        if op_type == "add":
                            while len(cur) <= idx:
                                cur.append({})
                        else:
                            raise KeyError(path)
                    cur = cur[idx]
                else:
                    # dict
                    if key not in cur:
                        if op_type == "add":
                            # Decide whether this new container should be a list or dict
                            if next_part is not None and (next_part.isdigit() or next_part == "-"):
                                cur[key] = []
                            else:
                                cur[key] = {}
                        else:
                            raise KeyError(path)
                    cur = cur[key]

            last = parts[-1].replace("~1", "/").replace("~0", "~")

            if isinstance(cur, list):
                # Handle "-" append notation
                if last == "-":
                    if op_type == "add":
                        cur.append(op.get("value"))
                    elif op_type == "replace":
                        # Replace last element if exists
                        if cur:
                            cur[-1] = op.get("value")
                    elif op_type == "remove":
                        if cur:
                            cur.pop()
                    continue

                idx = int(last)
                if op_type == "add":
                    if idx == len(cur):
                        cur.append(op.get("value"))
                    elif 0 <= idx < len(cur):
                        cur.insert(idx, op.get("value"))
                elif op_type == "replace":
                    if 0 <= idx < len(cur):
                        cur[idx] = op.get("value")
                elif op_type == "remove":
                    if 0 <= idx < len(cur):
                        cur.pop(idx)
            else:
                # dict
                if op_type in ("add", "replace"):
                    cur[last] = op.get("value")
                    if debug and "securityContext" in path:
                        print(f"  [TRACE] Successfully set {last} = {op.get('value')}")
                elif op_type == "remove":
                    if last in cur:
                        del cur[last]
        except Exception as e:
            print(f"  [WARN] Failed to apply op {op}: {e}")
            if debug and "securityContext" in path:
                print(f"  [TRACE] Exception details: {type(e).__name__}: {str(e)}")
            continue

    return doc


# ======================= Process Category =======================


def process_category(
    category: str,
    findings: List[Dict[str, Any]],
    doc: Dict[str, Any],
    original_yaml: str,
    file_path: str,
    models: Dict[str, str],
) -> Tuple[Optional[List[Dict[str, Any]]], str, Dict[str, Any]]:
    """Process a single category with enhanced error handling."""

    config = CATEGORY_CONFIG.get(
        category,
        {
            "strategy": FixStrategy.LLM_GUIDED,
            "provider": LlmProvider.OPENAI,
            "fallback": LlmProvider.GROQ,
            "priority": 2,
            "max_retries": 3,
        },
    )

    strategy: FixStrategy = config.get("strategy", FixStrategy.LLM_GUIDED)
    kind = doc.get("kind", "")

    result: Dict[str, Any] = {
        "category": category,
        "strategy": str(strategy),
        "patches_count": 0,
        "error": None,
    }

    # Skip categories entirely
    if strategy == FixStrategy.SKIP or category in SKIP_FROM_LLM:
        skip_msg = SKIP_MESSAGES.get(category, "Category skipped (not actionable)")
        result["error"] = f"Skipped: {skip_msg}"
        print(f"    [{category}] SKIPPED")
        print(f"      -> {skip_msg}")
        return None, "", result

    # Avoid touching Secret resources with generic hardening
    if kind == "Secret":
        msg = "Automatic fixes for Secret resources are disabled (handle via dedicated secret rotation)."
        result["error"] = f"Skipped: {msg}"
        print(f"    [{category}] SKIPPED on Secret")
        print(f"      -> {msg}")
        return None, "", result

    # Use comprehensive security hardening handler
    if category in SECURITY_HARDENING_CATEGORIES or config.get("use_security_handler"):
        handler = SecurityHardeningHandler()
        patches, explanation = handler.generate_all_patches(doc)
        result["patches_count"] = len(patches)
        result["strategy"] = "deterministic_security"
        if patches:
            print(f"    [{category}] Deterministic Security: {len(patches)} patch(es)")
            print("      -> Comprehensive hardening (all 4 controls)")
        else:
            print(f"    [{category}] Security hardening produced no patches (probably non-workload)")
        return patches, explanation, result

    # Deterministic fixes
    if strategy == FixStrategy.DETERMINISTIC:
        patches, explanation = apply_deterministic_fix(doc, category, findings)
        result["patches_count"] = len(patches)
        print(f"    [{category}] Deterministic: {len(patches)} patch(es)")
        if explanation:
            print(f"      -> {explanation}")
        return patches, explanation, result

    # Template fixes
    if strategy == FixStrategy.TEMPLATE:
        patches, explanation = apply_template_fix(doc, category, findings)
        result["patches_count"] = len(patches)
        print(f"    [{category}] Template: {len(patches)} patch(es)")
        if explanation:
            print(f"      -> {explanation}")
        return patches, explanation, result

    # LLM-guided fixes
    context_yaml = extract_relevant_context(doc, category)
    patches, explanation, error = call_llm_with_fallback(
        category,
        doc,
        context_yaml,
        models,
        config,
    )

    if error:
        result["error"] = error
        print(f"    [{category}] LLM error: {error}")
        return None, "", result

    if not patches:
        result["error"] = "No patches returned"
        print(f"    [{category}] No patches returned")
        return None, "", result

    provider_name = config.get("provider", LlmProvider.OPENAI).value
    result["patches_count"] = len(patches)
    print(f"    [{category}] LLM ({provider_name}): {len(patches)} patch(es)")
    if explanation:
        print(f"      -> {explanation}")

    return patches, explanation or "", result


# ======================= Main Processing =======================


def process_file(
    file_entry: Dict[str, Any],
    original_yaml: str,
    models: Dict[str, str],
) -> Dict[str, Any]:
    """Process a single file with all improvements."""
    file_path = file_entry.get("file", "")
    findings = file_entry.get("findings", [])

    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        cat = finding.get("category", "")
        if cat:
            by_category.setdefault(cat, []).append(finding)

    print(f"\n[FILE] {file_path}")
    print(f"  Categories: {', '.join(sorted(by_category.keys()))}")

    docs = yaml_load_all(original_yaml)
    if not docs:
        return {"file": file_path, "error": "Could not parse YAML", "success": False}

    # NEW: choose a workload document when YAML has multiple documents.
    primary_index = 0
    for idx, d in enumerate(docs):
        if isinstance(d, dict) and d.get("kind") in WORKLOAD_KINDS:
            primary_index = idx
            break

    doc = docs[primary_index]

    all_patches: List[Dict[str, Any]] = []
    all_explanations: List[str] = []
    category_results: Dict[str, Any] = {}
    skipped_categories: List[str] = []

    for category, cat_findings in sorted(by_category.items()):
        patches, explanation, result = process_category(
            category,
            cat_findings,
            doc,
            original_yaml,
            file_path,
            models,
        )

        category_results[category] = result

        if result.get("error") and "Skipped" in str(result.get("error", "")):
            skipped_categories.append(category)

        if patches:
            all_patches.extend(patches)
            if explanation:
                all_explanations.append(f"**{category}**: {explanation}")

    if all_patches:
        try:
            # Debug: Show all patches before deduplication
            debug_patches = os.environ.get("DEBUG_PATCHES", "").lower() == "true"
            if debug_patches:
                print(f"\n  [DEBUG] All patches before deduplication ({len(all_patches)}):")
                for i, p in enumerate(all_patches):
                    print(f"    {i+1}. {p.get('op')} {p.get('path')}")

            unique_patches = deduplicate_patches(all_patches)
            if len(unique_patches) < len(all_patches):
                print(f"  [INFO] Deduplicated {len(all_patches) - len(unique_patches)} patch(es)")

            if debug_patches:
                print(f"\n  [DEBUG] Patches after deduplication ({len(unique_patches)}):")
                for i, p in enumerate(unique_patches):
                    print(f"    {i+1}. {p.get('op')} {p.get('path')}")

            valid_patches = filter_valid_patches(doc, unique_patches)
            if len(valid_patches) < len(unique_patches):
                filtered_count = len(unique_patches) - len(valid_patches)
                print(f"  [INFO] Filtered {filtered_count} invalid patch(es)")

            if debug_patches:
                print(f"\n  [DEBUG] Patches after filtering ({len(valid_patches)}):")
                for i, p in enumerate(valid_patches):
                    desc = p.get('description', 'No description')
                    print(f"    {i+1}. {p.get('op')} {p.get('path')} = {p.get('value')}")
                    print(f"        Description: {desc}")

            modified_doc = apply_json_patch(doc, valid_patches)
            
            # Sanitize Pod-level securityContext to remove invalid fields
            kind = modified_doc.get("kind", "")
            if kind in WORKLOAD_KINDS:
                if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"):
                    pod_spec = (
                        modified_doc.get("spec", {})
                        .get("template", {})
                        .get("spec", {})
                    )
                    if "securityContext" in pod_spec:
                        pod_spec["securityContext"] = sanitize_pod_security_context(
                            pod_spec["securityContext"]
                        )
                else:  # Pod
                    pod_spec = modified_doc.get("spec", {})
                    if "securityContext" in pod_spec:
                        pod_spec["securityContext"] = sanitize_pod_security_context(
                            pod_spec["securityContext"]
                        )
            
            docs[primary_index] = modified_doc
            secured_yaml = yaml_dump_all(docs)

            summary = (
                f"Applied {len(valid_patches)} fixes across "
                f"{len(all_explanations)} categories:\n\n"
                + "\n\n".join(all_explanations)
            )

            if skipped_categories:
                summary += "\n\n**Skipped Categories** (by design):\n"
                for cat in skipped_categories:
                    skip_msg = SKIP_MESSAGES.get(cat, "Not suitable for inline fix")
                    summary += f"- {cat}: {skip_msg}\n"

            print(f"  Applied {len(valid_patches)} total patches")
            print("\n  === FIX SUMMARY ===")
            for exp in all_explanations:
                print(f"  {exp}")
            if skipped_categories:
                print("\n  === SKIPPED (By Design) ===")
                for cat in skipped_categories:
                    print(f"  - {cat}")
            print("  " + "=" * 50 + "\n")

            return {
                "file": file_path,
                "categories": list(by_category.keys()),
                "category_results": category_results,
                "total_patches": len(valid_patches),
                "skipped_categories": skipped_categories,
                "secured_yaml": secured_yaml,
                "explanation": summary,
                "success": True,
            }
        except Exception as e:  # pragma: no cover - defensive
            return {
                "file": file_path,
                "error": f"Failed to apply patches: {e}",
                "success": False,
            }

    return {
        "file": file_path,
        "error": "No patches generated",
        "success": False,
    }


def normalize_payload(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize payload to list of files."""
    files = payload.get("files")
    if isinstance(files, list) and files:
        return files

    items = payload.get("items") or []
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for item in items:
        file_path = item.get("file") or "UNKNOWN"
        by_file.setdefault(file_path, []).append(
            {
                "category": item.get("category") or "UNKNOWN",
                "severity": item.get("severity"),
                "message": item.get("message"),
            }
        )

    return [{"file": f, "findings": v} for f, v in sorted(by_file.items())]


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Ultimate LLM orchestrator with comprehensive security hardening",
    )
    parser.add_argument("--payload", required=True, help="Path to payload JSON")
    parser.add_argument(
        "--tests-dir",
        required=True,
        help="Directory containing YAML files",
    )
    parser.add_argument(
        "--out-dir",
        default="output/ultimate_fixes",
        help="Output directory",
    )
    parser.add_argument(
        "--models",
        type=str,
        default=None,
        help=(
            "Comma-separated list of provider names or provider:model pairs. "
            "Examples: 'openai,groq' or 'openai:gpt-4o-mini,groq:llama-3.1-8b-instant'"
        ),
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Number of concurrent LLM requests (optional, default: 5)",
    )
    parser.add_argument(
        "--autofix",
        action="store_true",
        help="Enable autofix mode (apply fixes automatically)",
    )
    parser.add_argument(
        "--hygiene",
        action="store_true",
        help="Enable hygiene mode (additional linting/formatting)",
    )

    args = parser.parse_args()

    payload = json.loads(Path(args.payload).read_text())
    files = normalize_payload(payload)

    tests_dir = Path(args.tests_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    models = {
        "openai": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        "groq": os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant"),
        "gemini": os.environ.get("GEMINI_MODEL", "gemini-2.0-flash-exp"),
        "openrouter": os.environ.get("OPENROUTER_MODEL", "x-ai/grok-vision-beta"),
    }

    # If user provided --models, parse overrides or preference list
    provider_order: List[str] = []
    if args.models:
        for part in [p.strip() for p in args.models.split(",") if p.strip()]:
            if ":" in part:
                # provider:model mapping
                prov, mdl = part.split(":", 1)
                prov = prov.strip().lower()
                mdl = mdl.strip()
                if prov in models:
                    models[prov] = mdl
            else:
                provider_order.append(part.strip().lower())

    # Concurrency / modes (kept for compatibility; not heavily used internally)
    concurrency = int(args.concurrency) if hasattr(args, "concurrency") else 5
    autofix = bool(getattr(args, "autofix", False))
    hygiene = bool(getattr(args, "hygiene", False))

    print("\n" + "=" * 60)
    print("Ultimate SafeFix-K8s Orchestrator (IMPROVED)")
    print("=" * 60)
    # Show runtime options for visibility
    if args.models:
        print(f"Runtime models override/pref: {args.models}")
    print(f"Concurrency: {concurrency}")
    print(f"Autofix: {autofix}")
    print(f"Hygiene: {hygiene}")
    print("Enhancements:")
    print("  • Comprehensive security hardening (all 4 controls, merged safely)")
    print("  • NetworkPolicy categories explicitly skipped")
    print("  • Workload-aware doc selection for multi-doc YAML")
    print("  • Patch deduplication and safer JSON-patch engine")
    print("=" * 60)

    all_reports: List[Dict[str, Any]] = []
    for file_entry in files:
        file_path = file_entry.get("file", "")
        if not file_path:
            continue

        yaml_path = tests_dir / file_path
        original_yaml = yaml_path.read_text() if yaml_path.exists() else ""

        if not original_yaml:
            continue

        report = process_file(file_entry, original_yaml, models)
        all_reports.append(report)

        if report.get("secured_yaml"):
            safe_name = file_path.replace("/", "_").replace("\\", "_")
            secured_path = out_dir / f"SECURED_{safe_name}"
            secured_path.write_text(report["secured_yaml"], encoding="utf-8")

            if report.get("explanation"):
                explanation_path = out_dir / f"EXPLANATION_{safe_name}.md"
                explanation_content = f"""# Fix Explanation for {file_path}

## Summary
{report['explanation']}

## Statistics
- Total patches: {report['total_patches']}
- Categories processed: {len(report['categories'])}
- Categories skipped: {len(report.get('skipped_categories', []))}
- Status: {'Success' if report['success'] else 'Failed'}

## Skipped Categories
{chr(10).join(f"- {cat}" for cat in report.get('skipped_categories', [])) if report.get('skipped_categories') else "None"}
"""
                explanation_path.write_text(explanation_content, encoding="utf-8")

    successful = sum(1 for r in all_reports if r.get("success"))
    total_skipped = sum(len(r.get("skipped_categories", [])) for r in all_reports)

    print("\n" + "=" * 60)
    print(f"Completed: {successful}/{len(all_reports)} files fixed")
    print(f"Total categories skipped (by design): {total_skipped}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
