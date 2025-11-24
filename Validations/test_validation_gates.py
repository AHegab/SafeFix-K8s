#!/usr/bin/env python3
"""
Comprehensive unit tests for validation_gates_improved.py
"""

import json
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Any

import yaml

# Import from the improved validation module
from validation_gates_improved import (
    ValidationConfig,
    ValidationFinding,
    ValidationResult,
    Severity,
    CategoryValidator,
    load_yaml,
    dump_yaml,
    autofix_schema_one,
    autofix_schema_all,
    get_pod_spec,
    iter_containers,
    iter_effective_security_contexts,
    check_dangerous,
    validate_category,
    analyze_diff,
)


class TestYAMLUtilities(unittest.TestCase):
    """Test YAML loading and dumping functions."""

    def test_load_yaml_single_doc(self):
        """Test loading a single YAML document."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("apiVersion: v1\nkind: Pod\nmetadata:\n  name: test")
            temp_path = Path(f.name)

        try:
            docs = load_yaml(temp_path)
            self.assertEqual(len(docs), 1)
            self.assertEqual(docs[0]['kind'], 'Pod')
        finally:
            temp_path.unlink()

    def test_load_yaml_multi_doc(self):
        """Test loading multiple YAML documents."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod1\n---\n")
            f.write("apiVersion: v1\nkind: Service\nmetadata:\n  name: svc1")
            temp_path = Path(f.name)

        try:
            docs = load_yaml(temp_path)
            self.assertEqual(len(docs), 2)
            self.assertEqual(docs[0]['kind'], 'Pod')
            self.assertEqual(docs[1]['kind'], 'Service')
        finally:
            temp_path.unlink()

    def test_load_yaml_invalid(self):
        """Test loading invalid YAML raises error."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: content: [")
            temp_path = Path(f.name)

        try:
            with self.assertRaises(RuntimeError):
                load_yaml(temp_path)
        finally:
            temp_path.unlink()

    def test_dump_yaml(self):
        """Test dumping YAML documents."""
        docs = [
            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "test"}},
            {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "svc"}}
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            temp_path = Path(f.name)

        try:
            dump_yaml(temp_path, docs)
            loaded = load_yaml(temp_path)
            self.assertEqual(len(loaded), 2)
            self.assertEqual(loaded[0]['kind'], 'Pod')
        finally:
            temp_path.unlink()


class TestSchemaAutoFix(unittest.TestCase):
    """Test schema auto-fix functionality."""

    def test_autofix_missing_metadata_name(self):
        """Test auto-fixing missing metadata.name."""
        doc = {"apiVersion": "v1", "kind": "Pod", "spec": {}}
        fixed, changes = autofix_schema_one(doc)

        self.assertIn("metadata", fixed)
        self.assertEqual(fixed["metadata"]["name"], "autofixed")
        self.assertTrue(any("metadata.name" in c for c in changes))

    def test_autofix_deployment_selector(self):
        """Test auto-fixing Deployment selector."""
        doc = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "test"},
            "spec": {
                "template": {
                    "metadata": {"labels": {"app": "myapp"}},
                    "spec": {"containers": []}
                }
            }
        }

        fixed, changes = autofix_schema_one(doc)

        self.assertIn("selector", fixed["spec"])
        self.assertEqual(fixed["spec"]["selector"]["matchLabels"], {"app": "myapp"})
        self.assertTrue(any("selector" in c for c in changes))

    def test_autofix_restart_policy(self):
        """Test auto-fixing missing restartPolicy."""
        doc = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "test"},
            "spec": {"containers": []}
        }

        fixed, changes = autofix_schema_one(doc)

        self.assertIn("restartPolicy", fixed["spec"])
        self.assertTrue(any("restartPolicy" in c for c in changes))

    def test_autofix_ingress_api_upgrade(self):
        """Test auto-fixing deprecated Ingress API version."""
        doc = {
            "apiVersion": "extensions/v1beta1",
            "kind": "Ingress",
            "metadata": {"name": "test"},
            "spec": {}
        }

        fixed, changes = autofix_schema_one(doc)

        self.assertEqual(fixed["apiVersion"], "networking.k8s.io/v1")
        self.assertIn("ingressClassName", fixed["spec"])
        self.assertTrue(any("apiVersion" in c for c in changes))

    def test_autofix_service_port_type(self):
        """Test auto-fixing Service port type."""
        doc = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "test"},
            "spec": {
                "ports": [{"port": "80", "targetPort": "8080"}]
            }
        }

        fixed, changes = autofix_schema_one(doc)

        self.assertEqual(fixed["spec"]["ports"][0]["port"], 80)
        self.assertIsInstance(fixed["spec"]["ports"][0]["port"], int)

    def test_autofix_all_docs(self):
        """Test auto-fixing multiple documents."""
        docs = [
            {"kind": "Pod", "spec": {}},
            {"kind": "Deployment", "spec": {}}
        ]

        fixed, changes = autofix_schema_all(docs)

        self.assertEqual(len(fixed), 2)
        self.assertTrue(all("metadata" in d for d in fixed))
        self.assertTrue(len(changes) > 0)


class TestPodSpecExtraction(unittest.TestCase):
    """Test pod spec extraction utilities."""

    def test_get_pod_spec_from_pod(self):
        """Test extracting pod spec from Pod resource."""
        doc = {
            "kind": "Pod",
            "spec": {
                "containers": [{"name": "app"}]
            }
        }

        pod_spec = get_pod_spec(doc)
        self.assertIn("containers", pod_spec)
        self.assertEqual(pod_spec["containers"][0]["name"], "app")

    def test_get_pod_spec_from_deployment(self):
        """Test extracting pod spec from Deployment resource."""
        doc = {
            "kind": "Deployment",
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{"name": "app"}]
                    }
                }
            }
        }

        pod_spec = get_pod_spec(doc)
        self.assertIn("containers", pod_spec)
        self.assertEqual(pod_spec["containers"][0]["name"], "app")

    def test_iter_containers(self):
        """Test iterating over containers."""
        doc = {
            "kind": "Pod",
            "spec": {
                "containers": [
                    {"name": "app"},
                    {"name": "sidecar"}
                ],
                "initContainers": [
                    {"name": "init"}
                ]
            }
        }

        containers = list(iter_containers(doc))
        self.assertEqual(len(containers), 3)
        self.assertEqual(containers[0][0], "app")
        self.assertEqual(containers[1][0], "sidecar")
        self.assertEqual(containers[2][0], "init:init")

    def test_iter_effective_security_contexts(self):
        """Test effective security context merging."""
        doc = {
            "kind": "Pod",
            "spec": {
                "securityContext": {
                    "runAsNonRoot": True,
                    "fsGroup": 1000
                },
                "containers": [
                    {
                        "name": "app",
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "capabilities": {
                                "drop": ["ALL"]
                            }
                        }
                    }
                ]
            }
        }

        contexts = list(iter_effective_security_contexts(doc))
        self.assertEqual(len(contexts), 1)

        name, effective = contexts[0]
        self.assertEqual(name, "app")
        self.assertTrue(effective["runAsNonRoot"])  # From pod
        self.assertEqual(effective["fsGroup"], 1000)  # From pod
        self.assertFalse(effective["allowPrivilegeEscalation"])  # From container
        self.assertIn("capabilities", effective)  # From container only


class TestDangerousConfigCheck(unittest.TestCase):
    """Test dangerous configuration detection."""

    def setUp(self):
        """Set up test configuration."""
        self.config = ValidationConfig()
        self.config.dangerous_fields = [
            {"field": "privileged", "value": True, "message": "Privileged mode"},
            {"field": "hostPID", "value": True, "message": "Host PID"},
        ]
        self.config.forbidden_capabilities = ["SYS_ADMIN", "NET_ADMIN"]

    def test_detect_privileged_container(self):
        """Test detection of privileged container."""
        doc = {
            "kind": "Pod",
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "securityContext": {"privileged": True}
                    }
                ]
            }
        }

        dangerous = check_dangerous(doc, self.config)
        self.assertEqual(len(dangerous), 1)
        self.assertIn("privileged", dangerous[0].lower())

    def test_detect_forbidden_capabilities(self):
        """Test detection of forbidden capabilities."""
        doc = {
            "kind": "Pod",
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "securityContext": {
                            "capabilities": {
                                "add": ["SYS_ADMIN", "NET_BIND_SERVICE"]
                            }
                        }
                    }
                ]
            }
        }

        dangerous = check_dangerous(doc, self.config)
        self.assertEqual(len(dangerous), 1)
        self.assertIn("SYS_ADMIN", dangerous[0])

    def test_detect_hostpath_volume(self):
        """Test detection of hostPath volumes."""
        doc = {
            "kind": "Pod",
            "spec": {
                "volumes": [
                    {
                        "name": "host-vol",
                        "hostPath": {"path": "/var/run/docker.sock"}
                    }
                ],
                "containers": [{"name": "app"}]
            }
        }

        dangerous = check_dangerous(doc, self.config)
        self.assertEqual(len(dangerous), 1)
        self.assertIn("hostPath", dangerous[0])

    def test_no_dangerous_config(self):
        """Test no dangerous configurations detected."""
        doc = {
            "kind": "Pod",
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "securityContext": {
                            "privileged": False,
                            "allowPrivilegeEscalation": False
                        }
                    }
                ]
            }
        }

        dangerous = check_dangerous(doc, self.config)
        self.assertEqual(len(dangerous), 0)


class TestCategoryValidators(unittest.TestCase):
    """Test individual category validators."""

    def setUp(self):
        """Set up test configuration and validator."""
        self.config = ValidationConfig()
        self.config.trusted_registries = ["docker.io", "gcr.io"]
        self.validator = CategoryValidator(self.config)

    def test_validate_privileged_false(self):
        """Test privileged=false validation."""
        sc_pass = {"privileged": False}
        sc_fail = {"privileged": True}

        passed, msg = self.validator.validate_privileged_false(sc_pass)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_privileged_false(sc_fail)
        self.assertFalse(passed)
        self.assertIn("must be false", msg)

    def test_validate_capabilities_drop_all(self):
        """Test capabilities drop ALL validation."""
        sc_pass = {"capabilities": {"drop": ["ALL"]}}
        sc_fail = {"capabilities": {"drop": ["NET_BIND_SERVICE"]}}
        sc_empty = {}

        passed, msg = self.validator.validate_capabilities_drop_all(sc_pass)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_capabilities_drop_all(sc_fail)
        self.assertFalse(passed)
        self.assertIn("missing 'ALL'", msg)

        passed, msg = self.validator.validate_capabilities_drop_all(sc_empty)
        self.assertFalse(passed)

    def test_validate_seccomp_profile(self):
        """Test seccomp profile validation."""
        sc_pass = {"seccompProfile": {"type": "RuntimeDefault"}}
        sc_fail = {"seccompProfile": {"type": "Unconfined"}}
        sc_missing = {}

        passed, msg = self.validator.validate_seccomp_profile_present(sc_pass)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_seccomp_profile_present(sc_fail)
        self.assertFalse(passed)
        self.assertIn("Unconfined", msg)

        passed, msg = self.validator.validate_seccomp_profile_present(sc_missing)
        self.assertFalse(passed)

    def test_validate_readonly_root_filesystem(self):
        """Test readOnlyRootFilesystem validation."""
        sc_pass = {"readOnlyRootFilesystem": True}
        sc_fail = {"readOnlyRootFilesystem": False}

        passed, msg = self.validator.validate_readonly_root_filesystem(sc_pass)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_readonly_root_filesystem(sc_fail)
        self.assertFalse(passed)

    def test_validate_run_as_non_root(self):
        """Test runAsNonRoot validation."""
        sc_pass = {"runAsNonRoot": True}
        sc_fail = {"runAsNonRoot": False}

        passed, msg = self.validator.validate_run_as_non_root(sc_pass)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_run_as_non_root(sc_fail)
        self.assertFalse(passed)

    def test_validate_resources_requests(self):
        """Test resource requests validation."""
        container_pass = {"resources": {"requests": {"cpu": "100m", "memory": "128Mi"}}}
        container_fail = {"resources": {}}

        passed, msg = self.validator.validate_resources_requests_present(container_pass)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_resources_requests_present(container_fail)
        self.assertFalse(passed)

    def test_validate_resources_limits(self):
        """Test resource limits validation."""
        container_pass = {"resources": {"limits": {"cpu": "500m", "memory": "512Mi"}}}
        container_fail = {"resources": {"requests": {"cpu": "100m"}}}

        passed, msg = self.validator.validate_resources_limits_present(container_pass)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_resources_limits_present(container_fail)
        self.assertFalse(passed)

    def test_validate_probes(self):
        """Test probes validation."""
        container_liveness = {"livenessProbe": {"httpGet": {"path": "/health"}}}
        container_readiness = {"readinessProbe": {"httpGet": {"path": "/ready"}}}
        container_both = {
            "livenessProbe": {"httpGet": {"path": "/health"}},
            "readinessProbe": {"httpGet": {"path": "/ready"}}
        }
        container_none = {}

        passed, msg = self.validator.validate_probes_present(container_liveness)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_probes_present(container_readiness)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_probes_present(container_both)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_probes_present(container_none)
        self.assertFalse(passed)

    def test_validate_image_tag_pinned(self):
        """Test image tag pinning validation."""
        container_pinned = {"image": "nginx:1.21.0"}
        container_digest = {"image": "nginx@sha256:abc123"}
        container_latest = {"image": "nginx:latest"}
        container_no_tag = {"image": "nginx"}

        passed, msg = self.validator.validate_image_tag_pinned(container_pinned)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_image_tag_pinned(container_digest)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_image_tag_pinned(container_latest)
        self.assertFalse(passed)
        self.assertIn("latest", msg)

        passed, msg = self.validator.validate_image_tag_pinned(container_no_tag)
        self.assertFalse(passed)

    def test_validate_trusted_registry(self):
        """Test trusted registry validation."""
        container_trusted = {"image": "gcr.io/my-project/app:v1"}
        container_untrusted = {"image": "untrusted.io/app:v1"}

        passed, msg = self.validator.validate_trusted_registry(container_trusted)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_trusted_registry(container_untrusted)
        self.assertFalse(passed)
        self.assertIn("untrusted", msg)

    def test_validate_automount_sa_token(self):
        """Test automountServiceAccountToken validation."""
        doc_pass = {
            "kind": "Pod",
            "spec": {"automountServiceAccountToken": False, "containers": []}
        }
        doc_fail = {
            "kind": "Pod",
            "spec": {"automountServiceAccountToken": True, "containers": []}
        }

        passed, msg = self.validator.validate_automount_sa_token_false(doc_pass)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_automount_sa_token_false(doc_fail)
        self.assertFalse(passed)

    def test_validate_non_default_service_account(self):
        """Test non-default service account validation."""
        doc_pass = {
            "kind": "Pod",
            "spec": {"serviceAccountName": "my-sa", "containers": []}
        }
        doc_fail = {
            "kind": "Pod",
            "spec": {"serviceAccountName": "default", "containers": []}
        }

        passed, msg = self.validator.validate_non_default_service_account(doc_pass)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_non_default_service_account(doc_fail)
        self.assertFalse(passed)

    def test_validate_non_default_namespace(self):
        """Test non-default namespace validation."""
        doc_pass = {
            "metadata": {"namespace": "production"},
            "kind": "Pod"
        }
        doc_fail = {
            "metadata": {"namespace": "default"},
            "kind": "Pod"
        }

        passed, msg = self.validator.validate_non_default_namespace(doc_pass)
        self.assertTrue(passed)

        passed, msg = self.validator.validate_non_default_namespace(doc_fail)
        self.assertFalse(passed)


class TestDiffAnalysis(unittest.TestCase):
    """Test diff analysis functionality."""

    def test_analyze_diff_security_context_added(self):
        """Test detection of added security context."""
        original = [{
            "kind": "Pod",
            "spec": {
                "containers": [{"name": "app"}]
            }
        }]

        secured = [{
            "kind": "Pod",
            "spec": {
                "securityContext": {"runAsNonRoot": True},
                "containers": [
                    {
                        "name": "app",
                        "securityContext": {"allowPrivilegeEscalation": False}
                    }
                ]
            }
        }]

        diff = analyze_diff(original, secured)

        self.assertIn("security_fields_added", diff)
        self.assertTrue(len(diff["security_fields_added"]) > 0)

    def test_analyze_diff_resources_added(self):
        """Test detection of added resources."""
        original = [{
            "kind": "Pod",
            "spec": {
                "containers": [{"name": "app"}]
            }
        }]

        secured = [{
            "kind": "Pod",
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "resources": {
                            "requests": {"cpu": "100m"},
                            "limits": {"cpu": "500m"}
                        }
                    }
                ]
            }
        }]

        diff = analyze_diff(original, secured)

        self.assertIn("resources_added", diff)
        self.assertTrue(len(diff["resources_added"]) > 0)


class TestValidationResult(unittest.TestCase):
    """Test ValidationResult data structure."""

    def test_validation_result_to_dict(self):
        """Test converting ValidationResult to dictionary."""
        result = ValidationResult(
            file="test.yaml",
            status="PASS",
            categories=["Security/PrivilegedContainer"],
            auto_fix_categories=["Security/PrivilegedContainer"]
        )

        result.findings.append(ValidationFinding(
            category="Security/PrivilegedContainer",
            severity=Severity.CRITICAL,
            passed=True,
            message="privileged=false",
            container="app"
        ))

        result_dict = result.to_dict()

        self.assertEqual(result_dict["file"], "test.yaml")
        self.assertEqual(result_dict["status"], "PASS")
        self.assertEqual(len(result_dict["findings"]), 1)
        self.assertEqual(result_dict["findings"][0]["category"], "Security/PrivilegedContainer")
        self.assertEqual(result_dict["findings"][0]["severity"], "CRITICAL")


class TestValidationConfig(unittest.TestCase):
    """Test configuration loading."""

    def test_default_config(self):
        """Test default configuration."""
        config = ValidationConfig()

        self.assertTrue(config.enable_kubeconform)
        self.assertTrue(config.enable_schema_autofix)
        self.assertEqual(config.max_workers, 4)

    def test_config_from_yaml(self):
        """Test loading configuration from YAML."""
        config_data = {
            "dangerous_fields": [
                {"field": "privileged", "value": True}
            ],
            "forbidden_capabilities": ["SYS_ADMIN"],
            "trusted_registries": ["docker.io"],
            "validation_settings": {
                "enable_kubeconform": False,
                "max_workers": 8,
                "strict_mode": True
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = Path(f.name)

        try:
            config = ValidationConfig.load(temp_path)

            self.assertEqual(len(config.dangerous_fields), 1)
            self.assertEqual(len(config.forbidden_capabilities), 1)
            self.assertFalse(config.enable_kubeconform)
            self.assertEqual(config.max_workers, 8)
            self.assertTrue(config.strict_mode)
        finally:
            temp_path.unlink()


def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(__import__(__name__))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    exit(run_tests())
