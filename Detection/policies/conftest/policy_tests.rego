package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Unit tests for Conftest policies
# Run with: conftest verify -p policy.rego -p policy_tests.rego

# Test 1: KSV_CAP_DROP_MISSING
test_caps_drop_missing_deny if {
    deny["KSV_CAP_DROP_MISSING: Container 'app' in Pod 'insecure-pod-caps' does not drop ALL capabilities. Add securityContext.capabilities.drop: [ALL]"] with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "insecure-pod-caps"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx"
                }
            ]
        }
    }
}

test_caps_drop_allow if {
    count(deny) == 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "secure-pod-caps"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx",
                    "securityContext": {
                        "capabilities": {
                            "drop": ["ALL"]
                        }
                    }
                }
            ]
        }
    }
}

# Test 2: KSV_PRIVILEGED
test_privileged_deny if {
    deny["KSV_PRIVILEGED: Container 'app' in Pod 'privileged-pod' runs in privileged mode. Set securityContext.privileged: false"] with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "privileged-pod"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx",
                    "securityContext": {
                        "privileged": true
                    }
                }
            ]
        }
    }
}

test_privileged_allow if {
    count(deny) == 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "secure-pod"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx",
                    "securityContext": {
                        "privileged": false
                    }
                }
            ]
        }
    }
}

# Test 3: KSV_ALLOW_PRIVILEGE_ESCALATION
test_allow_privilege_escalation_deny if {
    count(deny) > 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "escalation-pod"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx"
                }
            ]
        }
    }
}

test_allow_privilege_escalation_allow if {
    count(deny) == 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "secure-pod"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx",
                    "securityContext": {
                        "allowPrivilegeEscalation": false
                    }
                }
            ]
        }
    }
}

# Test 4: KSV_NO_SECCOMP
test_no_seccomp_deny if {
    count(deny) > 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "no-seccomp-pod"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx"
                }
            ]
        }
    }
}

test_no_seccomp_allow_pod_level if {
    count(deny) == 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "seccomp-pod"},
        "spec": {
            "securityContext": {
                "seccompProfile": {
                    "type": "RuntimeDefault"
                }
            },
            "containers": [
                {
                    "name": "app",
                    "image": "nginx"
                }
            ]
        }
    }
}

# Test 5: KSV_NO_APPARMOR
test_no_apparmor_deny if {
    count(deny) > 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "no-apparmor-pod"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx"
                }
            ]
        }
    }
}

test_no_apparmor_allow if {
    count(deny) == 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "apparmor-pod",
            "annotations": {
                "container.apparmor.security.beta.kubernetes.io/app": "runtime/default"
            }
        },
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx"
                }
            ]
        }
    }
}

# Test 6: KSV_READONLY_ROOTFS_FALSE
test_readonly_rootfs_deny if {
    count(deny) > 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "writable-rootfs-pod"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx"
                }
            ]
        }
    }
}

test_readonly_rootfs_allow if {
    count(deny) == 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "readonly-pod"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx",
                    "securityContext": {
                        "readOnlyRootFilesystem": true
                    }
                }
            ]
        }
    }
}

# Test 7: KSV_DEFAULT_SA_TOKEN
test_default_sa_token_deny if {
    count(deny) > 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "default-sa-pod"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx"
                }
            ]
        }
    }
}

test_default_sa_token_allow if {
    count(deny) == 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "custom-sa-pod"},
        "spec": {
            "serviceAccountName": "my-custom-sa",
            "automountServiceAccountToken": false,
            "containers": [
                {
                    "name": "app",
                    "image": "nginx"
                }
            ]
        }
    }
}

# Test 8: KSV_DEFAULT_NAMESPACE
test_default_namespace_deny if {
    count(deny) > 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "default-ns-pod"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx"
                }
            ]
        }
    }
}

test_default_namespace_allow if {
    count(deny) == 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "custom-ns-pod",
            "namespace": "production"
        },
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx"
                }
            ]
        }
    }
}

# Test 9: KSV_IMAGE_NOT_PINNED
test_image_not_pinned_latest_deny if {
    count(deny) > 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "latest-tag-pod"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx:latest"
                }
            ]
        }
    }
}

test_image_pinned_allow if {
    count(deny) == 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "pinned-pod"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx@sha256:abcd1234"
                }
            ]
        }
    }
}

# Test 10: KSV_NO_LIMITS_NO_PROBES
test_no_limits_no_probes_deny if {
    count(deny) > 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "no-limits-probes-pod"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx"
                }
            ]
        }
    }
}

test_limits_and_probes_allow if {
    count(deny) == 0 with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "secure-pod"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx",
                    "resources": {
                        "limits": {
                            "cpu": "1",
                            "memory": "512Mi"
                        }
                    },
                    "livenessProbe": {
                        "httpGet": {
                            "path": "/healthz",
                            "port": 8080
                        }
                    }
                }
            ]
        }
    }
}

