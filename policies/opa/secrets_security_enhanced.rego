package kubernetes.secrets_security

import rego.v1

# =============================================================================
# SECRETS & SENSITIVE DATA SECURITY POLICIES
# Detect hardcoded secrets, unencrypted data, and insecure secret usage
# =============================================================================

# -----------------------------------------------------------------------------
# 1. UNENCRYPTED SECRETS (High)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "Secret"
    input.type == "Opaque"
    not has_encryption_annotation
    msg := sprintf("HIGH: Secret '%s' is unencrypted - should use encryption at rest or external secret management", [input.metadata.name])
}

has_encryption_annotation if {
    annotations := input.metadata.annotations
    annotations["encryption.kubernetes.io/encrypted"] == "true"
}

# -----------------------------------------------------------------------------
# 2. SECRET IN ENVIRONMENT VARIABLE (Medium)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    env := container.env[_]
    env.value
    looks_like_secret(env.value)
    msg := sprintf("MEDIUM: Container '%s' has environment variable '%s' with potential hardcoded secret", [container.name, env.name])
}

looks_like_secret(value) if {
    # Check for common secret patterns
    regex.match("(?i)(password|passwd|pwd|secret|token|key|apikey|api_key)\\s*[:=]\\s*.+", value)
}

looks_like_secret(value) if {
    # Check for base64-like strings (might be encoded secrets)
    regex.match("^[A-Za-z0-9+/]{20,}={0,2}$", value)
    count(value) > 30
}

# -----------------------------------------------------------------------------
# 3. SECRET VALUE IN ENV (Not secretKeyRef) (High)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    env := container.env[_]
    env.value
    has_secret_keyword(env.name)
    msg := sprintf("HIGH: Container '%s' env var '%s' uses direct value instead of secretKeyRef", [container.name, env.name])
}

has_secret_keyword(name) if {
    lower_name := lower(name)
    regex.match(".*(password|passwd|pwd|secret|token|apikey|api_key|private_key|credential).*", lower_name)
}

# -----------------------------------------------------------------------------
# 4. SECRET MOUNTED AS ENVIRONMENT VARIABLE (Medium)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    container.envFrom[_].secretRef
    msg := sprintf("MEDIUM: Container '%s' mounts entire secret as env vars - prefer volume mounts for secrets", [container.name])
}

# -----------------------------------------------------------------------------
# 5. CONFIGMAP WITH SENSITIVE DATA (Medium)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "ConfigMap"
    key := object.keys(input.data)[_]
    has_secret_keyword(key)
    msg := sprintf("MEDIUM: ConfigMap '%s' has key '%s' that looks like sensitive data - use Secret instead", [input.metadata.name, key])
}

deny contains msg if {
    input.kind == "ConfigMap"
    value := input.data[_]
    looks_like_secret(value)
    msg := sprintf("MEDIUM: ConfigMap '%s' contains value that looks like sensitive data - use Secret instead", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 6. SECRET WITHOUT LABELS (Low)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "Secret"
    not input.metadata.labels
    msg := sprintf("LOW: Secret '%s' has no labels - consider adding labels for better organization", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 7. DOCKER REGISTRY SECRET IN DEFAULT NAMESPACE (High)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "Secret"
    input.type == "kubernetes.io/dockerconfigjson"
    namespace := object.get(input.metadata, "namespace", "default")
    namespace == "default"
    msg := sprintf("HIGH: Docker registry secret '%s' in default namespace - use dedicated namespace", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 8. TLS SECRET WITHOUT ROTATION ANNOTATION (Medium)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "Secret"
    input.type == "kubernetes.io/tls"
    not has_rotation_annotation
    msg := sprintf("MEDIUM: TLS Secret '%s' missing rotation annotation - should implement certificate rotation", [input.metadata.name])
}

has_rotation_annotation if {
    annotations := input.metadata.annotations
    annotations["cert-manager.io/common-name"]
}

has_rotation_annotation if {
    annotations := input.metadata.annotations
    annotations["rotation-timestamp"]
}

# -----------------------------------------------------------------------------
# 9. HARDCODED DATABASE CONNECTION STRING (High)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    env := container.env[_]
    value := env.value
    regex.match("(?i).*://.*:.*@.*", value)  # Matches user:pass@host patterns
    msg := sprintf("HIGH: Container '%s' env var '%s' contains database connection string with credentials", [container.name, env.name])
}

# -----------------------------------------------------------------------------
# 10. AWS/GCP/AZURE CREDENTIALS IN ENV (Critical)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    env := container.env[_]
    is_cloud_credential_key(env.name)
    env.value  # Has direct value instead of secretKeyRef
    msg := sprintf("CRITICAL: Container '%s' has hardcoded cloud credential '%s' - use secretKeyRef or workload identity", [container.name, env.name])
}

is_cloud_credential_key(key) if {
    cloud_cred_keys := [
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS", "GCP_SERVICE_ACCOUNT_KEY",
        "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"
    ]
    some cred in cloud_cred_keys
    upper(key) == cred
}

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------

get_pod_spec := input.spec if {
    input.kind == "Pod"
}

get_pod_spec := input.spec.template.spec if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"]
}

get_pod_spec := input.spec.jobTemplate.spec.template.spec if {
    input.kind == "CronJob"
}

all_containers := containers if {
    input.kind == "Pod"
    regular := array.concat(
        object.get(input.spec, "containers", []),
        object.get(input.spec, "initContainers", [])
    )
    containers := array.concat(regular, object.get(input.spec, "ephemeralContainers", []))
}

all_containers := containers if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"]
    spec := input.spec.template.spec
    regular := array.concat(
        object.get(spec, "containers", []),
        object.get(spec, "initContainers", [])
    )
    containers := array.concat(regular, object.get(spec, "ephemeralContainers", []))
}

all_containers := containers if {
    input.kind == "CronJob"
    spec := input.spec.jobTemplate.spec.template.spec
    regular := array.concat(
        object.get(spec, "containers", []),
        object.get(spec, "initContainers", [])
    )
    containers := array.concat(regular, object.get(spec, "ephemeralContainers", []))
}
