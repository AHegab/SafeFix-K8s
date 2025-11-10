package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# =============================================================================
# COMPREHENSIVE KUBERNETES SECURITY POLICY BUNDLE
# Combines 10 core security checks + extended policies from existing validators
# =============================================================================

# Helper: extract PodSpec from various workload kinds
get_pod_spec(resource) := spec if {
    resource.kind == "Pod"
    spec := resource.spec
}

get_pod_spec(resource) := spec if {
    resource.kind in ["Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"]
    spec := resource.spec.template.spec
}

get_pod_spec(resource) := spec if {
    resource.kind == "CronJob"
    spec := resource.spec.jobTemplate.spec.template.spec
}

# Helper: get all containers (containers + initContainers)
get_all_containers(pod_spec) := containers if {
    containers := array.concat(
        object.get(pod_spec, "containers", []),
        object.get(pod_spec, "initContainers", [])
    )
}

# Helper: check if container has AppArmor annotation
has_apparmor_annotation(resource, container_name) if {
    annotations := object.get(resource.metadata, "annotations", {})
    # Check for container-specific annotation
    profile := object.get(annotations, sprintf("container.apparmor.security.beta.kubernetes.io/%s", [container_name]), "")
    profile != ""
    profile != "unconfined"
}

has_apparmor_annotation(resource, container_name) if {
    annotations := object.get(resource.metadata, "annotations", {})
    # Check for pod-level annotation
    profile := object.get(annotations, sprintf("apparmor.security.beta.kubernetes.io/%s", [container_name]), "")
    profile != ""
    profile != "unconfined"
}

# Rule 1: KSV_CAP_DROP_MISSING
# Description: Container does not drop all default capabilities (ALL not in capabilities.drop)
# Severity: HIGH
# Suggested fix: Add securityContext.capabilities.drop: [ALL] to each container
deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    # Get securityContext
    sec_ctx := object.get(container, "securityContext", {})
    caps := object.get(sec_ctx, "capabilities", {})
    drop := object.get(caps, "drop", [])
    
    # Check if ALL is not in drop list
    not "ALL" in drop
    
    msg := sprintf("KSV_CAP_DROP_MISSING: Container '%s' in %s '%s' does not drop ALL capabilities. Add securityContext.capabilities.drop: [ALL]", 
        [container.name, input.kind, input.metadata.name])
}

# Rule 2: KSV_PRIVILEGED
# Description: Container runs in privileged mode
# Severity: CRITICAL
# Suggested fix: Set securityContext.privileged: false or remove the field
deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    sec_ctx := object.get(container, "securityContext", {})
    privileged := object.get(sec_ctx, "privileged", false)
    privileged == true
    
    msg := sprintf("KSV_PRIVILEGED: Container '%s' in %s '%s' runs in privileged mode. Set securityContext.privileged: false", 
        [container.name, input.kind, input.metadata.name])
}

# Rule 3: KSV_ALLOW_PRIVILEGE_ESCALATION
# Description: Container allows privilege escalation (not explicitly set to false)
# Severity: HIGH
# Suggested fix: Set securityContext.allowPrivilegeEscalation: false
deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    sec_ctx := object.get(container, "securityContext", {})
    # If allowPrivilegeEscalation is missing or not false, flag it
    ape := object.get(sec_ctx, "allowPrivilegeEscalation", null)
    ape != false
    
    msg := sprintf("KSV_ALLOW_PRIVILEGE_ESCALATION: Container '%s' in %s '%s' does not explicitly set allowPrivilegeEscalation: false", 
        [container.name, input.kind, input.metadata.name])
}

# Rule 4: KSV_NO_SECCOMP
# Description: No seccomp profile configured (missing or invalid)
# Severity: HIGH
# Suggested fix: Set securityContext.seccompProfile.type: RuntimeDefault
# Valid values: RuntimeDefault, runtime/default, docker/default
deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    # Check container-level seccomp
    sec_ctx := object.get(container, "securityContext", {})
    seccomp := object.get(sec_ctx, "seccompProfile", {})
    seccomp_type := object.get(seccomp, "type", "")
    
    # Also check pod-level seccomp
    pod_sec_ctx := object.get(pod_spec, "securityContext", {})
    pod_seccomp := object.get(pod_sec_ctx, "seccompProfile", {})
    pod_seccomp_type := object.get(pod_seccomp, "type", "")
    
    # Flag if neither container nor pod has valid seccomp
    not seccomp_type in ["RuntimeDefault", "runtime/default", "docker/default", "Localhost"]
    not pod_seccomp_type in ["RuntimeDefault", "runtime/default", "docker/default", "Localhost"]
    
    msg := sprintf("KSV_NO_SECCOMP: Container '%s' in %s '%s' has no seccomp profile. Set securityContext.seccompProfile.type: RuntimeDefault", 
        [container.name, input.kind, input.metadata.name])
}

# Rule 5: KSV_NO_APPARMOR
# Description: No AppArmor annotation configured for container
# Severity: MEDIUM
# Suggested fix: Add annotation container.apparmor.security.beta.kubernetes.io/<container>: runtime/default
deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    # Check if AppArmor annotation exists for this container
    not has_apparmor_annotation(input, container.name)
    
    msg := sprintf("KSV_NO_APPARMOR: Container '%s' in %s '%s' has no AppArmor annotation. Add annotation container.apparmor.security.beta.kubernetes.io/%s: runtime/default", 
        [container.name, input.kind, input.metadata.name, container.name])
}

# Rule 6: KSV_READONLY_ROOTFS_FALSE
# Description: Container does not have readOnlyRootFilesystem: true
# Severity: MEDIUM
# Suggested fix: Set securityContext.readOnlyRootFilesystem: true
deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    sec_ctx := object.get(container, "securityContext", {})
    readonly := object.get(sec_ctx, "readOnlyRootFilesystem", false)
    readonly != true
    
    msg := sprintf("KSV_READONLY_ROOTFS_FALSE: Container '%s' in %s '%s' does not have readOnlyRootFilesystem: true", 
        [container.name, input.kind, input.metadata.name])
}

# Rule 7: KSV_DEFAULT_SA_TOKEN
# Description: Uses default service account or automounts service account token
# Severity: MEDIUM
# Suggested fix: Set serviceAccountName to non-default SA and automountServiceAccountToken: false
deny contains msg if {
    pod_spec := get_pod_spec(input)
    
    # Check if using default service account
    sa_name := object.get(pod_spec, "serviceAccountName", "default")
    sa_name == "default"
    
    # Check if automountServiceAccountToken is not explicitly false
    automount := object.get(pod_spec, "automountServiceAccountToken", true)
    automount == true
    
    msg := sprintf("KSV_DEFAULT_SA_TOKEN: %s '%s' uses default service account with automountServiceAccountToken: true. Set serviceAccountName to non-default and automountServiceAccountToken: false", 
        [input.kind, input.metadata.name])
}

# Rule 8: KSV_DEFAULT_NAMESPACE
# Description: Resource deployed to default namespace
# Severity: LOW
# Suggested fix: Specify a non-default namespace in metadata.namespace
deny contains msg if {
    namespace := object.get(input.metadata, "namespace", "default")
    namespace == "default"
    
    msg := sprintf("KSV_DEFAULT_NAMESPACE: %s '%s' is deployed to default namespace. Specify metadata.namespace with a non-default value", 
        [input.kind, input.metadata.name])
}

# Rule 9: KSV_IMAGE_NOT_PINNED
# Description: Image not pinned by digest or uses floating tag
# Severity: MEDIUM
# Suggested fix: Pin image with @sha256:<digest> instead of using :latest or no tag
deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    image := container.image
    
    # Flag if image uses :latest
    contains(image, ":latest")
    
    msg := sprintf("KSV_IMAGE_NOT_PINNED: Container '%s' in %s '%s' uses :latest tag. Pin image with @sha256:<digest>", 
        [container.name, input.kind, input.metadata.name])
}

deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    image := container.image
    
    # Flag if image has no tag and no digest
    not contains(image, ":")
    not contains(image, "@sha256:")
    
    msg := sprintf("KSV_IMAGE_NOT_PINNED: Container '%s' in %s '%s' has no tag/digest. Pin image with @sha256:<digest>", 
        [container.name, input.metadata.name])
}

deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    image := container.image
    
    # Flag if image has tag but no digest
    contains(image, ":")
    not contains(image, ":latest")
    not contains(image, "@sha256:")
    
    # Additional check: ensure we're not being too strict for digests
    # Accept images with @sha256: as properly pinned
    not contains(image, "@")
    
    msg := sprintf("KSV_IMAGE_NOT_PINNED: Container '%s' in %s '%s' uses floating tag. Pin image with @sha256:<digest>", 
        [container.name, input.kind, input.metadata.name])
}

# Rule 10: KSV_NO_LIMITS_NO_PROBES
# Description: Container missing resource limits AND missing probes
# Severity: MEDIUM
# Suggested fix: Add resources.limits.cpu, resources.limits.memory, and at least one of livenessProbe/readinessProbe
# Tradeoff: Requiring limits on ALL containers can be too strict for some workloads; adjust as needed
deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    # Check for missing resource limits
    resources := object.get(container, "resources", {})
    limits := object.get(resources, "limits", {})
    cpu_limit := object.get(limits, "cpu", "")
    mem_limit := object.get(limits, "memory", "")
    
    missing_limits = cpu_limit == "" ; missing_limits = mem_limit == ""
    
    # Check for missing probes
    liveness := object.get(container, "livenessProbe", null)
    readiness := object.get(container, "readinessProbe", null)
    
    missing_probes = liveness == null ; missing_probes = readiness == null
    
    # Flag if BOTH limits and probes are missing
    missing_limits
    missing_probes
    
    msg := sprintf("KSV_NO_LIMITS_NO_PROBES: Container '%s' in %s '%s' missing resource limits (cpu/memory) AND probes (liveness/readiness)", 
        [container.name, input.kind, input.metadata.name])
}

# =============================================================================
# EXTENDED POLICIES FROM VALIDATIONS
# Additional security, networking, RBAC, and best-practice checks
# =============================================================================

# -----------------------------------------------------------------------------
# RESOURCE LIMITS (Strict variant - ALL containers must have limits)
# -----------------------------------------------------------------------------
deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    resources := object.get(container, "resources", {})
    limits := object.get(resources, "limits", {})
    not limits.cpu
    
    msg := sprintf("RESOURCE_LIMITS: Container '%s' in %s '%s' must set CPU limit", 
        [container.name, input.kind, input.metadata.name])
}

deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    resources := object.get(container, "resources", {})
    limits := object.get(resources, "limits", {})
    not limits.memory
    
    msg := sprintf("RESOURCE_LIMITS: Container '%s' in %s '%s' must set memory limit", 
        [container.name, input.kind, input.metadata.name])
}

deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    resources := object.get(container, "resources", {})
    requests := object.get(resources, "requests", {})
    not requests.cpu
    
    msg := sprintf("RESOURCE_REQUESTS: Container '%s' in %s '%s' must set CPU request", 
        [container.name, input.kind, input.metadata.name])
}

deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    resources := object.get(container, "resources", {})
    requests := object.get(resources, "requests", {})
    not requests.memory
    
    msg := sprintf("RESOURCE_REQUESTS: Container '%s' in %s '%s' must set memory request", 
        [container.name, input.kind, input.metadata.name])
}

# -----------------------------------------------------------------------------
# RUN AS NON-ROOT (Enhanced check)
# -----------------------------------------------------------------------------
deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    sec_ctx := object.get(container, "securityContext", {})
    run_as_non_root := object.get(sec_ctx, "runAsNonRoot", false)
    run_as_non_root != true
    
    # Also check pod-level
    pod_sec_ctx := object.get(pod_spec, "securityContext", {})
    pod_run_as_non_root := object.get(pod_sec_ctx, "runAsNonRoot", false)
    pod_run_as_non_root != true
    
    msg := sprintf("RUN_AS_NON_ROOT: Container '%s' in %s '%s' must set runAsNonRoot: true at pod or container level", 
        [container.name, input.kind, input.metadata.name])
}

# -----------------------------------------------------------------------------
# HOST NETWORK/PID/IPC
# -----------------------------------------------------------------------------
deny contains msg if {
    pod_spec := get_pod_spec(input)
    host_network := object.get(pod_spec, "hostNetwork", false)
    host_network == true
    
    msg := sprintf("HOST_NETWORK: %s '%s' must not use hostNetwork: true", 
        [input.kind, input.metadata.name])
}

deny contains msg if {
    pod_spec := get_pod_spec(input)
    host_pid := object.get(pod_spec, "hostPID", false)
    host_pid == true
    
    msg := sprintf("HOST_PID: %s '%s' must not use hostPID: true", 
        [input.kind, input.metadata.name])
}

deny contains msg if {
    pod_spec := get_pod_spec(input)
    host_ipc := object.get(pod_spec, "hostIPC", false)
    host_ipc == true
    
    msg := sprintf("HOST_IPC: %s '%s' must not use hostIPC: true", 
        [input.kind, input.metadata.name])
}

# -----------------------------------------------------------------------------
# HOST PATH VOLUMES
# -----------------------------------------------------------------------------
deny contains msg if {
    pod_spec := get_pod_spec(input)
    volumes := object.get(pod_spec, "volumes", [])
    volume := volumes[_]
    host_path := object.get(volume, "hostPath", null)
    host_path != null
    
    msg := sprintf("HOST_PATH: %s '%s' uses hostPath volume '%s' - avoid mounting host filesystem", 
        [input.kind, input.metadata.name, volume.name])
}

# -----------------------------------------------------------------------------
# IMAGE PULL POLICY
# -----------------------------------------------------------------------------
deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    pull_policy := object.get(container, "imagePullPolicy", "")
    pull_policy != "Always"
    
    # Exempt images with digest (they should use IfNotPresent)
    not contains(container.image, "@sha256:")
    
    msg := sprintf("IMAGE_PULL_POLICY: Container '%s' in %s '%s' should set imagePullPolicy: Always (unless using digest)", 
        [container.name, input.kind, input.metadata.name])
}

# -----------------------------------------------------------------------------
# HEALTH PROBES (Strict - require BOTH liveness and readiness)
# -----------------------------------------------------------------------------
deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := object.get(pod_spec, "containers", [])
    container := containers[_]
    
    liveness := object.get(container, "livenessProbe", null)
    liveness == null
    
    msg := sprintf("HEALTH_PROBES: Container '%s' in %s '%s' must define livenessProbe", 
        [container.name, input.kind, input.metadata.name])
}

deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := object.get(pod_spec, "containers", [])
    container := containers[_]
    
    readiness := object.get(container, "readinessProbe", null)
    readiness == null
    
    msg := sprintf("HEALTH_PROBES: Container '%s' in %s '%s' must define readinessProbe", 
        [container.name, input.kind, input.metadata.name])
}

# -----------------------------------------------------------------------------
# SECRETS SECURITY
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "Secret"
    input.type == "Opaque"
    annotations := object.get(input.metadata, "annotations", {})
    encrypted := object.get(annotations, "encryption.kubernetes.io/encrypted", "false")
    encrypted != "true"
    
    msg := sprintf("UNENCRYPTED_SECRET: Secret '%s' is unencrypted - use encryption at rest or external secret management", 
        [input.metadata.name])
}

deny contains msg if {
    pod_spec := get_pod_spec(input)
    containers := get_all_containers(pod_spec)
    container := containers[_]
    
    env := object.get(container, "env", [])[_]
    value := object.get(env, "value", "")
    value != ""
    
    # Check for cloud credentials
    upper_name := upper(env.name)
    upper_name in [
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS", "GCP_SERVICE_ACCOUNT_KEY",
        "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"
    ]
    
    msg := sprintf("HARDCODED_CLOUD_CREDS: Container '%s' in %s '%s' has hardcoded cloud credential '%s' - use secretKeyRef or workload identity", 
        [container.name, input.kind, input.metadata.name, env.name])
}

# -----------------------------------------------------------------------------
# CONFIGMAP WITH SENSITIVE DATA
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "ConfigMap"
    configmap_data := object.get(input, "data", {})
    key := object.keys(configmap_data)[_]
    
    lower_key := lower(key)
    contains(lower_key, "password")
    
    msg := sprintf("CONFIGMAP_SENSITIVE: ConfigMap '%s' has key '%s' that looks like sensitive data - use Secret instead", 
        [input.metadata.name, key])
}

deny contains msg if {
    input.kind == "ConfigMap"
    configmap_data := object.get(input, "data", {})
    key := object.keys(configmap_data)[_]
    
    lower_key := lower(key)
    regex.match(".*(secret|token|apikey|api_key|private_key|credential).*", lower_key)
    
    msg := sprintf("CONFIGMAP_SENSITIVE: ConfigMap '%s' has key '%s' that looks like sensitive data - use Secret instead", 
        [input.metadata.name, key])
}

# -----------------------------------------------------------------------------
# DEPLOYMENT SELECTOR MUST MATCH LABELS
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "Deployment"
    selector := input.spec.selector.matchLabels
    template_labels := object.get(input.spec.template.metadata, "labels", {})
    
    # Check if all selector labels are in template
    key := object.keys(selector)[_]
    not template_labels[key] == selector[key]
    
    msg := sprintf("DEPLOYMENT_SELECTOR: Deployment '%s' selector.matchLabels must match template.metadata.labels", 
        [input.metadata.name])
}

# -----------------------------------------------------------------------------
# HIGH AVAILABILITY (Require replicas >= 2 for production)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Deployment", "StatefulSet"]
    replicas := object.get(input.spec, "replicas", 1)
    replicas < 2
    
    # Only enforce for production namespace
    namespace := object.get(input.metadata, "namespace", "default")
    namespace in ["production", "prod"]
    
    msg := sprintf("HIGH_AVAILABILITY: %s '%s' in production must have replicas >= 2 (current: %d)", 
        [input.kind, input.metadata.name, replicas])
}

# -----------------------------------------------------------------------------
# INGRESS TLS REQUIRED
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "Ingress"
    tls := object.get(input.spec, "tls", [])
    count(tls) == 0
    
    msg := sprintf("INGRESS_TLS: Ingress '%s' must define spec.tls for HTTPS", 
        [input.metadata.name])
}

# -----------------------------------------------------------------------------
# NETWORK POLICY REQUIRED (per namespace)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet"]
    
    # This is a simplified check - in practice, you'd need to check if a NetworkPolicy exists
    # that targets this workload's labels
    annotations := object.get(input.metadata, "annotations", {})
    network_policy_exempt := object.get(annotations, "network-policy-exempt", "false")
    network_policy_exempt != "true"
    
    # Simplified: require annotation to confirm NetworkPolicy exists
    network_policy_confirmed := object.get(annotations, "network-policy-confirmed", "false")
    network_policy_confirmed != "true"
    
    msg := sprintf("NETWORK_POLICY: %s '%s' must be covered by a NetworkPolicy (add annotation network-policy-confirmed: true)", 
        [input.kind, input.metadata.name])
}

# -----------------------------------------------------------------------------
# RBAC: OVERLY PERMISSIVE RULES
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "Role"
    rule := input.rules[_]
    
    verbs := object.get(rule, "verbs", [])
    "*" in verbs
    
    msg := sprintf("RBAC_WILDCARD: Role '%s' grants wildcard verb '*' - use specific verbs instead", 
        [input.metadata.name])
}

deny contains msg if {
    input.kind == "ClusterRole"
    rule := input.rules[_]
    
    resources := object.get(rule, "resources", [])
    "*" in resources
    
    msg := sprintf("RBAC_WILDCARD: ClusterRole '%s' grants wildcard resource '*' - use specific resources instead", 
        [input.metadata.name])
}

deny contains msg if {
    input.kind in ["Role", "ClusterRole"]
    rule := input.rules[_]
    
    verbs := object.get(rule, "verbs", [])
    "delete" in verbs
    
    resources := object.get(rule, "resources", [])
    "secrets" in resources
    
    msg := sprintf("RBAC_DANGEROUS: %s '%s' allows deleting secrets - extremely dangerous permission", 
        [input.kind, input.metadata.name])
}

# -----------------------------------------------------------------------------
# DOCKER SOCKET MOUNT (Extremely dangerous)
# -----------------------------------------------------------------------------
deny contains msg if {
    pod_spec := get_pod_spec(input)
    volumes := object.get(pod_spec, "volumes", [])
    volume := volumes[_]
    
    host_path := object.get(volume, "hostPath", {})
    path := object.get(host_path, "path", "")
    
    path in ["/var/run/docker.sock", "/run/docker.sock"]
    
    msg := sprintf("DOCKER_SOCKET: %s '%s' mounts Docker socket - grants full cluster control", 
        [input.kind, input.metadata.name])
}

# -----------------------------------------------------------------------------
# CNI EMBEDDED PRIVILEGED CONFIG
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "Pod"
    annotations := object.get(input.metadata, "annotations", {})
    
    # Check for Multus CNI annotation
    multus_nets := object.get(annotations, "k8s.v1.cni.cncf.io/networks", "")
    multus_nets != ""
    
    # Check if CNI config contains privileged: true
    contains(multus_nets, "\"privileged\":true")
    
    msg := sprintf("CNI_PRIVILEGED: Pod '%s' has CNI annotation with privileged:true", 
        [input.metadata.name])
}

# -----------------------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------------------
default_name(n) = n if {
    n
}

default_name(n) = "(unnamed)" if {
    not n
}



