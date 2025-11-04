package kubernetes.comprehensive_security

import rego.v1

# =============================================================================
# COMPREHENSIVE KUBERNETES SECURITY POLICY
# Combines multiple security checks for better detection coverage
# =============================================================================

# -----------------------------------------------------------------------------
# 1. PRIVILEGED CONTAINERS (High Severity)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"]
    container := all_containers[_]
    container.securityContext.privileged == true
    msg := sprintf("CRITICAL: Container '%s' is running in privileged mode - grants full host access", [container.name])
}

# -----------------------------------------------------------------------------
# 2. CAPABILITIES - DROP ALL (High Severity)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    not has_drop_all_capabilities(container)
    msg := sprintf("HIGH: Container '%s' does not drop ALL capabilities - should drop ALL and add only required ones", [container.name])
}

has_drop_all_capabilities(container) if {
    drops := container.securityContext.capabilities.drop
    some drop in drops
    lower(drop) == "all"
}

# -----------------------------------------------------------------------------
# 3. DANGEROUS CAPABILITY ADDITIONS (High Severity)
# -----------------------------------------------------------------------------
dangerous_capabilities := [
    "SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE", 
    "SYS_BOOT", "MAC_ADMIN", "NET_ADMIN", "DAC_OVERRIDE",
    "DAC_READ_SEARCH", "SETUID", "SETGID", "SETPCAP"
]

deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    adds := container.securityContext.capabilities.add
    some add in adds
    some dangerous in dangerous_capabilities
    upper(add) == dangerous
    msg := sprintf("CRITICAL: Container '%s' adds dangerous capability '%s' - high security risk", [container.name, add])
}

# -----------------------------------------------------------------------------
# 4. ROOT USER (High Severity)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    not runs_as_non_root(container)
    msg := sprintf("HIGH: Container '%s' may run as root - set runAsNonRoot: true", [container.name])
}

runs_as_non_root(container) if {
    container.securityContext.runAsNonRoot == true
}

runs_as_non_root(container) if {
    container.securityContext.runAsUser > 0
}

# -----------------------------------------------------------------------------
# 5. PRIVILEGE ESCALATION (High Severity)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    not blocks_privilege_escalation(container)
    msg := sprintf("HIGH: Container '%s' allows privilege escalation - set allowPrivilegeEscalation: false", [container.name])
}

blocks_privilege_escalation(container) if {
    container.securityContext.allowPrivilegeEscalation == false
}

# -----------------------------------------------------------------------------
# 6. READ-ONLY ROOT FILESYSTEM (Medium Severity)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    not has_readonly_root_fs(container)
    msg := sprintf("MEDIUM: Container '%s' filesystem is not read-only - set readOnlyRootFilesystem: true", [container.name])
}

has_readonly_root_fs(container) if {
    container.securityContext.readOnlyRootFilesystem == true
}

# -----------------------------------------------------------------------------
# 7. HOST NAMESPACES (Critical Severity)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    pod_spec := get_pod_spec
    pod_spec.hostNetwork == true
    msg := "CRITICAL: Pod uses host network namespace - creates network-level privilege escalation risk"
}

deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    pod_spec := get_pod_spec
    pod_spec.hostPID == true
    msg := "CRITICAL: Pod uses host PID namespace - can view/kill host processes"
}

deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    pod_spec := get_pod_spec
    pod_spec.hostIPC == true
    msg := "CRITICAL: Pod uses host IPC namespace - can access host inter-process communication"
}

# -----------------------------------------------------------------------------
# 8. DOCKER SOCKET MOUNT (Critical Severity)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    pod_spec := get_pod_spec
    volume := pod_spec.volumes[_]
    volume.hostPath.path
    regex.match(".*docker\\.sock$", volume.hostPath.path)
    msg := sprintf("CRITICAL: Docker socket mounted as volume '%s' - grants container escape capability", [volume.name])
}

# -----------------------------------------------------------------------------
# 9. SENSITIVE HOST PATHS (High Severity)
# -----------------------------------------------------------------------------
sensitive_host_paths := [
    "/", "/boot", "/dev", "/etc", "/lib", "/proc", 
    "/sys", "/usr", "/var/run"
]

deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    pod_spec := get_pod_spec
    volume := pod_spec.volumes[_]
    path := volume.hostPath.path
    some sensitive in sensitive_host_paths
    startswith(path, sensitive)
    msg := sprintf("HIGH: Sensitive host path '%s' mounted as volume '%s'", [path, volume.name])
}

# -----------------------------------------------------------------------------
# 10. SECCOMP PROFILE (Medium Severity)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    pod_spec := get_pod_spec
    not has_seccomp_profile(pod_spec)
    container := all_containers[_]
    not has_container_seccomp(container)
    msg := sprintf("MEDIUM: Container '%s' missing seccomp profile - should use RuntimeDefault or Localhost", [container.name])
}

has_seccomp_profile(pod_spec) if {
    pod_spec.securityContext.seccompProfile.type
}

has_container_seccomp(container) if {
    container.securityContext.seccompProfile.type
}

# -----------------------------------------------------------------------------
# 11. APPARMOR PROFILE (Medium Severity)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    not has_apparmor_annotation(container.name)
    msg := sprintf("MEDIUM: Container '%s' missing AppArmor profile annotation", [container.name])
}

has_apparmor_annotation(container_name) if {
    annotations := input.metadata.annotations
    annotation_key := sprintf("container.apparmor.security.beta.kubernetes.io/%s", [container_name])
    annotations[annotation_key]
}

# -----------------------------------------------------------------------------
# 12. DEFAULT NAMESPACE (Medium Severity)
# -----------------------------------------------------------------------------
deny contains msg if {
    not input.metadata.namespace
    msg := sprintf("MEDIUM: Resource '%s' has no namespace - will default to 'default' namespace", [input.metadata.name])
}

deny contains msg if {
    input.metadata.namespace == "default"
    msg := sprintf("MEDIUM: Resource '%s' uses 'default' namespace - should use dedicated namespace", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 13. RESOURCE LIMITS (Medium Severity)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    not has_cpu_limit(container)
    msg := sprintf("MEDIUM: Container '%s' has no CPU limit - can starve other workloads", [container.name])
}

deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    not has_memory_limit(container)
    msg := sprintf("MEDIUM: Container '%s' has no memory limit - can cause OOM issues", [container.name])
}

deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    not has_cpu_request(container)
    msg := sprintf("LOW: Container '%s' has no CPU request - may affect scheduling", [container.name])
}

deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    not has_memory_request(container)
    msg := sprintf("LOW: Container '%s' has no memory request - may affect scheduling", [container.name])
}

has_cpu_limit(container) if {
    container.resources.limits.cpu
}

has_memory_limit(container) if {
    container.resources.limits.memory
}

has_cpu_request(container) if {
    container.resources.requests.cpu
}

has_memory_request(container) if {
    container.resources.requests.memory
}

# -----------------------------------------------------------------------------
# 14. IMAGE TAG LATEST (Low Severity)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := all_containers[_]
    uses_latest_tag(container.image)
    msg := sprintf("LOW: Container '%s' uses 'latest' tag or no tag - use specific version tags", [container.name])
}

uses_latest_tag(image) if {
    endswith(image, ":latest")
}

uses_latest_tag(image) if {
    not contains(image, ":")
}

# -----------------------------------------------------------------------------
# 15. LIVENESS/READINESS PROBES (Low Severity)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet"]
    container := all_containers[_]
    not container.livenessProbe
    msg := sprintf("LOW: Container '%s' has no liveness probe - may not restart on failure", [container.name])
}

deny contains msg if {
    input.kind in ["Deployment", "StatefulSet"]
    container := all_containers[_]
    not container.readinessProbe
    msg := sprintf("LOW: Container '%s' has no readiness probe - traffic may route to unhealthy pods", [container.name])
}

# -----------------------------------------------------------------------------
# 16. SERVICE ACCOUNT TOKEN (Medium Severity)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    pod_spec := get_pod_spec
    not blocks_sa_token_mount(pod_spec)
    uses_default_sa(pod_spec)
    msg := "MEDIUM: Default service account with automounted token - set automountServiceAccountToken: false"
}

blocks_sa_token_mount(pod_spec) if {
    pod_spec.automountServiceAccountToken == false
}

uses_default_sa(pod_spec) if {
    not pod_spec.serviceAccountName
}

uses_default_sa(pod_spec) if {
    pod_spec.serviceAccountName == "default"
}

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------

# Get pod spec based on resource kind
get_pod_spec := input.spec if {
    input.kind == "Pod"
}

get_pod_spec := input.spec.template.spec if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"]
}

get_pod_spec := input.spec.jobTemplate.spec.template.spec if {
    input.kind == "CronJob"
}

# Get all containers (regular + init)
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
