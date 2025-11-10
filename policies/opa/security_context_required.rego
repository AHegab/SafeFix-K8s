package kubernetes.securitycontext

# Restrict workload-focused checks to workload kinds only (exclude RBAC, ConfigMap, Secret, etc.)
workload_kinds := ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]

deny contains msg if {
  input.kind in workload_kinds
  some c
  containers := get_containers
  container := containers[c]
  not container.securityContext
  msg := sprintf("%s: missing securityContext", [input.metadata.name])
}

deny contains msg if {
  input.kind in workload_kinds
  some c
  containers := get_containers
  container := containers[c]
  not container.securityContext.runAsNonRoot
  msg := sprintf("%s: must set runAsNonRoot: true", [input.metadata.name])
}

# Helper to extract containers for both Pod and controller workloads
get_containers := input.spec.containers if {
  input.kind == "Pod"
}
get_containers := input.spec.template.spec.containers if {
  input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]
}
get_containers := input.spec.jobTemplate.spec.template.spec.containers if {
  input.kind == "CronJob"
}
