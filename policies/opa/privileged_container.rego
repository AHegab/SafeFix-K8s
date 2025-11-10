package kubernetes.privileged

workload_kinds := ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]

# Deny privileged containers in pod specs (exclude non-workload kinds like Role/ClusterRole)
deny contains msg if {
  input.kind == "Pod"
  some i
  c := input.spec.containers[i]
  c.securityContext.privileged == true
  name := input.metadata.name
  msg := sprintf("%s: container %v is privileged", [name, c.name])
}

deny contains msg if {
  input.kind == "Pod"
  some i
  c := input.spec.initContainers[i]
  c.securityContext.privileged == true
  name := input.metadata.name
  msg := sprintf("%s: init container %v is privileged", [name, c.name])
}

deny contains msg if {
  input.kind in workload_kinds
  input.kind != "Pod"
  ps := get_pod_spec
  some i
  c := ps.containers[i]
  c.securityContext.privileged == true
  name := input.metadata.name
  msg := sprintf("%s: container %v is privileged", [name, c.name])
}

deny contains msg if {
  input.kind in workload_kinds
  input.kind != "Pod"
  ps := get_pod_spec
  some i
  c := ps.initContainers[i]
  c.securityContext.privileged == true
  name := input.metadata.name
  msg := sprintf("%s: init container %v is privileged", [name, c.name])
}

# Helper to get pod spec for controllers
get_pod_spec := input.spec.template.spec if {
  input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]
}
get_pod_spec := input.spec.jobTemplate.spec.template.spec if {
  input.kind == "CronJob"
}

