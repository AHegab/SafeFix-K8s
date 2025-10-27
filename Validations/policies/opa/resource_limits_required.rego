package kubernetes.resources

deny contains msg if {
  kind := input.kind
  kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet"]
  some c
  container := input.spec.template.spec.containers[c]
  not container.resources.requests.cpu
  msg := sprintf("%s: missing cpu request", [input.metadata.name])
}

deny contains msg if {
  kind := input.kind
  kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet"]
  some c
  container := input.spec.template.spec.containers[c]
  not container.resources.requests.memory
  msg := sprintf("%s: missing memory request", [input.metadata.name])
}

deny contains msg if {
  kind := input.kind
  kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet"]
  some c
  container := input.spec.template.spec.containers[c]
  not container.resources.limits.cpu
  msg := sprintf("%s: missing cpu limit", [input.metadata.name])
}

deny contains msg if {
  kind := input.kind
  kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet"]
  some c
  container := input.spec.template.spec.containers[c]
  not container.resources.limits.memory
  msg := sprintf("%s: missing memory limit", [input.metadata.name])
}
