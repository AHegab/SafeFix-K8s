package kubernetes.probes

deny contains msg if {
  input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet"]
  some c
  container := input.spec.template.spec.containers[c]
  not container.livenessProbe
  msg := sprintf("%s: missing livenessProbe", [input.metadata.name])
}

deny contains msg if {
  input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet"]
  some c
  container := input.spec.template.spec.containers[c]
  not container.readinessProbe
  msg := sprintf("%s: missing readinessProbe", [input.metadata.name])
}
