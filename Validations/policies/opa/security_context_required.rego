package kubernetes.securitycontext

deny contains msg if {
  kind := input.kind
  kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet"]
  some c
  container := input.spec.template.spec.containers[c]
  not container.securityContext
  msg := sprintf("%s: missing securityContext", [input.metadata.name])
}

deny contains msg if {
  kind := input.kind
  kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet"]
  some c
  container := input.spec.template.spec.containers[c]
  not container.securityContext.runAsNonRoot
  msg := sprintf("%s: must set runAsNonRoot: true", [input.metadata.name])
}
