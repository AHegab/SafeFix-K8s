package kubernetes.privileged

# Deny privileged containers in Pods and workload templates
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
  input.kind != "Pod"
  ps := input.spec.template.spec
  some i
  c := ps.containers[i]
  c.securityContext.privileged == true
  name := input.metadata.name
  msg := sprintf("%s: container %v is privileged", [name, c.name])
}

deny contains msg if {
  input.kind != "Pod"
  ps := input.spec.template.spec
  some i
  c := ps.initContainers[i]
  c.securityContext.privileged == true
  name := input.metadata.name
  msg := sprintf("%s: init container %v is privileged", [name, c.name])
}

