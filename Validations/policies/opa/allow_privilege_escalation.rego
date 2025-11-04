package kubernetes.privilege

# For Pods and controllers, deny containers that set allowPrivilegeEscalation=true
deny contains msg if {
  input.kind == "Pod"
  some i
  container := input.spec.containers[i]
  container.securityContext.allowPrivilegeEscalation == true
  name := input.metadata.name
  msg := sprintf("%s: container %v sets allowPrivilegeEscalation=true", [name, container.name])
}

deny contains msg if {
  input.kind == "Pod"
  some i
  container := input.spec.initContainers[i]
  container.securityContext.allowPrivilegeEscalation == true
  name := input.metadata.name
  msg := sprintf("%s: init container %v sets allowPrivilegeEscalation=true", [name, container.name])
}

deny contains msg if {
  input.kind != "Pod"
  ps := input.spec.template.spec
  some i
  container := ps.containers[i]
  container.securityContext.allowPrivilegeEscalation == true
  name := input.metadata.name
  msg := sprintf("%s: container %v sets allowPrivilegeEscalation=true", [name, container.name])
}

deny contains msg if {
  input.kind != "Pod"
  ps := input.spec.template.spec
  some i
  container := ps.initContainers[i]
  container.securityContext.allowPrivilegeEscalation == true
  name := input.metadata.name
  msg := sprintf("%s: init container %v sets allowPrivilegeEscalation=true", [name, container.name])
}
