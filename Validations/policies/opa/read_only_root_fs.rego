package main

__doc__ := {
  "summary": "Require readOnlyRootFilesystem=true",
  "category": "pod-security",
}

# Pod containers
deny contains msg if {
  input.kind == "Pod"
  some i
  c := input.spec.containers[i]
  not c.securityContext
  msg := sprintf("container %q must set readOnlyRootFilesystem=true", [default_name(c.name)])
}

deny contains msg if {
  input.kind == "Pod"
  some i
  c := input.spec.containers[i]
  c.securityContext
  c.securityContext.readOnlyRootFilesystem != true
  msg := sprintf("container %q must set readOnlyRootFilesystem=true", [default_name(c.name)])
}

# Pod initContainers
deny contains msg if {
  input.kind == "Pod"
  input.spec.initContainers
  some i
  c := input.spec.initContainers[i]
  not c.securityContext
  msg := sprintf("init container %q must set readOnlyRootFilesystem=true", [default_name(c.name)])
}

deny contains msg if {
  input.kind == "Pod"
  input.spec.initContainers
  some i
  c := input.spec.initContainers[i]
  c.securityContext
  c.securityContext.readOnlyRootFilesystem != true
  msg := sprintf("init container %q must set readOnlyRootFilesystem=true", [default_name(c.name)])
}

# Template containers
deny contains msg if {
  input.kind != "Pod"
  some i
  c := input.spec.template.spec.containers[i]
  not c.securityContext
  msg := sprintf("container %q must set readOnlyRootFilesystem=true", [default_name(c.name)])
}

deny contains msg if {
  input.kind != "Pod"
  some i
  c := input.spec.template.spec.containers[i]
  c.securityContext
  c.securityContext.readOnlyRootFilesystem != true
  msg := sprintf("container %q must set readOnlyRootFilesystem=true", [default_name(c.name)])
}

# Template initContainers
deny contains msg if {
  input.kind != "Pod"
  input.spec.template.spec.initContainers
  some i
  c := input.spec.template.spec.initContainers[i]
  not c.securityContext
  msg := sprintf("init container %q must set readOnlyRootFilesystem=true", [default_name(c.name)])
}

deny contains msg if {
  input.kind != "Pod"
  input.spec.template.spec.initContainers
  some i
  c := input.spec.template.spec.initContainers[i]
  c.securityContext
  c.securityContext.readOnlyRootFilesystem != true
  msg := sprintf("init container %q must set readOnlyRootFilesystem=true", [default_name(c.name)])
}

default_name(n) = n if {
  n
}

default_name(n) = "(unnamed)" if {
  not n
}
