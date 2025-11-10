package main

__doc__ := {
  "summary": "Harden Linux capabilities (drop ALL; avoid adds)",
  "category": "pod-security",
}

# Any container that adds capabilities
deny contains msg if {
  input.kind == "Pod"
  some i
  c := input.spec.containers[i]
  c.securityContext.capabilities.add[_]
  msg := sprintf("container %q adds Linux capabilities", [default_name(c.name)])
}

deny contains msg if {
  input.kind == "Pod"
  some i
  c := input.spec.initContainers[i]
  c.securityContext.capabilities.add[_]
  msg := sprintf("init container %q adds Linux capabilities", [default_name(c.name)])
}

# Ensure drop ALL exists
deny contains msg if {
  input.kind == "Pod"
  some i
  c := input.spec.containers[i]
  not has_drop_all(c)
  msg := sprintf("container %q must drop ALL Linux capabilities", [default_name(c.name)])
}

deny contains msg if {
  input.kind == "Pod"
  some i
  c := input.spec.initContainers[i]
  not has_drop_all(c)
  msg := sprintf("init container %q must drop ALL Linux capabilities", [default_name(c.name)])
}

has_drop_all(c) = true if {
  some i
  regex.match("(?i)^all$", c.securityContext.capabilities.drop[i])
}

default_name(n) = n if {
  n
}

default_name(n) = "(unnamed)" if {
  not n
}
