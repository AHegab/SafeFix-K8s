package k8s.dynamic_ports

deny contains msg if {
  input.kind == "Pod"
  input.spec.hostNetwork == true
  not has_any_container_port
  msg := sprintf("Pod %q uses hostNetwork without explicit containerPort(s) — dynamic/ephemeral ports likely", [input.metadata.name])
}

has_any_container_port if {
  some i, j
  c := input.spec.containers[i]
  c.ports[j].containerPort > 0
}

has_any_container_port if {
  some i, j
  c := input.spec.initContainers[i]
  c.ports[j].containerPort > 0
}
