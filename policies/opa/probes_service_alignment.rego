package kubernetes.probes_alignment

# Enforce that liveness/readiness probe ports reference a defined container port.
# Works for Pod and controller objects (Deployment/StatefulSet/DaemonSet).

deny contains msg if {
  is_workload
  some i
  c := containers[i]
  probe_port := get_probe_port(c)
  not port_defined(c, probe_port)
  msg := sprintf("%s: probe port %v not defined as a containerPort/name", [workload_name, probe_port])
}

is_workload if {
  input.kind == "Pod"
}
is_workload if {
  input.kind == "Deployment"
}
is_workload if {
  input.kind == "StatefulSet"
}
is_workload if {
  input.kind == "DaemonSet"
}

containers[c] if {
  input.kind == "Pod"
  c := input.spec.containers[_]
}
containers[c] if {
  input.kind != "Pod"
  c := input.spec.template.spec.containers[_]
}

workload_name := n if {
  n := input.metadata.name
}

# Extract first available probe port from a container (httpGet or tcpSocket)
get_probe_port(c) := p if {
  p := c.livenessProbe.httpGet.port
}
get_probe_port(c) := p if {
  p := c.readinessProbe.httpGet.port
}
get_probe_port(c) := p if {
  p := c.livenessProbe.tcpSocket.port
}
get_probe_port(c) := p if {
  p := c.readinessProbe.tcpSocket.port
}

# Determine whether the probe port is defined in container ports (by number or name)
port_defined(c, p) if {
  is_number(p)
  some j
  c.ports[j].containerPort == to_number(sprintf("%v", [p]))
}
port_defined(c, p) if {
  some j
  name := lower(sprintf("%v", [p]))
  c.ports[j].name
  lower(c.ports[j].name) == name
}

## no explicit is_string helper; we pivot on not is_number for treating as name

# Optional: Basic Service -> workload targetPort alignment when both objects co-exist in the same input document
# Note: This only activates when the Service and matching Deployment/Pod are present together.

deny contains msg if {
  input.kind == "Service"
  s := input
  some i
  sp := s.spec.ports[i]
  target := target_port(sp)
  d := matching_workload(s)
  not workload_has_port(d, target)
  msg := sprintf("Service %q targetPort %v not found in matching workload containerPorts", [s.metadata.name, target])
}

# Extract numeric or named targetPort

target_port(sp) := p if {
  p := sp.targetPort
}

matching_workload(svc) := d if {
  # Try to find a Deployment whose template labels include the service selector
  some i
  d := data.documents[i]
  d.kind == "Deployment"
  d.metadata.namespace == svc.metadata.namespace
  selector := svc.spec.selector
  subset(selector, d.spec.template.metadata.labels)
}

subset(x, y) if {
  not exists_mismatch(x, y)
}

exists_mismatch(x, y) if {
  some k
  v := x[k]
  not y[k]
}

exists_mismatch(x, y) if {
  some k
  v := x[k]
  y[k]
  y[k] != v
}

workload_has_port(d, p) if {
  is_number(p)
  some i, j
  pn := to_number(sprintf("%v", [p]))
  d.spec.template.spec.containers[i].ports[j].containerPort == pn
}
workload_has_port(d, p) if {
  some i, j
  name := lower(sprintf("%v", [p]))
  d.spec.template.spec.containers[i].ports[j].name
  lower(d.spec.template.spec.containers[i].ports[j].name) == name
}
