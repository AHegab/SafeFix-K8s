# env_port_mismatch.rego
package safefixk8s.env_port_mismatch

# Detect containers that reference port numbers via environment variables
# but do not declare matching container ports.  Exposing ports that are not
# declared in the PodSpec can lead to unexpected or unused ports being open.
# This policy flags environment variables with names ending in "_PORT" when
# the referenced port is not listed in the container's ports array.

__rego_metadata__ := {
  "id": "SAFEPORT001",
  "title": "Environment port variables must have matching container ports",
  "severity": "low",
  "type": "OPAPolicy",
  "description": "Ensures that any environment variable ending with '_PORT' references a port that is explicitly exposed via containerPort.",
}

deny contains msg if {
  input.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet"]
  some container in get_containers(input)
  some env in container.env
  endswith(env.name, "_PORT")
  not port_declared(container, env.value)
  msg := sprintf("Container %s: environment variable %s refers to port %s but no matching containerPort is declared", [container.name, env.name, env.value])
}

# Helper to iterate over all containers across workload types
get_containers(obj) := obj.spec.containers if {
  obj.kind == "Pod"
}

get_containers(obj) := obj.spec.template.spec.containers if {
  obj.kind in ["Deployment", "StatefulSet", "DaemonSet"]
}

# Helper to check if a port is declared in container.ports
port_declared(container, port) if {
  some p in container.ports
  sprintf("%v", [p.containerPort]) == sprintf("%v", [port])
}
