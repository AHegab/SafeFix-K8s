package kubernetes.calico.networkpolicy

# Semantic validations for Calico NetworkPolicy (crd.projectcalico.org/v1).
# Goals:
# - Forbid endpointSelector fields under source/destination (use 'selector').
# - Ensure spec.selector is present.
# - Validate rule.action is one of [Allow, Deny, Log].
# - Sanity-check ports range when numeric.

is_calico_np if {
  lower(input.apiVersion) == "crd.projectcalico.org/v1"
  input.kind == "NetworkPolicy"
}

# 1) endpointSelector is not a valid field under source/destination in Calico NP rules

deny contains msg if {
  is_calico_np
  some i
  r := input.spec.egress[i]
  r.source.endpointSelector
  msg := sprintf("Calico NetworkPolicy %q: use 'selector' (not 'endpointSelector') under egress.source", [input.metadata.name])
}

deny contains msg if {
  is_calico_np
  some i
  r := input.spec.egress[i]
  r.destination.endpointSelector
  msg := sprintf("Calico NetworkPolicy %q: use 'selector' (not 'endpointSelector') under egress.destination", [input.metadata.name])
}

deny contains msg if {
  is_calico_np
  some i
  r := input.spec.ingress[i]
  r.source.endpointSelector
  msg := sprintf("Calico NetworkPolicy %q: use 'selector' (not 'endpointSelector') under ingress.source", [input.metadata.name])
}

deny contains msg if {
  is_calico_np
  some i
  r := input.spec.ingress[i]
  r.destination.endpointSelector
  msg := sprintf("Calico NetworkPolicy %q: use 'selector' (not 'endpointSelector') under ingress.destination", [input.metadata.name])
}

# 2) Require top-level selector present

deny contains msg if {
  is_calico_np
  not input.spec.selector
  msg := sprintf("Calico NetworkPolicy %q: spec.selector is required", [input.metadata.name])
}

# 3) Validate rule action

valid_action(a) if {
  a == "Allow"
}
valid_action(a) if {
  a == "Deny"
}
valid_action(a) if {
  a == "Log"
}

deny contains msg if {
  is_calico_np
  some i
  r := input.spec.egress[i]
  r.action
  not valid_action(r.action)
  msg := sprintf("Calico NetworkPolicy %q: invalid egress.action %q (expected Allow|Deny|Log)", [input.metadata.name, r.action])
}

deny contains msg if {
  is_calico_np
  some i
  r := input.spec.ingress[i]
  r.action
  not valid_action(r.action)
  msg := sprintf("Calico NetworkPolicy %q: invalid ingress.action %q (expected Allow|Deny|Log)", [input.metadata.name, r.action])
}

# 4) Ports sanity (numeric in range 1..65535)

num(x) := n if {
  n := to_number(sprintf("%v", [x]))
}

in_range(p) if {
  is_number(p)
  n := num(p)
  n >= 1
  n <= 65535
}

deny contains msg if {
  is_calico_np
  some i, j
  r := input.spec.egress[i]
  p := r.destination.ports[j]
  is_number(p)
  not in_range(p)
  msg := sprintf("Calico NetworkPolicy %q: egress.destination.port %v out of range (1-65535)", [input.metadata.name, p])
}

deny contains msg if {
  is_calico_np
  some i, j
  r := input.spec.ingress[i]
  p := r.destination.ports[j]
  is_number(p)
  not in_range(p)
  msg := sprintf("Calico NetworkPolicy %q: ingress.destination.port %v out of range (1-65535)", [input.metadata.name, p])
}
