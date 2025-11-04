# network_policy_selector.rego
package safefixk8s.network_policy_selector

# Deny when a network policy has no valid top‑level selector or uses
# unsupported selector fields.  Both Calico and Kubernetes network
# policies require either `selector` (Calico) or `podSelector` (Kubernetes)
# to match a set of pods.  Misconfigured selectors can result in a
# policy that matches no pods and therefore offers no protection.

__rego_metadata__ := {
  "id": "SAFENET001",
  "title": "NetworkPolicy must define a valid selector",
  "severity": "medium",
  "type": "OPAPolicy",
  "description": "Ensure that every NetworkPolicy defines a valid pod selector and does not use unsupported fields such as endpointSelector.",
}

# Helper to determine if a valid selector field is present on the policy.
valid_selector_field if {
  input.spec.selector
}

valid_selector_field if {
  input.spec.podSelector
}

# Deny if neither selector nor podSelector is present.
deny contains msg if {
  input.kind == "NetworkPolicy"
  not valid_selector_field
  msg := sprintf("NetworkPolicy %s: a pod selector must be defined using either 'selector' or 'podSelector'", [input.metadata.name])
}

# Deny when endpointSelector is used instead of the supported fields.  Calico
# policies should embed the selector in the top level and should not use
# endpointSelector under ingress or egress rules.
deny contains msg if {
  input.kind == "NetworkPolicy"
  some i
  input.spec.egress[i].source.endpointSelector
  msg := sprintf("NetworkPolicy %s: 'endpointSelector' is not a valid field; use 'selector' or 'podSelector' instead", [input.metadata.name])
}

deny contains msg if {
  input.kind == "NetworkPolicy"
  some i
  input.spec.ingress[i].source.endpointSelector
  msg := sprintf("NetworkPolicy %s: 'endpointSelector' is not a valid field; use 'selector' or 'podSelector' instead", [input.metadata.name])
}
