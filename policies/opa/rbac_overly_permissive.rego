# rbac_overly_permissive.rego
package safefixk8s.rbac_overly_permissive

# Detect RBAC roles that grant overly broad privileges.  Least‑privilege
# guidelines recommend that roles grant only the verbs required for
# operation.  Verbs such as '*' (wildcard) or destructive verbs like
# 'delete', 'patch' or 'update' should be carefully reviewed.

__rego_metadata__ := {
  "id": "SAFERBAC001",
  "title": "RBAC roles should not grant overly permissive verbs",
  "severity": "medium",
  "type": "OPAPolicy",
  "description": "Detects Roles or ClusterRoles that include wildcard verbs or destructive verbs (delete, patch, update) on any resource.",
}

deny contains msg if {
  # Apply to Role or ClusterRole
  input.kind in ["Role", "ClusterRole"]
  some rule in input.rules
  # Wildcard verbs grant all permissions
  rule.verbs[_] == "*"
  msg := sprintf("%s %s: wildcard verbs ('*') are overly permissive on resources %v", [input.kind, input.metadata.name, rule.resources])
}

deny contains msg if {
  input.kind in ["Role", "ClusterRole"]
  some rule in input.rules
  some verb in rule.verbs
  verb == "delete"
  msg := sprintf("%s %s: use of 'delete' verb on resources %v is overly permissive", [input.kind, input.metadata.name, rule.resources])
}

deny contains msg if {
  input.kind in ["Role", "ClusterRole"]
  some rule in input.rules
  some verb in rule.verbs
  verb == "patch"
  msg := sprintf("%s %s: use of 'patch' verb on resources %v is overly permissive", [input.kind, input.metadata.name, rule.resources])
}

deny contains msg if {
  input.kind in ["Role", "ClusterRole"]
  some rule in input.rules
  some verb in rule.verbs
  verb == "update"
  msg := sprintf("%s %s: use of 'update' verb on resources %v is overly permissive", [input.kind, input.metadata.name, rule.resources])
}
