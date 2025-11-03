package kubernetes.rbac_security

import rego.v1

# =============================================================================
# RBAC SECURITY POLICIES
# Detect overly permissive roles and dangerous RBAC configurations
# =============================================================================

# -----------------------------------------------------------------------------
# 1. WILDCARD VERBS (Critical)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Role", "ClusterRole"]
    rule := input.rules[_]
    verb := rule.verbs[_]
    verb == "*"
    msg := sprintf("CRITICAL: Role '%s' grants wildcard verbs (*) - violates least privilege", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 2. WILDCARD RESOURCES (Critical)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Role", "ClusterRole"]
    rule := input.rules[_]
    resource := rule.resources[_]
    resource == "*"
    msg := sprintf("CRITICAL: Role '%s' grants access to all resources (*) - overly permissive", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 3. WILDCARD API GROUPS (High)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Role", "ClusterRole"]
    rule := input.rules[_]
    apiGroup := rule.apiGroups[_]
    apiGroup == "*"
    msg := sprintf("HIGH: Role '%s' grants access to all API groups (*) - scope should be limited", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 4. DANGEROUS VERBS (High)
# -----------------------------------------------------------------------------
dangerous_verbs := ["delete", "deletecollection", "escalate", "bind", "impersonate", "create", "update", "patch"]

deny contains msg if {
    input.kind in ["Role", "ClusterRole"]
    rule := input.rules[_]
    verb := rule.verbs[_]
    some dangerous in dangerous_verbs
    verb == dangerous
    resource := rule.resources[_]
    is_sensitive_resource(resource)
    msg := sprintf("HIGH: Role '%s' grants '%s' on sensitive resource '%s'", [input.metadata.name, verb, resource])
}

# -----------------------------------------------------------------------------
# 5. SENSITIVE RESOURCES (High)
# -----------------------------------------------------------------------------
sensitive_resources := [
    "secrets", "configmaps", "serviceaccounts", 
    "roles", "clusterroles", "rolebindings", "clusterrolebindings",
    "pods/exec", "pods/attach", "pods/portforward"
]

is_sensitive_resource(resource) if {
    some sensitive in sensitive_resources
    resource == sensitive
}

# -----------------------------------------------------------------------------
# 6. CLUSTER-ADMIN ROLE USAGE (Critical)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["RoleBinding", "ClusterRoleBinding"]
    input.roleRef.name == "cluster-admin"
    subject := input.subjects[_]
    msg := sprintf("CRITICAL: Binding '%s' grants cluster-admin to '%s' - full cluster access", [input.metadata.name, subject.name])
}

# -----------------------------------------------------------------------------
# 7. SYSTEM:MASTERS GROUP (Critical)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["RoleBinding", "ClusterRoleBinding"]
    subject := input.subjects[_]
    subject.name == "system:masters"
    msg := sprintf("CRITICAL: Binding '%s' grants permissions to system:masters group", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 8. PODS/EXEC PERMISSION (High)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Role", "ClusterRole"]
    rule := input.rules[_]
    resource := rule.resources[_]
    resource == "pods/exec"
    verb := rule.verbs[_]
    verb in ["create", "*"]
    msg := sprintf("HIGH: Role '%s' allows exec into pods - potential privilege escalation", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 9. WILDCARD RESOURCE NAMES (Medium)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Role", "ClusterRole"]
    rule := input.rules[_]
    resourceName := rule.resourceNames[_]
    resourceName == "*"
    msg := sprintf("MEDIUM: Role '%s' uses wildcard resource names - should specify exact resources", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 10. MULTIPLE DANGEROUS VERBS (High)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Role", "ClusterRole"]
    rule := input.rules[_]
    dangerous_count := count([v | v := rule.verbs[_]; v in dangerous_verbs])
    dangerous_count > 2
    msg := sprintf("HIGH: Role '%s' has %d dangerous verbs in single rule - likely overly permissive", [input.metadata.name, dangerous_count])
}

# -----------------------------------------------------------------------------
# 11. SECRET ACCESS WITH WRITE (High)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind in ["Role", "ClusterRole"]
    rule := input.rules[_]
    resource := rule.resources[_]
    resource == "secrets"
    verb := rule.verbs[_]
    verb in ["create", "update", "patch", "delete", "*"]
    msg := sprintf("HIGH: Role '%s' can modify secrets - should be read-only if possible", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 12. CLUSTERROLE WITH DEFAULT NAMESPACE (Medium)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "ClusterRoleBinding"
    subject := input.subjects[_]
    subject.namespace == "default"
    msg := sprintf("MEDIUM: ClusterRoleBinding '%s' references subject in 'default' namespace", [input.metadata.name])
}
