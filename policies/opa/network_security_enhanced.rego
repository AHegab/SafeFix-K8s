package kubernetes.network_security

import rego.v1

# =============================================================================
# NETWORK SECURITY POLICIES
# Detect missing or misconfigured NetworkPolicies
# =============================================================================

# -----------------------------------------------------------------------------
# 1. NETWORK POLICY MISSING SELECTORS (High)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "NetworkPolicy"
    not input.spec.podSelector
    msg := sprintf("HIGH: NetworkPolicy '%s' missing podSelector - policy won't apply to any pods", [input.metadata.name])
}

deny contains msg if {
    input.kind == "NetworkPolicy"
    count(input.spec.podSelector.matchLabels) == 0
    not input.spec.podSelector.matchExpressions
    msg := sprintf("MEDIUM: NetworkPolicy '%s' has empty podSelector - applies to ALL pods in namespace (may be intentional)", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 2. ALLOW ALL INGRESS (Medium)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "NetworkPolicy"
    ingress := input.spec.ingress[_]
    not ingress.from
    msg := sprintf("MEDIUM: NetworkPolicy '%s' allows all ingress traffic - should restrict sources", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 3. ALLOW ALL EGRESS (Medium)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "NetworkPolicy"
    egress := input.spec.egress[_]
    not egress.to
    msg := sprintf("MEDIUM: NetworkPolicy '%s' allows all egress traffic - should restrict destinations", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 4. NO POLICY TYPES SPECIFIED (Medium)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "NetworkPolicy"
    not input.spec.policyTypes
    msg := sprintf("MEDIUM: NetworkPolicy '%s' does not specify policyTypes - defaults may be unclear", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 5. MISSING NAMESPACE IN PEER (Low)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "NetworkPolicy"
    peer := input.spec.ingress[_].from[_]
    peer.podSelector
    not peer.namespaceSelector
    msg := sprintf("LOW: NetworkPolicy '%s' ingress rule has podSelector without namespaceSelector - only matches same namespace", [input.metadata.name])
}

deny contains msg if {
    input.kind == "NetworkPolicy"
    peer := input.spec.egress[_].to[_]
    peer.podSelector
    not peer.namespaceSelector
    msg := sprintf("LOW: NetworkPolicy '%s' egress rule has podSelector without namespaceSelector - only matches same namespace", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 6. OVERLY BROAD NAMESPACE SELECTOR (Medium)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "NetworkPolicy"
    peer := input.spec.ingress[_].from[_]
    count(peer.namespaceSelector.matchLabels) == 0
    not peer.namespaceSelector.matchExpressions
    not peer.podSelector
    msg := sprintf("MEDIUM: NetworkPolicy '%s' allows traffic from all namespaces - overly permissive", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# 7. PORT RANGE TOO WIDE (Low)
# -----------------------------------------------------------------------------
deny contains msg if {
    input.kind == "NetworkPolicy"
    port := get_all_ports[_]
    port.port == 0
    msg := sprintf("LOW: NetworkPolicy '%s' allows all ports (0) - should specify exact ports", [input.metadata.name])
}

get_all_ports contains port if {
    port := input.spec.ingress[_].ports[_]
}

get_all_ports contains port if {
    port := input.spec.egress[_].ports[_]
}

# -----------------------------------------------------------------------------
# 8. DEPLOYMENT WITHOUT NETWORK POLICY (Medium)
# -----------------------------------------------------------------------------
# Note: This requires admission controller or periodic scan
deny contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet"]
    not has_network_policy_annotation
    msg := sprintf("MEDIUM: %s '%s' should have NetworkPolicy defined - missing network segmentation", [input.kind, input.metadata.name])
}

has_network_policy_annotation if {
    annotations := input.metadata.annotations
    annotations["network-policy.kubernetes.io/enforced"]
}

# -----------------------------------------------------------------------------
# 9. DEFAULT DENY NOT ENFORCED (Medium)
# -----------------------------------------------------------------------------
# Detect if namespace should have default deny-all policy
deny contains msg if {
    input.kind == "Namespace"
    not has_default_deny_label
    input.metadata.name != "kube-system"
    input.metadata.name != "kube-public"
    input.metadata.name != "kube-node-lease"
    msg := sprintf("MEDIUM: Namespace '%s' should label for default-deny NetworkPolicy enforcement", [input.metadata.name])
}

has_default_deny_label if {
    labels := input.metadata.labels
    labels["enforce-network-policy"] == "true"
}
