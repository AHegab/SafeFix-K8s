package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# Deny if no network policy is defined for the namespace
deny contains msg if {
    input.kind == "Deployment"
    not has_network_policy
    msg := sprintf("%s: no NetworkPolicy defined for workload", [input.metadata.name])
}

deny contains msg if {
    input.kind == "Pod"
    not has_network_policy
    msg := sprintf("%s: no NetworkPolicy defined for pod", [input.metadata.name])
}

deny contains msg if {
    input.kind == "StatefulSet"
    not has_network_policy
    msg := sprintf("%s: no NetworkPolicy defined for workload", [input.metadata.name])
}

deny contains msg if {
    input.kind == "DaemonSet"
    not has_network_policy
    msg := sprintf("%s: no NetworkPolicy defined for workload", [input.metadata.name])
}

# Helper to check if network policy exists (simplified - assumes it should exist)
has_network_policy if {
    # In a real scenario, this would check if a NetworkPolicy exists
    # For now, we deny if it's not explicitly defined in the same file
    false
}
