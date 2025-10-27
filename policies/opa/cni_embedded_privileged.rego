# policies/opa/cni_embedded_privileged.rego
package kubernetes.configmap.cni

parse_any(s) := obj if { not is_null(s); yaml.unmarshal(s, obj) } 
parse_any(s) := obj if { not is_null(s); json.unmarshal(s, obj) }

is_null(x) if { x == null }
is_null(x) if { x == "" }

deny contains msg if {
  input.kind == "ConfigMap"
  conf := input.data["cni.conf"]
  parsed := parse_any(conf)
  parsed.cni.privileged == true
  msg := sprintf("CNI config in %q/%q has privileged=true", [input.metadata.namespace, input.metadata.name])
}

# generic fallback – finds privileged: true anywhere in embedded content
deny contains msg if {
  input.kind == "ConfigMap"
  some k
  v := input.data[k]
  parsed := parse_any(v)
  some p; walk(parsed, [p, val]); p[_] == "privileged"; val == true
  msg := sprintf("Embedded config %q in %q/%q has privileged=true", [k, input.metadata.name, input.metadata.namespace])
}
