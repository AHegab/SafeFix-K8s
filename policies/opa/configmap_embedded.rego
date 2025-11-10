package k8s.configmap_embedded

deny contains msg if {
  input.kind == "ConfigMap"
  not allow_embedded
  some k
  v := input.data[k]
  suspicious(v)
  msg := sprintf("ConfigMap %q embeds potential secret in key %q (value redacted)", [input.metadata.name, k])
}

allow_embedded if {
  ann := input.metadata.annotations
  ann != null
  ann["safefixk8s.io/allow-embedded"] == "true"
}

suspicious(v) if {
  regex.match("(?i)(password|token|secret|apikey|api_key|access[_-]?key|private[_-]?key|credential)", sprintf("%v", [v]))
}
