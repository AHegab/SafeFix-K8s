package kubernetes.configmap_embedded

# set of risky keys we want to catch anywhere inside parsed data blobs
bad_keys = {"privileged", "allowPrivilegeEscalation"}

# ---- YAML path ---------------------------------------------------------------

deny[msg] {
  input.kind == "ConfigMap"
  some k
  v := input.data[k]
  parsed := yaml.unmarshal(v)
  is_object(parsed)
  walk(parsed, [p, val])
  some i
  key := p[i]
  bad_keys[key]
  val == true
  msg := sprintf("ConfigMap %q data[%q] contains %q: true (YAML)", [input.metadata.name, k, key])
}

# ---- JSON path ---------------------------------------------------------------

deny[msg] {
  input.kind == "ConfigMap"
  some k
  v := input.data[k]
  parsed := json.unmarshal(v)
  is_object(parsed)
  walk(parsed, [p, val])
  some i
  key := p[i]
  bad_keys[key]
  val == true
  msg := sprintf("ConfigMap %q data[%q] contains %q: true (JSON)", [input.metadata.name, k, key])
}

# ---- Optional: flag embedded hostPath anywhere in the blob -------------------

deny[msg] {
  input.kind == "ConfigMap"
  some k
  v := input.data[k]
  parsed := yaml.unmarshal(v)
  is_object(parsed)
  walk(parsed, [p, _])
  "hostPath" == p[_]
  msg := sprintf("ConfigMap %q data[%q] embeds a hostPath volume (YAML)", [input.metadata.name, k])
}

deny[msg] {
  input.kind == "ConfigMap"
  some k
  v := input.data[k]
  parsed := json.unmarshal(v)
  is_object(parsed)
  walk(parsed, [p, _])
  "hostPath" == p[_]
  msg := sprintf("ConfigMap %q data[%q] embeds a hostPath volume (JSON)", [input.metadata.name, k])
}
