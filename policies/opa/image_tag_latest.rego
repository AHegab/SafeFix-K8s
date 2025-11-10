package main

__doc__ := {
  "summary": "Disallow images using the latest tag or no tag",
  "category": "images",
}

# Pod containers - no tag
deny contains msg if {
  input.kind == "Pod"
  some i
  img := input.spec.containers[i].image
  not regex.match("@sha256:[a-f0-9]{6,}$", img)
  not regex.match(":[^/]+$", img)
  msg := sprintf("image %q has no tag (use immutable tag or digest)", [img])
}

# Pod containers - latest tag
deny contains msg if {
  input.kind == "Pod"
  some i
  img := input.spec.containers[i].image
  regex.match("(?i):latest$", img)
  msg := sprintf("image %q uses the 'latest' tag", [img])
}

# Pod initContainers - no tag
deny contains msg if {
  input.kind == "Pod"
  input.spec.initContainers
  some i
  img := input.spec.initContainers[i].image
  not regex.match("@sha256:[a-f0-9]{6,}$", img)
  not regex.match(":[^/]+$", img)
  msg := sprintf("image %q has no tag (use immutable tag or digest)", [img])
}

# Pod initContainers - latest tag
deny contains msg if {
  input.kind == "Pod"
  input.spec.initContainers
  some i
  img := input.spec.initContainers[i].image
  regex.match("(?i):latest$", img)
  msg := sprintf("image %q uses the 'latest' tag", [img])
}

# Template containers - no tag
deny contains msg if {
  input.kind != "Pod"
  ps := input.spec.template.spec
  some i
  img := ps.containers[i].image
  not regex.match("@sha256:[a-f0-9]{6,}$", img)
  not regex.match(":[^/]+$", img)
  msg := sprintf("image %q has no tag (use immutable tag or digest)", [img])
}

# Template containers - latest tag
deny contains msg if {
  input.kind != "Pod"
  ps := input.spec.template.spec
  some i
  img := ps.containers[i].image
  regex.match("(?i):latest$", img)
  msg := sprintf("image %q uses the 'latest' tag", [img])
}

# Template initContainers - no tag
deny contains msg if {
  input.kind != "Pod"
  ps := input.spec.template.spec
  ps.initContainers
  some i
  img := ps.initContainers[i].image
  not regex.match("@sha256:[a-f0-9]{6,}$", img)
  not regex.match(":[^/]+$", img)
  msg := sprintf("image %q has no tag (use immutable tag or digest)", [img])
}

# Template initContainers - latest tag
deny contains msg if {
  input.kind != "Pod"
  ps := input.spec.template.spec
  ps.initContainers
  some i
  img := ps.initContainers[i].image
  regex.match("(?i):latest$", img)
  msg := sprintf("image %q uses the 'latest' tag", [img])
}
