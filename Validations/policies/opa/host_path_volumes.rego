package main

__doc__ := {
  "summary": "Disallow hostPath volumes (incl. docker.sock)",
  "category": "filesystem",
}

deny contains msg if {
  ps := podspec(input)
  v := ps.volumes[_]
  v.hostPath
  hp := v.hostPath.path
  msg := sprintf("hostPath volume disallowed: %q", [hp])
}

deny contains msg if {
  ps := podspec(input)
  v := ps.volumes[_]
  v.hostPath
  regex.match("(?i)/var/run/docker\\.sock", v.hostPath.path)
  msg := "Mounting docker.sock is disallowed"
}

podspec(obj) = obj.spec if {
  obj.kind == "Pod"
}

podspec(obj) = obj.spec.jobTemplate.spec.template.spec if {
  obj.kind == "CronJob"
}

podspec(obj) = obj.spec.template.spec if {
  obj.kind != "Pod"
  obj.kind != "CronJob"
}
