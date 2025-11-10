package main

__doc__ := {
  "summary": "Disallow hostNetwork, hostPID, and hostIPC",
  "category": "pod-security",
}

deny contains msg if {
  ps := podspec(input)
  ps.hostNetwork == true
  msg := "hostNetwork must be false"
}

deny contains msg if {
  ps := podspec(input)
  ps.hostPID == true
  msg := "hostPID must be false"
}

deny contains msg if {
  ps := podspec(input)
  ps.hostIPC == true
  msg := "hostIPC must be false"
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