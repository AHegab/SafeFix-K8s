import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from LLMs.multi_llm_orchestrator import _apply_hygiene

sample = """
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
  initContainers:
  - name: init
    image: busybox:latest
    command: ["sh", "-c", "echo hi"]
"""

new_text, applied = _apply_hygiene(sample, "PRIVILEGED")
print("Applied ("+str(len(applied))+'):\n' + '\n'.join(' - ' + a for a in applied))
print("\nResulting YAML:\n" + new_text)
