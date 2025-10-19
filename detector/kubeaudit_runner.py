import subprocess, json, os, shutil
from pathlib import Path

def _run(cmd): 
    return subprocess.run(cmd, capture_output=True, text=True)

def _docker_available():
    return shutil.which("docker") is not None

def run_kubeaudit(input_path: str, output_path: str):
    os.makedirs(output_path, exist_ok=True)
    out_file = os.path.join(output_path, "kubeaudit_raw.json")

    repo_root = Path(__file__).resolve().parents[1]
    local_exe = repo_root / "tools" / ("kubeaudit.exe" if os.name == "nt" else "kubeaudit")
    input_abs = str(Path(input_path).resolve())

    if local_exe.exists():
        res = _run([str(local_exe), "all", "-f", input_abs, "-o", "json"])
    elif shutil.which("kubeaudit"):
        res = _run(["kubeaudit", "all", "-f", input_abs, "-o", "json"])
    elif _docker_available():
        repo_abs = str(repo_root.resolve())
        rel = str(Path(input_abs).resolve()).replace(repo_abs, "").lstrip("\\/").replace("\\", "/")
        res = _run([
            "docker","run","--rm","-v",f"{repo_abs}:/work:ro",
            "ghcr.io/shopify/kubeaudit:latest",
            "all","-f", f"/work/{rel}" if rel else "/work", "-o","json"
        ])
    else:
        raise RuntimeError("kubeaudit not found (tools/kubeaudit.exe, PATH) and Docker not available.")

    if res.returncode != 0:
        raise RuntimeError(f"kubeaudit failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")

    data = json.loads(res.stdout)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Raw results saved to {out_file}")
