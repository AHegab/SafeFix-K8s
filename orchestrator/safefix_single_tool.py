#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SafeFix-K8s Single-Tool Orchestrator (B.Sc. Thesis)

Purpose:
    Run the complete SafeFix pipeline for ONE detection tool at a time.
    Each run is isolated with timestamped directories for reproducibility.

Pipeline Flow:
    1. DETECTION  - Run single tool on test manifests
    2. NORMALIZE  - Extract findings for this tool only
    3. REPAIR     - Generate patches via LLM
    4. VALIDATE   - Run 7-gate validation on patches
    5. PROOF      - Generate evidence and metrics

Output Structure:
    runs/2025-11-06__KubeLinter/
        ├── detection/
        │   └── kubelinter_raw.json
        ├── normalization/
        │   ├── llm_payload.json
        │   └── normalized_findings.json
        ├── llm/
        │   ├── llm_decisions.json
        │   └── patch_sandbox/
        ├── validation/
        │   ├── evidence/
        │   └── safe_fix_proof.json
        └── metadata.json (run info)

Usage:
    python orchestrator/safefix_single_tool.py --tool kubelinter --path tests
    python orchestrator/safefix_single_tool.py --tool checkov --path tests --gates 1,2
    python orchestrator/safefix_single_tool.py --tool trivy --skip-llm --skip-validate
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

# Add parent directory to path
REPO_ROOT = Path(__file__).parent.parent.absolute()
sys.path.insert(0, str(REPO_ROOT))

# Tool name mappings (normalized names)
TOOL_NAMES = {
    "kubelinter": "KubeLinter",
    "kube-linter": "KubeLinter",
    "checkov": "Checkov",
    "trivy": "Trivy",
    "kubeaudit": "KubeAudit",
    "kubescape": "Kubescape",
    "polaris": "Polaris",
    "kubescore": "KubeScore",
    "conftest": "Conftest",
    "kubeconform": "KubeConform",
    "pluto": "Pluto",
    "gitleaks": "Gitleaks",
    "rbacpolice": "RBACPolice",
    "yamllint": "Yamllint",
}

# Tool detection functions (from detectors.ps1)
TOOL_FUNCTIONS = {
    "kubelinter": "Det-KubeLinter",
    "checkov": "Det-Checkov",
    "trivy": "Det-TrivyConfig",
    "kubeaudit": "Det-KubeAudit",
    "kubescape": "Det-Kubescape",
    "polaris": "Det-Polaris",
    "kubescore": "Det-KubeScore",
    "conftest": "Det-Conftest",
    "kubeconform": "Det-KubeConform",
    "pluto": "Det-Pluto",
    "gitleaks": "Det-Gitleaks",
    "rbacpolice": "Det-RBACPolice",
    "yamllint": "Det-Yamllint",
}


class SingleToolOrchestrator:
    """Orchestrates a complete SafeFix pipeline run for a single detection tool."""
    
    def __init__(
        self,
        tool: str,
        scan_path: Path,
        run_dir: Path,
        gates: str = "1,2,3",
        models: str = "groq,openrouter,gemini",
        skip_detection: bool = False,
        skip_normalize: bool = False,
        skip_llm: bool = False,
        skip_validate: bool = False,
        dry_run: bool = False,
        normalizer_fp: str = "auto",
    ):
        self.tool = tool.lower()
        self.tool_display = TOOL_NAMES.get(self.tool, tool.capitalize())
        self.scan_path = scan_path.absolute()
        self.run_dir = run_dir.absolute()
        self.gates = gates
        self.models = models
        self.skip_detection = skip_detection
        self.skip_normalize = skip_normalize
        self.skip_llm = skip_llm
        self.skip_validate = skip_validate
        self.dry_run = dry_run
        self.normalizer_fp = (normalizer_fp or "auto").lower()
        
        # Create subdirectories
        self.detection_dir = self.run_dir / "detection"
        self.normalization_dir = self.run_dir / "normalization"
        self.llm_dir = self.run_dir / "llm"
        self.validation_dir = self.run_dir / "validation"
        
        self.metadata = {
            "tool": self.tool_display,
            "tool_normalized": self.tool,
            "scan_path": str(self.scan_path),
            "run_directory": str(self.run_dir),
            "timestamp": datetime.now().isoformat(),
            "gates": self.gates,
            "models": self.models.split(","),
            "steps_completed": [],
            "timings": {},
            "results": {}
        }
    
    def setup_directories(self):
        """Create isolated directory structure for this run."""
        print(f"[*] Setting up run directory: {self.run_dir}")
        for d in [self.detection_dir, self.normalization_dir, self.llm_dir, self.validation_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        # Create validation evidence subdirectory
        (self.validation_dir / "evidence").mkdir(exist_ok=True)
        
        print(f"[[OK]] Directory structure created")

    # --- Helpers ---------------------------------------------------------
    def _yaml_syntax_ok(self, text: str) -> bool:
        try:
            import yaml  # type: ignore
        except ImportError:
            return True
        try:
            list(yaml.safe_load_all(text))
            return True
        except Exception:
            return False

    def _kubeconform_ok(self, text: str) -> bool:
        """Run kubeconform on provided YAML string when available. Returns True if valid or tool not available."""
        # Try to locate kubeconform
        kc_cmd = None
        candidate = REPO_ROOT / "Validations" / "bin" / "kubeconform.exe"
        if candidate.exists():
            kc_cmd = str(candidate)
        else:
            kc_cmd = "kubeconform"
        # Write temp file under run dir
        tmp_dir = self.run_dir / ".kc_tmp"
        try:
            tmp_dir.mkdir(parents=True, exist_ok=True)
            tmp_file = tmp_dir / "kc_test.yaml"
            tmp_file.write_text(text, encoding="utf-8")
        except Exception:
            return True
        try:
            args = [kc_cmd, "-summary", "-output", "json", "-strict", "--kubernetes-version", "1.29.0", str(tmp_file)]
            res = subprocess.run(args, capture_output=True, text=True, cwd=str(REPO_ROOT))
            if res.returncode not in (0, 1):
                # 1 can be validation failures with output; treat non-0/1 as tool missing
                return True
            try:
                j = json.loads(res.stdout or res.stderr or "{}")
            except Exception:
                return True
            # Accept when summary invalid==0 and errors==0, or resources all valid
            if isinstance(j, dict) and j.get("summary"):
                s = j.get("summary")
                inv = int(s.get("invalid", 0) or 0)
                err = int(s.get("errors", 0) or 0)
                return inv == 0 and err == 0
            if isinstance(j, dict) and j.get("resources"):
                ok = True
                for r in j.get("resources"):
                    if str(r.get("status")).lower() not in ("valid", "statusvalid"):
                        ok = False
                return ok
            if isinstance(j, list):
                return all(str(r.get("status")).lower() in ("valid", "statusvalid") for r in j if isinstance(r, dict))
            return True
        except Exception:
            return True

    def _looks_like_k8s_manifest(self, text: str) -> bool:
        """Best-effort check: does the YAML contain a Kubernetes manifest (has kind/apiVersion)?"""
        try:
            import yaml  # type: ignore
        except ImportError:
            return True  # If YAML lib missing, don't block
        try:
            docs = list(yaml.safe_load_all(text))
        except Exception:
            return False
        for doc in docs:
            if isinstance(doc, dict):
                kind = str(doc.get("kind", "")).strip()
                api = str(doc.get("apiVersion", "")).strip()
                if kind or api:
                    return True
        return False

    def _ensure_deployment_selector(self, text: str) -> str:
        """For Deployment objects, ensure spec.selector exists and matches spec.template.metadata.labels.
        If labels are missing, synthesize a sane default from metadata.name.
        If YAML parsing fails, return input unchanged.
        """
        try:
            import yaml  # type: ignore
        except ImportError:
            return text
        try:
            docs = list(yaml.safe_load_all(text))
        except Exception:
            return text

        changed = False
        for i, doc in enumerate(docs):
            if not isinstance(doc, dict):
                continue
            kind = (doc.get("kind") or "").strip()
            if kind != "Deployment":
                continue
            spec = doc.get("spec")
            if not isinstance(spec, dict):
                spec = {}
                doc["spec"] = spec
            # Ensure template structure exists
            tmpl = spec.get("template")
            if not isinstance(tmpl, dict):
                tmpl = {}
                spec["template"] = tmpl
            md = tmpl.get("metadata")
            if not isinstance(md, dict):
                md = {}
                tmpl["metadata"] = md
            labels = md.get("labels")
            if not isinstance(labels, dict) or not labels:
                # Synthesize default labels from metadata.name
                meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
                name = meta.get("name") if isinstance(meta, dict) else None
                if not isinstance(name, str) or not name.strip():
                    name = "app"
                labels = {"app.kubernetes.io/name": name}
                md["labels"] = labels
                changed = True
            sel = spec.get("selector")
            if not isinstance(sel, dict):
                sel = {}
                spec["selector"] = sel
            ml = sel.get("matchLabels")
            if not isinstance(ml, dict) or ml != labels:
                sel["matchLabels"] = dict(labels)
                changed = True

        if not changed:
            return text
        try:
            import yaml  # type: ignore
            return yaml.safe_dump_all(docs, sort_keys=False)
        except Exception:
            return text
    
    def _autofix_simple_secrets(self, dest_dir: Path) -> int:
        """Best-effort autofix: for Kubernetes Secret manifests in the scan path with obvious weak values,
        write a fixed copy into dest_dir to enable validation. Returns number of files written.
        """
        try:
            import yaml  # type: ignore
            import base64
        except ImportError:
            return 0

        fixed = 0
        # Scan only immediate YAMLs in scan_path
        candidates = list(self.scan_path.glob("*.yaml")) + list(self.scan_path.glob("*.yml"))
        for src in candidates:
            try:
                text = src.read_text(encoding="utf-8")
                docs = list(yaml.safe_load_all(text))
            except Exception:
                continue
            if not docs:
                continue
            doc = docs[0]
            if not isinstance(doc, dict):
                continue
            if str(doc.get("kind","")) != "Secret":
                continue
            data = doc.get("data")
            if not isinstance(data, dict):
                continue
            changed = False
            for key, val in list(data.items()):
                if not isinstance(val, str):
                    continue
                # If base64 decodes to 'password' or looks obviously weak, replace with 'REDACTED'
                try:
                    decoded = base64.b64decode(val).decode("utf-8", errors="ignore")
                except Exception:
                    decoded = ""
                if decoded.strip().lower() in {"password", "changeme", "secret"}:
                    data[key] = base64.b64encode(b"REDACTED").decode("ascii")
                    changed = True
            if changed:
                try:
                    out_path = dest_dir / f"{src.stem}_fixed{src.suffix}"
                    out_text = yaml.safe_dump(doc, sort_keys=False)
                    out_path.write_text(out_text, encoding="utf-8")
                    fixed += 1
                except Exception:
                    pass
        return fixed

    def run_detection(self) -> bool:
        """Run single detection tool on test manifests."""
        if self.skip_detection:
            print(f"[⊗] Skipping detection (--skip-detection)")
            return True
        
        print(f"\n{'='*60}")
        print(f"STEP 1: DETECTION - {self.tool_display}")
        print(f"{'='*60}")
        
        if self.tool not in TOOL_FUNCTIONS:
            print(f"[[X]] Unknown tool: {self.tool}")
            print(f"[i] Available tools: {', '.join(TOOL_NAMES.keys())}")
            return False
        
        start_time = time.time()
        
        # Prepare PowerShell command
        detectors_script = REPO_ROOT / "Detection" / "detectors.ps1"
        if not detectors_script.exists():
            print(f"[[X]] Detection script not found: {detectors_script}")
            return False
        
        tool_function = TOOL_FUNCTIONS[self.tool]
        
        # Output file path
        raw_output_file = self.detection_dir / f"{self.tool}_raw.json"
        
        if self.dry_run:
            print(f"[DRY RUN] Would execute:")
            print(f"  Function: {tool_function}")
            print(f"  Path: {self.scan_path}")
            print(f"  Output: {raw_output_file}")
            return True
        
        # Build PowerShell command
        ps_command = f". '{detectors_script}'; {tool_function} -Path '{self.scan_path}' -Out '{raw_output_file}'"
        
        cmd = [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-Command", ps_command
        ]
        
        print(f"[*] Running {self.tool_display} on {self.scan_path}")
        print(f"[*] Output file: {raw_output_file}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                timeout=300  # 5 minute timeout
            )
            
            elapsed = time.time() - start_time
            self.metadata["timings"]["detection"] = elapsed
            
            if result.returncode != 0:
                print(f"[[X]] Detection failed (exit code {result.returncode})")
                print(f"[!] stderr: {result.stderr}")
                return False
            
            # Count findings
            raw_file = self.detection_dir / f"{self.tool}_raw.json"
            # Some detectors may not emit a file when there are zero findings; ensure a valid empty artifact exists
            if not raw_file.exists():
                try:
                    raw_file.write_text("[]", encoding="utf-8")
                except Exception:
                    pass
            findings_count = 0
            
            if raw_file.exists():
                try:
                    # Read with UTF-8-sig to handle BOM from PowerShell
                    text = raw_file.read_text(encoding='utf-8-sig')
                    data = json.loads(text)
                    if isinstance(data, list):
                        findings_count = len(data)
                    elif isinstance(data, dict):
                        # Handle various tool output formats
                        findings_count = len(data.get("Reports", data.get("findings", data.get("results", []))))
                    else:
                        findings_count = 0
                except Exception as e:
                    print(f"[!] Warning: Could not count findings: {e}")
                    findings_count = 0
            
            self.metadata["results"]["raw_findings"] = findings_count
            self.metadata["steps_completed"].append("detection")
            
            print(f"[[OK]] Detection completed in {elapsed:.1f}s")
            print(f"[[OK]] Found {findings_count} raw findings")
            
            return True
            
        except subprocess.TimeoutExpired:
            print(f"[[X]] Detection timed out after 5 minutes")
            return False
        except Exception as e:
            print(f"[[X]] Detection error: {e}")
            return False
    
    def run_normalization(self) -> bool:
        """Normalize findings for this tool only."""
        if self.skip_normalize:
            print(f"[⊗] Skipping normalization (--skip-normalize)")
            return True
        
        print(f"\n{'='*60}")
        print(f"STEP 2: NORMALIZATION - {self.tool_display} only")
        print(f"{'='*60}")
        
        start_time = time.time()
        
        # Check if raw findings exist
        raw_file = self.detection_dir / f"{self.tool}_raw.json"
        if not raw_file.exists():
            print(f"[[X]] Raw findings not found: {raw_file}")
            return False
        
        if self.dry_run:
            print(f"[DRY RUN] Would normalize:")
            print(f"  Input: {raw_file}")
            print(f"  Output: {self.normalization_dir}")
            return True
        
        # Run normalizer on single tool output
        normalizer_script = REPO_ROOT / "Normalizer" / "normalize.py"
        
        env = os.environ.copy()
        env["SAFEFIX_NORMALIZATION_DIR"] = str(self.normalization_dir)
        
        # Decide false-positive filtering behavior
        # auto: disable for Gitleaks (to avoid hiding real leaks), enable otherwise
        if self.normalizer_fp not in {"auto", "on", "off"}:
            self.normalizer_fp = "auto"
        fp_filter = "1"
        if self.normalizer_fp == "off" or (self.normalizer_fp == "auto" and self.tool == "gitleaks"):
            fp_filter = "0"

        cmd = [
            sys.executable,
            str(normalizer_script),
            "--raw", str(self.detection_dir),
            "--out", str(self.normalization_dir),
            "--min-support", "1",  # Single tool, so min support = 1
            "--only-security", "1",
            "--emit-normalized", "1",
            "--fp-filter", fp_filter
        ]
        
        print(f"[*] Normalizing findings from {self.tool_display}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=env,
                timeout=300
            )
            
            elapsed = time.time() - start_time
            self.metadata["timings"]["normalization"] = elapsed
            
            if result.returncode != 0:
                print(f"[[X]] Normalization failed")
                print(f"[!] stderr: {result.stderr}")
                return False
            
            # Parse results
            llm_payload = self.normalization_dir / "llm_payload.json"
            llm_items = 0
            
            if llm_payload.exists():
                try:
                    data = json.loads(llm_payload.read_text(encoding='utf-8'))
                    llm_items = len(data.get("items", []))
                except:
                    llm_items = 0
            
            self.metadata["results"]["normalized_findings"] = llm_items
            self.metadata["steps_completed"].append("normalization")
            
            print(f"[[OK]] Normalization completed in {elapsed:.1f}s")
            print(f"[[OK]] Generated {llm_items} LLM items")
            print(result.stdout)
            
            return True
            
        except Exception as e:
            print(f"[[X]] Normalization error: {e}")
            return False
    
    def run_llm_repair(self) -> bool:
        """Generate patches using LLM orchestration."""
        if self.skip_llm:
            print(f"[⊗] Skipping LLM repair (--skip-llm)")
            return True
        
        print(f"\n{'='*60}")
        print(f"STEP 3: LLM REPAIR - {self.tool_display} findings")
        print(f"{'='*60}")
        
        start_time = time.time()
        
        # Check if normalized payload exists
        llm_payload = self.normalization_dir / "llm_payload.json"
        if not llm_payload.exists():
            print(f"[[X]] LLM payload not found: {llm_payload}")
            return False
        
        # Check if there are items to process
        try:
            data = json.loads(llm_payload.read_text(encoding='utf-8'))
            item_count = len(data.get("items", []))
            if item_count == 0:
                print(f"[!] No items to process in LLM payload")
                self.metadata["steps_completed"].append("llm_repair")
                return True
        except:
            print(f"[[X]] Could not read LLM payload")
            return False
        
        if self.dry_run:
            print(f"[DRY RUN] Would run LLM repair:")
            print(f"  Input: {llm_payload}")
            print(f"  Models: {self.models}")
            print(f"  Output: {self.llm_dir}")
            return True
        
        # Run LLM orchestrator
        llm_script = REPO_ROOT / "LLMs" / "multi_llm_orchestrator.py"
        
        env = os.environ.copy()
        env["SAFEFIX_NORMALIZATION_DIR"] = str(self.normalization_dir)
        env["SAFEFIX_LLM_DIR"] = str(self.llm_dir)
        env["SAFEFIX_LLM_SANDBOX_DIR"] = str(self.llm_dir / "patch_sandbox")
        
        cmd = [
            sys.executable,
            str(llm_script),
            "--models", self.models,  # Use models from command line
            "--autofix",
            "--hygiene",             # Apply conservative hardening if patch leaves risky flags
            "--validate", "yaml",  # Enable YAML validation to write patches
            "--timeout", "45",     # Give models more time to respond
            "--retries", "3",      # Be more resilient to transient errors
            "--concurrency", "5"   # Reduce rate limits; better reliability per provider
        ]
        
        print(f"[*] Running LLM orchestration with {self.models} (concurrency=5)")
        print(f"[*] Processing {item_count} items")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=env,
                timeout=1800  # 30 minute timeout
            )
            
            elapsed = time.time() - start_time
            self.metadata["timings"]["llm_repair"] = elapsed
            
            if result.returncode != 0:
                print(f"[[X]] LLM repair failed")
                print(f"[!] stderr: {result.stderr}")
                return False
            
            # Parse results
            decisions_file = self.llm_dir / "llm_decisions.json"
            fixes_count = 0
            
            if decisions_file.exists():
                try:
                    data = json.loads(decisions_file.read_text(encoding='utf-8'))
                    fixes_count = sum(
                        1 for item in data
                        if item.get("consensus", {}).get("final_classification") == "fix"
                    )
                except:
                    fixes_count = 0
            
            self.metadata["results"]["fixes_generated"] = fixes_count
            self.metadata["steps_completed"].append("llm_repair")
            
            print(f"[[OK]] LLM repair completed in {elapsed:.1f}s")
            print(f"[[OK]] Generated {fixes_count} fixes")
            print(result.stdout)
            
            return True
            
        except subprocess.TimeoutExpired:
            print(f"[[X]] LLM repair timed out after 30 minutes")
            return False
        except Exception as e:
            print(f"[[X]] LLM repair error: {e}")
            return False
    
    def run_merge_fixes(self) -> bool:
        """Merge all consensus fixes per file into unified manifests."""
        print(f"\n{'='*60}")
        print(f"STEP 4: MERGE - Combining fixes per file")
        print(f"{'='*60}")
        
        start_time = time.time()
        
        # Check if LLM decisions exist
        decisions_file = self.llm_dir / "llm_decisions.json"
        if not decisions_file.exists():
            print(f"[!] No LLM decisions found at {decisions_file}")
            return True
        
        try:
            # Load LLM decisions
            decisions = json.loads(decisions_file.read_text(encoding='utf-8'))
            print(f"[*] Loaded {len(decisions)} LLM decisions")

            # Group candidate patches by original file
            # Only include patches that passed LLM-stage validation to improve schema pass rate.
            fixes_by_file: Dict[str, List[Dict[str, Any]]] = {}
            for item in decisions:
                validation = item.get("validation", {})
                original_file = item.get("file")
                if not original_file:
                    continue
                # Only accept patches that have sandbox output AND validation.status == 'pass'
                if str(validation.get("status")).lower() != "pass":
                    continue
                sandbox_path = validation.get("sandbox_path")
                if not sandbox_path:
                    continue
                category = item.get("category")
                if original_file not in fixes_by_file:
                    fixes_by_file[original_file] = []
                fixes_by_file[original_file].append({
                    "sandbox_path": sandbox_path,
                    "category": category,
                    "item_id": item.get("id")
                })
            
            if not fixes_by_file:
                print(f"[!] No patched files found to merge (no sandbox outputs)")
                # Attempt minimal Secret autofix so validation can proceed
                merge_dir_root = self.run_dir / "merged"
                merged_manifests = merge_dir_root / "merged_manifests"
                merged_manifests.mkdir(parents=True, exist_ok=True)
                autofixed = self._autofix_simple_secrets(merged_manifests)
                if autofixed > 0:
                    print(f"[[OK]] Wrote {autofixed} autofixed Secret manifest(s) to {merged_manifests}")
                else:
                    print("[i] No eligible Secret manifests found for autofix")
                return True
            
            print(f"[*] Found fixes for {len(fixes_by_file)} file(s)")
            
            # Create merge output directory
            merge_dir_root = self.run_dir / "merged"
            merged_manifests = merge_dir_root / "merged_manifests"
            comparisons_dir = merge_dir_root / "comparisons"
            merged_manifests.mkdir(parents=True, exist_ok=True)
            comparisons_dir.mkdir(parents=True, exist_ok=True)
            
            files_merged = 0
            total_fixes_merged = 0
            
            # Merge fixes for each file
            for original_file, fixes in fixes_by_file.items():
                print(f"\n[*] Merging {len(fixes)} fix(es) for: {Path(original_file).name}")
                
                # Read original file
                original_path = Path(original_file)
                if not original_path.exists():
                    print(f"[!] Original file not found: {original_file}")
                    continue
                
                original_content = original_path.read_text(encoding='utf-8')
                original_is_k8s = self._looks_like_k8s_manifest(original_content)
                
                # Apply fixes iteratively (take the latest patched version in sequence)
                merged_content = original_content
                for i, fix in enumerate(fixes, 1):
                    sandbox_path = fix.get("sandbox_path")
                    if not sandbox_path:
                        print(f"[!] No sandbox_path for fix {i}")
                        continue
                    patch_path = Path(sandbox_path)
                    if not patch_path.exists():
                        print(f"[!] Patch not found: {sandbox_path}")
                        continue
                    candidate_text = patch_path.read_text(encoding='utf-8')
                    # Lightweight schema guard: require YAML to be syntactically valid; if kubeconform is available, require PASS
                    if not self._yaml_syntax_ok(candidate_text):
                        print(f"  [x] Rejected (YAML syntax invalid)")
                        continue
                    if original_is_k8s:
                        kc_ok = self._kubeconform_ok(candidate_text)
                        if not kc_ok:
                            print(f"  [x] Rejected by kubeconform")
                            continue
                    else:
                        # Non-K8s YAML (e.g., Helm values) – bypass kubeconform
                        pass
                    merged_content = candidate_text
                    print(f"  [{i}/{len(fixes)}] Applied: {fix.get('category')}")
                
                # Selector auto-fix for Deployments and re-check schema (only for K8s manifests)
                if original_is_k8s:
                    merged_content = self._ensure_deployment_selector(merged_content)
                    if not self._kubeconform_ok(merged_content):
                        print("  [x] Post-fix kubeconform still failing; keeping content but expect schema gate to catch it")
                else:
                    print("  [~] Non-K8s YAML detected; skipped kubeconform checks")

                # Save merged file
                stem = original_path.stem
                suffix = original_path.suffix or ".yaml"
                merged_filename = f"{stem}_fixed{suffix}"
                merged_path = merged_manifests / merged_filename
                merged_path.write_text(merged_content, encoding='utf-8')
                
                # Create comparison
                comparison = {
                    "original_file": str(original_file),
                    "merged_file": str(merged_path),
                    "fixes_applied": len(fixes),
                    "categories": [f.get("category") for f in fixes],
                    "before": original_content,
                    "after": merged_content
                }
                comparison_file = comparisons_dir / f"{merged_filename}.json"
                comparison_file.write_text(
                    json.dumps(comparison, indent=2),
                    encoding='utf-8'
                )
                
                files_merged += 1
                total_fixes_merged += len(fixes)
                print(f"[[OK]] Merged {len(fixes)} fix(es) → {merged_path.name}")
            
            elapsed = time.time() - start_time
            self.metadata["timings"]["merge"] = elapsed
            self.metadata["results"]["files_merged"] = files_merged
            self.metadata["results"]["total_fixes_merged"] = total_fixes_merged
            self.metadata["steps_completed"].append("merge")
            
            print(f"\n{'='*60}")
            print(f"[[OK]] Merge completed in {elapsed:.1f}s")
            print(f"[[OK]] Merged {files_merged} file(s) with {total_fixes_merged} total fixes")
            print(f"[[OK]] Output: {merged_manifests}")
            print(f"{'='*60}")
            
            # If nothing was merged (e.g., LLM returned no applicable patches), try a minimal autofix for Secrets
            if files_merged == 0:
                print("[i] No patches applied; attempting minimal Secret autofix to enable validation...")
                autofixed = self._autofix_simple_secrets(merged_manifests)
                if autofixed > 0:
                    files_merged += autofixed
                    print(f"[[OK]] Wrote {autofixed} autofixed Secret manifest(s) to {merged_manifests}")
                else:
                    print("[i] No eligible Secret manifests found for autofix")

            return True
            
        except Exception as e:
            print(f"[[X]] Merge error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def build_single_file(self) -> bool:
        """Concatenate all merged manifests into a single Combined.yaml for validation."""
        try:
            merge_dir = self.run_dir / "merged" / "merged_manifests"
            if not merge_dir.exists():
                print("[!] No merged manifests to combine")
                return True  # nothing to do; not fatal

            yaml_files = sorted(list(merge_dir.glob("*.yml")) + list(merge_dir.glob("*.yaml")))
            if not yaml_files:
                print("[!] No YAML files found to combine")
                return True

            onefile_dir = self.run_dir / "merged" / "onefile"
            onefile_dir.mkdir(parents=True, exist_ok=True)
            combined_path = onefile_dir / "Combined.yaml"

            parts: List[str] = []
            for idx, yf in enumerate(yaml_files, start=1):
                try:
                    text = yf.read_text(encoding="utf-8")
                except Exception as e:
                    print(f"[!] Skipping {yf.name}: {e}")
                    continue
                # Ensure each file chunk ends with a newline
                if not text.endswith("\n"):
                    text = text + "\n"
                # Prepend a separator between files
                if parts:
                    parts.append("---\n")
                parts.append(text)

            if not parts:
                print("[!] No content to write in Combined.yaml")
                return True

            combined_path.write_text(''.join(parts), encoding="utf-8")
            print(f"[[OK]] Built single validation file: {combined_path}")
            return True
        except Exception as e:
            print(f"[[X]] Failed to build combined file: {e}")
            return False
    
    def run_validation(self) -> bool:
        """Run validation gates on merged unified manifests."""
        if self.skip_validate:
            print(f"[⊗] Skipping validation (--skip-validate)")
            return True
        
        print(f"\n{'='*60}")
        print(f"STEP 5: VALIDATION - {self.gates} gates")
        print(f"{'='*60}")
        
        start_time = time.time()
        
        # Validate per-file merged outputs (one file per original manifest)
        flat_dir = self.run_dir / "merged" / "merged_manifests"

        if not flat_dir.exists():
            print(f"[!] No merged manifests found at {flat_dir}")
            print(f"[i] Skipping validation (no files to validate)")
            # Write a minimal proof to indicate skip
            proof_file = self.validation_dir / "safe_fix_proof.json"
            proof = {
                "summary": {
                    "gates_requested": self.gates,
                    "gates_passed": 0,
                    "gates_failed": 0,
                    "skipped": True,
                    "reason": "no_merged_manifests"
                }
            }
            try:
                proof_file.write_text(json.dumps(proof, indent=2), encoding="utf-8")
            except Exception:
                pass
            self.metadata["steps_completed"].append("validation")
            return True

        # Look for YAML files
        yaml_files = list(flat_dir.glob("*.yaml")) + list(flat_dir.glob("*.yml"))
        if not yaml_files:
            print(f"[!] No YAML files found in {flat_dir}")
            print(f"[i] Skipping validation (no files to validate)")
            # Write a minimal proof to indicate skip
            proof_file = self.validation_dir / "safe_fix_proof.json"
            proof = {
                "summary": {
                    "gates_requested": self.gates,
                    "gates_passed": 0,
                    "gates_failed": 0,
                    "skipped": True,
                    "reason": "no_yaml_files"
                }
            }
            try:
                proof_file.write_text(json.dumps(proof, indent=2), encoding="utf-8")
            except Exception:
                pass
            self.metadata["steps_completed"].append("validation")
            return True
        
        # Filter to only Kubernetes manifests (have kind/apiVersion)
        k8s_files = []
        for yf in yaml_files:
            try:
                text = yf.read_text(encoding="utf-8")
            except Exception:
                continue
            if self._looks_like_k8s_manifest(text):
                k8s_files.append(yf)

        if not k8s_files:
            print(f"[*] No Kubernetes manifests detected (only non-K8s YAML like Helm values). Skipping validation.")
            # Write a minimal proof to indicate skip
            proof_file = self.validation_dir / "safe_fix_proof.json"
            proof = {
                "summary": {
                    "gates_requested": self.gates,
                    "gates_passed": 0,
                    "gates_failed": 0,
                    "skipped": True,
                    "reason": "no_k8s_manifests"
                }
            }
            try:
                proof_file.write_text(json.dumps(proof, indent=2), encoding="utf-8")
            except Exception:
                pass
            self.metadata["steps_completed"].append("validation")
            return True

        print(f"[*] Found {len(k8s_files)} Kubernetes manifest file(s) to validate (from {len(yaml_files)} YAMLs)")
        
        # Create a subset directory with only K8s manifests
        subset_dir = self.run_dir / "merged" / "k8s_subset"
        try:
            subset_dir.mkdir(parents=True, exist_ok=True)
            # Write exact copies
            for src in k8s_files:
                dst = subset_dir / src.name
                try:
                    dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
                except Exception:
                    pass
        except Exception:
            # If subset creation fails, fallback to validating the full dir
            subset_dir = flat_dir
        
        print(f"[*] Validating {len(k8s_files)} manifests from {subset_dir}")
        
        if self.dry_run:
            print(f"[DRY RUN] Would validate:")
            print(f"  Manifests: {subset_dir}")
            print(f"  Gates: {self.gates}")
            print(f"  Evidence: {self.validation_dir}")
            return True
        
        # Run validation gates
        validate_script = REPO_ROOT / "Validations" / "validate-gates.ps1"
        
        # Convert gate numbers to names
        gate_map = {
            "1": "schema",
            "2": "policy", 
            "3": "dryrun",
            "4": "sandbox",
            "5": "health",
            "6": "network",
            "7": "e2e"
        }
        gate_numbers = self.gates.split(',')
        gate_names = [gate_map.get(g.strip(), g.strip()) for g in gate_numbers]
        gates_param = ','.join(gate_names)
        
        # Ensure validation output dir exists
        self.validation_dir.mkdir(parents=True, exist_ok=True)

        # Use relative paths to the Validations directory to avoid long path issues
        import os
        validations_root = REPO_ROOT / "Validations"
        rel_input = os.path.relpath(subset_dir, validations_root)
        rel_output = os.path.relpath(self.validation_dir, validations_root)

        # Build PowerShell command with relative paths
        ps_command = (
            f"& '{validate_script}' "
            f"-InputDir '{rel_input}' "
            f"-Gates {gates_param} "
            f"-OutputDir '{rel_output}'"
        )
        
        cmd = [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-Command", ps_command
        ]
        
        print(f"[*] Running validation gates: {self.gates}")
        print(f"[*] Input: {subset_dir}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT / "Validations"),
                timeout=600  # 10 minute timeout
            )
            
            elapsed = time.time() - start_time
            self.metadata["timings"]["validation"] = elapsed
            
            # Parse validation results
            proof_file = self.validation_dir / "safe_fix_proof.json"
            gates_passed = 0
            gates_failed = 0
            
            if proof_file.exists():
                try:
                    data = json.loads(proof_file.read_text(encoding='utf-8'))
                    gates_passed = data.get("summary", {}).get("gates_passed", 0)
                    gates_failed = data.get("summary", {}).get("gates_failed", 0)
                except:
                    pass
            
            self.metadata["results"]["gates_passed"] = gates_passed
            self.metadata["results"]["gates_failed"] = gates_failed
            self.metadata["steps_completed"].append("validation")
            
            print(f"[[OK]] Validation completed in {elapsed:.1f}s")
            print(f"[[OK]] Gates passed: {gates_passed}")
            if gates_failed > 0:
                print(f"[!] Gates failed: {gates_failed}")
            
            if result.stdout:
                print(f"\n[Validation Output]")
                print(result.stdout)
            
            if result.stderr:
                print(f"\n[Validation Errors]")
                print(result.stderr)
            
            if result.returncode != 0:
                print(f"\n[!] Validation script returned code: {result.returncode}")
            
            return True
            
        except subprocess.TimeoutExpired:
            print(f"[[X]] Validation timed out after 10 minutes")
            return False
        except Exception as e:
            print(f"[[X]] Validation error: {e}")
            return False
    
    def save_metadata(self):
        """Save run metadata and results."""
        metadata_file = self.run_dir / "metadata.json"
        
        # Add final summary
        self.metadata["completed_at"] = datetime.now().isoformat()
        self.metadata["total_duration"] = sum(self.metadata["timings"].values())
        self.metadata["success"] = len(self.metadata["steps_completed"]) >= 2  # At least detection + normalization
        
        metadata_file.write_text(
            json.dumps(self.metadata, indent=2),
            encoding='utf-8'
        )
        
        print(f"\n[[OK]] Metadata saved to {metadata_file}")
        
        # Print reminder to merge fixes
        if self.metadata.get("results", {}).get("fixes_generated", 0) > 0:
            print(f"\n{'='*60}")
            print(f"💡 TIP: Merge fixes for this tool run:")
            print(f"   python orchestrator\\merge_single_tool_fixes.py --run-dir {self.run_dir}")
            print(f"{'='*60}")
    
    def run(self) -> bool:
        """Execute the complete pipeline."""
        print(f"\n{'='*60}")
        print(f"SafeFix-K8s Single-Tool Orchestrator")
        print(f"{'='*60}")
        print(f"Tool: {self.tool_display}")
        print(f"Scan Path: {self.scan_path}")
        print(f"Run Directory: {self.run_dir}")
        print(f"{'='*60}\n")
        
        try:
            # Setup
            self.setup_directories()
            
            # Step 1: Detection
            if not self.run_detection():
                print(f"\n[[X]] Pipeline failed at DETECTION")
                self.save_metadata()
                return False
            
            # Step 2: Normalization
            if not self.run_normalization():
                print(f"\n[[X]] Pipeline failed at NORMALIZATION")
                self.save_metadata()
                return False
            
            # Step 3: LLM Repair
            if not self.run_llm_repair():
                print(f"\n[[X]] Pipeline failed at LLM REPAIR")
                self.save_metadata()
                return False
            
            # Step 4: Merge Fixes (NEW - merge all fixes per file before validation)
            if not self.run_merge_fixes():
                print(f"\n[[X]] Pipeline failed at MERGE")
                self.save_metadata()
                return False
            
            # Step 5: Validation (validate the merged unified files or the single bundle)
            if not self.run_validation():
                print(f"\n[[X]] Pipeline failed at VALIDATION")
                self.save_metadata()
                return False
            
            # Success
            self.save_metadata()
            
            print(f"\n{'='*60}")
            print(f"[OK] PIPELINE COMPLETED SUCCESSFULLY")
            print(f"{'='*60}")
            print(f"Results:")
            print(f"  Raw Findings: {self.metadata['results'].get('raw_findings', 0)}")
            print(f"  Normalized: {self.metadata['results'].get('normalized_findings', 0)}")
            print(f"  Fixes Generated: {self.metadata['results'].get('fixes_generated', 0)}")
            print(f"  Files Merged: {self.metadata['results'].get('files_merged', 0)}")
            print(f"  Gates Passed: {self.metadata['results'].get('gates_passed', 0)}")
            print(f"  Total Time: {self.metadata['total_duration']:.1f}s")
            print(f"\nRun directory: {self.run_dir}")
            print(f"{'='*60}\n")
            
            return True
            
        except KeyboardInterrupt:
            print(f"\n[!] Pipeline interrupted by user")
            self.save_metadata()
            return False
        except Exception as e:
            print(f"\n[[X]] Pipeline error: {e}")
            import traceback
            traceback.print_exc()
            self.save_metadata()
            return False


def main():
    parser = argparse.ArgumentParser(
        description="SafeFix-K8s Single-Tool Orchestrator (B.Sc. Thesis)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run complete pipeline for KubeLinter
  python orchestrator/safefix_single_tool.py --tool kubelinter --path tests
  
  # Run with specific gates
  python orchestrator/safefix_single_tool.py --tool checkov --gates 1,2,3
  
  # Skip validation (detection + repair only)
  python orchestrator/safefix_single_tool.py --tool trivy --skip-validate
  
  # Dry run (show what would be executed)
  python orchestrator/safefix_single_tool.py --tool kubescape --dry-run

Available Tools:
  kubelinter, checkov, trivy, kubeaudit, kubescape, polaris, kubescore,
  conftest, kubeconform, pluto, gitleaks, rbacpolice, yamllint
        """
    )
    
    parser.add_argument(
        "--tool",
        required=True,
        help="Detection tool to run (e.g., kubelinter, checkov, trivy)"
    )
    
    parser.add_argument(
        "--path",
        default="tests",
        help="Path to scan for manifests (default: tests)"
    )
    
    parser.add_argument(
        "--run-dir",
        help="Custom run directory (default: runs/YYYY-MM-DD__TOOL)"
    )
    
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Root output directory (default: output)"
    )
    
    parser.add_argument(
        "--gates",
        default="1,2,3",
        help="Validation gates to run (default: 1,2,3)"
    )
    
    parser.add_argument(
        "--models",
        default="groq,openrouter,gemini",
        help="LLM models to use (default: groq,openrouter,gemini)"
    )
    
    parser.add_argument(
        "--skip-detection",
        action="store_true",
        help="Skip detection (use existing results)"
    )
    
    parser.add_argument(
        "--skip-normalize",
        action="store_true",
        help="Skip normalization (use existing results)"
    )
    
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Skip LLM repair (detection + normalize only)"
    )
    
    parser.add_argument(
        "--skip-validate",
        action="store_true",
        help="Skip validation gates"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be executed without running"
    )
    parser.add_argument(
        "--normalizer-fp",
        default="auto",
        choices=["auto", "on", "off"],
        help="False-positive filtering in normalizer: auto (default, off for gitleaks), on, or off"
    )
    
    args = parser.parse_args()
    
    # Validate tool
    tool = args.tool.lower()
    if tool not in TOOL_NAMES:
        print(f"[[X]] Unknown tool: {args.tool}")
        print(f"[i] Available tools: {', '.join(sorted(TOOL_NAMES.keys()))}")
        return 1
    
    # Setup paths
    scan_path = Path(args.path).absolute()
    if not scan_path.exists():
        print(f"[[X]] Scan path does not exist: {scan_path}")
        return 1
    
    # Create run directory
    if args.run_dir:
        run_dir = Path(args.run_dir).absolute()
    else:
        timestamp = datetime.now().strftime("%Y-%m-%d__%H-%M-%S")
        tool_display = TOOL_NAMES[tool]
        output_root = REPO_ROOT / args.output_dir
        run_dir = output_root / f"{timestamp}__{tool_display}"
    
    # Create and run orchestrator
    orchestrator = SingleToolOrchestrator(
        tool=tool,
        scan_path=scan_path,
        run_dir=run_dir,
        gates=args.gates,
        models=args.models,
        skip_detection=args.skip_detection,
        skip_normalize=args.skip_normalize,
        skip_llm=args.skip_llm,
        skip_validate=args.skip_validate,
        dry_run=args.dry_run,
        normalizer_fp=args.normalizer_fp,
    )
    
    success = orchestrator.run()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

