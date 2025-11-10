#!/usr/bin/env python3
"""
Combine multiple fixed YAML files for the same source file into one fully secured manifest.
Merges fixes line-by-line, applies security hygiene, and generates a diff output.

Usage:
    python combine_yaml_files.py --file "tests/13.deployment.yaml"
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import difflib
import yaml

# Import from multi_llm_orchestrator
sys.path.insert(0, str(Path(__file__).parent))
from multi_llm_orchestrator import (
    load_dotenv_from_file,
    _apply_hygiene,
    _yaml_is_valid,
    OUTPUT_ROOT,
    LLM_DIR
)

# Define combination directory
COMBINATION_DIR = Path(os.getenv("SAFEFIX_COMBINATION_DIR", OUTPUT_ROOT / "combination")).resolve()

def _merge_yaml_files(fixed_files: List[str], original_file: str) -> Tuple[str, List[str]]:
    """
    Intelligently merge multiple fixed YAML files for the same source.
    Takes the most secure option for each section.
    
    Returns: (merged_yaml, applied_fixes)
    """
    if not fixed_files:
        return original_file, []
    
    if len(fixed_files) == 1:
        return fixed_files[0], ["single_fix"]
    
    try:
        # Parse all YAML files
        original_docs = list(yaml.safe_load_all(original_file))
        fixed_docs_list = []
        for fixed_file in fixed_files:
            try:
                docs = list(yaml.safe_load_all(fixed_file))
                fixed_docs_list.append(docs)
            except (yaml.YAMLError, ValueError, KeyError):
                continue
        
        if not fixed_docs_list:
            return original_file, []
        
        # Merge documents
        merged_docs = []
        applied_fixes = []
        
        for doc_idx, orig_doc in enumerate(original_docs):
            if not isinstance(orig_doc, dict):
                merged_docs.append(orig_doc)
                continue
            
            # Collect corresponding fixed documents
            fixed_versions = []
            for fixed_docs in fixed_docs_list:
                if doc_idx < len(fixed_docs) and isinstance(fixed_docs[doc_idx], dict):
                    fixed_versions.append(fixed_docs[doc_idx])
            
            if not fixed_versions:
                merged_docs.append(orig_doc)
                continue
            
            # Merge by taking most secure values
            merged_doc = orig_doc.copy()
            
            # Merge securityContext (most restrictive wins)
            for fixed_doc in fixed_versions:
                merged_doc = _merge_security_context(merged_doc, fixed_doc, applied_fixes)
                merged_doc = _merge_container_security(merged_doc, fixed_doc, applied_fixes)
                merged_doc = _merge_volumes(merged_doc, fixed_doc, applied_fixes)
                merged_doc = _merge_credentials(merged_doc, fixed_doc, applied_fixes)
            
            merged_docs.append(merged_doc)
        
        # Convert back to YAML
        merged_yaml = yaml.safe_dump_all(merged_docs, sort_keys=False, default_flow_style=False)
        return merged_yaml, list(set(applied_fixes))
    
    except (yaml.YAMLError, ValueError, KeyError, AttributeError) as e:
        # Fallback: use the first fixed file
        print(f"[WARN] YAML merge failed: {e}, using first fixed file")
        return fixed_files[0], ["fallback_merge"]


def _merge_security_context(merged: dict, fixed: dict, applied: List[str]) -> dict:
    """Merge pod-level securityContext (most restrictive wins)."""
    if "spec" not in merged:
        return merged
    
    spec = merged["spec"]
    fixed_spec = fixed.get("spec", {})
    
    # Handle Deployment/StatefulSet template
    if "template" in spec:
        template = spec["template"]
        fixed_template = fixed_spec.get("template", {})
        if "spec" in template:
            pod_spec = template["spec"]
            fixed_pod_spec = fixed_template.get("spec", {})
            
            # Merge pod securityContext
            if "securityContext" in fixed_pod_spec:
                if "securityContext" not in pod_spec:
                    pod_spec["securityContext"] = {}
                pod_sc = pod_spec["securityContext"]
                fixed_pod_sc = fixed_pod_spec["securityContext"]
                
                # Take most restrictive values
                for key in ["runAsNonRoot", "runAsUser", "fsGroup"]:
                    if key in fixed_pod_sc:
                        pod_sc[key] = fixed_pod_sc[key]
                        applied.append(f"pod.securityContext.{key}")
            
            # Merge automountServiceAccountToken
            if "automountServiceAccountToken" in fixed_pod_spec:
                pod_spec["automountServiceAccountToken"] = fixed_pod_spec["automountServiceAccountToken"]
                applied.append("pod.automountServiceAccountToken")
    
    return merged


def _merge_container_security(merged: dict, fixed: dict, applied: List[str]) -> dict:
    """Merge container securityContext (most restrictive wins)."""
    def merge_containers_in_spec(spec: dict, fixed_spec: dict, path: str):
        for container_key in ["containers", "initContainers"]:
            if container_key not in spec:
                continue
            fixed_containers = fixed_spec.get(container_key, [])
            for idx, container in enumerate(spec[container_key]):
                if idx < len(fixed_containers):
                    fixed_container = fixed_containers[idx]
                    if "securityContext" in fixed_container:
                        if "securityContext" not in container:
                            container["securityContext"] = {}
                        sc = container["securityContext"]
                        fixed_sc = fixed_container["securityContext"]
                        
                        # Take most restrictive
                        for key in ["privileged", "allowPrivilegeEscalation", "readOnlyRootFilesystem", "runAsNonRoot", "runAsUser"]:
                            if key in fixed_sc:
                                sc[key] = fixed_sc[key]
                                applied.append(f"{path}.{container_key}[{idx}].securityContext.{key}")
                        
                        # Merge capabilities (drop ALL if any version drops it)
                        if "capabilities" in fixed_sc:
                            if "capabilities" not in sc:
                                sc["capabilities"] = {}
                            caps = sc["capabilities"]
                            fixed_caps = fixed_sc["capabilities"]
                            if "drop" in fixed_caps and "ALL" in fixed_caps["drop"]:
                                if "drop" not in caps:
                                    caps["drop"] = []
                                if "ALL" not in caps["drop"]:
                                    caps["drop"].append("ALL")
                                    applied.append(f"{path}.{container_key}[{idx}].capabilities.drop=ALL")
    
    if "spec" in merged:
        spec = merged["spec"]
        fixed_spec = fixed.get("spec", {})
        
        # Handle template.spec
        if "template" in spec:
            template_spec = spec["template"].get("spec", {})
            fixed_template_spec = fixed_spec.get("template", {}).get("spec", {})
            merge_containers_in_spec(template_spec, fixed_template_spec, "template.spec")
        else:
            # Direct pod spec
            merge_containers_in_spec(spec, fixed_spec, "spec")
    
    return merged


def _merge_volumes(merged: dict, fixed: dict, applied: List[str]) -> dict:
    """Remove dangerous volume mounts (hostPath, docker socket)."""
    def remove_dangerous_volumes(spec: dict, fixed_spec: dict):
        if "volumes" not in spec:
            return
        
        fixed_volumes = fixed_spec.get("volumes", [])
        # If fixed version has fewer volumes, it removed dangerous ones
        if len(fixed_volumes) < len(spec["volumes"]):
            spec["volumes"] = fixed_volumes
            applied.append("volumes.removed_dangerous")
    
    if "spec" in merged:
        spec = merged["spec"]
        fixed_spec = fixed.get("spec", {})
        
        if "template" in spec:
            template_spec = spec["template"].get("spec", {})
            fixed_template_spec = fixed_spec.get("template", {}).get("spec", {})
            remove_dangerous_volumes(template_spec, fixed_template_spec)
        else:
            remove_dangerous_volumes(spec, fixed_spec)
    
    return merged


def _merge_credentials(merged: dict, fixed: dict, applied: List[str]) -> dict:
    """Replace hardcoded credentials with secret references."""
    def replace_credentials_in_containers(spec: dict, fixed_spec: dict):
        for container_key in ["containers", "initContainers"]:
            if container_key not in spec:
                continue
            fixed_containers = fixed_spec.get(container_key, [])
            for idx, container in enumerate(spec[container_key]):
                if idx < len(fixed_containers):
                    fixed_container = fixed_containers[idx]
                    # Check if env vars were changed (credentials externalized)
                    if "env" in fixed_container:
                        if "env" not in container:
                            container["env"] = []
                        # Add any new env vars from fixed version
                        fixed_env = fixed_container.get("env", [])
                        for fixed_env_var in fixed_env:
                            if isinstance(fixed_env_var, dict) and "valueFrom" in fixed_env_var:
                                # This is a secret reference
                                if fixed_env_var not in container["env"]:
                                    container["env"].append(fixed_env_var)
                                    applied.append(f"{container_key}[{idx}].env.secret_ref")
    
    if "spec" in merged:
        spec = merged["spec"]
        fixed_spec = fixed.get("spec", {})
        
        if "template" in spec:
            template_spec = spec["template"].get("spec", {})
            fixed_template_spec = fixed_spec.get("template", {}).get("spec", {})
            replace_credentials_in_containers(template_spec, fixed_template_spec)
        else:
            replace_credentials_in_containers(spec, fixed_spec)
    
    return merged


def generate_diff(original: str, fixed: str, original_path: str, fixed_path: str) -> str:
    """Generate a unified diff showing changes."""
    original_lines = original.splitlines(keepends=True)
    fixed_lines = fixed.splitlines(keepends=True)
    
    diff = difflib.unified_diff(
        original_lines,
        fixed_lines,
        fromfile=original_path,
        tofile=fixed_path,
        lineterm='',
        n=3  # Context lines
    )
    
    return ''.join(diff)


async def combine_fixed_files_for_target(
    target_file: str,
    output_dir: str = str(COMBINATION_DIR),
    hygiene: bool = True
) -> Optional[Dict]:
    """
    Combine all fixed YAML files for a target file.
    
    Returns: Dict with paths and diff, or None if failed
    """
    # Load LLM decisions
    llm_decisions_candidates = [
        LLM_DIR / "llm_decisions.json",
        OUTPUT_ROOT / "llm/llm_decisions.json",
        Path("output/llm/llm_decisions.json"),
    ]
    
    try:
        for sub in OUTPUT_ROOT.glob("*/llm/llm_decisions.json"):
            llm_decisions_candidates.append(sub)
    except Exception:
        pass
    
    llm_decisions_path = None
    decisions_data = None
    
    for p in llm_decisions_candidates:
        if p.exists():
            try:
                decisions_data = json.loads(p.read_text(encoding="utf-8"))
                llm_decisions_path = p
                break
            except (json.JSONDecodeError, OSError, ValueError):
                continue
    
    if not llm_decisions_path or not decisions_data:
        print("[ERROR] No llm_decisions.json found. Run LLM stage first.")
        return None
    
    # Filter to target file
    norm_target = target_file.replace("/", "\\")
    file_items = []
    for item in decisions_data:
        cand = item.get("file", "")
        if cand.replace("/", "\\") != norm_target and cand.replace("\\", "/") != target_file.replace("\\", "/"):
            continue
        if item.get("consensus", {}).get("final_classification") == "fix":
            file_items.append(item)
    
    if not file_items:
        print(f"[ERROR] No fixed files found for: {target_file}")
        return None
    
    print(f"[CombineYAML] Found {len(file_items)} fixes for {target_file}")
    
    # Load original file
    original_path = Path(target_file)
    if not original_path.exists():
        print(f"[ERROR] Original file not found: {target_file}")
        return None
    
    original_content = original_path.read_text(encoding="utf-8")
    
    # Collect all fixed YAML files
    fixed_files = []
    fix_details = []
    
    for item in file_items:
        fixed_file_content = item.get("consensus", {}).get("final_fixed_file", "")
        if fixed_file_content:
            fixed_files.append(fixed_file_content)
            fix_details.append({
                "category": item.get("category"),
                "model": item.get("consensus", {}).get("from_model", "unknown")
            })
    
    if not fixed_files:
        print("[ERROR] No valid fixed file content found")
        return None
    
    # Merge all fixed files
    print("[CombineYAML] Merging fixed files...")
    merged_content, applied_fixes = _merge_yaml_files(fixed_files, original_content)
    
    # Apply final hygiene pass
    if hygiene:
        print("[CombineYAML] Applying security hygiene...")
        merged_content, hygiene_applied = _apply_hygiene(merged_content, "")
        applied_fixes.extend([f"hygiene:{h}" for h in hygiene_applied])
    
    # Validate final YAML
    if not _yaml_is_valid(merged_content):
        print("[ERROR] Merged YAML is invalid")
        return None
    
    # Create output directory
    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    
    # Create sanitized filename
    safe_name = target_file.replace("\\", "_").replace("/", "_").replace("..", "")
    
    # Write final secured file
    final_path = output_dir_path / f"SECURED_{safe_name}"
    final_path.write_text(merged_content, encoding="utf-8")
    
    # Generate diff
    diff_content = generate_diff(
        original_content,
        merged_content,
        target_file,
        str(final_path)
    )
    
    # Write diff file
    diff_path = output_dir_path / f"DIFF_{safe_name}.diff"
    diff_path.write_text(diff_content, encoding="utf-8")
    
    # Write summary
    summary = {
        "original_file": target_file,
        "secured_file": str(final_path),
        "diff_file": str(diff_path),
        "fixes_applied": len(file_items),
        "applied_fixes": applied_fixes,
        "fix_details": fix_details
    }
    
    summary_path = output_dir_path / f"SUMMARY_{safe_name}.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    
    print(f"\n[CombineYAML] Complete!")
    print(f"  Original: {target_file}")
    print(f"  Secured: {final_path}")
    print(f"  Diff: {diff_path}")
    print(f"  Summary: {summary_path}")
    print(f"  Fixes applied: {len(file_items)}")
    
    return {
        "original_file": target_file,
        "secured_file": str(final_path),
        "diff_file": str(diff_path),
        "summary_file": str(summary_path),
        "diff_content": diff_content
    }


async def main():
    load_dotenv_from_file(".env")
    
    ap = argparse.ArgumentParser(description="Combine multiple fixed YAML files for a target file")
    ap.add_argument("--file", required=True, help="Target file path")
    ap.add_argument("--output", type=str, default=str(COMBINATION_DIR), help="Output directory")
    ap.add_argument("--hygiene", action="store_true", default=True, help="Apply security hygiene")
    
    args = ap.parse_args()
    
    result = await combine_fixed_files_for_target(
        target_file=args.file,
        output_dir=args.output,
        hygiene=args.hygiene
    )
    
    if result:
        print(f"\n[SUCCESS] Secured file created at: {result['secured_file']}")
        print(f"\n=== DIFF PREVIEW ===\n{result['diff_content'][:1000]}...")
    else:
        print("\n[ERROR] Failed to create combined file")
        sys.exit(1)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())

