#!/usr/bin/env python3
"""
Combine multiple patches for the same file into a single, fully-hardened output.

This script processes all findings for a given file and applies patches iteratively,
resulting in one completely secured YAML file with all issues fixed.

Usage:
    python combine_patches.py --file "tests/13.nginx_privileged_deployment.yaml"
    python combine_patches.py --file "tests/13.nginx_privileged_deployment.yaml" --models groq,openrouter,gemini
"""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Any

# Import from multi_llm_orchestrator
sys.path.insert(0, str(Path(__file__).parent))
from multi_llm_orchestrator import (
    load_dotenv_from_file, system_prompt, make_user_prompt, ask_all,
    validate_response, _validate_and_write_patch, MODELS, PROVIDER_PRIORITY,
    LLM_TIMEOUT_SECONDS, RETRIES
)
import asyncio
import hashlib
import time

async def combine_patches_for_file(
    target_file: str,
    models: List[str],
    payload_path: str = "output/llm_payload.json",
    output_dir: str = "output/combined_patches",
    retries: int = 3,
    timeout_seconds: int = 60,
    autofix: bool = True,
    hygiene: bool = True
) -> Dict:
    """
    Process all findings for a single file and combine patches into one final output.
    
    Returns:
        Path to the final combined patch file
    """
    # Load payload
    candidates = [
        Path("output/llm_payload.json"),
        Path("Detection/output/llm_payload.json"),
    ]
    payload_path = None
    for p in candidates:
        if p.exists():
            payload_path = p
            break
    
    if not payload_path:
        print(f"[ERROR] No llm_payload.json found")
        return None
    
    data = json.loads(payload_path.read_text(encoding="utf-8"))
    all_items = data.get("items", data if isinstance(data, list) else [])
    
    # Filter to only this file
    norm_target = target_file.replace("/", "\\")
    file_items = [
        item for item in all_items 
        if item.get("file", "").replace("/", "\\") == norm_target
    ]
    
    if not file_items:
        print(f"[ERROR] No findings for file: {target_file}")
        return None
    
    print(f"[CombinePatch] Found {len(file_items)} findings for {target_file}")
    print(f"[CombinePatch] Using models: {models}")
    print(f"[CombinePatch] Starting iterative patching...")
    
    # Start with original file
    original_path = Path(target_file)
    if not original_path.exists():
        print(f"[ERROR] File not found: {target_file}")
        return None
    
    # Create output directory
    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    
    # Create sandbox directory for patch validation
    sandbox_dir = output_dir_path / "sandbox"
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    
    # Read original content
    current_content = original_path.read_text(encoding="utf-8")
    
    successful_patches = 0
    decisions = []
    
    for idx, item in enumerate(file_items, 1):
        print(f"\n[{idx}/{len(file_items)}] Processing: {item.get('category', 'UNKNOWN')}")
        
        # Update item with current content
        item_copy = dict(item)
        item_copy["original_manifest"] = current_content
        
        # Get patches from all models
        prompt = make_user_prompt(item_copy)
        votes = await ask_all(models, prompt, retries, timeout_seconds)
        
        # Debug: print votes
        if idx <= 2:  # Only print for first 2 findings
            print(f"  DEBUG: Votes = {json.dumps(votes, indent=2)}")
        
        # Find best patch
        best_patch = None
        best_model = None
        
        for model_name in PROVIDER_PRIORITY:
            if model_name not in votes:
                continue
            resp = votes[model_name]
            
            # Debug
            if idx <= 2:
                print(f"  DEBUG [{model_name}]: classification={resp.get('classification')}, has_patch={bool(resp.get('patch'))}")
            
            if resp.get("classification") == "fix" and resp.get("patch"):
                # Apply the patch to current_content manually
                # Create the original file path structure in sandbox to match the diff target
                temp_file_path = sandbox_dir / original_path
                temp_file_path.parent.mkdir(parents=True, exist_ok=True)
                temp_file_path.write_text(current_content, encoding="utf-8")
                
                # Try to apply this patch
                result = _validate_and_write_patch(
                    str(temp_file_path),
                    resp["patch"],
                    idx,
                    str(sandbox_dir),
                    "yaml",  # validate_mode
                    item.get("category", ""),
                    autofix,
                    hygiene
                )
                
                if idx <= 2:
                    print(f"  DEBUG: Validation result = {result.get('status')}, reason = {result.get('reason', 'N/A')}")
                
                if result.get("status") == "pass":
                    best_patch = resp["patch"]
                    best_model = model_name
                    
                    # Update current_content with patched version
                    sandbox_path = Path(result["sandbox_path"])
                    if sandbox_path.exists():
                        current_content = sandbox_path.read_text(encoding="utf-8")
                        successful_patches += 1
                        print(f"  [OK] Applied patch from {model_name}")
                    break
        
        # Record decision
        decisions.append({
            "finding": idx,
            "category": item.get("category"),
            "severity": item.get("severity"),
            "models_voted": list(votes.keys()),
            "selected_model": best_model,
            "patch_applied": best_patch is not None,
            "votes": {k: {"classification": v.get("classification")} for k, v in votes.items()}
        })
        
        if not best_patch:
            print(f"  [!] No valid patch from any model")
    
    # Final output
    final_dir = Path("output/combined_patches")
    final_dir.mkdir(parents=True, exist_ok=True)
    
    # Create sanitized filename
    safe_name = target_file.replace("\\", "_").replace("/", "_").replace("..", "")
    final_path = final_dir / f"SECURED_{safe_name}"
    
    # Write final combined file using current_content
    final_path.write_text(current_content, encoding="utf-8")
    
    # Write decisions log
    decisions_path = final_dir / f"DECISIONS_{safe_name}.json"
    decisions_path.write_text(
        json.dumps({
            "original_file": target_file,
            "total_findings": len(file_items),
            "successful_patches": successful_patches,
            "models_used": models,
            "decisions": decisions
        }, indent=2),
        encoding="utf-8"
    )
    
    print(f"\n[CombinePatch] Complete!")
    print(f"  Original findings: {len(file_items)}")
    print(f"  Patches applied: {successful_patches}")
    print(f"  Output: {final_path}")
    print(f"  Decisions: {decisions_path}")
    
    return final_path

async def main():
    load_dotenv_from_file(".env")
    
    ap = argparse.ArgumentParser(description="Combine multiple patches for a single file")
    ap.add_argument("--file", required=True, help="Target file path (e.g., tests/13.nginx_privileged_deployment.yaml)")
    ap.add_argument("--models", type=str, default="groq,openrouter,gemini", 
                    help="Comma-separated providers: groq,openrouter,gemini,ollama")
    ap.add_argument("--timeout", type=int, default=LLM_TIMEOUT_SECONDS, help="Per-request timeout seconds")
    ap.add_argument("--retries", type=int, default=RETRIES, help="Retries per model")
    ap.add_argument("--validate", type=str, default="yaml", choices=["none", "yaml"],
                    help="Validation mode")
    ap.add_argument("--autofix", action="store_true", default=True,
                    help="Conservatively flip privileged:true and allowPrivilegeEscalation:true to false")
    ap.add_argument("--hygiene", action="store_true", default=True,
                    help="Apply conservative hygiene hardening")
    
    args = ap.parse_args()
    
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    
    result = await combine_patches_for_file(
        target_file=args.file,
        models=models,
        timeout_seconds=args.timeout,
        retries=args.retries,
        autofix=args.autofix,
        hygiene=args.hygiene
    )
    
    if result:
        print(f"\n✅ Success! Secured file created at: {result}")
    else:
        print(f"\n❌ Failed to create combined patch")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
