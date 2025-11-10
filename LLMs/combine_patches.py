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
from typing import Dict, List, Tuple
import re
import difflib

# Import from multi_llm_orchestrator
sys.path.insert(0, str(Path(__file__).parent))
from multi_llm_orchestrator import (
    load_dotenv_from_file,
    _validate_and_write_patch,
    LLM_TIMEOUT_SECONDS, RETRIES,
    _apply_hygiene as orchestrator_hygiene
)
import asyncio

OUTPUT_ROOT = Path(os.getenv("SAFEFIX_OUTPUT_ROOT", "output")).resolve()
NORMALIZATION_DIR = Path(os.getenv("SAFEFIX_NORMALIZATION_DIR", OUTPUT_ROOT / "normalization"))
LLM_DIR = Path(os.getenv("SAFEFIX_LLM_DIR", OUTPUT_ROOT / "llm"))
COMBINATION_DIR = Path(os.getenv("SAFEFIX_COMBINATION_DIR", OUTPUT_ROOT / "combination"))

# ---------------------------
# Lightweight hygiene (fallback if orchestrator hygiene not imported)
# ---------------------------
try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None

def _combine_hygiene(text: str) -> tuple[str, list[str]]:
    """Apply baseline hardening to final combined YAML even if original patches skipped hygiene.
    Reuses orchestrator hygiene if available; otherwise performs a minimal regex-based pass.
    Returns (new_text, applied_rules)."""
    # Prefer orchestrator rich hygiene (already adds resources, image pin, etc.)
    try:
        new_text, applied = orchestrator_hygiene(text, "")
        if applied:
            return new_text, [f"orchestrator:{a}" for a in applied]
    except Exception:
        pass
    applied: list[str] = []
    original = text
    # Simple regex flips
    def sub(pat, repl, tag):
        nonlocal text
        new_t = re.sub(pat, repl, text, flags=re.I|re.M)
        if new_t != text:
            applied.append(tag)
            text = new_t
    sub(r"(?m)^(\s*)privileged:\s*true\b", r"\1privileged: false", "privileged:false")
    sub(r"(?m)^(\s*)allowPrivilegeEscalation:\s*true\b", r"\1allowPrivilegeEscalation: false", "allowPrivilegeEscalation:false")
    # Inject automountServiceAccountToken: false if pod spec and missing
    if "kind: Pod" in text and "automountServiceAccountToken" not in text:
        m = re.search(r"(?m)^spec:\s*$", text)
        if m:
            insert_at = m.end()
            text = text[:insert_at] + "\n  automountServiceAccountToken: false" + text[insert_at:]
            applied.append("pod.automountServiceAccountToken:false")
    return text, applied


# ---------------------------
# Post-patch validation utils
# ---------------------------
def _strip_diff_artifacts(text: str) -> Tuple[str, bool]:
    """Remove stray unified-diff leading '+' that accidentally got into final content.
    Returns (clean_text, changed).
    Conservative rule: only strip single leading '+' when the remainder looks like a YAML key line (contains ':').
    """
    changed = False
    out_lines: List[str] = []
    for line in text.splitlines(keepends=True):
        lstr = line.lstrip()
        # Only strip a single '+' that is followed by a YAML-ish key (e.g., 'password: ...')
        if lstr.startswith('+') and not lstr.startswith('++'):
            candidate = lstr[1:].lstrip()
            if ':' in candidate and not candidate.startswith('---') and not candidate.startswith('+++'):
                indent = len(line) - len(line.lstrip())
                newline_char = '\n' if line.endswith('\n') else ''
                out_lines.append(' ' * indent + candidate + newline_char)
                changed = True
                continue
        out_lines.append(line)
    return ("".join(out_lines), changed)


def _contains_rbac_cluster_admin(content: str) -> bool:
    c = content.lower()
    return ('kind: clusterrolebinding' in c) and ('name: cluster-admin' in c)


def _contains_plus_artifacts(content: str) -> bool:
    # Lines that begin with '+' (diff artifacts) suggest invalid YAML
    for line in content.splitlines():
        if line.lstrip().startswith('+') and not line.lstrip().startswith('++'):
            return True
    return False


def _bool_in(content: str, needle: str) -> bool:
    return needle.lower() in content.lower()


def _security_improvements(original: str, current: str) -> Dict[str, bool]:
    """Heuristic improvements detector for pod/container security."""
    return {
        "privileged_removed": _bool_in(original, 'privileged: true') and (not _bool_in(current, 'privileged: true')),
        "no_priv_esc_added": (not _bool_in(original, 'allowPrivilegeEscalation: false')) and _bool_in(current, 'allowPrivilegeEscalation: false'),
        "run_as_non_root_added": (not _bool_in(original, 'runAsNonRoot: true')) and _bool_in(current, 'runAsNonRoot: true'),
        "ro_fs_added": (not _bool_in(original, 'readOnlyRootFilesystem: true')) and _bool_in(current, 'readOnlyRootFilesystem: true'),
        "caps_drop_all": _bool_in(current, 'capabilities') and _bool_in(current, 'drop') and (_bool_in(current, ' drop: - all') or _bool_in(current, ' drop: - ALL') or _bool_in(current, 'drop:\n            - ALL') or _bool_in(current, 'drop:\n                - all')),
    }


def _is_secret_externalized(original: str, current: str) -> bool:
    """Treat as improved if password value changed from literal to env/placeholder or secret reference."""
    orig_has_literal = False
    curr_has_external = False
    for line in original.splitlines():
        if 'password:' in line and ('${' not in line) and ('secretKeyRef' not in original):
            orig_has_literal = True
            break
    if ('secretKeyRef' in current) or ('envFrom' in current) or ('${' in current):
        curr_has_external = True
    return orig_has_literal and curr_has_external


def _validate_effectiveness(original: str, current: str) -> Tuple[str, List[str]]:
    """Return (status, issues).
    status in {EFFECTIVE, INEFFECTIVE, INVALID, MANUAL_REQUIRED}
    """
    issues: List[str] = []

    # Invalid YAML heuristics (diff artifacts)
    if _contains_plus_artifacts(current):
        issues.append("Diff artifacts detected ('+' prefixes)")
        return ("INVALID", issues)

    # RBAC cluster-admin
    if _contains_rbac_cluster_admin(current):
        issues.append("ClusterRoleBinding to cluster-admin present")
        return ("MANUAL_REQUIRED", issues)

    # Secrets externalization
    if _is_secret_externalized(original, current):
        return ("EFFECTIVE", issues)

    # Security hardening
    imp = _security_improvements(original, current)
    if any(imp.values()):
        # If privileged is still true while other improvements present, mark as INEFFECTIVE
        if _bool_in(current, 'privileged: true'):
            issues.append("Container still privileged: true")
            return ("INEFFECTIVE", issues)
        return ("EFFECTIVE", issues)

    # If nothing changed materially, ineffective
    issues.append("No material security improvement detected")
    return ("INEFFECTIVE", issues)


def _ensure_doc_start_and_lf(content: str) -> str:
    """Ensure YAML document start and LF newlines."""
    text = content.replace('\r\n', '\n').replace('\r', '\n')
    if text.lstrip().startswith('apiVersion:') and not text.lstrip().startswith('---'):
        # Prepend doc start preserving leading whitespace/newline
        leading = ''
        idx = 0
        while idx < len(text) and text[idx] in ['\n', ' ', '\t']:
            leading += text[idx]
            idx += 1
        text = f"---\n{text}" if leading == '' else text.replace(leading + 'apiVersion:', f"---\n{leading}apiVersion:", 1)
    return text


def _attempt_privileged_autofix(current: str) -> Tuple[str, bool]:
    """Conservatively flip privileged:true to false and add allowPrivilegeEscalation: false if missing under same block."""
    if 'privileged: true' not in current:
        return current, False
    lines = current.splitlines(keepends=True)
    changed = False
    for i, line in enumerate(lines):
        if 'privileged: true' in line:
            # Flip to false
            lines[i] = line.replace('privileged: true', 'privileged: false')
            changed = True
            # Try to add allowPrivilegeEscalation: false if not present nearby (next few lines until indent decreases)
            indent = len(line) - len(line.lstrip())
            insert_at = i + 1
            has_no_priv_esc = False
            j = i + 1
            while j < len(lines):
                next_line = lines[j]
                nindent = len(next_line) - len(next_line.lstrip())
                if next_line.strip() == '' or next_line.lstrip().startswith('#'):
                    j += 1
                    continue
                if nindent <= indent:
                    break
                if 'allowPrivilegeEscalation' in next_line:
                    has_no_priv_esc = True
                    break
                j += 1
            if not has_no_priv_esc:
                newline_char = '\n'
                lines.insert(insert_at + 0, ' ' * (indent) + 'allowPrivilegeEscalation: false' + newline_char)
            break
    return ''.join(lines), changed

async def combine_patches_for_file(
    target_file: str,
    models: List[str],
    payload_path: str = str(NORMALIZATION_DIR / "llm_payload.json"),
    output_dir: str = str(COMBINATION_DIR),
    categories: List[str] | None = None,
    retries: int = 3,
    timeout_seconds: int = 60,
    autofix: bool = True,
    hygiene: bool = False
) -> Dict:
    """
    Process all findings for a single file and combine patches into one final output.
    Uses pre-generated LLM decisions from llm_decisions.json instead of re-querying models.
    
    Returns:
        Path to the final combined patch file
    """
    # Load LLM decisions (already has consensus)
    # Discover llm_decisions.json robustly across standard and tool-scoped locations.
    # Prefer an llm_decisions.json that actually contains entries for target_file.
    llm_decisions_candidates = [
        LLM_DIR / "llm_decisions.json",
        OUTPUT_ROOT / "llm/llm_decisions.json",
        Path("output/llm/llm_decisions.json"),
        Path("output/llm_decisions.json"),
    ]
    # Also search tool-specific paths like output/<tool>/llm/llm_decisions.json
    try:
        for sub in OUTPUT_ROOT.glob("*/llm/llm_decisions.json"):
            llm_decisions_candidates.append(sub)
    except Exception:
        pass

    llm_decisions_path = None
    norm_target_all = {target_file.replace("\\", "/").lower(), target_file.replace("/", "\\").lower()}
    for p in llm_decisions_candidates:
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            # If this decisions file references our target file, prefer it.
            for it in data:
                f = str(it.get("file", "")).strip()
                fl = f.lower()
                if fl in norm_target_all or any(fl.endswith(nt) for nt in norm_target_all):
                    llm_decisions_path = p
                    decisions_data = data
                    break
            if llm_decisions_path:
                break
        except Exception:
            continue
    # Fallback to first existing candidate if none matched the file
    if not llm_decisions_path:
        for p in llm_decisions_candidates:
            if p.exists():
                try:
                    decisions_data = json.loads(p.read_text(encoding="utf-8"))
                    llm_decisions_path = p
                    break
                except Exception:
                    continue

    if not llm_decisions_path:
        print("[ERROR] No llm_decisions.json found. Run LLM stage first.")
        return None
    
    # Filter to only this file
    norm_target = target_file.replace("/", "\\")
    file_items = []
    for item in decisions_data:
        cand = item.get("file", "")
        if cand.replace("/", "\\") != norm_target and cand.replace("\\", "/") != target_file.replace("\\", "/"):
            continue
        if categories and item.get("category") not in categories:
            continue
        file_items.append(item)
    
    if not file_items:
        if categories:
            joined = ", ".join(categories)
            print(f"[ERROR] No findings for file: {target_file} matching categories: {joined}")
        else:
            print(f"[ERROR] No findings for file: {target_file}")
        return None
    
    print(f"[CombinePatch] Found {len(file_items)} findings for {target_file}")
    print(f"[CombinePatch] Using models: {models}")
    print("[CombinePatch] Starting iterative patching...")
    
    # Start with original file
    original_path = Path(target_file)
    if not original_path.exists():
        print(f"[ERROR] File not found: {target_file}")
        return None
    
    # Create output directory
    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    os.environ["SAFEFIX_COMBINATION_DIR"] = str(output_dir_path)
    
    # Create sandbox directory for patch validation
    sandbox_dir = output_dir_path / "sandbox"
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    
    # Read original content
    current_content = original_path.read_text(encoding="utf-8")
    
    successful_patches = 0
    decisions = []
    
    for idx, item in enumerate(file_items, 1):
        print(f"\n[{idx}/{len(file_items)}] Processing: {item.get('category', 'UNKNOWN')}")
        
        # Get consensus from LLM decisions
        consensus = item.get("consensus", {})
        final_classification = consensus.get("final_classification", "needs_review")
        final_patch = consensus.get("final_patch", "")
        from_model = consensus.get("from_model", "")
        
        # Debug: print consensus
        if idx <= 2:  # Only print for first 2 findings
            print(f"  DEBUG: Consensus classification={final_classification}, has_patch={bool(final_patch)}, from_model={from_model}")
        
        # Apply patch if consensus says fix
        best_patch = None
        best_model = None
        used_fixed_file = False
        model_fixed_file = consensus.get("final_fixed_file", "") if isinstance(consensus, dict) else ""
        
        if final_classification == "fix" and final_patch:
            # Apply the patch to current_content
            # Create the original file path structure in sandbox to match the diff target
            temp_file_path = sandbox_dir / original_path
            temp_file_path.parent.mkdir(parents=True, exist_ok=True)
            pre_patch_content = current_content
            temp_file_path.write_text(pre_patch_content, encoding="utf-8")
            
            # Try to apply the consensus patch
            result = _validate_and_write_patch(
                str(temp_file_path),
                final_patch,
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
                best_patch = final_patch
                best_model = from_model
                
                # Update current_content with patched version
                sandbox_path = Path(result["sandbox_path"])
                if sandbox_path.exists():
                    current_content = sandbox_path.read_text(encoding="utf-8")
                    successful_patches += 1
                    print(f"  [OK] Applied patch from {from_model}")
            elif item.get("category") == "HARD_CODED_CREDS":
                # Fallback: Simple text replacement for hardcoded credentials
                print(f"  [INFO] Patch failed, trying simple replacement for HARD_CODED_CREDS...")
                try:
                    # Extract what the patch is trying to set (even if malformed)
                    # Look for lines with password: ${...} or similar patterns
                    replacement_line = None
                    for line in final_patch.splitlines():
                        if "password:" in line.lower() and ("${" in line or "<" in line or "ENV" in line.upper()):
                            replacement_line = line.strip()
                            break
                    
                    if replacement_line:
                        print(f"  DEBUG: Replacement line: {replacement_line}")
                        # Find and replace the password line in current content
                        lines = current_content.splitlines(keepends=True)
                        for i, line in enumerate(lines):
                            line_stripped = line.strip()
                            if "password:" in line_stripped.lower() and "${" not in line_stripped and "<" not in line_stripped:
                                # Replace the password line, preserving indentation
                                indent = len(line) - len(line.lstrip())
                                newline_char = "\n" if line.endswith("\n") else ""
                                lines[i] = " " * indent + replacement_line + newline_char
                                current_content = "".join(lines)
                                successful_patches += 1
                                best_patch = f"text_replacement: {replacement_line}"
                                best_model = from_model + " (fallback)"
                                print(f"  [OK] Applied simple replacement for hardcoded credential")
                                break
                    else:
                        print(f"  [WARN] Could not extract replacement line from patch")
                except Exception as e:
                    print(f"  [WARN] Fallback replacement failed: {e}")
            elif model_fixed_file:
                # Attempt to derive patch from the full fixed file provided by the model
                print("  [INFO] Patch failed; deriving diff from provided fixed manifest...")
                diff_text = ''.join(difflib.unified_diff(
                    pre_patch_content.splitlines(keepends=True),
                    model_fixed_file.splitlines(keepends=True),
                    fromfile=f"a/{target_file}",
                    tofile=f"b/{target_file}"
                ))
                if diff_text:
                    alt_result = _validate_and_write_patch(
                        str(temp_file_path),
                        diff_text,
                        idx,
                        str(sandbox_dir),
                        "yaml",
                        item.get("category", ""),
                        autofix=autofix,
                        hygiene=hygiene
                    )
                    if alt_result.get("status") == "pass":
                        sandbox_path = Path(alt_result["sandbox_path"])
                        if sandbox_path.exists():
                            current_content = sandbox_path.read_text(encoding="utf-8")
                            successful_patches += 1
                            best_patch = diff_text
                            best_model = from_model
                            used_fixed_file = True
                            print("  [OK] Applied diff derived from fixed manifest")
                    else:
                        print(f"  [WARN] Derived diff invalid: {alt_result.get('reason')}")
            else:
                # Conservative fallback: if patch failed for PRIVILEGED, try direct toggle
                cat = str(item.get("category", "")).upper()
                if "PRIVILEG" in cat:
                    auto_fixed, changed = _attempt_privileged_autofix(current_content)
                    if changed:
                        # Ensure YAML doc start and normalize newlines
                        current_content = _ensure_doc_start_and_lf(auto_fixed)
                        successful_patches += 1
                        best_patch = "fallback:privileged_toggle"
                        best_model = (from_model or "consensus") + " (fallback)"
                        print("  [OK] Applied fallback: set privileged:false and added allowPrivilegeEscalation:false")
                    else:
                        print("  [INFO] Fallback skipped: no privileged:true found in current content")
        
        # Get votes from consensus for decision logging
        votes = consensus.get("votes", {})
        
        # Record decision
        decisions.append({
            "finding": idx,
            "category": item.get("category"),
            "severity": item.get("severity"),
            "models_voted": list(votes.keys()),
            "selected_model": best_model,
            "patch_applied": best_patch is not None,
            "used_fixed_manifest": used_fixed_file,
            "votes": {k: {"classification": v.get("classification")} for k, v in votes.items()}
        })
        
        if not best_patch:
            print("  [!] No valid patch from any model")
    
    # Final output (cleanup, validate efficacy)
    final_dir = output_dir_path
    final_dir.mkdir(parents=True, exist_ok=True)
    
    # Create sanitized filename
    safe_name = target_file.replace("\\", "_").replace("/", "_").replace("..", "")
    
    # Attempt to strip accidental diff artifacts before validation, then normalize YAML formatting
    cleaned, cleaned_changed = _strip_diff_artifacts(current_content)
    if cleaned_changed:
        print("  [INFO] Cleaned diff artifacts from final content")
        current_content = cleaned
    current_content = _ensure_doc_start_and_lf(current_content)
    
    status, issues = _validate_effectiveness(
        original_path.read_text(encoding="utf-8"),
        current_content,
    )

    # Final hygiene pass if requested via environment (SAFEFIX_COMBINE_HYGIENE=1) or if ineffective due to missing basics
    want_hygiene = os.getenv("SAFEFIX_COMBINE_HYGIENE", "1") == "1"
    if want_hygiene:
        if status != "EFFECTIVE" or any(k in current_content for k in [": latest", "privileged: true"]):
            hardened_text, applied_h = _combine_hygiene(current_content)
            if applied_h:
                current_content = hardened_text
                # Re-evaluate effectiveness after hygiene
                status, issues = _validate_effectiveness(
                    original_path.read_text(encoding="utf-8"),
                    current_content,
                )

    # Optional privileged auto-fix attempt if ineffective solely due to privilege remaining
    if status == "INEFFECTIVE" and any('privileged' in s.lower() for s in issues):
        auto_fixed, changed = _attempt_privileged_autofix(current_content)
        if changed:
            print("  [INFO] Applied privileged auto-fix (privileged: true -> false) and added allowPrivilegeEscalation: false")
            current_content = auto_fixed
            # Re-normalize and re-evaluate
            current_content = _ensure_doc_start_and_lf(current_content)
            status, issues = _validate_effectiveness(
                original_path.read_text(encoding="utf-8"),
                current_content,
            )
    
    prefix = {
        "EFFECTIVE": "SECURED_",
        "INEFFECTIVE": "INEFFECTIVE_",
        "INVALID": "INVALID_",
        "MANUAL_REQUIRED": "MANUAL_REQUIRED_",
    }.get(status, "INEFFECTIVE_")
    final_path = final_dir / f"{prefix}{safe_name}"
    
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
    
    # Write validation report
    validation_path = final_dir / f"VALIDATION_{safe_name}.json"
    validation_path.write_text(
        json.dumps({
            "original_file": target_file,
            "status": status,
            "issues": issues,
            "successful_patches": successful_patches
        }, indent=2),
        encoding="utf-8"
    )

    # If RBAC manual required, scaffold a least-privilege template for guidance
    if status == "MANUAL_REQUIRED" and _contains_rbac_cluster_admin(current_content):
        scaffold_path = final_dir / f"SCAFFOLD_{safe_name}"
        scaffold = (
            "# Least-Privilege RBAC scaffold. Replace resources/verbs with exact needs.\n"
            "apiVersion: v1\n"
            "kind: Namespace\n"
            "metadata:\n"
            "  name: app-namespace\n"
            "---\n"
            "apiVersion: v1\n"
            "kind: ServiceAccount\n"
            "metadata:\n"
            "  name: app-sa\n"
            "  namespace: app-namespace\n"
            "automountServiceAccountToken: false\n"
            "---\n"
            "apiVersion: rbac.authorization.k8s.io/v1\n"
            "kind: Role\n"
            "metadata:\n"
            "  name: app-role\n"
            "  namespace: app-namespace\n"
            "rules:\n"
            "  - apiGroups: ['']\n"
            "    resources: ['pods']\n"
            "    verbs: ['get', 'list', 'watch']\n"
            "---\n"
            "apiVersion: rbac.authorization.k8s.io/v1\n"
            "kind: RoleBinding\n"
            "metadata:\n"
            "  name: app-binding\n"
            "  namespace: app-namespace\n"
            "subjects:\n"
            "  - kind: ServiceAccount\n"
            "    name: app-sa\n"
            "    namespace: app-namespace\n"
            "roleRef:\n"
            "  apiGroup: rbac.authorization.k8s.io\n"
            "  kind: Role\n"
            "  name: app-role\n"
        )
        scaffold_path.write_text(scaffold, encoding="utf-8")
        print(f"  [INFO] Wrote RBAC scaffold: {scaffold_path}")
    
    print("\n[CombinePatch] Complete!")
    print(f"  Original findings: {len(file_items)}")
    print(f"  Patches applied: {successful_patches}")
    print(f"  Output: {final_path} [{status}]")
    print(f"  Decisions: {decisions_path}")
    print(f"  Validation: {validation_path}")
    
    return final_path

async def main():
    load_dotenv_from_file(".env")
    
    ap = argparse.ArgumentParser(description="Combine multiple patches for a single file")
    ap.add_argument("--file", required=True, help="Target file path (e.g., tests/13.nginx_privileged_deployment.yaml)")
    ap.add_argument("--models", type=str, default="groq,openrouter,gemini", 
                    help="Comma-separated providers: groq,openrouter,gemini,ollama")
    ap.add_argument("--categories", type=str, default="",
                    help="Comma-separated list of finding categories to include (optional)")
    ap.add_argument("--timeout", type=int, default=LLM_TIMEOUT_SECONDS, help="Per-request timeout seconds")
    ap.add_argument("--retries", type=int, default=RETRIES, help="Retries per model")
    ap.add_argument("--validate", type=str, default="yaml", choices=["none", "yaml"],
                    help="Validation mode")
    ap.add_argument("--autofix", action="store_true", default=True,
                    help="Conservatively flip privileged:true and allowPrivilegeEscalation:true to false")
    ap.add_argument("--hygiene", action="store_true", default=False,
                    help="Apply conservative hygiene hardening")
    
    args = ap.parse_args()
    
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    categories = [c.strip() for c in args.categories.split(",") if c.strip()]
    
    result = await combine_patches_for_file(
        target_file=args.file,
        models=models,
        categories=categories or None,
        timeout_seconds=args.timeout,
        retries=args.retries,
        autofix=args.autofix,
        hygiene=args.hygiene
    )
    
    if result:
        print(f"\n[SUCCESS] Secured file created at: {result}")
    else:
        print("\n[ERROR] Failed to create combined patch")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
