#!/usr/bin/env python3
"""Collect accepted fixed YAMLs from each run into llm/final_fixes.
Criteria: consensus.final_classification == 'fix' AND validation.status == 'pass'
Writes copies to: output/<run>/llm/final_fixes/<relative_path>
"""
from pathlib import Path
import json
import shutil

def collect_for_run(run_dir: Path) -> int:
    llm_dir = run_dir / 'llm'
    decisions_file = llm_dir / 'llm_decisions.json'
    sandbox_dir = llm_dir / 'patch_sandbox'
    final_out = llm_dir / 'final_fixes'
    if not decisions_file.exists() or not sandbox_dir.exists():
        return 0
    try:
        decisions = json.loads(decisions_file.read_text(encoding='utf-8'))
    except Exception:
        return 0
    if isinstance(decisions, dict):
        decisions = list(decisions.values())
    copied = 0
    for idx, item in enumerate(decisions, start=1):
        cons = item.get('consensus', {})
        val = item.get('validation', {})
        if cons.get('final_classification') != 'fix':
            continue
        if val.get('status') != 'pass':
            continue
        rel_file = item.get('file')
        if not isinstance(rel_file, str) or not rel_file:
            continue
        # patched file path under sandbox: <sandbox>/<idx>/<rel_file>
        src = sandbox_dir / str(idx) / rel_file
        if not src.exists():
            continue
        dst = final_out / rel_file
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied += 1
    return copied

def main():
    output_root = Path('output')
    runs = sorted([p for p in output_root.glob('2025-11-06__*') if (p/'llm').exists()])
    total = 0
    for run in runs:
        n = collect_for_run(run)
        if n:
            print(f"Collected {n} fixed files for {run.name}")
            total += n
    print(f"Total collected: {total}")

if __name__ == '__main__':
    main()
