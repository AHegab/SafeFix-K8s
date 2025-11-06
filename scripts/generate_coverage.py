#!/usr/bin/env python3
"""
Generate a coverage CSV/XLSX from Detection/output/raw results.
Creates updated_coverage.csv and updated_coverage.xlsx in repo root.
"""
import argparse
import json
import re
from pathlib import Path
import pandas as pd

TOOLS_MAP = {
    "trivy_config_raw.json": "Trivy",
    "checkov_raw.json": "Checkov",
    "kubeaudit_raw.json": "Kubeaudit",
    "kubelinter_raw.json": "KubeLinter",
    "polaris_raw.json": "Polaris",
    "kubescore_raw.json": "KubeScore",
    "kubescape_raw.json": "Kubescape",
    "conftest_raw.json": "Conftest",
    "kubeconform_raw.json": "KubeConform",
    "rbacpolice_raw.json": "RBAC-Police",
    "pluto_raw.json": "Pluto",
    "gitleaks_raw.json": "Gitleaks",
    "yamllint_raw.txt": "Yamllint"
}

# Patterns to normalize verbose findings into short, human-friendly labels.
# Each tuple is (regex, label). Regex is applied case-insensitive.
PATTERNS = [
    (r"privileg", "Privileged container"),
    (r"privilege escalation|allowprivileg|allow_privilege|privilegeEscalation", "Privilege escalation allowed"),
    (r"capabilit|drop\s+capabilities", "Default capabilities not dropped"),
    (r"default service account|default account", "Default service account token mounted"),
    (r"default namespace", "Default namespace"),
    (r"read-?only root|readonlyrootfilesystem|read only filesystem", "Filesystem not read-only"),
    (r"imagepullpolicy.*always|image pull policy.*always|ImagePullPolicy not Always", "ImagePullPolicy not Always"),
    (r"image not pinned|not pinned by digest|pinned by digest", "Image not pinned by digest"),
    (r"no cpu limit|no cpu request|cpu limit missing|cpu request missing", "No CPU limit/request"),
    (r"no memory limit|no memory request|memory limit missing|memory request missing", "No memory limit/request"),
    (r"liveness.*probe|no livenessprobe|missing liveness", "No livenessProbe"),
    (r"readiness.*probe|no readinessprobe|missing readiness", "No readinessProbe"),
    (r"seccomp|seccompprofile", "No seccomp profile"),
    (r"runasnonroot|run as non-root|runs as root|run as root", "Runs as root user"),
    (r"securitycontext|no security context|missing security context", "No security context"),
    (r"network policy|no network policy|networkpolicy", "No network policy"),
    (r"apparmor", "No AppArmor profile"),
    (r"standalone pod|standalonepod|pod with no controller", "Standalone Pod"),
    (r"privileged cni|cni plugin|multus|privileged cni plugin", "Privileged CNI plugin config"),
    (r"service account token|automountserviceaccounttoken", "Default service account token mounted"),
]


def load_raw_text(path: Path) -> str:
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            return json.dumps(data, ensure_ascii=False)
        else:
            return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return path.read_text(encoding="utf-8", errors="ignore")


def extract_filenames_from_text(text: str):
    return set(re.findall(r"[\w\-\./\\]+\.ya?ml", text, flags=re.IGNORECASE))


def _gather_strings_from_json(obj):
    """Recursively gather all string values from a JSON-like structure."""
    results = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            results.extend(_gather_strings_from_json(v))
    elif isinstance(obj, list):
        for item in obj:
            results.extend(_gather_strings_from_json(item))
    elif isinstance(obj, str):
        results.append(obj)
    else:
        # convert other scalars to string
        try:
            results.append(str(obj))
        except Exception:
            pass
    return results


def extract_vulns_for_file(text: str, filename: str):
    """Heuristic extraction of vulnerability/misconfiguration snippets related to filename.

    Returns a list of short text snippets (strings).
    """
    snippets = []
    if not text:
        return snippets

    fname = filename.lower()

    # Try JSON-aware extraction first
    t = text.strip()
    if t.startswith("{") or t.startswith("["):
        try:
            data = json.loads(text)
            strs = _gather_strings_from_json(data)
            for s in strs:
                s_l = s.lower()
                if fname in s_l or any(tok in s_l for tok in ("message", "description", "rule", "id", "title", "check", "failure", "error", "vulnerability", "misconfig")):
                    # compact whitespace
                    snippet = re.sub(r"\s+", " ", s).strip()
                    snippets.append(snippet)
        except Exception:
            # fall back to line-based
            pass

    # Line-based scanning: find lines that mention the filename or common markers
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for i, line in enumerate(lines):
        low = line.lower()
        if fname in low or any(k in low for k in ("fail", "error", "warning", "vulnerability", "misconfig", "rule", "ckv_", "ksv_", "cve-")):
            # include a small window around the line for context
            ctx = []
            if i - 1 >= 0:
                ctx.append(lines[i - 1])
            ctx.append(line)
            if i + 1 < len(lines):
                ctx.append(lines[i + 1])
            snippet = " ".join(ctx)
            snippet = re.sub(r"\s+", " ", snippet).strip()
            snippets.append(snippet)

    # dedupe while preserving order
    seen = set()
    out = []
    for s in snippets:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def derive_labels_and_tool_marks(file_name: str, tool_texts: dict, file_vulns_raw: dict):
    """Return ordered list of (label, tool_marks) for a given file.

    tool_texts: dict mapping tool col name -> large text (lowercase)
    file_vulns_raw: dict mapping file_name -> list of prefixed snippets like '[Tool] snippet'
    """
    combined = "\n".join(tool_texts.values())
    labels = []
    # find patterns in combined text
    for pattern, label in PATTERNS:
        if re.search(pattern, combined, flags=re.IGNORECASE):
            labels.append(label)

    # Only include human-friendly labels derived from PATTERNS.
    # If no pattern matched, add a single concise 'Other' row using the first raw snippet as fallback.
    if not labels:
        # try to get a short snippet from file_vulns_raw
        fallback = None
        raws = file_vulns_raw.get(file_name.lower(), [])
        if raws:
            # take first snippet, strip tool prefix
            m = re.match(r"\[(.*?)\]\s*(.*)", raws[0])
            fallback = m.group(2) if m else raws[0]
            fallback = re.sub(r"\s+", " ", fallback).strip()
            if len(fallback) > 80:
                fallback = fallback[:80] + "..."
        labels = [fallback or "Finding"]

    # For each label, compute per-tool marks
    rows = []
    for label in labels:
        tool_marks = {}
        for col, txt in tool_texts.items():
            mark = ""
            # If tool text mentions the label tokens, mark it
            # use a simple token-based heuristic: check any word from label in tool text
            for tok in re.findall(r"\w+", label.lower()):
                if tok and tok in txt:
                    mark = "✔"
                    break
            # As a second pass, check raw snippets belonging to this tool for filename and label tokens
            if not mark:
                for raw in file_vulns_raw.get(file_name.lower(), []):
                    if raw.lower().startswith(f"[{col.lower()}]" ) or f"[{col.lower()}]" in raw.lower():
                        if any(tok in raw.lower() for tok in re.findall(r"\w+", label.lower())):
                            mark = "✔"
                            break
            tool_marks[col] = mark
        rows.append((label, tool_marks))
    return rows


def tokenize(s):
    return re.findall(r"\w+", str(s).lower())


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--raw", required=False, default="Detection/output/raw", help="Detection/output/raw directory")
    p.add_argument("--out-csv", default="updated_coverage.csv", help="Output CSV path")
    p.add_argument("--out-xlsx", default="updated_coverage.xlsx", help="Output XLSX path")
    args = p.parse_args()

    raw_dir = Path(args.raw)
    out_csv = Path(args.out_csv)
    out_xlsx = Path(args.out_xlsx)

    if not raw_dir.exists():
        raise SystemExit(f"Raw dir not found: {raw_dir}")

    # load raw tool outputs into memory
    tool_text = {}
    for fname, colname in TOOLS_MAP.items():
        fpath = raw_dir / fname
        if fpath.exists():
            tool_text[colname] = load_raw_text(fpath).lower()
        else:
            tool_text[colname] = ""

    # discover test files (scan tests/ folder and any references in outputs)
    workspace_root = Path(__file__).parent.parent
    tests_dir = workspace_root / "tests"
    files = []
    if tests_dir.exists():
        for pth in sorted(tests_dir.glob("**/*")):
            if pth.is_file() and pth.suffix.lower() in {".yaml", ".yml"}:
                files.append(pth.relative_to(workspace_root).as_posix())

    # also include filenames referenced in tool outputs
    referenced = set()
    for txt in tool_text.values():
        for f in extract_filenames_from_text(txt):
            referenced.add(Path(f).name)
    # combine and unique
    file_rows = []
    seen = set()
    for f in files:
        name = Path(f).name
        if name not in seen:
            file_rows.append({"File": f, "Vulns": ""})
            seen.add(name)
    for name in sorted(referenced):
        if name not in seen:
            file_rows.append({"File": name, "Vulns": ""})
            seen.add(name)

    if not file_rows:
        # fallback: include any raw files' names
        for txt in tool_text.values():
            for f in extract_filenames_from_text(txt):
                name = Path(f).name
                if name not in seen:
                    file_rows.append({"File": name, "Vulns": ""})
                    seen.add(name)

    # Build DataFrame
    df = pd.DataFrame(file_rows)
    # Ensure tool columns exist
    for col in TOOLS_MAP.values():
        if col not in df.columns:
            df[col] = ""

    # build file->tools map (presence)
    file_tools = {}
    for col, txt in tool_text.items():
        for f in extract_filenames_from_text(txt):
            key = Path(f).name.lower()
            file_tools.setdefault(key, set()).add(col)

    # build file->vulns map using heuristics per tool (prefixed with tool name)
    file_vulns = {}
    for col, txt in tool_text.items():
        for row in list(df["File"]):
            name = Path(str(row)).name
            key = name.lower()
            vulns = extract_vulns_for_file(txt, name)
            if vulns:
                prefixed = [f"[{col}] {v}" for v in vulns]
                file_vulns.setdefault(key, []).extend(prefixed)

    # iterate rows and fill cells
    # Build new long-format rows: one row per vuln label for each file
    long_rows = []
    for row in file_rows:
        file_path = row["File"]
        file_name = Path(str(file_path)).name
        key = file_name.lower()
        # derive labels and per-tool marks
        label_rows = derive_labels_and_tool_marks(file_name, tool_text, file_vulns)
        # If derive returned zero (shouldn't), create a fallback
        if not label_rows:
            label_rows = [("Finding", {col: ("✔" if key in tool_text.get(col, "") else "") for col in TOOLS_MAP.values()})]

        first = True
        for label, tool_marks in label_rows:
            out = {col: tool_marks.get(col, "") for col in TOOLS_MAP.values()}
            out_row = {"File": file_path if first else "", "Vulns": label}
            out_row.update(out)
            long_rows.append(out_row)
            first = False

    # Create DataFrame from long rows
    df_long = pd.DataFrame(long_rows)

    # write outputs (long format)
    df_long.to_csv(out_csv, index=False)
    with pd.ExcelWriter(out_xlsx, engine="openpyxl") as writer:
        df_long.to_excel(writer, index=False, sheet_name="Coverage")

    # Basic Excel styling for readability (openpyxl)
    try:
        from openpyxl import load_workbook
        from openpyxl.styles import PatternFill, Font, Alignment

        wb = load_workbook(out_xlsx)
        ws = wb["Coverage"]
        # header style
        header_fill = PatternFill(start_color="2F4F4F", end_color="2F4F4F", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True)
        for cell in ws[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center", vertical="center")

        # Auto column widths (simple heuristic)
        for col in ws.columns:
            max_length = 0
            col_letter = col[0].column_letter
            for cell in col:
                try:
                    val = str(cell.value) if cell.value is not None else ""
                    if len(val) > max_length:
                        max_length = len(val)
                except Exception:
                    pass
            adjusted_width = min(max(10, int(max_length * 0.9)), 60)
            ws.column_dimensions[col_letter].width = adjusted_width

        wb.save(out_xlsx)
    except Exception:
        # styling is best-effort
        pass

    print(f"Updated CSV written to: {out_csv}")
    print(f"Updated XLSX written to: {out_xlsx}")


if __name__ == "__main__":
    main()
