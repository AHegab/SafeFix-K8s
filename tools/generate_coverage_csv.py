import csv
from pathlib import Path
from typing import Dict, Set, Tuple

# Reuse detection logic from the Excel generator
from tools.coverage_data import load_expected_by_file, build_detected_map, TOOLS

# Generates a single CSV sheet that consolidates coverage across all tests files.
# - Rows include both expected categories and potential false positives.
# - Columns list each tool with 1/0 indicating detection presence per category.
# Output: output/coverage_matrix.csv

ROOT = Path(__file__).resolve().parents[1]
OUT_CSV = ROOT / 'output' / 'coverage_matrix.csv'


def main() -> None:
    expected_by_file: Dict[str, Set[str]] = load_expected_by_file()
    detect: Dict[Tuple[str, str], Set[str]] = build_detected_map()

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    # CSV header
    headers = ['file', 'category', 'expected'] + TOOLS

    # Write with UTF-8 BOM so Excel opens cleanly on Windows
    with open(OUT_CSV, 'w', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        # Stable ordering: by file name then type (expected first), then category
        for file_key in sorted(expected_by_file.keys()):
            expected_cats = sorted(list(expected_by_file.get(file_key, set())))
            # False positives: detected categories not in expected
            all_detected_cats = sorted({cat for (fk, cat) in detect.keys() if fk == file_key})
            fp_cats = [c for c in all_detected_cats if c not in expected_cats]

            # Expected rows
            for cat in expected_cats:
                row = [file_key, cat, 1]
                tools_for_cat = detect.get((file_key, cat), set())
                row.extend([1 if tool in tools_for_cat else 0 for tool in TOOLS])
                writer.writerow(row)

            # Potential False Positives rows
            for cat in fp_cats:
                row = [file_key, cat, 0]
                tools_for_cat = detect.get((file_key, cat), set())
                row.extend([1 if tool in tools_for_cat else 0 for tool in TOOLS])
                writer.writerow(row)

    print(OUT_CSV)


if __name__ == '__main__':
    main()
