# Logging Feature Documentation

## Overview
SafeFixK8s now includes comprehensive logging for all detection and normalization operations. Every run creates timestamped log files that capture:
- Start/end times
- Per-tool execution status
- Errors and warnings
- File operations
- Summary statistics

---

## Log Files Location

All logs are stored in:
```
output/logs/
├── detectors_YYYYMMDD_HHMMSS.log    # PowerShell detector runs
├── normalizer_YYYYMMDD_HHMMSS.log   # Python normalizer runs
└── kubescape_download.log           # Kubescape artifact downloads
```

**Example:**
```
output/logs/
├── detectors_20251016_143025.log
├── normalizer_20251016_143127.log
└── kubescape_download.log
```

---

## Detector Logs (PowerShell)

### Format
```
[YYYY-MM-DD HH:MM:SS] [LEVEL] Message
```

### Example Log Entry
```
[2025-10-16 14:30:25] [INFO] ============================================================
[2025-10-16 14:30:25] [INFO] SafeFixK8s Detectors Starting
[2025-10-16 14:30:25] [INFO] Log file: output\logs\detectors_20251016_143025.log
[2025-10-16 14:30:25] [INFO] Target path: tests
[2025-10-16 14:30:25] [INFO] ============================================================
[2025-10-16 14:30:25] [INFO] Running 13 detector tools
[2025-10-16 14:30:25] [INFO] Starting KubeLinter
[2025-10-16 14:30:28] [INFO] KubeLinter completed in 3.45 seconds (status: ok)
[2025-10-16 14:30:28] [INFO] Starting Polaris
[2025-10-16 14:30:32] [INFO] Polaris completed in 4.12 seconds (status: ok)
[2025-10-16 14:30:32] [ERROR] Gitleaks failed: Docker container error
[2025-10-16 14:30:32] [WARN] Creating placeholder for gitleaks : Docker container error
[2025-10-16 14:31:10] [INFO] Total time: 45.23 sec
[2025-10-16 14:31:10] [INFO] All detectors finished.
[2025-10-16 14:31:10] [INFO] Log saved to: output\logs\detectors_20251016_143025.log
```

### What Gets Logged
- ✅ Start time and configuration
- ✅ Each tool's start/completion/duration
- ✅ Success/failure status per tool
- ✅ Error messages with details
- ✅ Placeholder file creation (when tools fail)
- ✅ Total runtime
- ✅ Final log file location

---

## Normalizer Logs (Python)

### Format
```
[YYYY-MM-DD HH:MM:SS] [LEVEL] Message
```

### Example Log Entry
```
[2025-10-16 14:31:27] [INFO] ============================================================
[2025-10-16 14:31:27] [INFO] SafeFixK8s Normalizer Starting
[2025-10-16 14:31:27] [INFO] Log file: output/logs/normalizer_20251016_143127.log
[2025-10-16 14:31:27] [INFO] ============================================================
[2025-10-16 14:31:27] [INFO] Starting collection from all raw files
[2025-10-16 14:31:27] [INFO] Parsing kubelinter from kubelinter_raw.json
[2025-10-16 14:31:27] [INFO]   → kubelinter: 45 findings
[2025-10-16 14:31:27] [INFO] Parsing polaris from polaris_raw.json
[2025-10-16 14:31:27] [INFO]   → polaris: 98 findings
[2025-10-16 14:31:27] [WARN] Placeholder/diagnostic text in gitleaks_raw.json; skipping.
[2025-10-16 14:31:27] [INFO]   → gitleaks: 0 findings
[2025-10-16 14:31:28] [INFO] Collection complete: 716 total findings
[2025-10-16 14:31:28] [INFO] Building normalized findings bundle
[2025-10-16 14:31:28] [INFO] Writing normalized findings to output/normalized_findings.json
[2025-10-16 14:31:28] [INFO] ✓ Wrote output/normalized_findings.json with 716 findings (with duplicates)
[2025-10-16 14:31:28] [INFO] Generating detection matrix
[2025-10-16 14:31:28] [INFO] Building CSV matrix with 234 rows
[2025-10-16 14:31:28] [INFO] CSV matrix written successfully
[2025-10-16 14:31:28] [INFO] Deleted kubelinter_raw.json
[2025-10-16 14:31:28] [INFO] Deleted polaris_raw.json
[2025-10-16 14:31:28] [INFO] ✓ Cleanup complete: removed 13 raw file(s)
[2025-10-16 14:31:28] [INFO] ============================================================
[2025-10-16 14:31:28] [INFO] Normalizer completed successfully
[2025-10-16 14:31:28] [INFO] Log saved to: output/logs/normalizer_20251016_143127.log
[2025-10-16 14:31:28] [INFO] ============================================================
```

### What Gets Logged
- ✅ Start time and log file location
- ✅ Per-tool parsing status
- ✅ Finding counts per tool
- ✅ Warnings for placeholder/empty files
- ✅ Errors during parsing (with tracebacks)
- ✅ File write operations
- ✅ Matrix generation progress
- ✅ Cleanup operations
- ✅ Final statistics

---

## Log Levels

### INFO (Cyan in console)
Normal operations, progress updates, statistics

### WARN (Yellow in console)
Non-critical issues:
- Placeholder files detected
- Empty raw outputs
- Skipped files

### ERROR (Red in console)
Critical failures:
- Tool execution failures
- JSON parsing errors
- File write errors
- Fatal exceptions

---

## Console vs. File Output

### Console (Terminal)
- **Colored output** for easy reading
- **Essential messages** only
- Progress bars and summaries

### Log File (Persistent)
- **All messages** (verbose)
- **Exact timestamps**
- **Full error details** (stack traces)
- **Kept permanently** (not auto-deleted)

---

## Using Logs for Debugging

### 1. Check if a tool failed
```powershell
# Open latest detector log
Get-ChildItem "output\logs\detectors_*.log" | Sort-Object -Descending | Select-Object -First 1 | Get-Content
```

### 2. Filter for errors only
```powershell
Get-Content "output\logs\detectors_*.log" | Select-String "\[ERROR\]"
```

### 3. See which tools succeeded
```powershell
Get-Content "output\logs\detectors_*.log" | Select-String "completed in.*status: ok"
```

### 4. Check normalizer warnings
```powershell
Get-Content "output\logs\normalizer_*.log" | Select-String "\[WARN\]"
```

### 5. View last 50 lines of latest log
```powershell
Get-ChildItem "output\logs\*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content -Tail 50
```

---

## Log Retention

### Current Policy
- ✅ **Logs are kept permanently** (not auto-deleted)
- ✅ One log file per run (timestamped)
- ✅ Logs are **gitignored** (not committed to repo)

### Manual Cleanup
If logs accumulate, clean them manually:

```powershell
# Delete logs older than 7 days
Get-ChildItem "output\logs\*.log" | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-7)} | Remove-Item

# Delete all logs (keep directory)
Remove-Item "output\logs\*.log"
```

---

## Git Ignore Configuration

The `.gitignore` now excludes all generated files:

```gitignore
# Generated outputs
/output/raw/*.json
/output/raw/*.txt
/output/normalized_findings.json
/output/tool_detection_matrix.csv
/output/tool_detection_matrix.json
/output/thesis_*.csv

# Log files
/output/logs/*.log
/output/logs/*.txt

# Cached Docker images
/images/*.tar

# Downloaded tools
/tools/kubescape/kubescape.exe
/tools/kubescape/artifacts/
```

**But keeps directory structure:**
```gitignore
!output/.gitkeep
!output/raw/.gitkeep
!output/logs/.gitkeep
!images/.gitkeep
!tools/.gitkeep
```

---

## Example: Troubleshooting a Failed Run

### Scenario: Normalizer fails with "Bad JSON"

**1. Check the error in console:**
```
[2025-10-16 14:31:27] [ERROR] trivy-config: FAILED - Expecting value: line 1 column 1 (char 0)
```

**2. Open the log file:**
```powershell
code "output\logs\normalizer_20251016_143127.log"
```

**3. Find the full error:**
```
[2025-10-16 14:31:27] [ERROR] trivy-config: FAILED - Expecting value: line 1 column 1 (char 0)
Traceback (most recent call last):
  File "normalizer/normalize_all.py", line 458, in collect_all
    tool_findings = parser_func(file_path)
  File "normalizer/normalize_all.py", line 198, in from_trivy_config
    data = load_json(p) or {}
  ...
```

**4. Check the raw file:**
```powershell
cat "output\raw\trivy_config_raw.json"
```

**5. Check detector log for trivy-config:**
```powershell
Get-Content "output\logs\detectors_*.log" | Select-String "TrivyConfig" -Context 5
```

**Result:** Find that TrivyConfig failed during detection, created empty file, causing normalizer to fail.

**Fix:** Re-run detector with verbose Docker output to diagnose.

---

## Benefits

### For Development
- ✅ **Debug tool failures** without re-running
- ✅ **Track performance** (which tools are slow)
- ✅ **Identify patterns** in errors

### For Thesis
- ✅ **Document methodology** (exact tools run, when, how long)
- ✅ **Report issues** encountered during evaluation
- ✅ **Reproducibility** (log proves exact steps taken)

### For Production
- ✅ **Audit trail** (when scans ran, what they found)
- ✅ **Error alerting** (grep logs for [ERROR])
- ✅ **Performance monitoring** (track tool execution times)

---

## Summary

| Feature | Detectors | Normalizer |
|---------|-----------|------------|
| **Log file** | `detectors_YYYYMMDD_HHMMSS.log` | `normalizer_YYYYMMDD_HHMMSS.log` |
| **Location** | `output/logs/` | `output/logs/` |
| **Levels** | INFO, WARN, ERROR | INFO, WARN, ERROR |
| **Console colors** | ✅ Yes | ✅ Yes |
| **Timestamps** | ✅ Yes | ✅ Yes |
| **Tool timing** | ✅ Yes | ✅ Yes (per parser) |
| **Error traces** | ✅ Yes | ✅ Yes (full traceback) |
| **Auto-delete** | ❌ No (kept) | ❌ No (kept) |
| **Gitignored** | ✅ Yes | ✅ Yes |

---

## Next Steps

1. **Run a test:**
   ```powershell
   Det-RunAll -Path "tests"
   python normalizer\normalize_all.py
   ```

2. **Check the logs:**
   ```powershell
   ls output\logs\*.log
   ```

3. **Review log contents:**
   ```powershell
   Get-Content output\logs\detectors_*.log | more
   Get-Content output\logs\normalizer_*.log | more
   ```

4. **Test error handling:**
   - Intentionally break a tool (e.g., wrong Docker image name)
   - Check log for [ERROR] entries
   - Verify placeholder file creation

---

**Your SafeFixK8s pipeline now has production-ready logging! 📝✅**
