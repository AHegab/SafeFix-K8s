# Example Detection Matrix Output

## What the CSV Looks Like

When you open `tool_detection_matrix.csv` in Excel, you'll see something like this:

| RuleID | Severity | ResourceKind | ResourceName | File | DetectionCount | ToolCount | checkov | gitleaks | kubelinter | kubescape | kubescore | kubesec | polaris | terrascan | trivy-config | trufflehog | yamllint |
|--------|----------|--------------|--------------|------|----------------|-----------|---------|----------|------------|-----------|-----------|---------|---------|-----------|--------------|------------|----------|
| no-read-only-root-fs | HIGH | Deployment | orders | orders-deploy.yaml | 5 | 5 | ✓ | | ✓ | ✓ | | | ✓ | | ✓ | | |
| privileged-container | CRITICAL | Pod | nginx | nginx.yaml | 4 | 4 | ✓ | | ✓ | ✓ | | ✓ | | | | | |
| missing-resource-limits | MEDIUM | Deployment | app | app.yaml | 6 | 6 | ✓ | | ✓ | ✓ | ✓ | | ✓ | ✓ | | | |
| image-pull-policy-latest | LOW | Deployment | backend | backend.yaml | 3 | 3 | | | | ✓ | ✓ | | ✓ | | | | |
| yaml-syntax-error | LOW | YAML | config.yaml | config.yaml | 1 | 1 | | | | | | | | | | | ✓ |

---

## What the Columns Mean

### Identification Columns
- **RuleID** — The security check/rule identifier (e.g., "no-read-only-root-fs")
- **Severity** — Highest severity reported (CRITICAL > HIGH > MEDIUM > LOW > INFO)
- **ResourceKind** — Type of K8s resource (Deployment, Pod, Service, etc.)
- **ResourceName** — Name of the specific resource
- **File** — YAML file where the issue was found

### Statistics Columns
- **DetectionCount** — Total number of times this issue was detected (across all tools)
- **ToolCount** — Number of unique tools that detected this issue

### Tool Columns (one per scanner)
- **✓** — This tool detected the issue
- **(empty)** — This tool did not detect the issue

---

## How to Analyze in Excel

### 1. Sort by Detection Count (Descending)
This shows you the **highest-confidence issues** (detected by most tools):

```
Sort by: DetectionCount (Z → A)
```

**Interpretation:**
- **DetectionCount ≥ 5** → Very high confidence (most tools agree)
- **DetectionCount = 3-4** → High confidence (multiple tools agree)
- **DetectionCount = 2** → Medium confidence (2 tools agree)
- **DetectionCount = 1** → Low confidence (only 1 tool, needs validation)

---

### 2. Filter by Severity = "CRITICAL" or "HIGH"
Shows the **most dangerous issues** first:

```
Filter: Severity → Select "CRITICAL" and "HIGH"
Sort by: DetectionCount (Z → A)
```

**Result:** Prioritized list of critical issues that multiple tools confirm.

---

### 3. Count Checkmarks per Tool Column
Shows **which tools are most effective**:

```
# In Excel, at the bottom of each tool column:
=COUNTIF(H:H, "✓")  # For kubelinter column
=COUNTIF(I:I, "✓")  # For polaris column
... etc.
```

**Result:** Tool effectiveness ranking (total detections per tool).

---

### 4. Conditional Formatting
Highlight high-confidence issues:

```
1. Select the DetectionCount column
2. Home → Conditional Formatting → Color Scales
3. Red (low) → Green (high)
```

**Result:** Visual heatmap showing consensus levels.

---

### 5. Pivot Table Analysis
Create a **Tool vs. Severity** matrix:

```
1. Insert → PivotTable
2. Rows: Severity
3. Columns: One column per tool
4. Values: Count of ✓ marks
```

**Result:**
|  | checkov | kubelinter | polaris | ... |
|--|---------|------------|---------|-----|
| CRITICAL | 12 | 8 | 15 | ... |
| HIGH | 34 | 28 | 42 | ... |
| MEDIUM | 23 | 19 | 31 | ... |

---

## Example Analysis Queries

### Q1: Which tool found the most CRITICAL issues?
```excel
# Filter Severity = "CRITICAL"
# Count ✓ marks in each tool column
# Tool with most ✓ wins
```

**Use Case:** Identify the best tool for critical security issues.

---

### Q2: Which issues should I fix first?
```excel
# Filter:
#   - Severity = "CRITICAL" or "HIGH"
#   - DetectionCount >= 3
# Sort by Severity (CRITICAL first)
```

**Result:** High-priority, high-confidence issues.

---

### Q3: Which issues might be false positives?
```excel
# Filter:
#   - ToolCount = 1  (only one tool detected)
#   - Severity = "LOW" or "INFO"
```

**Result:** Candidates for manual validation (low confidence).

---

### Q4: Which tools have unique detections?
```python
# In Python (not Excel):
df = pd.read_csv("tool_detection_matrix.csv")
single_tool = df[df["ToolCount"] == 1]

tool_columns = ["checkov", "kubelinter", "polaris", ...]
for tool in tool_columns:
    unique_to_tool = single_tool[single_tool[tool] == "✓"]
    print(f"{tool}: {len(unique_to_tool)} unique findings")
```

**Result:**
```
checkov: 12 unique findings
kubelinter: 8 unique findings
kubescape: 34 unique findings  ← Most unique detections
polaris: 21 unique findings
...
```

**Interpretation:** Kubescape finds the most issues that other tools miss (high value).

---

## Example JSON Query (Programmatic)

```python
import json

with open("tool_detection_matrix.json") as f:
    data = json.load(f)

# Q: Which tool is most effective?
stats = data["toolStats"]
best = max(stats.items(), key=lambda x: x[1]["total"])
print(f"Most effective: {best[0]} with {best[1]['total']} detections")

# Q: How many high-confidence issues?
high_conf = [r for r in data["matrix"] if r["toolCount"] >= 3]
print(f"High-confidence issues: {len(high_conf)}")

# Q: What's the consensus rate?
total = data["totalIssues"]
multi_tool = len([r for r in data["matrix"] if r["toolCount"] >= 2])
consensus_rate = (multi_tool / total * 100)
print(f"Consensus rate: {consensus_rate:.1f}%")
```

**Output:**
```
Most effective: kubescape with 123 detections
High-confidence issues: 80
Consensus rate: 62.8%
```

---

## Visualization Examples

### 1. Tool Effectiveness Bar Chart
```python
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("thesis_tool_ranking.csv")
df.plot.bar(x="Tool", y="Total", figsize=(12,6))
plt.title("Tool Detection Effectiveness")
plt.ylabel("Total Findings")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
plt.savefig("tool_effectiveness.png", dpi=300)
```

---

### 2. Consensus Distribution Pie Chart
```python
df = pd.read_csv("thesis_consensus_dist.csv")
df.plot.pie(y="IssueCount", labels=df["ToolCount"], autopct="%1.1f%%")
plt.title("Issue Consensus Distribution")
plt.ylabel("")
plt.savefig("consensus_dist.png", dpi=300)
```

---

### 3. Severity Stacked Bar
```python
df = pd.read_csv("tool_detection_matrix.csv")
severity_counts = df.groupby(["Severity"]).size()
severity_counts.plot.barh()
plt.title("Security Issue Severity Breakdown")
plt.xlabel("Number of Issues")
plt.tight_layout()
plt.savefig("severity_breakdown.png", dpi=300)
```

---

## Real-World Example Output

After running on `tests/orders-deploy.yaml`, you might see:

```
============================================================
TOOL DETECTION SUMMARY
============================================================
Total unique issues: 12
Total findings (with duplicates): 23

Per-Tool Statistics:
Tool                 Total      Unique    
----------------------------------------
kubescape            8          3         
polaris              6          2         
trivy-config         5          1         
kubescore            4          0         
checkov              0          0         
gitleaks             0          0         
kubelinter           0          0         
...
============================================================
```

**Interpretation:**
- **12 unique security issues** found across all tools
- **23 total detections** (some issues detected by multiple tools)
- **Kubescape** found 8 issues, 3 of which only it detected (unique value)
- **Kubescore** found 4 issues, but all were also found by other tools (zero unique)
- Most tools found zero issues (because `orders-deploy.yaml` is already hardened)

---

## Tips for Thesis

### For Chapter 5 (Evaluation)

1. **Use real-world repos** (not just test files):
   - Kubernetes examples repo
   - Helm chart repos
   - Your own projects

2. **Run on multiple datasets**:
   - Small (10-20 manifests)
   - Medium (50-100 manifests)
   - Large (200+ manifests)

3. **Compare results**:
   - Tool A found 45 issues in Dataset 1
   - Tool B found 67 issues in Dataset 1
   - But 23 issues overlap (both tools agree)
   - 22 unique to Tool A, 44 unique to Tool B

4. **Manual validation sample**:
   - Pick 50 random issues from the matrix
   - Manually verify if they're true positives
   - Calculate FP rate per tool
   - Tools with low FP rate + high unique count = most valuable

5. **Create summary table**:

| Tool | Total | Unique | FP Rate | Precision | Recall |
|------|-------|--------|---------|-----------|--------|
| Kubescape | 123 | 34 | 12% | 88% | 67% |
| Polaris | 98 | 21 | 8% | 92% | 58% |
| Trivy | 87 | 14 | 15% | 85% | 52% |

---

## Final Tips

✅ **Open CSV in Excel** → Easy sorting/filtering  
✅ **Use JSON in Python** → Programmatic analysis  
✅ **Run analyze_matrix.py** → Auto-generate thesis CSVs  
✅ **Manual validation** → Calculate true/false positive rates  
✅ **Create visualizations** → Bar charts, pie charts, heatmaps  

**Your detection matrix is now ready for thesis evaluation! 🎓📊**
