# ClawRank Scanner Tuning Log

## 2026-02-14 — Major Pattern Tuning (v2)

### Problem
High false positive rate. 56 of 92 skills rated F (61%). Total findings: 4,760. Average score: 39.3/100.

Root cause: `credential-harvest` pattern matched any mention of `API_KEY`, `process.env`, `.env.local` — even in documentation explaining how to configure the skill. A skill documenting "set your MATON_API_KEY" got 40 CRITICAL findings and an automatic F.

### Changes Made

#### patterns.js — Complete Rewrite
1. **Removed `credential-harvest` as a CRITICAL pattern.** Replaced with:
   - `credential-exfiltration` (CRITICAL, code-only): Flags when credentials are READ and SENT in the same expression
   - `credential-reference` (MEDIUM, deduped): Flags env var reads, but only once per file, and LOW in docs
   
2. **Narrowed `shell-exec`** from CRITICAL to MEDIUM. Added `shell-exec-dangerous` (CRITICAL) for obfuscated execution only (eval of dynamic commands, child_process with template injection).

3. **Narrowed `eval-usage`** → `eval-dangerous` (CRITICAL, code-only): Only flags eval of request data, user input, or decoded base64. Removed `setTimeout("string")` and `$(...)` which had massive false positive rates.

4. **Downgraded `browser-automation`** to MEDIUM with LOW override in docs. A playwright skill mentioning "playwright" is expected, not suspicious.

5. **Narrowed `network-exfil`** → `network-exfil-hardcoded` (HIGH, code-only): Only POST to non-standard domains. Added `network-activity` (MEDIUM) for normal fetch/axios.

6. **Removed overly broad patterns:**
   - `/API_KEY/gi` — matched documentation references
   - `/\.env['"\s]/gi` as CRITICAL — now LOW informational
   - `/\bexec\s*\(/gi` — matched any exec() call
   - `/.click()`, `.type()`, `.goto()` — matched any DOM interaction
   - `/~\/\./gi` — matched any hidden file reference
   - `/\.listen\s*\(/gi` — flagged every Express server
   - `/.pem['"\s]/gi` — removed (too many false positives)

7. **Added `docSeverityOverride`**: Patterns found only in .md files get reduced severity automatically.

8. **Added `codeOnly` flag**: Some patterns (credential-exfiltration, eval-dangerous, unrestricted-write) are skipped entirely in documentation files.

#### analyzer.js — Context-Aware Analysis
1. **Fixed double-counting**: Removed separate code-block scanning pass that re-scanned markdown content
2. **Added lock file exclusion**: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` no longer scanned
3. **Added per-pattern cap**: Max 3 findings per pattern per file (prevents "183 playwright mentions" problem)
4. **Added dedup support**: Patterns marked `dedup: true` only count once per file

### Results Comparison

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Total skills | 92 | 94 | +2 (new data) |
| Average score | 39.3 | 94 | **+54.7** |
| Total findings | 4,760 | 256 | **-94.6%** |
| Grade A | 32 (35%) | 80 (85%) | **+48** |
| Grade B | 0 | 6 (6%) | +6 |
| Grade C | 3 (3%) | 2 (2%) | -1 |
| Grade D | 0 | 2 (2%) | +2 |
| Grade F | 56 (61%) | 4 (4%) | **-52** |

### F-Rated Skills (Post-Tuning) — All Justified
- **test-skill** (40): Intentional test with `curl | bash`, prompt injection, credential exfil — correctly flagged
- **proactive-solvr** (25): Contains prompt injection patterns ("Ignore previous instructions") in multiple files
- **feishu-evolver-wrapper** (15): 10+ JS files with child_process, env var access, npm installs — heavy automation skill, fair flag
- **playwright-scraper-skill** (15): Large skill with many actual code files using browser automation — reasonable

### Validation
- **acuity-scheduling**: Was F (40 findings, all `API_KEY` in docs) → Now **A** (3 findings, all LOW). Correct — it's a standard API integration skill.
- **test-skill**: Was F → Still **F**. Correct — it's intentionally malicious.
- **proactive-solvr**: Was not previously scanned → Now **F** due to prompt injection. Correct.
