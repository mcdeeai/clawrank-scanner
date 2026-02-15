# ClawRank Scanner

> **Nearly 900 malicious skills. 18,000+ exposed instances. Four named attack campaigns.**
>
> The OpenClaw ecosystem is under attack. We scanned 162 ClawHub skills and found 18 that should never run on anyone's machine. This is the tool we built to find them.

[![npm version](https://img.shields.io/npm/v/clawrank-scanner.svg)](https://www.npmjs.com/package/clawrank-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why This Exists

In February 2026, researchers discovered that **20% of ClawHub skills contained malicious code** — from ClickFix social engineering to silent identity hijacking to reverse shells. Cisco, Kaspersky, Palo Alto, and 1Password all published warnings. A CVE was issued (CVE-2026-25253). Agents were running skills that stole credentials, overwrote SOUL.md files, and opened backdoors — sometimes for days before anyone noticed.

ClawRank Scanner is a static analysis tool that checks skill files **before you run them**. It's not magic — it's pattern matching against the attacks that are actually happening right now.

**Know before you run.**

## Quick Start

```bash
# Scan any skill directory
npx clawrank-scanner ./my-skill
```

That's it. No install required. Zero dependencies.

## Install (optional)

```bash
npm install -g clawrank-scanner
```

## Usage

```bash
# Scan a skill directory
clawrank-scanner scan ./my-skill

# Shorthand
clawrank-scanner ./my-skill

# JSON output for CI/pipelines
clawrank-scanner scan ./my-skill --json

# Show version
clawrank-scanner --version
```

## What We Found

We scanned 162 skills from ClawHub:

- **132** scored A (clean)
- **9** scored B (low risk)
- **4** scored C or D (moderate to significant risk)
- **18** scored F (dangerous patterns detected)

The F-grades included remote code execution, credential exfiltration, shell injection with user input, and Discord webhook data theft.

## What It Scans For

31 detection patterns across 12 categories, mapped to real attacks in the wild:

| Category | Real-World Attack |
|---|---|
| **Social Engineering** | ClawHavoc ClickFix campaign — fake errors trick users into running malicious commands |
| **Identity Hijack** | SOUL.md silent overwrite — agent ran as someone else for 3 days undetected |
| **Memory Exfiltration** | Skills reading MEMORY.md and session state to steal personal data |
| **Config Tampering** | Modifying gateway config to disable security sandboxing |
| **Reverse Shell** | Polymarket campaign — netcat and /dev/tcp backdoors |
| **Dormant Payloads** | AuthTool campaign — skills that phone home and eval remote code on command |
| **Webhook Exfiltration** | Credentials sent to Discord/Slack webhooks |
| **Code Execution** | Remote code download, eval abuse, shell injection |
| **Data Exfiltration** | SSH keys, API tokens, environment variables |
| **Obfuscation** | Base64 encoding to hide payloads |
| **Supply Chain** | Unauthorized skill chain installs, bootstrapping |
| **Impersonation** | Fake system messages, tool output spoofing |

All patterns are **context-aware** — findings in documentation are scored differently than in executable code. `.git/` and `node_modules/` directories are automatically skipped.

## Grading Scale

| Grade | Score | Meaning |
|---|---|---|
| **A** | 90–100 | Excellent — minimal risk |
| **B** | 80–89 | Good — low risk |
| **C** | 70–79 | Fair — moderate risk |
| **D** | 60–69 | Poor — significant risk |
| **F** | 0–59 | Fail — dangerous patterns detected |

## Example Output

```
🔍 Scanning: ./my-skill

Security Score: 82/100 (Grade B)

🟠 HIGH (1):
  - Shell command execution with user input
    File: index.js:42
    Snippet: exec(`ls ${userInput}`)

🟡 MEDIUM (2):
  - File system write access
    File: handler.js:15
    Snippet: fs.writeFileSync(path, data)

💾 Results saved to: results/my-skill.json
```

## Zero Dependencies

Pure Node.js. No install bloat. 17 KB. Just security scanning.

## About ClawRank

ClawRank is the trust layer for the AI agent economy. We track who's building, what's safe, and what's not — so you can make informed decisions before running code you didn't write.

- 🌐 [clawrank.io](https://clawrank.io)
- 🔒 [Security Trust Index](https://clawrank.io/security)
- 📦 [GitHub](https://github.com/mcdeeai/clawrank-scanner)

## License

MIT
