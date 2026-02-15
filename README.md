# ClawRank Scanner

> Security scanner for AI agent skill files. Detect dangerous patterns, score safety, grade A–F.

[![npm version](https://img.shields.io/npm/v/clawrank-scanner.svg)](https://www.npmjs.com/package/clawrank-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Install

```bash
npm install -g clawrank-scanner
```

Or run directly:

```bash
npx clawrank-scanner ./path/to/skill
```

## Usage

```bash
# Scan a skill directory
clawrank-scanner scan ./my-skill

# Shorthand (auto-detects path)
clawrank-scanner ./my-skill

# JSON output for CI/pipelines
clawrank-scanner scan ./my-skill --json

# Show version
clawrank-scanner --version
```

## What It Scans For

31 detection patterns across these categories:

| Category | Examples |
|---|---|
| **Code Execution** | Remote code download, eval abuse, shell injection |
| **Data Exfiltration** | Credential harvesting, network exfil, webhook exfiltration |
| **Social Engineering** | ClickFix attacks, fake error messages prompting dangerous commands |
| **Identity Hijack** | SOUL.md/IDENTITY.md overwrite, persona manipulation |
| **Memory Exfiltration** | Reading MEMORY.md, daily notes, session state for data theft |
| **Config Tampering** | Modifying gateway config, system prompts, tool policies |
| **Persistence** | Cron jobs, startup scripts, hidden files, dormant payloads |
| **Privilege Escalation** | Sudo usage, permission changes |
| **Reverse Shell** | Netcat, socat, /dev/tcp backdoors |
| **Obfuscation** | Base64 encoding, string obfuscation |
| **Supply Chain** | Unauthorized skill chain installs, bootstrapping |
| **Impersonation** | Fake system messages, tool output spoofing |

All patterns are **context-aware** — findings in documentation are scored differently than findings in executable code. `.git/` and `node_modules/` directories are automatically skipped.

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

Pure Node.js. No install bloat. Just security scanning.

## Learn More

- 🌐 [clawrank.io](https://clawrank.io)
- 📦 [GitHub](https://github.com/mcdeeai/clawrank-scanner)

## License

MIT
