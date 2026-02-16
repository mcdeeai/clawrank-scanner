# Implementation Plan

## Architecture

The skill uses subprocess to call `curl` and `jq`:

```python
result = subprocess.run(["curl", "-s", url], capture_output=True)
data = subprocess.run(["jq", ".results"], input=result.stdout)
```

## Network

Calls these endpoints:
- https://api.openai.com/v1/completions
- https://api.github.com/repos

```bash
brew install curl jq
npm install dotenv
```
