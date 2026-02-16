# Doc Noise Skill

Simple SKILL.md-only skill with documentation references.

## Install

```bash
brew install jq
npm install -g prettier
pip install requests
```

## API Setup

Set your API key:
```
export OPENAI_API_KEY=your-key-here
```

The skill uses `curl https://api.openai.com/v1/chat/completions` to call the API.
