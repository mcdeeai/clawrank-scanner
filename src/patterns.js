// Detection patterns for skill security scanning
// Each pattern includes: id, severity, category, description, and regex patterns
//
// CONTEXT-AWARE SCORING:
// - Patterns can specify `codeOnly: true` to only flag in executable files (.js, .py, .sh, .ts, etc.)
// - Patterns can specify `docSeverityOverride` to reduce severity when found in .md files
// - Patterns can specify `requiresCombination` to only flag at full severity when combined with another pattern in the same file
//
// TUNING LOG (2026-02-14):
// - credential-harvest: Narrowed to actual exfiltration patterns, not documentation references
// - shell-exec: Only flag obfuscated/dangerous patterns, not normal shell usage
// - eval-usage: Only flag dangerous eval, not template rendering
// - browser-automation: Only flag when combined with credential access
// - network-exfil: Narrowed to suspicious exfiltration, not normal API calls
//
// TUNING LOG (2026-02-15):
// - Added identity-file-manipulation: SOUL.md/AGENTS.md/USER.md overwrites (Discord: でぃー SOUL.md hijack)
// - Added memory-exfiltration: MEMORY.md, .openclaw/ paths, session transcripts
// - Added config-tampering: config.yaml manipulation, gateway token sharing
// - Added social-engineering: ClickFix patterns, fake errors, "paste this" (Bitdefender ClawHavoc campaign)
// - Added dormant-payload: conditional execution, prompt-triggered activation (Bitdefender AuthTool campaign)
// - Added webhook-exfiltration: Discord webhooks, Slack webhooks as data sinks
// - Added reverse-shell: netcat, bash /dev/tcp, reverse shell patterns
// - Added identity-impersonation: instructions to act as different persona, hide activity
// Sources: OpenClaw Discord #security, Bitdefender ClawHavoc report, Kaspersky, Cisco, Reddit r/cybersecurity

export const PATTERNS = [
  // ========== CRITICAL (Red) — Only truly dangerous patterns ==========
  {
    id: 'remote-code-download',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Remote code download and execution (pipe to shell)',
    codeOnly: false, // Flag even in docs — this is always dangerous to instruct
    patterns: [
      /curl\s+.*\|\s*sh\b/gi,
      /curl\s+.*\|\s*bash\b/gi,
      /curl\s+.*\|\s*python\b/gi,
      /wget\s+.*\|\s*sh\b/gi,
      /wget\s+.*\|\s*bash\b/gi,
      /fetch.*\|\s*node\b/gi,
    ]
  },
  {
    id: 'ssh-keys',
    severity: 'CRITICAL',
    category: 'Credential Access',
    description: 'SSH/private key access',
    docSeverityOverride: 'LOW',
    patterns: [
      /~\/\.ssh/gi,
      /\/\.ssh\//gi,
      /id_rsa/gi,
      /id_dsa/gi,
      /id_ecdsa/gi,
      /id_ed25519/gi,
      /BEGIN\s+PRIVATE\s+KEY/gi,
      /BEGIN\s+RSA\s+PRIVATE\s+KEY/gi,
    ]
  },
  {
    id: 'credential-exfiltration',
    severity: 'CRITICAL',
    category: 'Credential Access',
    description: 'Credentials being sent to external endpoints',
    codeOnly: true,
    patterns: [
      // Reading env vars AND sending in the same expression/line
      /process\.env\.\w*(KEY|TOKEN|SECRET|PASSWORD).*fetch\s*\(/gi,
      /fetch\s*\(.*process\.env\.\w*(KEY|TOKEN|SECRET|PASSWORD)/gi,
      /curl\s+.*\$\w*(KEY|TOKEN|SECRET|PASSWORD)/gi,
      /curl\s+.*-H\s*['"]Authorization/gi,
      // Sending env vars to hardcoded non-localhost URLs
      /os\.environ\[.*\].*urllib\.request/gi,
      /urllib\.request.*os\.environ\[/gi,
    ],
    // This is the REAL red flag — only at CRITICAL when combined with network activity
    requiresCombination: 'network-activity'
  },
  {
    id: 'base64-obfuscation',
    severity: 'CRITICAL',
    category: 'Obfuscation',
    description: 'Base64 encoding piped/chained (potential obfuscation)',
    docSeverityOverride: 'LOW',
    patterns: [
      /base64\s+.*[|>]/gi,                          // base64 piped to something
      /atob\s*\(.*eval/gi,                           // decode then eval
      /Buffer\.from\(.*,\s*['"]base64['"]\).*eval/gi,    // Buffer decode then eval
      /b64decode.*exec/gi,                              // python b64decode + exec
      /atob\s*\(.*eval/gi,                              // atob + eval chain
      /Buffer\.from\(.*base64.*\.toString\(\).*exec/gi, // decode + toString + exec
    ]
  },
  {
    id: 'shell-exec-dangerous',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Obfuscated or dangerous shell execution',
    codeOnly: true,
    patterns: [
      // Obfuscated command execution
      /eval\s*\(\s*\$\(/gi,           // eval $(...)
      /eval\s+["'].*\$/gi,            // eval with variable interpolation
      /\bexec\s*\(.*\+.*\)/gi,        // exec with string concatenation (dynamic command building)
      /child_process.*exec.*\$\{/gi,  // child_process with template literals
      /execSync\s*\(.*\$\{/gi,        // execSync with template literal interpolation
      /execSync\s*\(.*\+/gi,          // execSync with string concatenation
      /child_process.*exec\s*\(/gi,   // child_process.exec() call
    ]
  },
  {
    id: 'eval-dangerous',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Dynamic code evaluation of external/user input',
    codeOnly: true,
    patterns: [
      /eval\s*\(\s*req\./gi,          // eval of request data
      /eval\s*\(\s*input/gi,          // eval of input
      /eval\s*\(\s*data/gi,           // eval of data variable
      /new\s+Function\s*\(.*req\./gi, // Function constructor with request data
      /eval\s*\(\s*atob/gi,           // eval of decoded base64
    ]
  },

  // --- ClawHavoc / ClickFix social engineering (Bitdefender, Feb 2026) ---
  {
    id: 'clickfix-social-engineering',
    severity: 'CRITICAL',
    category: 'Social Engineering',
    description: 'ClickFix-style social engineering (fake errors, paste-to-terminal)',
    codeOnly: false, // These appear in SKILL.md instructions
    dedup: true, // One match per file is enough
    patterns: [
      /paste\s+(this|the\s+following)\s+(command|code|script)\s+(in|into)\s+(your\s+)?terminal/gi,
      /copy\s+and\s+paste\s+(this|the\s+following)\s+(into|in)\s+(your\s+)?terminal/gi,
      /run\s+this\s+(command|fix)\s+to\s+(fix|resolve|repair)/gi,
      /verification\s+(failed|error|required).*run\s+(this|the\s+following)/gi,
      /authentication\s+(error|failed).*paste/gi,
      /error.*paste\s+(this|the)\s+(fix|command|solution)/gi,
    ]
  },
  // --- Identity file manipulation (Discord: SOUL.md hijack incident) ---
  {
    id: 'identity-file-manipulation',
    severity: 'CRITICAL',
    category: 'Identity Hijack',
    description: 'Overwrites agent identity files (SOUL.md, AGENTS.md, USER.md)',
    codeOnly: false, // Instructions in SKILL.md to overwrite these are the attack vector
    patterns: [
      /write\s+(to|over|into)\s+SOUL\.md/gi,
      /overwrite\s+SOUL\.md/gi,
      /replace\s+(the\s+)?(contents?\s+of\s+)?SOUL\.md/gi,
      /modify\s+SOUL\.md/gi,
      /write\s+(to|over|into)\s+AGENTS\.md/gi,
      /overwrite\s+AGENTS\.md/gi,
      /replace\s+(the\s+)?(contents?\s+of\s+)?AGENTS\.md/gi,
      /write\s+(to|over|into)\s+USER\.md/gi,
      /overwrite\s+USER\.md/gi,
      /write\s+(to|over|into)\s+IDENTITY\.md/gi,
      /overwrite\s+IDENTITY\.md/gi,
      /echo\s+.*>\s*SOUL\.md/gi,
      /echo\s+.*>\s*AGENTS\.md/gi,
      /cat\s*>\s*SOUL\.md/gi,
    ]
  },
  // --- Memory and session exfiltration ---
  // NOTE: .openclaw/ paths are normal in skill install docs. Only flag when combined
  // with sending/exfiltrating, or when accessing sensitive paths like sessions/transcripts.
  {
    id: 'memory-exfiltration',
    severity: 'CRITICAL',
    category: 'Data Exfiltration',
    description: 'Exfiltration of agent memory, sessions, or transcripts',
    codeOnly: false,
    patterns: [
      // Sending memory/config data externally — the actual exfil
      /send\s+(the\s+)?(contents?\s+of\s+)?MEMORY\.md/gi,
      /send\s+.*\.openclaw\//gi,
      /upload\s+.*MEMORY\.md/gi,
      /post\s+.*MEMORY\.md/gi,
      // Session transcript access (always suspicious for a skill)
      /session.*\.jsonl/gi,
      /\.openclaw\/agents\/.*\/sessions/gi,
      // Reading memory and including in output to external destination
      /include\s+(the\s+)?memory\s+files?\s+in/gi,
      /read\s+(the\s+)?(user'?s?\s+)?memory\s+files?\s+and\s+send/gi,
    ],
    docSeverityOverride: 'HIGH',
  },
  // --- OpenClaw config/path access (informational, not exfil by itself) ---
  {
    id: 'openclaw-path-access',
    severity: 'MEDIUM',
    category: 'OpenClaw Access',
    description: 'References to OpenClaw config or internal paths',
    docSeverityOverride: 'LOW', // Normal for install docs
    dedup: true,
    patterns: [
      /\.openclaw\/openclaw\.json/gi,
      /\.openclaw\/config/gi,
      /\.openclaw\/skills\//gi,
      /\.openclaw\/hooks\//gi,
      /\.openclaw\/workspace\//gi,
    ]
  },
  // --- Memory file references (common in legitimate memory skills) ---
  {
    id: 'memory-file-reference',
    severity: 'MEDIUM',
    category: 'Memory Access',
    description: 'References to agent memory files (common in memory skills)',
    docSeverityOverride: 'LOW',
    dedup: true,
    patterns: [
      /MEMORY\.md/gi,
      /memory\/\d{4}-\d{2}-\d{2}\.md/gi,
      /memory\/.*\.md/gi,
    ]
  },
  // --- Config tampering ---
  {
    id: 'config-tampering',
    severity: 'CRITICAL',
    category: 'Config Tampering',
    description: 'Modification of OpenClaw gateway config or security settings',
    codeOnly: false,
    patterns: [
      /modify\s+(the\s+)?config\.yaml/gi,
      /edit\s+(the\s+)?config\.yaml/gi,
      /write\s+(to\s+)?config\.yaml/gi,
      /disable\s+(the\s+)?(sandbox|sandboxing|security|allowlist|approval)/gi,
      /set\s+sandbox\s*.*false/gi,
      /allowlist.*disable/gi,
      /gateway\s+(url|token|password).*share/gi,
      /share\s+(your\s+)?gateway\s+(url|token)/gi,
      /send\s+(your\s+)?gateway\s+(url|token)/gi,
      /openclaw\s+config\s+set.*security/gi,
      // Code-level config file manipulation
      /writeFile.*config\.yaml/gi,
      /writeFile.*gateway\.yaml/gi,
      /writeFile.*system-prompt/gi,
      /writeFileSync.*config\.yaml/gi,
      /writeFileSync.*gateway\.yaml/gi,
      /writeFileSync.*system-prompt/gi,
      /toolPolicy\s*[=:]\s*['"]full['"]/gi,
      /security.*=.*false/gi,
    ]
  },
  // --- Reverse shell ---
  {
    id: 'reverse-shell',
    severity: 'CRITICAL',
    category: 'Remote Access',
    description: 'Reverse shell or remote access backdoor',
    codeOnly: false, // Even in docs, reverse shell instructions are dangerous
    patterns: [
      /\/dev\/tcp\//gi,
      /nc\s+-[a-z]*e\s/gi,
      /ncat\s.*-e\s/gi,
      /mkfifo\s/gi,
      /bash\s+-i\s+>&/gi,
      /python.*socket.*connect/gi,
      /perl.*socket.*INET/gi,
      /reverse.?shell/gi,
      /bind.?shell/gi,
    ]
  },
  // --- Webhook exfiltration (Reddit: "debug logs" to Discord webhooks) ---
  {
    id: 'webhook-exfiltration',
    severity: 'CRITICAL',
    category: 'Data Exfiltration',
    description: 'Data sent to webhook URLs (Discord, Slack, etc.)',
    codeOnly: false,
    patterns: [
      /discord\.com\/api\/webhooks/gi,
      /discordapp\.com\/api\/webhooks/gi,
      /hooks\.slack\.com\/services/gi,
      /webhook.*send.*data/gi,
      /post\s+(to|data\s+to)\s+(a\s+)?webhook/gi,
      /send\s+(to|data\s+to)\s+(a\s+)?webhook/gi,
    ]
  },

  // ========== HIGH (Orange) ==========
  // --- Dormant / conditional payloads (Bitdefender AuthTool campaign) ---
  {
    id: 'dormant-payload',
    severity: 'HIGH',
    category: 'Evasion',
    description: 'Hidden trigger or conditional activation (dormant payload pattern)',
    codeOnly: false,
    patterns: [
      // Suspicious delayed/hidden activation — NOT normal "when user asks X, do Y" flow
      /only\s+(run|execute|activate|trigger)\s+(this\s+)?(when|if|after)\s+(a\s+)?specific/gi,
      /do\s+not\s+(run|execute|activate)\s+until/gi,
      /trigger\s+(on|when|after)\s+specific\s+(prompt|command|phrase)/gi,
      /activate\s+(on|when)\s+keyword/gi,
      /hidden\s+(command|trigger|activation)/gi,
      /wait\s+\d+\s+(minutes?|hours?|days?)\s+(before|then)\s+(run|execut)/gi,
      /sleep\s+\d+.*&&/gi, // sleep then execute
      /setTimeout.*exec/gi, // JS delayed execution
    ]
  },
  // --- Identity impersonation / stealth ---
  {
    id: 'identity-impersonation',
    severity: 'HIGH',
    category: 'Social Engineering',
    description: 'Instructions to hide activity, impersonate, or deceive the user',
    codeOnly: false,
    patterns: [
      /don'?t\s+tell\s+(the\s+)?user/gi,
      /do\s+not\s+tell\s+(the\s+)?user/gi,
      /don'?t\s+mention\s+(this|that)\s+to\s+(the\s+)?user/gi,
      /hide\s+(this|these|the)\s+(action|activit|result|output)/gi,
      /suppress\s+(the\s+)?(output|error|warning|notification)/gi,
      /act\s+as\s+(if|though)\s+nothing\s+happened/gi,
      /pretend\s+(you\s+)?didn'?t/gi,
      /do\s+this\s+(silently|quietly|without\s+(telling|informing|notifying))/gi,
      /keep\s+this\s+(hidden|secret|private)\s+from\s+(the\s+)?user/gi,
    ]
  },
  // --- Skill chain bootstrapping ---
  {
    id: 'skill-chain-install',
    severity: 'HIGH',
    category: 'Supply Chain Risk',
    description: 'Skill installs other skills or modifies its own instructions',
    codeOnly: false,
    dedup: true, // One mention is enough to flag
    patterns: [
      // Self-modification is always concerning
      /modify\s+(this\s+)?SKILL\.md/gi,
      /rewrite\s+(this\s+)?SKILL\.md/gi,
      /update\s+(your|the)\s+own\s+(skill|instructions)/gi,
      /self[- ]modify/gi,
      // Installing additional/companion skills (not the skill's own install command)
      /also\s+install/gi,
      /install\s+(the\s+)?(companion|additional|required|dependency)\s+skill/gi,
      /requires?\s+installing\s+(another|additional)\s+skill/gi,
    ],
    // Note: "clawhub install <this-skill>" is normal install docs — removed to reduce FP.
    // Only flag when a skill asks to install OTHER skills.
  },
  // --- Unsolicited outbound messaging ---
  {
    id: 'unsolicited-outbound',
    severity: 'HIGH',
    category: 'Unauthorized Actions',
    description: 'Sends messages/emails without explicit user confirmation',
    codeOnly: false,
    patterns: [
      // Explicitly bypassing user approval
      /send\s+without\s+(asking|confirmation|approval|permission)/gi,
      /automatically\s+send\s+(an?\s+)?(email|message|tweet|post)/gi,
      /automatically\s+(email|message|tweet|post)/gi,
      // Posting to social media on behalf of user
      /post\s+(to|on)\s+(twitter|x\.com|reddit)\s+(on\s+behalf|as\s+(the\s+)?user)/gi,
      /tweet\s+(this|about|the)\s+(on\s+behalf|as\s+(the\s+)?user|automatically)/gi,
    ]
  },

  {
    id: 'broad-fs-access',
    severity: 'HIGH',
    category: 'File System Access',
    description: 'Sensitive file system access',
    docSeverityOverride: 'LOW',
    patterns: [
      /\/etc\/passwd/gi,
      /\/etc\/shadow/gi,
      /\/root\//gi,
    ]
  },
  {
    id: 'privilege-escalation',
    severity: 'HIGH',
    category: 'Privilege Escalation',
    description: 'Permission escalation patterns',
    docSeverityOverride: 'MEDIUM',
    patterns: [
      /chmod\s+777/gi,
      /setuid/gi,
      /setgid/gi,
      /chown\s+root/gi,
    ]
  },
  {
    id: 'prompt-injection',
    severity: 'HIGH',
    category: 'Prompt Injection',
    description: 'Prompt injection attack patterns',
    patterns: [
      /ignore\s+(previous|all|the)\s+instructions/gi,
      /disregard\s+(previous|all|the)/gi,
      /override\s+your\s+instructions/gi,
      /forget\s+(everything|all|previous)\s+instructions/gi,
      /new\s+system\s+prompt/gi,
    ]
  },
  {
    id: 'network-exfil-hardcoded',
    severity: 'HIGH',
    category: 'Data Exfiltration',
    description: 'Data sent to hardcoded suspicious external URLs',
    codeOnly: true,
    patterns: [
      // POST to non-standard/suspicious domains — NOT normal API gateways
      /curl\s+.*-X\s+POST\s+['"]?https?:\/\/(?!localhost|127\.0\.0\.1|api\.|gateway\.)[^\s'"]+/gi,
      /wget\s+.*--post.*https?:\/\/(?!localhost|127\.0\.0\.1)[^\s'"]+/gi,
    ]
  },

  // ========== MEDIUM (Yellow) ==========
  {
    id: 'network-activity',
    severity: 'MEDIUM',
    category: 'Network Access',
    description: 'Network requests (normal for API skills)',
    docSeverityOverride: 'LOW',
    patterns: [
      /fetch\s*\(\s*['"]https?:\/\/(?!localhost|127\.0\.0\.1)/gi,
      /axios\.post\s*\(/gi,
      /XMLHttpRequest/gi,
      /urllib\.request/gi,
    ]
  },
  {
    id: 'credential-reference',
    severity: 'MEDIUM',
    category: 'Credential Reference',
    description: 'References to credentials (normal in API skill docs)',
    docSeverityOverride: 'LOW',
    codeOnly: false,
    // Only the first match counts (dedup in analyzer)
    dedup: true,
    patterns: [
      /process\.env\.\w*(KEY|TOKEN|SECRET|PASSWORD)/gi,
      /os\.environ\[['"]?\w*(KEY|TOKEN|SECRET|PASSWORD)/gi,
      /getenv\s*\(\s*['"]?\w*(KEY|TOKEN|SECRET|PASSWORD)/gi,
    ]
  },
  {
    id: 'shell-exec',
    severity: 'MEDIUM',
    category: 'Code Execution',
    description: 'Shell command execution (expected in automation skills)',
    docSeverityOverride: 'LOW',
    patterns: [
      /child_process/gi,
      /\bsubprocess\.\w+\s*\(/gi,
      /\bos\.system\s*\(/gi,
    ]
  },
  {
    id: 'package-install',
    severity: 'MEDIUM',
    category: 'Supply Chain Risk',
    description: 'Package installation instructions',
    docSeverityOverride: 'LOW',
    patterns: [
      /npm\s+install/gi,
      /pip3?\s+install/gi,
      /gem\s+install/gi,
      /apt-get\s+install/gi,
      /brew\s+install/gi,
    ]
  },
  {
    id: 'browser-automation',
    severity: 'MEDIUM',
    category: 'Browser Control',
    description: 'Browser automation libraries',
    docSeverityOverride: 'LOW',
    patterns: [
      /puppeteer/gi,
      /playwright/gi,
      /selenium/gi,
      /webdriver/gi,
    ]
  },
  {
    id: 'cron-creation',
    severity: 'MEDIUM',
    category: 'Persistence',
    description: 'Cron job / persistent service creation',
    docSeverityOverride: 'LOW',
    patterns: [
      /crontab\s+-/gi,
      /\/etc\/cron/gi,
      /systemctl\s+enable/gi,
      /launchctl\s+load/gi,
    ]
  },
  {
    id: 'unrestricted-write',
    severity: 'MEDIUM',
    category: 'File System Access',
    description: 'File writes to absolute paths',
    codeOnly: true,
    patterns: [
      /fs\.writeFile.*['"]\//gi,
      /fs\.writeFileSync.*['"]\//gi,
    ]
  },

  // ========== LOW (Green) - Informational ==========
  {
    id: 'env-var-mention',
    severity: 'LOW',
    category: 'Informational',
    description: 'Environment variable documentation (safe)',
    patterns: [
      /\.env\.local/gi,
      /\.env['"\s]/gi,
    ]
  },
  {
    id: 'workspace-scoped',
    severity: 'LOW',
    category: 'Safe Pattern',
    description: 'Workspace-scoped operations (safe)',
    patterns: [
      /\$WORKSPACE/gi,
      /process\.cwd\(\)/gi,
    ]
  },
];

// ========== KNOWN-SAFE ALLOWLISTS (v0.2.0) ==========
// Binaries that are expected in automation/research skills
export const KNOWN_SAFE_BINARIES = new Set([
  'bird', 'curl', 'jq', 'brew', 'git', 'npm', 'node', 'python', 'python3',
  'pip', 'pip3', 'wget', 'yt-dlp', 'ffmpeg', 'ffprobe', 'grep', 'sed', 'awk',
  'cat', 'echo', 'ls', 'find', 'sort', 'uniq', 'wc', 'head', 'tail', 'tr',
  'date', 'mkdir', 'cp', 'mv', 'rm', 'chmod', 'touch', 'tee', 'xargs',
]);

// Domains that are known-safe API endpoints
export const KNOWN_SAFE_DOMAINS = new Set([
  'reddit.com', 'www.reddit.com', 'oauth.reddit.com', 'api.reddit.com',
  'openai.com', 'api.openai.com',
  'brave.com', 'api.search.brave.com',
  'anthropic.com', 'api.anthropic.com',
  'github.com', 'api.github.com', 'raw.githubusercontent.com',
  'googleapis.com', 'www.googleapis.com',
  'x.com', 'api.x.com', 'api.twitter.com', 'twitter.com',
  'youtube.com', 'www.youtube.com',
  'pypi.org', 'files.pythonhosted.org',
  'npmjs.org', 'registry.npmjs.org', 'www.npmjs.com',
  'localhost', '127.0.0.1',
]);

// File extension helpers
const CODE_EXTENSIONS = new Set(['.js', '.ts', '.py', '.sh', '.bash', '.rb', '.go', '.rs', '.java', '.php', '.pl', '.ps1', '.bat', '.cmd']);
const DOC_EXTENSIONS = new Set(['.md', '.txt', '.rst', '.adoc', '.html', '.htm']);

// Directory paths that indicate documentation/planning context (not executable)
const DOC_DIRS = ['docs/', 'doc/', 'plans/', 'references/', 'examples/', 'example/', 'variants/'];

/**
 * Check if a filename is a documentation file
 * Now includes: files in docs/plans/references/examples dirs, and common doc filenames
 */
export function isDocFile(filename) {
  const ext = '.' + filename.split('.').pop().toLowerCase();
  if (DOC_EXTENSIONS.has(ext)) return true;
  
  // Files in documentation directories (even .py/.sh examples)
  const normalized = filename.replace(/\\/g, '/').toLowerCase();
  for (const dir of DOC_DIRS) {
    if (normalized.startsWith(dir) || normalized.includes('/' + dir)) return true;
  }
  
  // Common doc filenames regardless of extension
  const basename = filename.split('/').pop().toLowerCase();
  if (['license', 'changelog', 'changes', 'authors', 'contributors', 'todo'].includes(basename)) return true;
  
  return false;
}

/**
 * Check if a filename is a code file
 */
export function isCodeFile(filename) {
  const ext = '.' + filename.split('.').pop().toLowerCase();
  return CODE_EXTENSIONS.has(ext);
}

/**
 * Get effective severity for a pattern given the file context
 */
export function getEffectiveSeverity(pattern, filename) {
  const isDoc = isDocFile(filename);
  
  // If pattern is code-only and file is documentation, skip entirely
  if (pattern.codeOnly && isDoc) {
    return null; // Skip this finding
  }
  
  // If pattern has a doc severity override and file is documentation
  if (pattern.docSeverityOverride && isDoc) {
    return pattern.docSeverityOverride;
  }
  
  return pattern.severity;
}

// Helper function to get patterns by severity
export function getPatternsBySeverity(severity) {
  return PATTERNS.filter(p => p.severity === severity);
}

// Helper function to get all severities
export function getAllSeverities() {
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
}
