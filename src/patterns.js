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
      /base64\s+.*[|>]/gi,     // base64 piped to something
      /atob\s*\(.*eval/gi,     // decode then eval
      /Buffer\.from\(.*,\s*['"]base64['"]\).*eval/gi,
      /b64decode.*exec/gi,
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

  // ========== HIGH (Orange) ==========
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

// File extension helpers
const CODE_EXTENSIONS = new Set(['.js', '.ts', '.py', '.sh', '.bash', '.rb', '.go', '.rs', '.java', '.php', '.pl', '.ps1', '.bat', '.cmd']);
const DOC_EXTENSIONS = new Set(['.md', '.txt', '.rst', '.adoc', '.html', '.htm']);

/**
 * Check if a filename is a documentation file
 */
export function isDocFile(filename) {
  const ext = '.' + filename.split('.').pop().toLowerCase();
  return DOC_EXTENSIONS.has(ext);
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
