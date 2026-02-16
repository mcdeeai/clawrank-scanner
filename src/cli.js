#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { analyzeSkill, analyzeAllSkills } from './analyzer.js';
import { scoreAnalysis, generateScoreSummary } from './scorer.js';
import { loadAllResults, generateStatistics, saveSummaryReport } from './report.js';

const DATA_DIR = path.join(process.cwd(), 'data');
const RESULTS_DIR = path.join(process.cwd(), 'results');

/**
 * Scans a single skill directory
 * @param {string} skillPath - Path to skill directory
 */
const SCANNER_VERSION = '0.2.0';

async function scanSkill(skillPath, jsonMode = false, reportMode = false) {
  if (!jsonMode) console.log(`🔍 Scanning: ${skillPath}\n`);

  if (!fs.existsSync(skillPath)) {
    console.error(`❌ Error: Path does not exist: ${skillPath}`);
    process.exit(1);
  }

  const analysis = await analyzeSkill(skillPath);
  const scored = scoreAnalysis(analysis);

  if (jsonMode) {
    console.log(JSON.stringify(scored, null, 2));
    return;
  }

  // Display results
  console.log(generateScoreSummary(scored));

  if (scored.findings && scored.findings.length > 0) {
    console.log('\nFindings:\n');
    
    // Group by severity
    const bySeverity = {};
    for (const finding of scored.findings) {
      if (!bySeverity[finding.severity]) {
        bySeverity[finding.severity] = [];
      }
      bySeverity[finding.severity].push(finding);
    }

    // Display in order
    for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      if (bySeverity[severity]) {
        const emoji = severity === 'CRITICAL' ? '🔴' : 
                      severity === 'HIGH' ? '🟠' :
                      severity === 'MEDIUM' ? '🟡' : '🟢';
        
        console.log(`${emoji} ${severity} (${bySeverity[severity].length}):`);
        
        for (const finding of bySeverity[severity].slice(0, 10)) {
          console.log(`  - ${finding.description}`);
          console.log(`    File: ${finding.file}:${finding.line}`);
          console.log(`    Snippet: ${finding.snippet}`);
          if (finding.context) {
            console.log(`    💡 ${finding.context}`);
          }
          console.log();
        }

        if (bySeverity[severity].length > 10) {
          console.log(`  ... and ${bySeverity[severity].length - 10} more\n`);
        }
      }
    }
  }

  // Save results
  const slug = path.basename(skillPath);
  if (!fs.existsSync(RESULTS_DIR)) {
    fs.mkdirSync(RESULTS_DIR, { recursive: true });
  }

  const resultPath = path.join(RESULTS_DIR, `${slug}.json`);
  fs.writeFileSync(resultPath, JSON.stringify(scored, null, 2), 'utf-8');
  console.log(`💾 Results saved to: ${resultPath}`);

  // Generate report if --report flag
  if (reportMode) {
    generateSkillReport(skillPath, scored);
  }
}

/**
 * Generate a per-skill JSON + Markdown report
 */
function generateSkillReport(skillPath, scored) {
  const slug = path.basename(skillPath);
  
  // Try to read SKILL.md for summary
  let skillSummary = 'No SKILL.md found.';
  const skillMdPath = path.join(skillPath, 'SKILL.md');
  if (fs.existsSync(skillMdPath)) {
    const content = fs.readFileSync(skillMdPath, 'utf-8');
    // Take first paragraph after the title
    const lines = content.split('\n').filter(l => l.trim() && !l.startsWith('#'));
    skillSummary = lines.slice(0, 3).join(' ').substring(0, 300);
  }

  // JSON report
  const jsonReport = {
    skillName: slug,
    grade: scored.grade,
    score: scored.score,
    filesScanned: scored.filesScanned,
    findings: (scored.findings || []).map(f => ({
      severity: f.severity,
      category: f.category,
      description: f.description,
      patternId: f.patternId,
      file: f.file,
      line: f.line,
      snippet: f.snippet,
      context: f.context || null,
      allowlisted: f.allowlisted || false,
    })),
    timestamp: new Date().toISOString(),
    scannerVersion: SCANNER_VERSION,
  };

  const reportDir = path.join(RESULTS_DIR, 'reports');
  if (!fs.existsSync(reportDir)) fs.mkdirSync(reportDir, { recursive: true });

  const jsonPath = path.join(reportDir, `${slug}.json`);
  fs.writeFileSync(jsonPath, JSON.stringify(jsonReport, null, 2), 'utf-8');

  // Markdown report
  const emoji = scored.grade === 'A' ? '🟢' : scored.grade === 'B' ? '🟡' : scored.grade === 'C' ? '🟠' : '🔴';
  let md = `# ClawRank Security Report: ${slug}\n\n`;
  md += `**Grade:** ${emoji} ${scored.grade} (${scored.score}/100)\n`;
  md += `**Files Scanned:** ${scored.filesScanned}\n`;
  md += `**Scanner Version:** ${SCANNER_VERSION}\n`;
  md += `**Generated:** ${new Date().toISOString()}\n\n`;
  md += `## Summary\n\n${skillSummary}\n\n`;

  if (scored.findings && scored.findings.length > 0) {
    md += `## Findings\n\n`;
    
    for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      const group = scored.findings.filter(f => f.severity === severity);
      if (group.length === 0) continue;
      
      const sevEmoji = severity === 'CRITICAL' ? '🔴' : severity === 'HIGH' ? '🟠' : severity === 'MEDIUM' ? '🟡' : '🟢';
      md += `### ${sevEmoji} ${severity} (${group.length})\n\n`;
      
      for (const f of group) {
        md += `**${f.description}** — \`${f.file}:${f.line}\`\n`;
        md += `\`\`\`\n${f.snippet}\n\`\`\`\n`;
        if (f.context) {
          md += `> 💡 ${f.context}\n`;
        }
        md += `\n`;
      }
    }

    // What to Consider section
    md += `## What to Consider\n\n`;
    const critCount = scored.severityCounts?.CRITICAL || 0;
    const highCount = scored.severityCounts?.HIGH || 0;
    const medCount = scored.severityCounts?.MEDIUM || 0;
    const allowlistedCount = scored.findings.filter(f => f.allowlisted).length;

    if (critCount > 0) {
      md += `⚠️ **${critCount} critical finding(s)** detected that may pose significant security risk.\n\n`;
    }
    if (highCount > 0) {
      md += `🟠 **${highCount} high-severity finding(s)** that warrant careful review.\n\n`;
    }
    if (allowlistedCount > 0) {
      md += `✅ **${allowlistedCount} finding(s)** were identified as known-safe patterns (severity reduced by one level).\n\n`;
    }
    if (medCount > 0) {
      md += `🟡 **${medCount} medium-severity finding(s)** are typical for automation skills but should be understood.\n\n`;
    }

    // Summarize what the skill does based on findings
    const usesSubprocess = scored.findings.some(f => f.patternId === 'shell-exec' || f.patternId === 'shell-exec-dangerous');
    const usesNetwork = scored.findings.some(f => f.patternId === 'network-activity' || f.patternId === 'network-exfil-hardcoded');
    const usesCredentials = scored.findings.some(f => f.patternId === 'credential-reference');

    if (usesSubprocess || usesNetwork || usesCredentials) {
      md += `**This skill:**\n`;
      if (usesSubprocess) {
        const bins = scored.findings.filter(f => f.allowlisted && f.allowlistReason === 'known-safe binary').map(f => f.context?.match(/'([^']+)'/)?.[1]).filter(Boolean);
        md += `- Uses subprocess execution${bins.length ? ` (targets: ${[...new Set(bins)].join(', ')})` : ''}\n`;
      }
      if (usesNetwork) {
        const domains = scored.findings.filter(f => f.allowlisted && f.allowlistReason === 'known-safe domain').map(f => f.context?.match(/goes to ([^,]+)/)?.[1]).filter(Boolean);
        md += `- Makes network requests${domains.length ? ` (to: ${[...new Set(domains)].join(', ')})` : ''}\n`;
      }
      if (usesCredentials) {
        md += `- References API keys/tokens via environment variables\n`;
      }
      md += `\n`;
    }
  } else {
    md += `## Findings\n\n✅ No security issues detected.\n\n`;
  }

  md += `---\n*Report generated by ClawRank Security Scanner v${SCANNER_VERSION}*\n`;

  const mdPath = path.join(reportDir, `${slug}.md`);
  fs.writeFileSync(mdPath, md, 'utf-8');

  console.log(`\n📋 Report generated:`);
  console.log(`  JSON: ${jsonPath}`);
  console.log(`  Markdown: ${mdPath}`);
}

/**
 * Scans all skills in the data directory
 */
async function scanAll() {
  console.log('🔍 Scanning all skills...\n');

  if (!fs.existsSync(DATA_DIR)) {
    console.error(`❌ Error: Data directory does not exist: ${DATA_DIR}`);
    console.error('Run the scraper first: node src/scraper.js');
    process.exit(1);
  }

  const results = await analyzeAllSkills(DATA_DIR);

  console.log(`\n📊 Scoring results...\n`);

  // Ensure results directory exists
  if (!fs.existsSync(RESULTS_DIR)) {
    fs.mkdirSync(RESULTS_DIR, { recursive: true });
  }

  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;

  for (const result of results) {
    const scored = scoreAnalysis(result);
    
    // Count severity
    if (scored.severityCounts) {
      critical += scored.severityCounts.CRITICAL || 0;
      high += scored.severityCounts.HIGH || 0;
      medium += scored.severityCounts.MEDIUM || 0;
      low += scored.severityCounts.LOW || 0;
    }

    // Save individual result
    const resultPath = path.join(RESULTS_DIR, `${scored.slug}.json`);
    fs.writeFileSync(resultPath, JSON.stringify(scored, null, 2), 'utf-8');

    // Progress indicator
    const emoji = scored.score >= 90 ? '✅' : 
                  scored.score >= 70 ? '⚠️' : '❌';
    console.log(`${emoji} ${scored.slug}: ${scored.score}/100 (${scored.grade})`);
  }

  console.log(`\n✅ Scan complete!`);
  console.log(`  - Scanned: ${results.length} skills`);
  console.log(`  - 🔴 Critical findings: ${critical}`);
  console.log(`  - 🟠 High findings: ${high}`);
  console.log(`  - 🟡 Medium findings: ${medium}`);
  console.log(`  - 🟢 Low findings: ${low}`);
  console.log(`  - 📁 Results saved to: ${RESULTS_DIR}`);
  console.log(`\nRun 'node src/cli.js report' to generate summary report.`);
}

/**
 * Generates a summary report from all results
 */
function generateReport() {
  console.log('📊 Generating summary report...\n');

  const results = loadAllResults();

  if (results.length === 0) {
    console.error('❌ No results found. Run scan-all first.');
    process.exit(1);
  }

  const stats = generateStatistics(results);
  const paths = saveSummaryReport(stats);

  console.log(`\n✅ Report generated!`);
  console.log(`  - JSON: ${paths.jsonPath}`);
  console.log(`  - Markdown: ${paths.mdPath}`);
  
  // Display quick stats
  console.log(`\n📊 Quick Stats:`);
  console.log(`  - Total skills: ${stats.totalSkills}`);
  console.log(`  - Average score: ${stats.averageScore}/100`);
  console.log(`  - Grade A: ${stats.scoreDistribution.A}`);
  console.log(`  - Grade B: ${stats.scoreDistribution.B}`);
  console.log(`  - Grade C: ${stats.scoreDistribution.C}`);
  console.log(`  - Grade D: ${stats.scoreDistribution.D}`);
  console.log(`  - Grade F: ${stats.scoreDistribution.F}`);
  console.log(`  - High-risk skills: ${stats.dangerousSkills.length}`);
}

/**
 * Displays usage information
 */
function showHelp() {
  console.log(`
ClawRank Security Scanner v0.2.0

Usage:
  clawrank-scanner scan <path>      Scan a single skill directory
  clawrank-scanner <path>           Scan a single skill (shorthand)
  clawrank-scanner scan-all         Scan all skills in data/
  clawrank-scanner report           Generate summary report

Options:
  --json                            Output results as JSON
  --report                          Generate JSON + Markdown report files
  --version, -v                     Show version
  --help, -h                        Show this help

Examples:
  npx clawrank-scanner scan ./my-skill
  npx clawrank-scanner ./my-skill --json
  clawrank-scanner scan-all

Learn more: https://clawrank.io
`);
}

// Main CLI handler
async function main() {
  const args = process.argv.slice(2);
  const jsonMode = args.includes('--json');
  const reportMode = args.includes('--report');
  const filteredArgs = args.filter(a => a !== '--json' && a !== '--report');
  const command = filteredArgs[0];

  switch (command) {
    case '--version':
    case '-v':
      console.log(SCANNER_VERSION);
      break;

    case 'scan':
      if (filteredArgs.length < 2) {
        console.error('❌ Error: Missing path argument');
        console.error('Usage: clawrank-scanner scan <path>');
        process.exit(1);
      }
      await scanSkill(filteredArgs[1], jsonMode, reportMode);
      break;

    case 'scan-all':
      await scanAll();
      break;

    case 'report':
      generateReport();
      break;

    case 'help':
    case '--help':
    case '-h':
      showHelp();
      break;

    default:
      // If first arg looks like a path, treat as implicit scan
      if (command && !command.startsWith('-') && fs.existsSync(command)) {
        await scanSkill(command, jsonMode, reportMode);
      } else {
        if (command) {
          console.error(`❌ Unknown command: ${command}\n`);
        }
        showHelp();
        process.exit(1);
      }
  }
}

main().catch(error => {
  console.error('❌ Fatal error:', error.message);
  process.exit(1);
});
