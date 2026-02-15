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
async function scanSkill(skillPath, jsonMode = false) {
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
ClawRank Security Scanner v0.1.0

Usage:
  clawrank-scanner scan <path>      Scan a single skill directory
  clawrank-scanner <path>           Scan a single skill (shorthand)
  clawrank-scanner scan-all         Scan all skills in data/
  clawrank-scanner report           Generate summary report

Options:
  --json                            Output results as JSON
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
  const filteredArgs = args.filter(a => a !== '--json');
  const command = filteredArgs[0];

  switch (command) {
    case '--version':
    case '-v':
      console.log('0.1.0');
      break;

    case 'scan':
      if (filteredArgs.length < 2) {
        console.error('❌ Error: Missing path argument');
        console.error('Usage: clawrank-scanner scan <path>');
        process.exit(1);
      }
      await scanSkill(filteredArgs[1], jsonMode);
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
        await scanSkill(command, jsonMode);
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
