import fs from 'fs';
import path from 'path';

const RESULTS_DIR = path.join(process.cwd(), 'results');

/**
 * Reads all scan results from the results directory
 * @returns {Array} Array of scan results
 */
export function loadAllResults() {
  const results = [];
  
  if (!fs.existsSync(RESULTS_DIR)) {
    return results;
  }

  const files = fs.readdirSync(RESULTS_DIR);
  
  for (const file of files) {
    if (file.endsWith('.json') && file !== 'summary.json') {
      const filePath = path.join(RESULTS_DIR, file);
      try {
        const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
        results.push(data);
      } catch (error) {
        console.error(`Error reading ${file}:`, error.message);
      }
    }
  }
  
  return results;
}

/**
 * Generates aggregate statistics from all scan results
 * @param {Array} results - Array of scan results
 * @returns {Object} Aggregate statistics
 */
export function generateStatistics(results) {
  const stats = {
    totalSkills: results.length,
    skillsScanned: 0,
    skillsWithErrors: 0,
    totalFindings: 0,
    findingsBySeverity: {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0
    },
    scoreDistribution: {
      A: 0, // 90-100
      B: 0, // 80-89
      C: 0, // 70-79
      D: 0, // 60-69
      F: 0  // 0-59
    },
    topPatterns: {},
    dangerousSkills: [],
    safeSkills: [],
    averageScore: 0
  };

  let totalScore = 0;

  for (const result of results) {
    if (result.error) {
      stats.skillsWithErrors++;
      continue;
    }

    stats.skillsScanned++;
    
    // Score distribution
    if (result.grade) {
      stats.scoreDistribution[result.grade]++;
    }

    // Accumulate score
    if (typeof result.score === 'number') {
      totalScore += result.score;
    }

    // Count findings
    if (result.findings && Array.isArray(result.findings)) {
      stats.totalFindings += result.findings.length;

      for (const finding of result.findings) {
        // Count by severity
        if (stats.findingsBySeverity.hasOwnProperty(finding.severity)) {
          stats.findingsBySeverity[finding.severity]++;
        }

        // Count by pattern
        const patternId = finding.patternId || 'unknown';
        if (!stats.topPatterns[patternId]) {
          stats.topPatterns[patternId] = {
            count: 0,
            severity: finding.severity,
            description: finding.description
          };
        }
        stats.topPatterns[patternId].count++;
      }
    }

    // Categorize skills
    const skill = {
      slug: result.slug,
      score: result.score,
      grade: result.grade,
      findings: result.totalFindings || 0
    };

    if (result.score < 70 || (result.severityCounts && result.severityCounts.CRITICAL > 0)) {
      stats.dangerousSkills.push(skill);
    } else if (result.score >= 90) {
      stats.safeSkills.push(skill);
    }
  }

  // Calculate average score
  if (stats.skillsScanned > 0) {
    stats.averageScore = Math.round(totalScore / stats.skillsScanned);
  }

  // Sort top patterns by count
  stats.topPatterns = Object.entries(stats.topPatterns)
    .map(([id, data]) => ({ id, ...data }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // Sort dangerous skills by score (worst first)
  stats.dangerousSkills.sort((a, b) => a.score - b.score);

  return stats;
}

/**
 * Generates a markdown report
 * @param {Object} stats - Statistics object
 * @returns {string} Markdown report
 */
export function generateMarkdownReport(stats) {
  const timestamp = new Date().toISOString().split('T')[0];
  
  let md = `# ClawRank Security Report\n\n`;
  md += `**Generated:** ${timestamp}\n\n`;
  md += `---\n\n`;
  
  // Executive Summary
  md += `## Executive Summary\n\n`;
  md += `- **Total Skills Analyzed:** ${stats.totalSkills}\n`;
  md += `- **Successfully Scanned:** ${stats.skillsScanned}\n`;
  md += `- **Scan Errors:** ${stats.skillsWithErrors}\n`;
  md += `- **Total Security Findings:** ${stats.totalFindings}\n`;
  md += `- **Average Security Score:** ${stats.averageScore}/100\n\n`;

  // Risk Overview
  md += `## Risk Overview\n\n`;
  
  const pctSafe = stats.skillsScanned > 0 
    ? Math.round((stats.scoreDistribution.A / stats.skillsScanned) * 100) 
    : 0;
  const pctDangerous = stats.skillsScanned > 0 
    ? Math.round(((stats.scoreDistribution.D + stats.scoreDistribution.F) / stats.skillsScanned) * 100) 
    : 0;
  
  md += `- **Safe Skills (A):** ${stats.scoreDistribution.A} (${pctSafe}%)\n`;
  md += `- **At-Risk Skills (D/F):** ${stats.scoreDistribution.D + stats.scoreDistribution.F} (${pctDangerous}%)\n\n`;

  // Grade Distribution
  md += `### Grade Distribution\n\n`;
  md += `| Grade | Count | Percentage |\n`;
  md += `|-------|-------|------------|\n`;
  for (const [grade, count] of Object.entries(stats.scoreDistribution)) {
    const pct = stats.skillsScanned > 0 
      ? Math.round((count / stats.skillsScanned) * 100) 
      : 0;
    const emoji = grade === 'A' ? '🟢' : grade === 'B' ? '🟡' : grade === 'F' ? '🔴' : '🟠';
    md += `| ${emoji} ${grade} | ${count} | ${pct}% |\n`;
  }
  md += `\n`;

  // Findings by Severity
  md += `## Findings by Severity\n\n`;
  md += `| Severity | Count |\n`;
  md += `|----------|-------|\n`;
  md += `| 🔴 CRITICAL | ${stats.findingsBySeverity.CRITICAL} |\n`;
  md += `| 🟠 HIGH | ${stats.findingsBySeverity.HIGH} |\n`;
  md += `| 🟡 MEDIUM | ${stats.findingsBySeverity.MEDIUM} |\n`;
  md += `| 🟢 LOW | ${stats.findingsBySeverity.LOW} |\n`;
  md += `\n`;

  // Top Patterns
  if (stats.topPatterns.length > 0) {
    md += `## Top Security Patterns Detected\n\n`;
    md += `| Pattern | Severity | Count | Description |\n`;
    md += `|---------|----------|-------|-------------|\n`;
    
    for (const pattern of stats.topPatterns) {
      const emoji = pattern.severity === 'CRITICAL' ? '🔴' : 
                    pattern.severity === 'HIGH' ? '🟠' :
                    pattern.severity === 'MEDIUM' ? '🟡' : '🟢';
      md += `| ${pattern.id} | ${emoji} ${pattern.severity} | ${pattern.count} | ${pattern.description} |\n`;
    }
    md += `\n`;
  }

  // Dangerous Skills
  if (stats.dangerousSkills.length > 0) {
    md += `## ⚠️ High-Risk Skills (Score < 70 or Critical Findings)\n\n`;
    md += `| Skill | Score | Grade | Findings |\n`;
    md += `|-------|-------|-------|----------|\n`;
    
    const topDangerous = stats.dangerousSkills.slice(0, 20);
    for (const skill of topDangerous) {
      md += `| ${skill.slug} | ${skill.score}/100 | ${skill.grade} | ${skill.findings} |\n`;
    }
    
    if (stats.dangerousSkills.length > 20) {
      md += `\n*... and ${stats.dangerousSkills.length - 20} more high-risk skills*\n`;
    }
    md += `\n`;
  }

  // Safe Skills
  if (stats.safeSkills.length > 0) {
    md += `## ✅ Safe Skills (Score ≥ 90)\n\n`;
    md += `${stats.safeSkills.length} skills received an A grade with minimal security concerns.\n\n`;
  }

  // Recommendations
  md += `## Recommendations\n\n`;
  
  if (stats.findingsBySeverity.CRITICAL > 0) {
    md += `⚠️ **CRITICAL:** ${stats.findingsBySeverity.CRITICAL} critical security findings detected. These skills should be reviewed immediately and potentially removed from the marketplace.\n\n`;
  }
  
  if (pctDangerous > 20) {
    md += `⚠️ **HIGH RISK PREVALENCE:** ${pctDangerous}% of skills are high-risk (D/F grade). Consider implementing mandatory security reviews before publication.\n\n`;
  }
  
  if (stats.topPatterns.length > 0 && stats.topPatterns[0].severity === 'CRITICAL') {
    md += `⚠️ **COMMON CRITICAL PATTERN:** The most common security issue is "${stats.topPatterns[0].description}" (${stats.topPatterns[0].count} occurrences). This pattern should be highlighted in developer documentation.\n\n`;
  }

  md += `---\n\n`;
  md += `*Report generated by ClawRank Security Scanner*\n`;
  
  return md;
}

/**
 * Saves the summary report to disk
 * @param {Object} stats - Statistics object
 */
export function saveSummaryReport(stats) {
  if (!fs.existsSync(RESULTS_DIR)) {
    fs.mkdirSync(RESULTS_DIR, { recursive: true });
  }

  // Save JSON summary
  const jsonPath = path.join(RESULTS_DIR, 'summary.json');
  fs.writeFileSync(jsonPath, JSON.stringify(stats, null, 2), 'utf-8');
  console.log(`📄 Saved JSON summary: ${jsonPath}`);

  // Save markdown report
  const markdown = generateMarkdownReport(stats);
  const mdPath = path.join(RESULTS_DIR, 'summary.md');
  fs.writeFileSync(mdPath, markdown, 'utf-8');
  console.log(`📄 Saved markdown report: ${mdPath}`);

  return { jsonPath, mdPath };
}
