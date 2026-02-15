/**
 * Scoring engine for skill security analysis
 */

const SEVERITY_DEDUCTIONS = {
  CRITICAL: 30,
  HIGH: 15,
  MEDIUM: 5,
  LOW: 0
};

const GRADE_THRESHOLDS = {
  A: 90,
  B: 80,
  C: 70,
  D: 60,
  F: 0
};

const COLOR_MAP = {
  A: 'green',
  B: 'yellow',
  C: 'orange',
  D: 'orange',
  F: 'red'
};

/**
 * Calculates security score from findings
 * @param {Array} findings - Array of security findings
 * @returns {Object} Score object with score, grade, color, and breakdown
 */
export function calculateScore(findings) {
  let score = 100;
  const severityCounts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };

  // Count findings by severity
  for (const finding of findings) {
    if (severityCounts.hasOwnProperty(finding.severity)) {
      severityCounts[finding.severity]++;
    }
  }

  // Apply deductions
  for (const [severity, count] of Object.entries(severityCounts)) {
    const deduction = SEVERITY_DEDUCTIONS[severity] * count;
    score -= deduction;
  }

  // Floor at 0
  score = Math.max(0, score);

  // Determine grade
  const grade = getGrade(score);
  
  // Determine color
  const color = COLOR_MAP[grade];

  // Calculate total deductions for breakdown
  const deductions = {};
  for (const [severity, count] of Object.entries(severityCounts)) {
    if (count > 0) {
      deductions[severity] = {
        count,
        perFinding: SEVERITY_DEDUCTIONS[severity],
        total: SEVERITY_DEDUCTIONS[severity] * count
      };
    }
  }

  return {
    score,
    grade,
    color,
    severityCounts,
    deductions,
    totalFindings: findings.length
  };
}

/**
 * Gets letter grade for a score
 * @param {number} score - Numeric score (0-100)
 * @returns {string} Letter grade (A-F)
 */
function getGrade(score) {
  if (score >= GRADE_THRESHOLDS.A) return 'A';
  if (score >= GRADE_THRESHOLDS.B) return 'B';
  if (score >= GRADE_THRESHOLDS.C) return 'C';
  if (score >= GRADE_THRESHOLDS.D) return 'D';
  return 'F';
}

/**
 * Generates a score summary with analysis
 * @param {Object} scoreData - Score object from calculateScore
 * @returns {string} Human-readable summary
 */
export function generateScoreSummary(scoreData) {
  const { score, grade, color, severityCounts, totalFindings } = scoreData;
  
  let summary = `Security Score: ${score}/100 (Grade ${grade})\n`;
  summary += `Risk Level: ${color.toUpperCase()}\n`;
  summary += `Total Findings: ${totalFindings}\n\n`;
  
  if (totalFindings === 0) {
    summary += '✅ No security issues detected.\n';
  } else {
    summary += 'Findings by Severity:\n';
    
    if (severityCounts.CRITICAL > 0) {
      summary += `  🔴 CRITICAL: ${severityCounts.CRITICAL}\n`;
    }
    if (severityCounts.HIGH > 0) {
      summary += `  🟠 HIGH: ${severityCounts.HIGH}\n`;
    }
    if (severityCounts.MEDIUM > 0) {
      summary += `  🟡 MEDIUM: ${severityCounts.MEDIUM}\n`;
    }
    if (severityCounts.LOW > 0) {
      summary += `  🟢 LOW: ${severityCounts.LOW}\n`;
    }
  }
  
  return summary;
}

/**
 * Scores a skill analysis result
 * @param {Object} analysis - Analysis result from analyzer
 * @returns {Object} Analysis with score added
 */
export function scoreAnalysis(analysis) {
  const score = calculateScore(analysis.findings || []);
  
  return {
    ...analysis,
    score: score.score,
    grade: score.grade,
    color: score.color,
    severityCounts: score.severityCounts,
    deductions: score.deductions,
    totalFindings: score.totalFindings
  };
}
