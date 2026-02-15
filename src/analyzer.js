import fs from 'fs';
import path from 'path';
import { PATTERNS, getEffectiveSeverity, isDocFile } from './patterns.js';

/**
 * Analyzes a skill directory for security vulnerabilities
 * @param {string} skillPath - Path to the skill directory
 * @returns {Object} Analysis results with findings
 */
export async function analyzeSkill(skillPath) {
  const findings = [];
  const files = [];

  try {
    // Read all files in the skill directory recursively
    function readDirRecursive(dir, baseDir = dir) {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        const relativePath = path.relative(baseDir, fullPath);
        
        if (entry.isDirectory()) {
          // Skip directories that aren't skill content
          if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === '.svn') continue;
          readDirRecursive(fullPath, baseDir);
        } else if (entry.isFile()) {
          // Skip metadata.json (our own artifact) and lock files
          if (entry.name === 'metadata.json') continue;
          if (entry.name === 'package-lock.json' || entry.name === 'yarn.lock' || entry.name === 'pnpm-lock.yaml') continue;
          
          try {
            const content = fs.readFileSync(fullPath, 'utf-8');
            files.push({
              name: relativePath,
              path: fullPath,
              content: content
            });
            
            // Analyze this file
            const fileFindings = analyzeFile(relativePath, content);
            findings.push(...fileFindings);
          } catch (error) {
            // Skip binary files or files that can't be read as UTF-8
            if (error.code !== 'EISDIR') {
              console.error(`  ⚠️  Could not read ${relativePath}: ${error.message}`);
            }
          }
        }
      }
    }
    
    readDirRecursive(skillPath);

    return {
      skillPath,
      filesScanned: files.length,
      findings,
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    return {
      skillPath,
      error: error.message,
      filesScanned: 0,
      findings: [],
      timestamp: new Date().toISOString()
    };
  }
}

/**
 * Analyzes a single file for security issues
 * @param {string} filename - Name of the file
 * @param {string} content - File content
 * @returns {Array} Array of findings
 */
function analyzeFile(filename, content) {
  const findings = [];
  const lines = content.split('\n');
  const MAX_FINDINGS_PER_PATTERN = 3; // Cap findings per pattern per file
  const patternCounts = {}; // Track count per pattern

  // Single pass over the file content — no double-counting from code blocks
  for (const pattern of PATTERNS) {
    // Get effective severity based on file type
    const effectiveSeverity = getEffectiveSeverity(pattern, filename);
    
    // If null, skip this pattern entirely for this file type
    if (effectiveSeverity === null) continue;
    
    patternCounts[pattern.id] = 0;
    
    for (const regex of pattern.patterns) {
      if (patternCounts[pattern.id] >= MAX_FINDINGS_PER_PATTERN) break;
      if (pattern.dedup && patternCounts[pattern.id] >= 1) break;
      
      const matches = findMatches(content, regex);
      
      for (const match of matches) {
        if (patternCounts[pattern.id] >= MAX_FINDINGS_PER_PATTERN) break;
        if (pattern.dedup && patternCounts[pattern.id] >= 1) break;
        
        const lineNumber = getLineNumber(content, match.index);
        const lineContent = lines[lineNumber - 1] || '';
        
        findings.push({
          severity: effectiveSeverity,
          category: pattern.category,
          description: pattern.description,
          patternId: pattern.id,
          file: filename,
          line: lineNumber,
          snippet: lineContent.trim().substring(0, 100),
          matched: match.text
        });
        
        patternCounts[pattern.id]++;
      }
    }
  }

  return findings;
}

/**
 * Extracts code blocks from markdown content
 * @param {string} content - Markdown content
 * @param {string} filename - Filename (to check if it's markdown)
 * @returns {Array} Array of code blocks with metadata
 */
function extractCodeBlocks(content, filename) {
  if (!filename.endsWith('.md')) return [];
  
  const blocks = [];
  const lines = content.split('\n');
  let inCodeBlock = false;
  let currentBlock = null;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    if (line.trim().startsWith('```')) {
      if (!inCodeBlock) {
        // Start of code block
        const language = line.trim().substring(3).trim() || 'plaintext';
        currentBlock = {
          language,
          startLine: i + 1,
          code: ''
        };
        inCodeBlock = true;
      } else {
        // End of code block
        if (currentBlock) {
          blocks.push(currentBlock);
        }
        inCodeBlock = false;
        currentBlock = null;
      }
    } else if (inCodeBlock && currentBlock) {
      currentBlock.code += line + '\n';
    }
  }
  
  return blocks;
}

/**
 * Finds all matches of a regex in content
 * @param {string} content - Content to search
 * @param {RegExp} regex - Regular expression
 * @returns {Array} Array of matches with index and text
 */
function findMatches(content, regex) {
  const matches = [];
  
  // Reset regex to ensure we start from the beginning
  const globalRegex = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
  
  let match;
  while ((match = globalRegex.exec(content)) !== null) {
    matches.push({
      index: match.index,
      text: match[0]
    });
  }
  
  return matches;
}

/**
 * Gets the line number for a given character index
 * @param {string} content - Full content
 * @param {number} index - Character index
 * @returns {number} Line number (1-indexed)
 */
function getLineNumber(content, index) {
  return content.substring(0, index).split('\n').length;
}

/**
 * Analyzes multiple skills in a directory
 * @param {string} dataDir - Directory containing skill subdirectories
 * @returns {Array} Array of analysis results
 */
export async function analyzeAllSkills(dataDir) {
  const results = [];
  
  try {
    const entries = fs.readdirSync(dataDir, { withFileTypes: true });
    
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const skillPath = path.join(dataDir, entry.name);
        console.log(`Analyzing ${entry.name}...`);
        
        const analysis = await analyzeSkill(skillPath);
        results.push({
          slug: entry.name,
          ...analysis
        });
      }
    }
  } catch (error) {
    console.error(`Error analyzing skills: ${error.message}`);
  }
  
  return results;
}
