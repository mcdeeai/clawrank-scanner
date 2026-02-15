#!/usr/bin/env node

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';

const execAsync = promisify(exec);

const DATA_DIR = path.join(process.cwd(), 'data');

/**
 * Executes clawhub explore to get list of skills
 * @param {number} limit - Maximum number of skills to fetch
 * @returns {Promise<Array>} Array of skill metadata
 */
async function exploreSkills(limit = 200) {
  console.log(`🔍 Exploring ClawHub for up to ${limit} skills...`);
  
  try {
    const { stdout } = await execAsync(`clawhub explore --limit ${limit} --json`);
    
    // Parse JSON from stdout (may have leading text)
    const jsonStart = stdout.indexOf('{');
    const jsonStr = stdout.substring(jsonStart);
    const data = JSON.parse(jsonStr);
    
    const skills = data.items || [];
    
    console.log(`✅ Found ${skills.length} skills on ClawHub`);
    return skills;
  } catch (error) {
    console.error('❌ Error exploring ClawHub:', error.message);
    throw error;
  }
}

/**
 * Fetches details for a specific skill
 * @param {string} slug - Skill slug
 * @returns {Promise<Object>} Skill details with files
 */
async function inspectSkill(slug) {
  try {
    // Get metadata
    const { stdout: metaOut } = await execAsync(`clawhub inspect ${slug} --json`);
    const jsonStart = metaOut.indexOf('{');
    const metaJson = metaOut.substring(jsonStart);
    const metadata = JSON.parse(metaJson);
    
    // Get file list
    const { stdout: filesOut } = await execAsync(`clawhub inspect ${slug} --files --json`);
    const filesJsonStart = filesOut.indexOf('{');
    const filesJson = filesOut.substring(filesJsonStart);
    const filesData = JSON.parse(filesJson);
    
    const files = [];
    
    // Get file list from version.files
    const fileList = filesData.version?.files || filesData.files || [];
    
    // Fetch each file's content
    if (Array.isArray(fileList) && fileList.length > 0) {
      for (const file of fileList) {
        try {
          const { stdout: fileContent } = await execAsync(`clawhub inspect ${slug} --file "${file.path}"`);
          files.push({
            name: file.path,
            path: file.path,
            content: fileContent,
            size: file.size
          });
        } catch (fileError) {
          console.error(`  ⚠️  Could not fetch ${file.path}:`, fileError.message);
        }
      }
    }
    
    return {
      ...metadata,
      files
    };
  } catch (error) {
    console.error(`❌ Error inspecting ${slug}:`, error.message);
    return null;
  }
}

/**
 * Saves skill files to disk
 * @param {string} slug - Skill slug
 * @param {Object} skillData - Skill data with files
 */
function saveSkillFiles(slug, skillData) {
  const skillDir = path.join(DATA_DIR, slug);
  
  // Create skill directory
  if (!fs.existsSync(skillDir)) {
    fs.mkdirSync(skillDir, { recursive: true });
  }

  // Save each file
  if (skillData.files && Array.isArray(skillData.files)) {
    for (const file of skillData.files) {
      const filePath = path.join(skillDir, file.name);
      
      // Create parent directories if needed
      const fileDir = path.dirname(filePath);
      if (!fs.existsSync(fileDir)) {
        fs.mkdirSync(fileDir, { recursive: true });
      }
      
      fs.writeFileSync(filePath, file.content, 'utf-8');
    }
    console.log(`  💾 Saved ${skillData.files.length} files`);
  } else if (skillData.content) {
    // Single file skill (likely SKILL.md)
    const filePath = path.join(skillDir, 'SKILL.md');
    fs.writeFileSync(filePath, skillData.content, 'utf-8');
    console.log(`  💾 Saved SKILL.md`);
  }

  // Save metadata
  const metadataPath = path.join(skillDir, 'metadata.json');
  fs.writeFileSync(metadataPath, JSON.stringify(skillData, null, 2), 'utf-8');
}

/**
 * Main scraper function
 */
async function main() {
  console.log('🚀 ClawHub Skill Scraper\n');

  // Ensure data directory exists
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  try {
    // Get list of skills
    const skills = await exploreSkills(200);

    console.log(`\n📥 Fetching skill details...\n`);

    let successCount = 0;
    let errorCount = 0;

    // Fetch each skill
    for (let i = 0; i < skills.length; i++) {
      const skill = skills[i];
      const slug = skill.slug || skill.id || skill.name;
      
      console.log(`[${i + 1}/${skills.length}] ${slug}`);

      // Skip already-scraped skills
      const existingDir = path.join(DATA_DIR, slug);
      if (fs.existsSync(existingDir) && fs.readdirSync(existingDir).length > 0) {
        console.log(`  ⏭️  Already scraped, skipping`);
        successCount++;
        continue;
      }

      const skillData = await inspectSkill(slug);
      
      if (skillData) {
        saveSkillFiles(slug, skillData);
        successCount++;
      } else {
        errorCount++;
      }

      // Small delay to avoid overwhelming the API
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    console.log(`\n✅ Scraping complete!`);
    console.log(`  ✅ Successfully fetched: ${successCount}`);
    console.log(`  ❌ Errors: ${errorCount}`);
    console.log(`  📁 Data saved to: ${DATA_DIR}`);

  } catch (error) {
    console.error('\n❌ Fatal error:', error.message);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { exploreSkills, inspectSkill, saveSkillFiles };
