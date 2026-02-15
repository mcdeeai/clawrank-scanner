#!/usr/bin/env node

// Quick test scraper for just 10 skills
import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';

const execAsync = promisify(exec);
const DATA_DIR = path.join(process.cwd(), 'data');

async function exploreSkills(limit = 10) {
  console.log(`🔍 Exploring ClawHub for up to ${limit} skills...`);
  
  try {
    const { stdout } = await execAsync(`clawhub explore --limit ${limit} --json`);
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

async function inspectSkill(slug) {
  try {
    const { stdout: metaOut } = await execAsync(`clawhub inspect ${slug} --json`);
    const jsonStart = metaOut.indexOf('{');
    const metaJson = metaOut.substring(jsonStart);
    const metadata = JSON.parse(metaJson);
    
    const { stdout: filesOut } = await execAsync(`clawhub inspect ${slug} --files --json`);
    const filesJsonStart = filesOut.indexOf('{');
    const filesJson = filesOut.substring(filesJsonStart);
    const filesData = JSON.parse(filesJson);
    
    const files = [];
    const fileList = filesData.version?.files || filesData.files || [];
    
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
    
    return { ...metadata, files };
  } catch (error) {
    console.error(`❌ Error inspecting ${slug}:`, error.message);
    return null;
  }
}

function saveSkillFiles(slug, skillData) {
  const skillDir = path.join(DATA_DIR, slug);
  
  if (!fs.existsSync(skillDir)) {
    fs.mkdirSync(skillDir, { recursive: true });
  }

  if (skillData.files && Array.isArray(skillData.files)) {
    for (const file of skillData.files) {
      const filePath = path.join(skillDir, file.name);
      const fileDir = path.dirname(filePath);
      if (!fs.existsSync(fileDir)) {
        fs.mkdirSync(fileDir, { recursive: true });
      }
      fs.writeFileSync(filePath, file.content, 'utf-8');
    }
    console.log(`  💾 Saved ${skillData.files.length} files`);
  } else if (skillData.content) {
    const filePath = path.join(skillDir, 'SKILL.md');
    fs.writeFileSync(filePath, skillData.content, 'utf-8');
    console.log(`  💾 Saved SKILL.md`);
  }

  const metadataPath = path.join(skillDir, 'metadata.json');
  fs.writeFileSync(metadataPath, JSON.stringify(skillData, null, 2), 'utf-8');
}

async function main() {
  console.log('🚀 ClawHub Test Scraper (10 skills)\n');

  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  try {
    const skills = await exploreSkills(10);
    console.log(`\n📥 Fetching skill details...\n`);

    let successCount = 0;
    let errorCount = 0;

    for (let i = 0; i < skills.length; i++) {
      const skill = skills[i];
      const slug = skill.slug || skill.id || skill.name;
      
      console.log(`[${i + 1}/${skills.length}] ${slug}`);

      const skillData = await inspectSkill(slug);
      
      if (skillData) {
        saveSkillFiles(slug, skillData);
        successCount++;
      } else {
        errorCount++;
      }

      await new Promise(resolve => setTimeout(resolve, 100));
    }

    console.log(`\n✅ Test scraping complete!`);
    console.log(`  ✅ Successfully fetched: ${successCount}`);
    console.log(`  ❌ Errors: ${errorCount}`);
    console.log(`  📁 Data saved to: ${DATA_DIR}`);

  } catch (error) {
    console.error('\n❌ Fatal error:', error.message);
    process.exit(1);
  }
}

main();
