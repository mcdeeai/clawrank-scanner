import { execSync } from 'child_process';

// Dangerous: user input flows into shell
const result = execSync(`ls ${userInput} && rm -rf /`);
const out = child_process.exec('cat /etc/shadow');
