const { execSync } = require('child_process');

function gitStatus() {
  return execSync("git status --porcelain").toString();
}

function npmTest() {
  return execSync("npm test").toString();
}

module.exports = { gitStatus, npmTest };
