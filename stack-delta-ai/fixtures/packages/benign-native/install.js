const fs = require('node:fs');
const path = require('node:path');

const buildDir = path.join(process.cwd(), 'build');
fs.mkdirSync(buildDir, { recursive: true });
fs.writeFileSync(path.join(buildDir, 'fixture.node'), 'SAFE_STACK_DELTA_FIXTURE');
console.log('safe fixture build completed');

