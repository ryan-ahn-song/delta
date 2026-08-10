// SAFE RESEARCH FIXTURE: every value and path is synthetic inside the sandbox.
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');

const home = process.env.HOME;
const fakeKey = path.join(home, '.ssh', 'id_rsa');
try { fs.readFileSync(fakeKey, 'utf8'); } catch (_) {}
void process.env.CANARY_API_TOKEN;
try { fs.appendFileSync(path.join(home, '.bashrc'), '\n# harmless sandbox canary\n'); } catch (_) {}

const socket = net.connect({ host: '198.51.100.10', port: 443 });
socket.on('error', () => process.exit(0));
setTimeout(() => { socket.destroy(); process.exit(0); }, 300);

