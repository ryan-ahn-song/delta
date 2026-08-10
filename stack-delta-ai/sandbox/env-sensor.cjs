'use strict';

const fs = require('node:fs');
const original = process.env;
const logPath = original.STACK_DELTA_ENV_LOG;
const active = Boolean(original.npm_lifecycle_event);
const ignored = new Set([
  'STACK_DELTA_ENV_LOG', 'NODE_OPTIONS', 'npm_config_user_agent', 'npm_node_execpath',
  'npm_execpath', 'npm_package_json', 'npm_config_noproxy', 'npm_config_userconfig',
  'npm_config_local_prefix', 'npm_command', 'npm_lifecycle_event', 'npm_lifecycle_script',
  'npm_package_name', 'npm_package_version', 'PATH', 'PWD', 'OLDPWD', 'SHLVL', '_'
]);
const seen = new Set();

function record(name) {
  if (!active || !logPath || ignored.has(name) || seen.has(name)) return;
  seen.add(name);
  const row = JSON.stringify({ name, timestamp: Date.now() / 1000 });
  try { fs.appendFileSync(logPath, row + '\n', { encoding: 'utf8' }); } catch (_) {}
}

try {
  Object.defineProperty(process, 'env', {
    configurable: false,
    enumerable: true,
    value: new Proxy(original, {
      get(target, property, receiver) {
        if (typeof property === 'string') record(property);
        return Reflect.get(target, property, receiver);
      },
      has(target, property) {
        if (typeof property === 'string') record(property);
        return Reflect.has(target, property);
      }
    })
  });
} catch (_) {
  // Sensor failure must not alter the package's behavior; syscall tracing still runs.
}
