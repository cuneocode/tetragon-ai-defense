// undo-aidef-shim.js
// Reverts OpenClaw gateway config to use openai-codex/gpt-5.1 as primary
// and resets the vLLM provider baseUrl back to 127.0.0.1:8000/v1.
//
// Usage:
//   node undo-aidef-shim.js
//   openclaw gateway config.apply --file /home/cuneocode/.openclaw/openclaw.json

const fs = require('fs');
const path = require('path');

const CONFIG_PATH = '/home/cuneocode/.openclaw/openclaw.json';

function main() {
  const absPath = path.resolve(CONFIG_PATH);
  const raw = fs.readFileSync(absPath, 'utf8');
  const config = JSON.parse(raw);

  // Reset vLLM baseUrl
  if (
    config.models &&
    config.models.providers &&
    config.models.providers.vllm
  ) {
    console.log(
      'Resetting models.providers.vllm.baseUrl to http://127.0.0.1:8000/v1'
    );
    config.models.providers.vllm.baseUrl = 'http://127.0.0.1:8000/v1';
  } else {
    console.warn(
      'Warning: models.providers.vllm not found; not changing baseUrl.'
    );
  }

  // Reset default primary model
  if (
    config.agents &&
    config.agents.defaults &&
    config.agents.defaults.model
  ) {
    console.log(
      'Resetting agents.defaults.model.primary to openai-codex/gpt-5.1'
    );
    config.agents.defaults.model.primary = 'openai-codex/gpt-5.1';
  } else {
    console.warn(
      'Warning: agents.defaults.model.primary not found; not changing primary.'
    );
  }

  fs.writeFileSync(absPath, JSON.stringify(config, null, 2) + '\n', 'utf8');
  console.log('\nConfig updated. Now run:');
  console.log(
    '  openclaw gateway config.apply --file /home/cuneocode/.openclaw/openclaw.json'
  );
}

main();
