import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('examples/demo.sh shows demos 1-3 with the expected verdicts', { skip: process.platform === 'win32' ? 'bash script' : false }, () => {
  const script = fileURLToPath(new URL('../examples/demo.sh', import.meta.url));
  const result = spawnSync('bash', [script], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const out = result.stdout;
  assert.match(out, /ok {3}VERIFIED +docs-helper/u);
  assert.match(out, /Demo 1[\s\S]*FAIL UNAPPROVED_CHANGE docs-helper[\s\S]*diff: CONTENT_CHANGED, recertification_required=true/u);
  assert.match(out, /Demo 2[\s\S]*UNTRUSTED_SIGNER +docs-helper +signer [\s\S]*UNTRUSTED_SIGNER +deploy-prod +approver "Alice" is not authorized/u);
  assert.match(out, /Demo 3[\s\S]*2\/2 Skills verified[\s\S]*REVOKED +docs-helper[\s\S]*REVOKED +docs-index[\s\S]*0\/2 Skills verified/u);
});
