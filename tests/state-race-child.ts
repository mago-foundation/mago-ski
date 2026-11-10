// Child of state-race.test.ts: records ascending trust root versions in a shared host state file.
import { recordDocumentVersions } from '../src/policy.ts';

const [file, rootKeyId, startText, countText, stepText] = process.argv.slice(2) as [string, string, string, string, string];
const start = Number(startText);
const count = Number(countText);
const step = Number(stepText);
let failures = 0;
for (let i = 0; i < count; i += 1) {
  // A write that runs out of its retry budget fails closed; the next value is higher, so retrying it is harmless.
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      await recordDocumentVersions(file, { rootKeyId, trustRoot: start + i * step });
      break;
    } catch {
      failures += 1;
    }
  }
}
console.log(JSON.stringify({ start, failures }));
