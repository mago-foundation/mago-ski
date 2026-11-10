// Takes the README screenshots (docs/images/gui-*.png) of the real app in English, with Playwright's Electron driver.
// Not type-checked: Playwright is not a dependency of this package. Needs a display (xvfb-run on a headless Linux) and,
// as root, an unprivileged user: Electron refuses to run its sandbox as root.
//
//   node scripts/screenshots.ts prepare DIR      demo home with an organisation (keys, policy) and settings.json {"lang":"en"};
//                                                writes DIR/pin/policy.json, the organisation pin for the admin shots
//   (as root) install DIR/pin/ as /etc/mago-ski/ - a root-owned folder, bind-mounted or copied - because the admin rack reads
//   the organisation only from there. Without it the admin shots show "Not installed" and the script says so.
//   node scripts/screenshots.ts shoot DIR OUT    window 1280x800 at device scale factor 2: OUT/gui-observe.png,
//                                                gui-admin-templates.png, gui-admin-approve.png, gui-admin-approvers.png (Manage approvers:
//                                                TRUST ROOT with the approver list, and POLICY CHECK), gui-admin-revoke.png (Revoke: TARGET with
//                                                the approvers and a reviewed Skill), gui-admin-refresh.png (Refresh revocation list) and
//                                                gui-admin-timestamp.png (Sign timestamp)
//
// The demo organisation is a policy v2 one with freshness (a recovery set and a signed timestamp), so the three 2b templates have
// documents to show. The native dialogs cannot be clicked by Playwright; the script answers them in the main process: the key dialog
// with DIR/keys/alice.pem (approver), root.pem or timestamp.pem, and every confirmation (the offline question and the review of one
// Skill) with the confirming button. The script never presses a signing button, so nothing is signed.
import { spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const gui = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const [command, target, outArg] = process.argv.slice(2);
if (!target || (command !== 'prepare' && command !== 'shoot') || (command === 'shoot' && !outArg)) {
  console.error('usage: node scripts/screenshots.ts prepare DIR | shoot DIR OUT');
  process.exit(2);
}
const dir = path.resolve(target);
const pinFile = path.join(dir, 'pin', 'policy.json');
const PIN_PATH = '/etc/mago-ski/policy.json';
const demo = (...args: string[]) => {
  const r = spawnSync(process.execPath, [path.join(gui, 'scripts', 'demo.ts'), ...args], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr);
};

if (command === 'prepare') {
  demo('setup', dir, '--freshness');
  await mkdir(path.join(dir, 'gui-data'), { recursive: true });
  await writeFile(path.join(dir, 'gui-data', 'settings.json'), '{"lang":"en"}\n');
  // The same organisation as the demo policy, with absolute paths: the pin is read from /etc/mago-ski, not from the demo home.
  const policy = JSON.parse(await readFile(path.join(dir, 'home', '.mago-ski', 'policy.json'), 'utf8')) as Record<string, any>;
  const documents = path.join(dir, 'home', '.mago-ski');
  await mkdir(path.dirname(pinFile), { recursive: true });
  await writeFile(pinFile, JSON.stringify({
    policy_version: policy.policy_version, mode: policy.mode, root_fingerprint: policy.root_fingerprint,
    ...(policy.recovery ? { recovery: policy.recovery, root_events: path.join(documents, 'root-events.json') } : {}),
    trust_root: path.join(documents, 'trust-root.json'), revocations: path.join(documents, 'revocations.json'),
    ...(policy.freshness ? { freshness: { ...policy.freshness, timestamp: path.join(documents, 'timestamp.json') } } : {}),
  }, null, 2), { mode: 0o644 });
  console.log(`prepared ${dir}; the pin to install as ${PIN_PATH} is ${pinFile}`);
  process.exit(0);
}

const out = path.resolve(outArg!);
await mkdir(out, { recursive: true });
const { _electron } = require('playwright') as typeof import('playwright');
const electronPath = require('electron') as unknown as string;
const installed = await readFile(PIN_PATH, 'utf8').catch(() => null);
const pinInstalled = installed !== null && installed === (await readFile(pinFile, 'utf8').catch(() => ''));

const app = await _electron.launch({
  executablePath: electronPath,
  args: [gui, '--force-device-scale-factor=2', ...(process.getuid?.() === 0 ? ['--no-sandbox'] : [])],
  env: { ...process.env, HOME: path.join(dir, 'home'), MAGO_SKI_GUI_DATA: path.join(dir, 'gui-data') },
});
const errors: string[] = [];
const page = await app.firstWindow();
page.on('pageerror', (e: Error) => errors.push(e.message));
page.on('console', (m: { type(): string; text(): string }) => { if (m.type() === 'error') errors.push(m.text()); });
await app.evaluate(({ BrowserWindow }) => { BrowserWindow.getAllWindows()[0]!.setContentSize(1280, 800); });
await page.reload();
await page.waitForSelector('.row');
const shot = (name: string) => page.screenshot({ path: path.join(out, name) });

// 1. Observation: the Skill list and one changed Skill's detail.
demo('change', dir);
await page.waitForSelector('.row .state.changed', { timeout: 15_000 });
await page.click('.row:has-text("docs-helper")');
await page.waitForSelector('.diff .dl.add');
await page.waitForTimeout(500);
await shot('gui-observe.png');

// 2. The admin tab: the organisation pin and the template picker.
await page.click('.tab[data-tab="admin"]');
await page.waitForSelector('.tpl');
await page.waitForTimeout(1000);
await shot('gui-admin-templates.png');

// 3. The Approve template with the approver key loaded and a Skill in INSPECT.
if (pinInstalled) {
  await app.evaluate(({ dialog }, key) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [key] }) as never; }, path.join(dir, 'keys', 'alice.pem'));
  await page.click('[data-action="arm"]');
  await page.waitForSelector('.admin-dev.done[data-admin-device="identity"]');
  await page.click('[data-admin-device="inspect"]');
  await page.click('[data-skill="docs-helper"]');
  await page.waitForSelector('#tab-admin .tbl');
  await page.waitForTimeout(500);
  await page.evaluate(() => document.querySelector('#tab-admin .tpl-grid')?.scrollIntoView());
  await page.waitForTimeout(300);
  await shot('gui-admin-approve.png');

  // 4. Manage approvers: TRUST ROOT with the approver list, POLICY CHECK beside it. Reading the document needs no key.
  await page.click('[data-template="approvers"]');
  await page.click('[data-admin-device="trustroot"]');
  await page.waitForSelector('#tab-admin tr[data-approver]');
  // The tab reads the document and runs POLICY CHECK on its own when the template opens.
  await page.waitForSelector('#tab-admin .admin-dev[data-admin-device="policy"]:not(.waiting)');
  await page.waitForTimeout(500);
  // Taller window so the chain and the approver list are both in the shot.
  await app.evaluate(({ BrowserWindow }) => { BrowserWindow.getAllWindows()[0]!.setContentSize(1280, 1000); });
  await page.waitForTimeout(300);
  await page.evaluate(() => document.querySelector('#tab-admin .rack-wrap')?.scrollIntoView());
  await page.waitForTimeout(300);
  await shot('gui-admin-approvers.png');

  // The 2b templates: each arms its own key (a template change drops the key). The native confirmations are answered with the confirming button.
  await app.evaluate(({ dialog }) => { dialog.showMessageBox = async () => ({ response: 1, checkboxChecked: false }) as never; });
  const arm = async (keyFile: string) => {
    await app.evaluate(({ dialog }, key) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [key] }) as never; }, path.join(dir, 'keys', keyFile));
    await page.click('[data-admin-device="identity"]');
    await page.click('[data-action="arm"]');
    await page.waitForSelector('.admin-dev.done[data-admin-device="identity"]');
  };
  const frame = async (selector: string) => {
    await page.waitForSelector(selector);
    await page.waitForSelector('#tab-admin .admin-dev[data-admin-device="policy"]:not(.waiting)');
    await page.waitForTimeout(500);
    await page.evaluate(() => document.querySelector('#tab-admin .rack-wrap')?.scrollIntoView());
    await page.waitForTimeout(300);
  };

  // 5. Revoke: the root key, a reviewed Skill (the review is a native confirmation), and an approver chosen as the target.
  await page.click('[data-template="revoke"]');
  await arm('root.pem');
  await page.click('[data-admin-device="target"]');
  await page.waitForSelector('#tab-admin tr[data-skill="docs-helper"]');
  await page.click('[data-action="review-docs-helper"]');
  await page.waitForSelector('#tab-admin tr[data-skill="docs-helper"] [data-action^="target-skill-"]');
  await page.click('#tab-admin tr[data-target-key] [data-action^="target-"]');
  await frame('#tab-admin .admin-dev.done[data-admin-device="target"]');
  await shot('gui-admin-revoke.png');

  // 6. Refresh revocation list.
  await page.click('[data-template="refresh"]');
  await arm('root.pem');
  await page.click('[data-admin-device="refresh"]');
  await frame('#tab-admin [data-action="refresh-revocations"]');
  await shot('gui-admin-refresh.png');

  // 7. Sign timestamp: the timestamp key, which is a different session from the root key.
  await page.click('[data-template="timestamp"]');
  await arm('timestamp.pem');
  await page.click('[data-admin-device="timestamp"]');
  await frame('#tab-admin [data-action="sign-timestamp"]');
  await shot('gui-admin-timestamp.png');
} else {
  console.warn(`${PIN_PATH} is not ${pinFile}: install the pin first; the admin shots after the templates one were not taken and the templates shot shows no pin`);
}
await app.close();
if (errors.length) console.warn('page errors:', errors);
console.log(`screenshots in ${out}`);
process.exit(pinInstalled && errors.length === 0 ? 0 : 1);
