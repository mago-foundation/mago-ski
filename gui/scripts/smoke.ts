// Drives the built app with Playwright's Electron support and saves screenshots.
// Not type-checked: Playwright is not a dependency of this package.
// Needs Playwright (not a dependency of this package) and a display (use xvfb-run on a headless Linux).
//   node scripts/smoke.ts OUT_DIR
import { spawnSync } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { _electron } = require('playwright') as typeof import('playwright');
const electronPath = require('electron') as unknown as string;

const gui = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.resolve(process.argv[2] ?? path.join(gui, 'dist', 'smoke'));
const dir = await mkdtemp(path.join(os.tmpdir(), 'mago-ski-smoke-'));
const demo = (...args: string[]) => {
  const r = spawnSync(process.execPath, [path.join(gui, 'scripts', 'demo.ts'), ...args], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr);
};
demo('setup', dir, '--org');

const app = await _electron.launch({
  executablePath: electronPath,
  args: [gui, ...(process.getuid?.() === 0 ? ['--no-sandbox'] : [])],
  env: { ...process.env, HOME: path.join(dir, 'home'), MAGO_SKI_GUI_DATA: path.join(dir, 'gui-data') },
});
const errors: string[] = [];
const page = await app.firstWindow();
page.on('pageerror', (e: Error) => errors.push(e.message));
page.on('console', (m: { type(): string; text(): string }) => { if (m.type() === 'error') errors.push(m.text()); });
await page.setViewportSize({ width: 1500, height: 1080 });
// Reload with the listeners attached, so errors during the first load (CSP violations included) are caught.
await page.reload();
await page.waitForSelector('.row');
await page.screenshot({ path: path.join(out, '1-first-run.png') });

demo('change', dir);
await page.waitForSelector('.row .state.changed', { timeout: 15_000 });
await page.click('.row:has-text("docs-helper")');
await page.waitForSelector('.diff .dl.add');
await page.screenshot({ path: path.join(out, '2-change-detected.png') });

await page.click('.files .file:has-text("scripts/export.js")');
await page.screenshot({ path: path.join(out, '3-new-script.png') });

await page.click('button:has-text("변경 확인 완료")');
await page.waitForSelector('.result.ok');
await page.screenshot({ path: path.join(out, '4-remembered.png') });

await page.click('.device[data-device="gate"]');
await page.waitForSelector('.concept-pane .tbl');
await page.screenshot({ path: path.join(out, '5-approval-gate.png') });

await page.click('.tab[data-tab="activity"]');
await page.screenshot({ path: path.join(out, '6-activity.png') });
await page.click('.tab[data-tab="settings"]');
await page.screenshot({ path: path.join(out, '7-settings.png') });

await app.close();
if (errors.length) { console.error('renderer errors:\n' + errors.join('\n')); process.exit(1); }
console.log(`screenshots in ${out}`);
