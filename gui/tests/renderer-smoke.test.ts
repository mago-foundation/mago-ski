// Renderer smoke test (docs/design/gui-admin-phase2.md, P9 item 6): the real renderer, compiled from source, in a Chromium page with a
// fake window.magoSki. It opens every admin template with a root key armed and approvers present, and fails on any page error or
// console error. The 2a crash (a `const` used before its declaration in the approver table) shipped because no test ever ran the
// renderer. Skipped, with the reason, when Playwright or its Chromium cannot be loaded.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const gui = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);

// The page cannot import modules over file:// (CORS), so a throwaway HTTP server on 127.0.0.1 serves the build (the renderer imports ../i18n).
const TYPES: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

/** Realistic data for the fake RendererApi. Runs in the page, so it is plain data plus one function. */
function installFakeApi(): void {
  const id = (n: string) => `sha256:${n.repeat(64)}`;
  const ROOT = id('a'), ALICE = id('b'), BOB = id('c'), DIGEST = id('d'), DIGEST2 = id('e'), TS = id('f');
  const now = '2026-02-01T00:00:00Z';
  const instance = (n: number, name: string, digest: string) => ({
    id: `i${n}`, name, path: `/home/u/.claude/skills/${name}`, rootId: 'r1', rootLabel: '~/.claude/skills', state: 'unchanged', error: null,
    firstSeen: now, lastChecked: now, currentDigest: digest, baselineDigest: digest, baselineAt: now, changedFiles: 0,
    pki: { verdict: 'VERIFIED', reason: 'verified', digest, certificateId: 'c1', approverKeyId: ALICE, checkedAt: now }, pkiCurrent: true,
  });
  const serviceView = {
    service: { status: 'watching', lastCheckAt: now, lastError: null, platformSupported: true, platform: 'linux', dataDir: '/home/u/.mago-ski', historyReset: null },
    roots: [{ id: 'r1', path: '/home/u/.claude/skills', label: '~/.claude/skills', origin: 'default', exists: true, error: null, tooDeep: [] }],
    instances: [instance(1, 'docs-helper', DIGEST), instance(2, 'pdf-tools', DIGEST2)],
    checks: [{ at: now, outcome: 'same', skills: 2 }], history: [],
    host: { name: 'Pi', agentDir: '/home/u/.pi', present: true, extensionListed: true, policy: { kind: 'loaded', path: '/etc/mago-ski/policy.json', mode: 'enforce', trustOk: true, trustNote: null }, appliesAt: 'next-session', recentDecisions: [] },
    prefs: { notify: 'grouped', retainContent: true, retentionDays: 30 },
  };
  const status = {
    pin: { kind: 'loaded', path: '/etc/mago-ski/policy.json', reason: null, rootKeyId: ROOT, activeRootKeyId: ROOT, mode: 'enforce', trustOk: true, trustNote: null },
    hostPolicyDiffers: false,
    armed: { role: 'root', keyId: ROOT, name: null, scopes: null, expiresAt: null, note: null },
    idleMinutes: 0, memoryReset: null, rollback: false,
  };
  const approver = (keyId: string, name: string, scopes: string[]) => ({ keyId, name, scopes, expiresAt: '2027-02-01T00:00:00Z', expired: false, forbidden: null });
  const trustRoot = {
    ok: true, path: '/etc/mago-ski/trust-root.json', sha256: id('1'), version: 3, expiresAt: '2027-02-01T00:00:00Z', expired: false,
    approvers: [approver(ALICE, 'Alice Kim', ['docs-*']), approver(BOB, 'Bob Lee', ['*'])], stale: false, signedByPreviousRoot: false, note: null,
  };
  const revocations = {
    ok: true, path: '/etc/mago-ski/revocations.json', sha256: id('2'), version: 2, expiresAt: '2026-03-01T00:00:00Z', expired: false,
    keys: [{ keyId: id('9'), reason: 'laptop lost', revokedAt: now }], digests: [], stale: false, signedByPreviousRoot: false,
  };
  const timestamp = {
    ok: true, configured: true, path: '/etc/mago-ski/timestamp.json', keyId: TS, version: 4, expiresAt: '2026-02-02T00:00:00Z', readable: true,
    matches: true, maxLifetime: '1d', lifetimes: ['6h', '12h', '24h'], disabled: null,
  };
  const ok = async () => ({ ok: true });
  const write = async () => ({ ok: true, version: 5, path: '/etc/mago-ski/x.json', needsTimestamp: false, memoryWarning: false });
  const detail = (instanceId: string) => ({
    instanceId, name: 'docs-helper', path: '/home/u/.claude/skills/docs-helper', digest: DIGEST, totalBytes: 120,
    files: [{ path: 'SKILL.md', size: 120, sha256: id('3'), exec: false }], excluded: [], certificate: null,
    verdict: { verdict: 'VERIFIED', reason: 'verified' }, inspected: true, verdictStale: false,
  });
  (globalThis as unknown as { magoSki: unknown }).magoSki = {
    getView: async () => serviceView, checkNow: async () => serviceView, getDetail: async () => null, markReviewed: ok, rememberVersion: ok,
    addRoot: async () => serviceView, removeRoot: async () => serviceView, setPrefs: async () => serviceView, copyText: async () => {},
    dismissHistoryReset: async () => serviceView, getLang: async () => 'en', setLang: async (l: string) => l, onUpdate: () => () => {},
    admin: {
      status: async () => status, arm: async () => ({ ok: true, role: status.armed }), disarm: async () => status,
      inspect: async (instanceId: string) => detail(instanceId), review: ok, approve: ok,
      check: async () => ({ verdict: 'VERIFIED', reason: 'verified', trustOk: true, trustNote: null }),
      resetMemory: async () => ({ ok: true, status }), dismissMemoryReset: async () => status, trustRoot: async () => trustRoot,
      addApprover: write, removeApprover: write, renewTrustRoot: write,
      verifyAll: async () => ({ skills: 2, counts: { VERIFIED: 2 }, trustOk: true, trustNote: null, timestampMismatch: false }),
      revocations: async () => revocations,
      revocationSkills: async () => [
        { instanceId: 'i1', name: 'docs-helper', digest: DIGEST, reviewed: true, error: null },
        { instanceId: 'i2', name: 'pdf-tools', digest: DIGEST2, reviewed: false, error: null },
      ],
      revocationTargets: async () => [
        { kind: 'key', keyId: ALICE, label: 'Alice Kim' }, { kind: 'key', keyId: BOB, label: 'Bob Lee' },
        { kind: 'digest', digest: DIGEST, skillName: 'docs-helper', instanceId: 'i1' },
      ],
      revoke: write, refreshRevocations: write, timestamp: async () => timestamp, signTimestamp: write,
    },
  };
}

let skipReason: string | null = null;
let chromium: { launch(o: object): Promise<any> } | null = null;
try {
  chromium = (require('playwright') as { chromium: { launch(o: object): Promise<any> } }).chromium;
} catch (error) {
  skipReason = `Playwright cannot be loaded (${(error as Error).message.split('\n')[0]}); put it on NODE_PATH to run this test`;
}

test('every admin template opens in the real renderer without a page error', { skip: skipReason ?? false }, async (t) => {
  const out = await mkdtemp(path.join(process.env.TMPDIR ?? '/tmp', 'mago-ski-renderer-'));
  t.after(() => rm(out, { recursive: true, force: true }));
  const tsc = path.join(gui, 'node_modules', '.bin', 'tsc');
  execFileSync(process.execPath, [tsc, '-p', path.join(gui, 'tsconfig.renderer.json'), '--outDir', out], { cwd: gui, stdio: 'pipe' });
  const root = path.join(out, 'gui', 'src');
  for (const file of ['index.html', 'styles.css']) await cp(path.join(gui, 'src', 'renderer', file), path.join(root, 'renderer', file));

  const server: Server = createServer((req, res) => {
    const name = (req.url ?? '/').split('?')[0]!.replace(/^\/+/u, '') || 'renderer/index.html';
    readFile(path.join(root, path.normalize(name).replace(/^(\.\.[/\\])+/u, ''))).then(
      (body) => { res.writeHead(200, { 'content-type': TYPES[path.extname(name)] ?? 'application/octet-stream' }); res.end(body); },
      () => { res.writeHead(404); res.end(); });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const port = (server.address() as { port: number }).port;

  let browser;
  try {
    browser = await chromium!.launch({ args: ['--no-sandbox'] });
  } catch (error) {
    t.skip(`Chromium cannot be launched (${(error as Error).message.split('\n')[0]})`);
    return;
  }
  t.after(() => browser.close());
  const page = await browser.newPage();
  const errors: string[] = [];
  page.on('pageerror', (e: Error) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m: { type(): string; text(): string }) => { if (m.type() === 'error') errors.push(`console: ${m.text()}`); });
  await page.addInitScript(installFakeApi);
  const drive = async () => {
    await page.goto(`http://127.0.0.1:${port}/renderer/index.html`);
    await page.waitForSelector('#count', { state: 'attached' });
    await page.waitForTimeout(500);
    await page.click('.tab[data-tab="admin"]');
    await page.waitForSelector('.tpl');

    const templates: string[] = await page.$$eval('.tpl', (cards: Array<{ getAttribute(n: string): string | null }>) => cards.map((c) => c.getAttribute('data-template') ?? ''));
    assert.deepEqual(templates, ['approve', 'approvers', 'revoke', 'refresh', 'timestamp', 'setup', 'incident']);
    const seen: Record<string, string> = {};
    for (const name of templates) {
      await page.click(`[data-template="${name}"]`, { force: true });
      await page.waitForSelector(`[data-template="${name}"][aria-pressed="true"]`);
      // Open every device of the rack, so each pane draws with the fake documents.
      const devices: string[] = await page.$$eval('#tab-admin [data-admin-device]', (els: Array<{ getAttribute(n: string): string | null }>) => els.map((e) => e.getAttribute('data-admin-device') ?? ''));
      for (const device of devices) {
        await page.click(`#tab-admin [data-admin-device="${device}"]`);
        await page.waitForTimeout(150);
      }
      seen[name] = devices.join(',');
    }
    // The panes that carry the lists the 2a crash and the 2b targets are drawn from.
    await page.click('[data-template="approvers"]');
    await page.click('#tab-admin [data-admin-device="trustroot"]');
    await page.waitForSelector('#tab-admin tr[data-approver]');
    await page.click('[data-template="revoke"]');
    await page.click('#tab-admin [data-admin-device="target"]');
    await page.waitForSelector('#tab-admin tr[data-target-key]');
    await page.waitForTimeout(300);
    return seen;
  };
  let seen: Record<string, string>;
  try {
    seen = await drive();
  } catch (error) {
    // A page error usually shows up first as a timeout waiting for something that never drew; report the real cause.
    if (errors.length > 0) assert.deepEqual(errors, [], (error as Error).message.split('\n')[0]);
    throw error;
  }
  assert.deepEqual(errors, []);
  assert.ok(seen.approvers!.includes('trustroot') && seen.revoke!.includes('target') && seen.timestamp!.length > 0, JSON.stringify(seen));
});
