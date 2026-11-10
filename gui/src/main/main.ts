// Electron main process: owns the observation service and the only window.
// The renderer is sandboxed and reaches the service only through the narrow IPC surface below.
import { app, BrowserWindow, clipboard, dialog, ipcMain, Notification, session, type IpcMainInvokeEvent } from 'electron';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { LANGS, langFromLocale, t, type Lang } from '../i18n/messages.ts';
import { loadPublicKeyBytes } from '../../../src/keys.ts';
import { readRegularFile } from '../../../src/fs-safe.ts';
import { AdminSession, LIFETIMES } from '../service/admin.ts';
import { ObservationService } from '../service/service.ts';
import { readLang, writeLang } from '../service/settings.ts';
import type { AdminReviewSummary, AdminSignSummary, InstanceView, Prefs } from '../service/types.ts';
import {
  cancelLabel, keyPickerAllFiles, keyPickerTitle, lastApproverDialog, notificationGrouped, notificationImmediate, offlineDialog, publicKeyPickerTitle,
  resetDialog, reviewDialog, rootPickerTitle, signDialog, startFailure, type DialogText,
} from './dialog-text.ts';
import { parseAddApprover, parseRefresh, parseRemoveApprover, parseRenew, parseRevoke, parseSignTimestamp } from './ipc-args.ts';

const here = path.dirname(fileURLToPath(import.meta.url));
const rendererIndex = path.join(here, '..', 'renderer', 'index.html');
const rendererUrl = pathToFileURL(rendererIndex).href;
const preloadPath = path.join(here, '..', 'preload', 'preload.cjs');

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const ID = /^[A-Za-z0-9-]{1,80}$/u;

app.setName('mago-ski');
if (process.env.MAGO_SKI_GUI_DATA) app.setPath('userData', path.resolve(process.env.MAGO_SKI_GUI_DATA));

let window: BrowserWindow | null = null;
let service: ObservationService | null = null;
let admin: AdminSession | null = null;
/** The language of native dialogs, notifications and session messages; read again each time one is built. */
let currentLang: Lang = 'en';

function requireString(value: unknown, pattern: RegExp, label: string): string {
  if (typeof value !== 'string' || !pattern.test(value)) throw new Error(`invalid ${label}`);
  return value;
}

/** Every handler checks that the call comes from our own page, not from anything it might have navigated to. */
function handle(channel: string, fn: (...args: unknown[]) => unknown): void {
  ipcMain.handle(channel, (event: IpcMainInvokeEvent, ...args: unknown[]) => {
    if (event.senderFrame?.url !== rendererUrl) throw new Error('unexpected sender');
    return fn(...args);
  });
}

function notify(changed: InstanceView[]): void {
  const mode = service?.view().prefs.notify;
  if (!mode || mode === 'off' || !Notification.isSupported()) return;
  // Some Linux notification daemons interpret markup in the body; Skill names are untrusted.
  const plain = (text: string) => text.replace(/[<>&]/gu, '');
  const show = (title: string, body: string) => {
    const n = new Notification({ title: plain(title), body: plain(body), silent: true });
    n.on('click', () => { window?.show(); window?.focus(); });
    n.show();
  };
  if (mode === 'immediate') {
    for (const instance of changed) {
      const text = notificationImmediate(currentLang, instance.name);
      show(text.title, text.body);
    }
  } else {
    const text = notificationGrouped(currentLang, changed.map((i) => i.name));
    show(text.title, text.body);
  }
}

function registerIpc(svc: ObservationService): void {
  handle('view:get', () => svc.view());
  handle('view:check', async () => { await svc.check(); return svc.view(); });
  handle('detail:get', (id) => svc.detail(requireString(id, ID, 'instance id')));
  handle('action:reviewed', (id, digest) => svc.markReviewed(requireString(id, ID, 'instance id'), requireString(digest, DIGEST, 'digest')));
  handle('action:remember', (id, digest) => svc.rememberVersion(requireString(id, ID, 'instance id'), requireString(digest, DIGEST, 'digest')));
  // The renderer never supplies a path: the user picks one in a native dialog owned by this process.
  handle('roots:add', async () => {
    const options: Electron.OpenDialogOptions = { title: rootPickerTitle(currentLang), properties: ['openDirectory'] };
    const picked = window ? await dialog.showOpenDialog(window, options) : await dialog.showOpenDialog(options);
    if (!picked.canceled && picked.filePaths[0]) await svc.addRoot(picked.filePaths[0]);
    return svc.view();
  });
  handle('roots:remove', async (id) => { await svc.removeRoot(requireString(id, /^user-[0-9a-f-]{36}$/u, 'root id')); return svc.view(); });
  handle('prefs:set', async (prefs) => {
    if (typeof prefs !== 'object' || prefs === null) throw new Error('invalid preferences');
    await svc.setPrefs(prefs as Partial<Prefs>);
    return svc.view();
  });
  handle('history:dismiss-reset', async () => { await svc.dismissHistoryReset(); return svc.view(); });
  handle('settings:get-lang', () => currentLang);
  handle('settings:set-lang', async (lang) => {
    if (typeof lang !== 'string' || !(LANGS as readonly string[]).includes(lang)) throw new Error('invalid language');
    await writeLang(app.getPath('userData'), lang as Lang);
    currentLang = lang as Lang;
    return currentLang;
  });
  registerAdminIpc(svc);
  handle('clipboard:write', (text) => {
    if (typeof text !== 'string' || text.length > 4096) throw new Error('invalid text');
    clipboard.writeText(text);
  });
}

/** A native confirmation: cancel is the default and the escape answer; only the second button confirms. */
async function confirmBox(options: DialogText): Promise<boolean> {
  const box: Electron.MessageBoxOptions = {
    type: 'warning', buttons: [cancelLabel(currentLang), options.action], defaultId: 0, cancelId: 0, noLink: true,
    title: options.title, message: options.message, detail: options.detail,
  };
  const result = window ? await dialog.showMessageBox(window, box) : await dialog.showMessageBox(box);
  return result.response === 1;
}

const ADMIN_RAW_REASON_LIMIT = 4096;

function confirmReview(s: AdminReviewSummary): Promise<boolean> {
  return confirmBox(reviewDialog(currentLang, s));
}

function confirmSign(s: AdminSignSummary): Promise<boolean> {
  return confirmBox(signDialog(currentLang, s));
}

function confirmReset(): Promise<boolean> {
  return confirmBox(resetDialog(currentLang));
}

function confirmOffline(): Promise<boolean> {
  return confirmBox(offlineDialog(currentLang));
}

function confirmLastApprover(): Promise<boolean> {
  return confirmBox(lastApproverDialog(currentLang));
}

/** The approver's public key: chosen in a native dialog, read at most 64 KiB and loaded here; a failure carries no path. */
async function pickPublicKey(): Promise<{ ok: true; key: import('../../../src/keys.ts').PublicKeyInfo } | { ok: false; reason: string }> {
  const options: Electron.OpenDialogOptions = {
    title: publicKeyPickerTitle(currentLang), properties: ['openFile', 'showHiddenFiles'],
    filters: [{ name: 'PEM', extensions: ['pem', 'pub'] }, { name: keyPickerAllFiles(currentLang), extensions: ['*'] }],
  };
  const picked = window ? await dialog.showOpenDialog(window, options) : await dialog.showOpenDialog(options);
  if (picked.canceled || !picked.filePaths[0]) return { ok: false, reason: 'cancelled' };
  try {
    return { ok: true, key: loadPublicKeyBytes(await readRegularFile(picked.filePaths[0], 'Public key', 64 * 1024)) };
  } catch {
    return { ok: false, reason: 'unreadable' };
  }
}

/**
 * Administration rack (docs/spec/gui-admin-rack-v1.md). The renderer never names a file or sees key material: the key is
 * chosen in a dialog owned by this process and stays in the AdminSession.
 */
function registerAdminIpc(svc: ObservationService): void {
  const session = new AdminSession({
    instance: (id) => {
      const found = svc.view().instances.find((i) => i.id === id);
      return found ? { path: found.path, name: found.name } : null;
    },
    instances: () => svc.view().instances.map((i) => ({ id: i.id, path: i.path, name: i.name })),
    hostPolicyPath: () => svc.view().host.policy.path,
    confirmReview, confirmSign, confirmReset, confirmOffline, confirmLastApprover, pickPublicKey,
    stateDir: app.getPath('userData'),
    discoveryRoots: () => svc.view().roots.map((r) => r.path),
    skillFolders: () => svc.view().instances.map((i) => i.path),
    hostSkillDirs: () => svc.hostSkillDirs(),
    lang: () => currentLang,
  });
  admin = session;
  handle('admin:status', () => session.status());
  handle('admin:arm', async () => {
    const options: Electron.OpenDialogOptions = { title: keyPickerTitle(currentLang), properties: ['openFile', 'showHiddenFiles'], filters: [{ name: 'PEM', extensions: ['pem'] }, { name: keyPickerAllFiles(currentLang), extensions: ['*'] }] };
    let chosen: string | null;
    try {
      chosen = await session.pickFile(async () => {
        const picked = window ? await dialog.showOpenDialog(window, options) : await dialog.showOpenDialog(options);
        return picked.canceled || !picked.filePaths[0] ? null : picked.filePaths[0];
      });
    } catch (error) {
      return { ok: false, reason: error instanceof Error ? error.message : t(currentLang, 'admin.err.cooldown') };
    }
    if (chosen === null) return { ok: false, reason: 'cancelled' };
    return await session.arm(chosen);
  });
  handle('admin:disarm', () => { session.disarm(); return session.status(); });
  handle('admin:inspect', (id) => session.inspect(requireString(id, ID, 'instance id')));
  handle('admin:review', (id) => session.review(requireString(id, ID, 'instance id')));
  handle('admin:approve', (id, digest, lifetime, reason) => {
    if (typeof lifetime !== 'string' || !(LIFETIMES as readonly string[]).includes(lifetime)) throw new Error('invalid lifetime');
    if (typeof reason !== 'string' || reason.length > ADMIN_RAW_REASON_LIMIT) throw new Error('invalid reason');
    return session.approve(requireString(id, ID, 'instance id'), requireString(digest, DIGEST, 'digest'), lifetime as (typeof LIFETIMES)[number], reason);
  });
  handle('admin:check', (id) => session.check(requireString(id, ID, 'instance id')));
  handle('admin:reset-memory', () => session.resetMemory());
  handle('admin:dismiss-memory-reset', () => { session.dismissMemoryReset(); return session.status(); });
  handle('admin:trust-root', () => session.trustRoot());
  handle('admin:add-approver', (arg) => session.addApprover(parseAddApprover(arg)));
  handle('admin:remove-approver', (arg) => { const o = parseRemoveApprover(arg); return session.removeApprover(o.keyId, o.trustRootLifetime); });
  handle('admin:renew-trust-root', (arg) => session.renewTrustRoot(parseRenew(arg).lifetime));
  handle('admin:verify-all', () => session.verifyAll());
  handle('admin:revocations', () => session.revocations());
  handle('admin:revocation-skills', () => session.revocationSkills());
  handle('admin:revocation-targets', () => session.revocationTargets());
  handle('admin:revoke', (arg) => session.revoke(parseRevoke(arg)));
  handle('admin:refresh-revocations', (arg) => session.refreshRevocations(parseRefresh(arg).lifetime));
  handle('admin:timestamp', () => session.timestamp());
  handle('admin:sign-timestamp', (arg) => session.signTimestamp(parseSignTimestamp(arg).lifetime));
}

function createWindow(): BrowserWindow {
  const win = new BrowserWindow({
    width: 1360, height: 920, minWidth: 960, minHeight: 640,
    title: 'mago-ski', backgroundColor: '#ecebe6', autoHideMenuBar: true, show: false,
    webPreferences: {
      preload: preloadPath, contextIsolation: true, sandbox: true, nodeIntegration: false,
      webSecurity: true, spellcheck: false, devTools: !app.isPackaged,
    },
  });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event) => event.preventDefault());
  // Anything that replaces or loses the page ends the armed key; nothing may sign on behalf of a page that is gone.
  const disarm = () => admin?.disarm();
  let loaded = false;
  win.webContents.on('did-start-navigation', disarm);
  win.webContents.on('render-process-gone', disarm);
  win.webContents.on('destroyed', disarm);
  win.webContents.on('did-finish-load', () => {
    if (loaded) disarm();
    loaded = true;
  });
  win.once('ready-to-show', () => win.show());
  void win.loadFile(rendererIndex);
  return win;
}

async function main(): Promise<void> {
  if (!app.requestSingleInstanceLock()) {
    app.quit();
    return;
  }
  await app.whenReady();
  // The page needs no camera, notifications API, clipboard read or any other permission.
  session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);

  currentLang = (await readLang(app.getPath('userData'))) ?? langFromLocale(app.getLocale());
  service = new ObservationService({ dataDir: app.getPath('userData') });
  registerIpc(service);
  service.on('update', (view) => window?.webContents.send('view:update', view));
  service.on('changes', (changed: InstanceView[]) => notify(changed));

  window = createWindow();
  app.on('second-instance', () => { window?.show(); window?.focus(); });
  // Closing the window stops observation; the window footer says so.
  app.on('window-all-closed', () => app.quit());
  app.on('before-quit', () => { admin?.disarm(); void service?.stop(); });
  await service.start();
}

main().catch((error) => {
  dialog.showErrorBox('mago-ski', startFailure(currentLang, error instanceof Error ? error.message : String(error)));
  app.exit(1);
});
