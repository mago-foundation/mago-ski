// Electron main process: owns the observation service and the only window.
// The renderer is sandboxed and reaches the service only through the narrow IPC surface below.
import { app, BrowserWindow, clipboard, dialog, ipcMain, Notification, session, type IpcMainInvokeEvent } from 'electron';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ObservationService } from '../service/service.ts';
import type { InstanceView, Prefs } from '../service/types.ts';

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
    for (const instance of changed) show(`${instance.name}: 기록한 버전에서 내용이 바뀌었어요`, '변경 내용을 확인할 수 있어요. 관찰 모드는 실행을 막지 않아요.');
  } else {
    const names = changed.map((i) => i.name).join(', ');
    show(`Skill ${changed.length}개의 내용이 바뀌었어요`, `${names} · 변경 내용을 확인할 수 있어요.`);
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
    const options: Electron.OpenDialogOptions = { title: 'Skill 폴더 추가', properties: ['openDirectory'] };
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
  handle('clipboard:write', (text) => {
    if (typeof text !== 'string' || text.length > 4096) throw new Error('invalid text');
    clipboard.writeText(text);
  });
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

  service = new ObservationService({ dataDir: app.getPath('userData') });
  registerIpc(service);
  service.on('update', (view) => window?.webContents.send('view:update', view));
  service.on('changes', (changed: InstanceView[]) => notify(changed));

  window = createWindow();
  app.on('second-instance', () => { window?.show(); window?.focus(); });
  // Closing the window stops observation; the window footer says so.
  app.on('window-all-closed', () => app.quit());
  app.on('before-quit', () => { void service?.stop(); });
  await service.start();
}

main().catch((error) => {
  dialog.showErrorBox('mago-ski', `시작하지 못했어요: ${error instanceof Error ? error.message : String(error)}`);
  app.exit(1);
});
