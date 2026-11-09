// Electron main process: owns the observation service and the only window.
// The renderer is sandboxed and reaches the service only through the narrow IPC surface below.
import { app, BrowserWindow, clipboard, dialog, ipcMain, Notification, session, type IpcMainInvokeEvent } from 'electron';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { AdminSession, dialogSafe, LIFETIMES } from '../service/admin.ts';
import { ObservationService } from '../service/service.ts';
import type { AdminReviewSummary, AdminSignSummary, InstanceView, Prefs } from '../service/types.ts';

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
  registerAdminIpc(svc);
  handle('clipboard:write', (text) => {
    if (typeof text !== 'string' || text.length > 4096) throw new Error('invalid text');
    clipboard.writeText(text);
  });
}

/** A native confirmation: cancel is the default and the escape answer; only the second button confirms. */
async function confirmBox(options: { title: string; message: string; detail: string; action: string }): Promise<boolean> {
  const box: Electron.MessageBoxOptions = {
    type: 'warning', buttons: ['취소', options.action], defaultId: 0, cancelId: 0, noLink: true,
    title: options.title, message: options.message, detail: options.detail,
  };
  const result = window ? await dialog.showMessageBox(window, box) : await dialog.showMessageBox(box);
  return result.response === 1;
}

const ADMIN_RAW_REASON_LIMIT = 4096;

function confirmReview(s: AdminReviewSummary): Promise<boolean> {
  return confirmBox({
    title: 'Skill 검토 확인', message: '이 정확한 버전의 파일을 모두 검토했나요?', action: '검토함',
    detail: [`Skill: ${dialogSafe(s.skillName)}`, `폴더: ${dialogSafe(s.skillPath)}`, `버전: ${s.digest}`, `파일: ${s.files}개`].join('\n'),
  });
}

function confirmSign(s: AdminSignSummary): Promise<boolean> {
  return confirmBox({
    title: '인증서 서명', message: '이 Skill 버전에 인증서를 서명할까요?', action: '서명',
    detail: [
      `Skill: ${dialogSafe(s.skillName)}`, `폴더: ${dialogSafe(s.skillPath)}`, `검토한 버전: ${s.reviewedDigest}`, `서명할 버전: ${s.digest}`,
      `기간: ${s.lifetime} (만료 ${s.expiresAt})`, `이유: ${dialogSafe(s.reason)}`,
      `키: ${s.role} · ${dialogSafe(s.keyName ?? '-')} · ${s.keyId}`,
    ].join('\n'),
  });
}

function confirmReset(): Promise<boolean> {
  return confirmBox({
    title: '기록 초기화', message: '이 컴퓨터가 기억하는 조직 문서 버전을 지울까요? 오래된 문서를 다시 받아들일 수 있게 돼요.',
    detail: '', action: '초기화',
  });
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
    hostPolicyPath: () => svc.view().host.policy.path,
    confirmReview, confirmSign, confirmReset,
    stateDir: app.getPath('userData'),
    discoveryRoots: () => svc.view().roots.map((r) => r.path),
    skillFolders: () => svc.view().instances.map((i) => i.path),
    hostSkillDirs: () => svc.hostSkillDirs(),
  });
  admin = session;
  handle('admin:status', () => session.status());
  handle('admin:arm', async () => {
    const options: Electron.OpenDialogOptions = { title: '서명 키 불러오기 (개인 키 PEM)', properties: ['openFile', 'showHiddenFiles'], filters: [{ name: 'PEM', extensions: ['pem'] }, { name: '모든 파일', extensions: ['*'] }] };
    let chosen: string | null;
    try {
      chosen = await session.pickFile(async () => {
        const picked = window ? await dialog.showOpenDialog(window, options) : await dialog.showOpenDialog(options);
        return picked.canceled || !picked.filePaths[0] ? null : picked.filePaths[0];
      });
    } catch (error) {
      return { ok: false, reason: error instanceof Error ? error.message : '잠시 후 다시 시도하세요' };
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
  dialog.showErrorBox('mago-ski', `시작하지 못했어요: ${error instanceof Error ? error.message : String(error)}`);
  app.exit(1);
});
