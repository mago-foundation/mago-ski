// Sandboxed preload: exposes exactly the RendererApi, nothing from Node or Electron itself.
import type { IpcRendererEvent } from 'electron';
import type { Lang } from '../i18n/messages.ts';
import type { AdminApproverLifetime, AdminLifetime, AdminListLifetime, AdminRevokeRequest, AdminTimestampLifetime, AdminTrustRootLifetime, Prefs, RendererApi, ServiceView } from '../service/types.ts';

const { contextBridge, ipcRenderer } = require('electron') as typeof import('electron');

const api: RendererApi = {
  getView:         () => ipcRenderer.invoke('view:get'),
  checkNow:        () => ipcRenderer.invoke('view:check'),
  getDetail:       (id: string) => ipcRenderer.invoke('detail:get', id),
  markReviewed:    (id: string, digest: string) => ipcRenderer.invoke('action:reviewed', id, digest),
  rememberVersion: (id: string, digest: string) => ipcRenderer.invoke('action:remember', id, digest),
  addRoot:         () => ipcRenderer.invoke('roots:add'),
  removeRoot:      (id: string) => ipcRenderer.invoke('roots:remove', id),
  setPrefs:        (prefs: Partial<Prefs>) => ipcRenderer.invoke('prefs:set', prefs),
  copyText:        (text: string) => ipcRenderer.invoke('clipboard:write', text),
  dismissHistoryReset: () => ipcRenderer.invoke('history:dismiss-reset'),
  getLang:         () => ipcRenderer.invoke('settings:get-lang'),
  setLang:         (lang: Lang) => ipcRenderer.invoke('settings:set-lang', lang),
  onUpdate: (listener: (view: ServiceView) => void) => {
    const wrapped = (_event: IpcRendererEvent, view: ServiceView) => listener(view);
    ipcRenderer.on('view:update', wrapped);
    return () => { ipcRenderer.removeListener('view:update', wrapped); };
  },
  admin: {
    status:           () => ipcRenderer.invoke('admin:status'),
    arm:              () => ipcRenderer.invoke('admin:arm'),
    disarm:           () => ipcRenderer.invoke('admin:disarm'),
    inspect:          (id: string) => ipcRenderer.invoke('admin:inspect', id),
    review:           (id: string) => ipcRenderer.invoke('admin:review', id),
    approve:          (id: string, digest: string, lifetime: AdminLifetime, reason: string) => ipcRenderer.invoke('admin:approve', id, digest, lifetime, reason),
    check:            (id: string) => ipcRenderer.invoke('admin:check', id),
    resetMemory:      () => ipcRenderer.invoke('admin:reset-memory'),
    dismissMemoryReset: () => ipcRenderer.invoke('admin:dismiss-memory-reset'),
    trustRoot:        () => ipcRenderer.invoke('admin:trust-root'),
    addApprover:      (o: { name: string; scopes: string[]; lifetime: AdminApproverLifetime; trustRootLifetime?: AdminTrustRootLifetime }) => ipcRenderer.invoke('admin:add-approver', o),
    removeApprover:   (o: { keyId: string; trustRootLifetime?: AdminTrustRootLifetime }) => ipcRenderer.invoke('admin:remove-approver', o),
    renewTrustRoot:   (o: { lifetime: AdminTrustRootLifetime }) => ipcRenderer.invoke('admin:renew-trust-root', o),
    verifyAll:        () => ipcRenderer.invoke('admin:verify-all'),
    revocations:      () => ipcRenderer.invoke('admin:revocations'),
    revocationSkills: () => ipcRenderer.invoke('admin:revocation-skills'),
    revocationTargets: () => ipcRenderer.invoke('admin:revocation-targets'),
    revoke:           (o: { target: AdminRevokeRequest; reason: string; lifetime: AdminListLifetime }) => ipcRenderer.invoke('admin:revoke', o),
    refreshRevocations: (o: { lifetime: AdminListLifetime }) => ipcRenderer.invoke('admin:refresh-revocations', o),
    timestamp:        () => ipcRenderer.invoke('admin:timestamp'),
    signTimestamp:    (o: { lifetime: AdminTimestampLifetime }) => ipcRenderer.invoke('admin:sign-timestamp', o),
  },
};

contextBridge.exposeInMainWorld('magoSki', api);
