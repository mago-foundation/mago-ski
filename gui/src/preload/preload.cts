// Sandboxed preload: exposes exactly the RendererApi, nothing from Node or Electron itself.
import type { IpcRendererEvent } from 'electron';
import type { AdminLifetime, Prefs, RendererApi, ServiceView } from '../service/types.ts';

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
    confirmInspected: (id: string, digest: string) => ipcRenderer.invoke('admin:confirm-inspected', id, digest),
    approve:          (id: string, digest: string, lifetime: AdminLifetime, reason: string) => ipcRenderer.invoke('admin:approve', id, digest, lifetime, reason),
    check:            (id: string) => ipcRenderer.invoke('admin:check', id),
  },
};

contextBridge.exposeInMainWorld('magoSki', api);
