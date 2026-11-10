// Administration rack (docs/spec/gui-admin-rack-v1.md): the organisation pin, the template picker and the devices of
// the "Approve a Skill version" template. Key material never reaches this page: the main process holds the armed key
// and decides every signature; this module only shows state and sends instance ids, digests and text.
import type {
  AdminCheckView, AdminInspectView, AdminLifetime, AdminPinView, AdminRole, AdminStatusView, ChangeView, RendererApi, ServiceView,
} from '../service/types.ts';
import { t, type MessageKey } from '../i18n/messages.ts';
import { h } from './dom.ts';
import { noteText, tr, type Note } from './lang.ts';

type TemplateKey = 'approve' | 'approvers' | 'revoke' | 'publish' | 'setup' | 'incident';
type DeviceKey = 'identity' | 'inspect' | 'approve' | 'check';
type DeviceState = 'locked' | 'waiting' | 'ready' | 'done' | 'failed';

const TEMPLATES: Array<{ key: TemplateKey; chain: string; phase: 1 | 2 | 3 }> = [
  { key: 'approve',   chain: 'IDENTITY → INSPECT → APPROVE → POLICY CHECK', phase: 1 },
  { key: 'approvers', chain: 'IDENTITY → TRUST ROOT → POLICY CHECK', phase: 2 },
  { key: 'revoke',    chain: 'IDENTITY → INSPECT → REVOKE → POLICY CHECK', phase: 2 },
  { key: 'publish',   chain: 'IDENTITY → REVOCATION REFRESH → TIMESTAMP → POLICY CHECK', phase: 2 },
  { key: 'setup',     chain: 'KEYS → ROOT INIT → RECOVERY SET → POLICY CHECK', phase: 3 },
  { key: 'incident',  chain: 'IDENTITY → ROOT EVENT → ADOPT → POLICY CHECK', phase: 3 },
];
const TEMPLATE_TITLE: Record<TemplateKey, MessageKey> = {
  approve: 'admin.tpl.approve.title', approvers: 'admin.tpl.approvers.title', revoke: 'admin.tpl.revoke.title',
  publish: 'admin.tpl.publish.title', setup: 'admin.tpl.setup.title', incident: 'admin.tpl.incident.title',
};
const TEMPLATE_ROLE: Record<TemplateKey, MessageKey> = {
  approve: 'admin.tpl.approve.role', approvers: 'admin.tpl.approvers.role', revoke: 'admin.tpl.revoke.role',
  publish: 'admin.tpl.publish.role', setup: 'admin.tpl.setup.role', incident: 'admin.tpl.incident.role',
};

const ROLE_LABEL: Record<AdminRole, string> = { root: 'ROOT', approver: 'APPROVER', recovery: 'RECOVERY', timestamp: 'TIMESTAMP', none: '—' };
const ROLE_NAME_KEY: Record<AdminRole, MessageKey> = {
  root: 'admin.role.root', approver: 'admin.role.approver', recovery: 'admin.role.recovery', timestamp: 'admin.role.timestamp', none: 'admin.role.none',
};
const roleName = (role: AdminRole): string => tr(ROLE_NAME_KEY[role]);
const STATE_KEY: Record<DeviceState, MessageKey> = {
  locked: 'admin.state.locked', waiting: 'admin.state.waiting', ready: 'admin.state.ready', done: 'admin.state.done', failed: 'admin.state.failed',
};
const LIFETIMES: AdminLifetime[] = ['30d', '90d', '180d'];
const lifetimeLabel = (value: AdminLifetime): string => tr('admin.lifetime', { n: Number.parseInt(value, 10) });

let api: RendererApi;
let container: HTMLElement;
let view: ServiceView;
let status: AdminStatusView | null = null;
let statusLoading = false;
let template: TemplateKey = 'approve';
let device: DeviceKey = 'identity';
let skillId: string | null = null;
let inspected: AdminInspectView | null = null;
let change: ChangeView | null = null;
let lifetime: AdminLifetime = '90d';
let reason = '';
let signed: { certificateId: string; certificatePath: string; expiresAt: string } | null = null;
let checked: AdminCheckView | null = null;
let message: Note | null = null;
let busy = false;

const short = (digest: string | null | undefined): string => (digest ? `${digest.slice(0, 13)}…${digest.slice(-4)}` : '—');

/** Same rule as the engine's scopeMatches, for display only; the main process decides. */
function scopeCovers(scope: string, name: string): boolean {
  if (scope === '*') return true;
  if (scope.endsWith('*')) return name.startsWith(scope.slice(0, -1));
  return scope === name;
}

const POLL_MS = 5000;
let pollTimer: ReturnType<typeof setInterval> | null = null;

/** Polls the status while the Admin tab is visible, so the main process re-checks the pin and the role on its own. */
export function setAdminPolling(on: boolean, renderer: RendererApi): void {
  api = renderer;
  if (!on) {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
    return;
  }
  if (pollTimer) return;
  pollTimer = setInterval(() => { if (!statusLoading) void refreshStatus(); }, POLL_MS);
}

/** Asks for the status now, e.g. after a language change, so the main process's texts come back in the new language. */
export function refreshAdminStatus(): void {
  if (api && !statusLoading) void refreshStatus();
}

export function renderAdmin(target: HTMLElement, next: ServiceView, renderer: RendererApi): void {
  api = renderer;
  container = target;
  view = next;
  // A Skill that changed under an inspection voids it, as the main process would.
  const current = skillId ? next.instances.find((i) => i.id === skillId) : undefined;
  if (inspected && (!current || current.currentDigest !== inspected.digest)) {
    resetFrom('inspect');
    message = { ok: false, text: () => tr('admin.msg.skillChanged') };
  }
  if (!status && !statusLoading) void refreshStatus();
  draw();
}

/** Status requests are numbered; a response is adopted only if no newer request was sent after it. */
let statusSent = 0;

/** Must equal admin.err.memoryBusy, which the main process writes in whichever language was in effect. */
const isMemoryBusy = (reason: string | null): boolean => reason === t('ko', 'admin.err.memoryBusy') || reason === t('en', 'admin.err.memoryBusy');

async function fetchStatus(): Promise<void> {
  statusSent += 1;
  const mine = statusSent;
  let next: AdminStatusView;
  try {
    next = await api.admin.status();
  } catch {
    return;
  }
  if (mine === statusSent) adoptStatus(next);
}

/** A call that returns a status goes through the same counter as a fetch, so an older response never overwrites a newer one. */
async function statusFrom(call: () => Promise<AdminStatusView>): Promise<void> {
  statusSent += 1;
  const mine = statusSent;
  const next = await call();
  if (mine === statusSent) status = next;
}

async function refreshStatus(): Promise<void> {
  statusLoading = true;
  try {
    await fetchStatus();
  } finally {
    statusLoading = false;
  }
}

/** Takes a status from the main process. The page redraws only when something changed, so typing is never interrupted. */
function adoptStatus(next: AdminStatusView): void {
  const previous = status;
  status = next;
  if (previous?.armed && !next.armed) {
    // The main process dropped the key (pin or role change, idle, or a disarm): nothing recorded for it stands.
    resetFrom('inspect');
    message ??= { ok: false, text: () => tr('admin.msg.keyDropped') };
  } else if (previous && JSON.stringify(previous) === JSON.stringify(next)) {
    return;
  }
  draw();
}

function resetFrom(step: 'inspect' | 'approve'): void {
  if (step === 'inspect') { inspected = null; change = null; }
  signed = null;
  checked = null;
}

async function run(action: () => Promise<void>): Promise<void> {
  if (busy) return;
  busy = true;
  message = null;
  draw();
  try {
    await action();
  } catch (error) {
    message = { ok: false, text: error instanceof Error ? error.message : String(error) };
  } finally {
    busy = false;
    draw();
  }
}

// ------------------------------------------------------------------ device states

function states(): Record<DeviceKey, { state: DeviceState; why: string }> {
  const armed = status?.armed ?? null;
  const pinOk = status?.pin.kind === 'loaded';
  const identity: { state: DeviceState; why: string } = !pinOk ? { state: 'locked', why: tr('admin.why.noPin') }
    : armed?.role === 'approver' ? { state: 'done', why: `${armed.name ?? ''} · ${armed.scopes?.join(', ') ?? ''}` }
    : armed ? { state: 'failed', why: tr('admin.why.wrongRole', { role: roleName(armed.role) }) }
    : { state: 'ready', why: tr('admin.why.loadApprover') };
  const inspect: { state: DeviceState; why: string } = identity.state !== 'done' ? { state: 'waiting', why: tr('admin.why.loadApproverFirst') }
    : inspected?.inspected ? { state: 'done', why: `${inspected.name} · ${short(inspected.digest)}` }
    : { state: 'ready', why: skillId ? tr('admin.why.confirmVersion') : tr('admin.why.pickSkill') };
  const approve: { state: DeviceState; why: string } = inspect.state !== 'done' && !signed ? { state: 'waiting', why: tr('admin.why.reviewFirst') }
    : signed ? { state: 'done', why: tr('admin.why.certificate', { id: short(signed.certificateId) }) }
    : { state: 'ready', why: tr('admin.why.signReady') };
  const check: { state: DeviceState; why: string } = !skillId ? { state: 'waiting', why: tr('admin.why.pickSkill') }
    : checked ? { state: checked.verdict === 'VERIFIED' ? 'done' : 'failed', why: checked.verdict ?? checked.reason }
    : { state: 'ready', why: tr('admin.why.checkReady') };
  return { identity, inspect, approve, check };
}

// ------------------------------------------------------------------ drawing

function draw(): void {
  if (!container) return;
  const tpl = TEMPLATES.find((x) => x.key === template)!;
  const parts: Array<HTMLElement | null> = [
    h('div', { class: 'section-head' }, h('h2', {}, tr('admin.head.title')), h('span', { class: 'spacer' }),
      h('span', { class: 'hint', style: 'margin:0' }, tr('admin.head.hint'))),
    pinPanel(status?.pin ?? null),
    status?.hostPolicyDiffers ? h('div', { class: 'banner', style: 'margin:10px 0' }, tr('admin.hostDiffers')) : null,
    h('h2', {}, tr('admin.templates')),
    h('div', { class: 'tpl-grid' }, ...TEMPLATES.map(templateCard)),
    tpl.phase === 1 ? approveRack() : h('div', { class: 'empty-state' }, tr('admin.tpl.later', { title: tr(TEMPLATE_TITLE[tpl.key]), n: tpl.phase })),
    tpl.phase === 1 ? deviceDetail() : null,
  ];
  container.replaceChildren(...parts.filter((part): part is HTMLElement => part !== null));
}

function pinPanel(pin: AdminPinView | null): HTMLElement {
  if (!pin) return h('p', { class: 'hint' }, tr('admin.pin.loading'));
  const stateText: Record<AdminPinView['kind'], string> = {
    loaded: tr('admin.pin.loaded'), missing: tr('admin.pin.missing'), unprotected: tr('admin.pin.unprotected'), invalid: tr('admin.pin.invalid'),
  };
  const rows: HTMLElement[] = [
    h('dt', {}, tr('admin.pin.label')), h('dd', {}, pin.path),
    h('dt', {}, tr('admin.pin.state')), h('dd', {}, `${stateText[pin.kind]}${pin.reason ? ` · ${pin.reason}` : ''}`),
  ];
  if (pin.kind === 'loaded') rows.push(
    h('dt', {}, tr('admin.pin.rootKey')), h('dd', {}, `${pin.activeRootKeyId ?? tr('admin.pin.unknown')}${pin.activeRootKeyId && pin.activeRootKeyId !== pin.rootKeyId ? ` ${tr('admin.pin.replaced')}` : ''}`),
    h('dt', {}, tr('admin.pin.modeTrust')), h('dd', {}, `${pin.mode} · ${pin.trustOk ? tr('admin.pin.trustOk') : tr('admin.pin.trustFail', { note: pin.trustNote ?? '' })}`),
  );
  const notices: HTMLElement[] = [];
  if (status?.memoryReset) {
    notices.push(h('div', { class: 'banner', style: 'margin:10px 0' },
      `${tr('admin.pin.memoryReset', { backup: status.memoryReset.backup })} `,
      button(tr('admin.close'), () => void run(async () => { await statusFrom(() => api.admin.dismissMemoryReset()); }), { id: 'dismiss-memory-reset' })));
  }
  // An unreadable memory file can only be recovered by moving it aside, which needs no read permission.
  if (status?.rollback || (pin.kind === 'invalid' && isMemoryBusy(pin.reason))) {
    notices.push(h('div', { class: 'banner', style: 'margin:10px 0' },
      `${tr('admin.pin.rollback')} `,
      button(tr('admin.pin.resetButton'), () => void run(async () => {
        statusSent += 1;
        const mine = statusSent;
        const result = await api.admin.resetMemory();
        if (mine === statusSent) status = result.status;
        resetFrom('inspect');
        if (!result.ok) message = { ok: false, text: result.message };
      }), { id: 'reset-memory' })));
  }
  const help = pin.kind === 'missing' || pin.kind === 'unprotected'
    ? h('p', { class: 'hint' }, tr('admin.pin.help'))
    : null;
  return h('div', {}, h('dl', { class: 'kv' }, ...rows), ...notices, help);
}

function templateCard(t: (typeof TEMPLATES)[number]): HTMLElement {
  const disabled = t.phase !== 1;
  const card = h('button', { class: 'tpl', 'aria-pressed': String(t.key === template), 'aria-disabled': String(disabled), 'data-template': t.key },
    h('span', { class: 'tpl-title' }, tr(TEMPLATE_TITLE[t.key])),
    h('span', { class: 'tpl-chain' }, t.chain),
    h('span', { class: 'tpl-role' }, disabled ? tr('admin.tpl.planned', { n: t.phase, role: tr(TEMPLATE_ROLE[t.key]) }) : tr(TEMPLATE_ROLE[t.key])));
  card.addEventListener('click', () => {
    if (t.key === template) return;
    template = t.key;
    resetFrom('inspect');
    skillId = null;
    // Changing the template drops the armed key (spec: armed key lifetime).
    void run(async () => { if (status?.armed) { await statusFrom(() => api.admin.disarm()); message = { ok: true, text: () => tr('admin.tpl.switched') }; } });
  });
  return card;
}

function faceplate(key: DeviceKey, name: string, state: { state: DeviceState; why: string }, ...body: HTMLElement[]): HTMLElement {
  const live = state.state === 'ready' || state.state === 'done';
  const el = h('div', {
    class: `device admin-dev ${state.state}`, tabindex: 0, role: 'button', 'aria-selected': String(device === key), 'data-admin-device': key, style: 'width:250px',
  },
    h('div', { class: 'dev-head' },
      h('span', { class: 'power', role: 'img', 'aria-pressed': String(live), 'aria-label': tr(STATE_KEY[state.state]) }),
      h('span', { class: 'dev-name' }, name), h('span', { class: 'spacer' }),
      h('span', { class: `dev-tag state-${state.state}` }, tr(STATE_KEY[state.state]))),
    h('div', { class: 'dev-body', style: 'flex-direction:column;align-items:center;justify-content:center;gap:10px;padding:14px' }, ...body),
    h('div', { class: 'dev-foot' }, state.why));
  el.addEventListener('click', () => { device = key; draw(); });
  el.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); device = key; draw(); } });
  return el;
}

function screen(big: string, small: string, cls = ''): HTMLElement {
  return h('div', { class: 'screen' }, h('div', { class: `big ${cls}` }, big), h('div', { class: 'small' }, small));
}

function approveRack(): HTMLElement {
  const s = states();
  const armed = status?.armed ?? null;
  const verdictClass = checked?.verdict === 'VERIFIED' ? 'verified' : checked ? 'problem' : '';
  const link = (on: boolean) => h('div', { class: `link${on ? ' live' : ''}` });
  return h('section', { class: 'rack-wrap', style: 'margin:14px 0 0' },
    h('div', { class: 'rack-head' }, 'ADMIN CHAIN / APPROVE A SKILL VERSION', h('div', { class: 'spacer' }),
      h('div', { class: 'legend' }, h('span', {}, tr('admin.chain.legend')))),
    h('div', { class: 'chain' },
      faceplate('identity', 'SKI / IDENTITY', s.identity,
        h('div', { class: 'sec-label' }, 'KEY SLOT'),
        screen(armed ? ROLE_LABEL[armed.role] : 'EMPTY', armed ? short(armed.keyId) : tr('admin.screen.noKey'), armed?.role === 'approver' ? 'verified' : armed ? 'warn' : '')),
      link(s.identity.state === 'done'),
      faceplate('inspect', 'SKI / INSPECT', s.inspect,
        h('div', { class: 'sec-label' }, 'VERSION'),
        screen(inspected?.name ?? '—', inspected ? short(inspected.digest) : tr('admin.screen.noSkill'), inspected?.inspected ? 'verified' : '')),
      link(s.inspect.state === 'done'),
      faceplate('approve', 'SKI / APPROVE', s.approve,
        h('div', { class: 'sec-label' }, 'LIFETIME'),
        screen(signed ? 'SIGNED' : lifetimeLabel(lifetime), signed ? short(signed.certificateId) : tr('admin.screen.lifetime'), signed ? 'verified' : '')),
      link(s.approve.state === 'done'),
      faceplate('check', 'SKI / POLICY CHECK', s.check,
        h('div', { class: 'sec-label' }, 'VERDICT'),
        screen(checked?.verdict ?? '—', checked ? (checked.trustOk ? tr('admin.screen.trustOk') : tr('admin.screen.trustFail')) : tr('admin.screen.pinBasis'), verdictClass))));
}

function deviceDetail(): HTMLElement {
  const pane = h('section', { class: 'admin-detail' });
  const titles: Record<DeviceKey, string> = { identity: tr('admin.dev.identity'), inspect: tr('admin.dev.inspect'), approve: tr('admin.dev.approve'), check: tr('admin.dev.check') };
  pane.append(h('h2', {}, titles[device]));
  if (device === 'identity') identityDetail(pane);
  if (device === 'inspect') inspectDetail(pane);
  if (device === 'approve') approveDetail(pane);
  if (device === 'check') checkDetail(pane);
  if (message) pane.append(h('div', { class: `result ${message.ok ? 'ok' : 'err'}` }, noteText(message)));
  return pane;
}

function button(label: string, onClick: () => void, options: { primary?: boolean; disabled?: boolean; id?: string } = {}): HTMLButtonElement {
  const b = h('button', { class: `btn${options.primary ? ' primary' : ''}`, disabled: options.disabled || busy, ...(options.id ? { 'data-action': options.id } : {}) }) as HTMLButtonElement;
  b.textContent = label;
  b.addEventListener('click', onClick);
  return b;
}

function identityDetail(pane: HTMLElement): void {
  const armed = status?.armed ?? null;
  pane.append(h('p', { class: 'hint' },
    tr('admin.identity.hint', { minutes: status?.idleMinutes ?? 15 })));
  if (armed) {
    pane.append(h('dl', { class: 'kv' },
      h('dt', {}, tr('admin.identity.role')), h('dd', {}, roleName(armed.role)),
      h('dt', {}, tr('admin.identity.key')), h('dd', {}, armed.keyId),
      ...(armed.name ? [h('dt', {}, tr('admin.identity.name')), h('dd', {}, armed.name)] : []),
      ...(armed.scopes ? [h('dt', {}, tr('admin.identity.scopes')), h('dd', {}, armed.scopes.join(', '))] : []),
      ...(armed.expiresAt ? [h('dt', {}, tr('admin.identity.expires')), h('dd', {}, armed.expiresAt)] : [])));
    if (armed.role === 'root' || armed.role === 'recovery')
      pane.append(h('div', { class: 'banner', style: 'margin:10px 0' }, tr('admin.identity.offlineWarn')));
  }
  pane.append(h('div', { class: 'cmd', style: 'margin-top:12px' },
    button(armed ? tr('admin.identity.loadOther') : tr('admin.identity.load'), () => void run(async () => {
      const result = await api.admin.arm();
      if (!result.ok && result.reason !== 'cancelled') message = { ok: false, text: () => tr('admin.identity.unusable', { reason: result.reason }) };
      if (result.ok) message = { ok: true, text: () => tr('admin.identity.accepted', { role: roleName(result.role.role) }) };
      resetFrom('inspect');
      await fetchStatus();
    }), { primary: !armed, disabled: status?.pin.kind !== 'loaded', id: 'arm' }),
    armed ? button(tr('admin.identity.unload'), () => void run(async () => { await statusFrom(() => api.admin.disarm()); resetFrom('inspect'); message = { ok: true, text: () => tr('admin.identity.unloaded') }; }), { id: 'disarm' }) : null));
}

async function selectSkill(id: string): Promise<void> {
  await run(async () => {
    skillId = id;
    resetFrom('inspect');
    inspected = await api.admin.inspect(id);
    const detail = await api.getDetail(id);
    change = detail?.change && detail.change.currentDigest === inspected.digest ? detail.change : null;
  });
}

function inspectDetail(pane: HTMLElement): void {
  const list = h('div', { class: 'seg', style: 'flex-wrap:wrap' }, ...view.instances.map((i) => {
    const b = h('button', { 'aria-pressed': String(i.id === skillId), 'data-skill': i.name }, i.name);
    b.addEventListener('click', () => void selectSkill(i.id));
    return b;
  }));
  pane.append(h('p', { class: 'hint' }, tr('admin.inspect.hint')), list);
  if (!inspected) return;
  const i = inspected;
  pane.append(h('dl', { class: 'kv', style: 'margin-top:14px' },
    h('dt', {}, 'Skill'), h('dd', {}, `${i.name} · ${i.path}`),
    h('dt', {}, tr('admin.inspect.version')), h('dd', {}, i.digest),
    h('dt', {}, tr('admin.inspect.size')), h('dd', {}, tr('admin.inspect.sizeValue', { n: i.files.length, bytes: i.totalBytes })),
    h('dt', {}, tr('admin.inspect.verdict')), h('dd', {}, i.verdictStale ? tr('admin.inspect.stale') : i.verdict ? `${i.verdict.verdict} · ${i.verdict.reason}` : tr('admin.inspect.noPin')),
    ...(i.certificate ? [h('dt', {}, tr('admin.inspect.cert')), h('dd', {}, `${short(i.certificate.id)} · ${i.certificate.approverKeyId.slice(0, 16)}… · ${i.certificate.issuedAt} ~ ${i.certificate.expiresAt} · "${i.certificate.reason}"`)] : []),
    ...(i.excluded.length ? [h('dt', {}, tr('admin.inspect.excluded')), h('dd', {}, i.excluded.join(', '))] : [])));
  if (change) pane.append(h('p', { class: 'hint', style: 'margin-top:10px' },
    `${tr('admin.inspect.changedFiles', { files: change.files.map((f) => `${f.path} (${f.change})`).join(', ') })}${change.addedOrigins.length ? ` · ${tr('admin.inspect.newOrigins', { origins: change.addedOrigins.join(', ') })}` : ''} · ${tr('admin.inspect.lineChanges')}`));
  pane.append(h('table', { class: 'tbl', style: 'margin-top:10px' },
    h('tr', {}, h('th', {}, tr('admin.inspect.file')), h('th', {}, tr('admin.inspect.fileSize')), h('th', {}, tr('admin.inspect.exec')), h('th', {}, 'SHA-256')),
    ...i.files.map((f) => h('tr', {}, h('td', { class: 'mono' }, f.path), h('td', {}, String(f.size)), h('td', {}, f.exec ? tr('admin.inspect.yes') : ''), h('td', { class: 'mono' }, f.sha256.slice(0, 16) + '…')))));
  const armedApprover = status?.armed?.role === 'approver';
  pane.append(h('div', { class: 'cmd', style: 'margin-top:12px' },
    button(i.inspected ? tr('admin.inspect.confirmed') : tr('admin.inspect.confirm'), () => void run(async () => {
      // The page only asks; a native window owned by the main process shows the exact version and records the answer.
      const result = await api.admin.review(i.instanceId);
      if (!result.ok) { message = { ok: false, text: result.message }; await fetchStatus(); return; }
      inspected = await api.admin.inspect(i.instanceId);
      if (!inspected.inspected) { message = { ok: false, text: () => tr('admin.inspect.changedDuring') }; return; }
      message = { ok: true, text: () => tr('admin.inspect.recorded', { digest: i.digest }) };
      device = 'approve';
    }), { primary: !i.inspected, disabled: !armedApprover || i.inspected, id: 'confirm' })));
}

function approveDetail(pane: HTMLElement): void {
  const armed = status?.armed ?? null;
  if (!inspected?.inspected && !signed) { pane.append(h('p', { class: 'hint' }, tr('admin.approve.needReview'))); return; }
  if (signed) {
    pane.append(h('dl', { class: 'kv' },
      h('dt', {}, tr('admin.approve.certificate')), h('dd', {}, signed.certificateId),
      h('dt', {}, tr('admin.approve.savedAt')), h('dd', {}, signed.certificatePath),
      h('dt', {}, tr('admin.approve.expires')), h('dd', {}, signed.expiresAt)));
    return;
  }
  const i = inspected!;
  const scopes = armed?.scopes ?? [];
  const covered = scopes.some((s) => scopeCovers(s, i.name));
  let signButton: HTMLButtonElement;
  const area = h('textarea', { class: 'reason', rows: 3, maxlength: 1024, placeholder: tr('admin.approve.placeholder') }) as HTMLTextAreaElement;
  area.value = reason;
  const lifetimeSeg = h('div', { class: 'seg' }, ...LIFETIMES.map((value) => {
    const b = h('button', { 'aria-pressed': String(value === lifetime) }, lifetimeLabel(value));
    b.addEventListener('click', () => { lifetime = value; draw(); });
    return b;
  }));
  pane.append(
    h('dl', { class: 'kv' },
      h('dt', {}, tr('admin.approve.skillName')), h('dd', {}, i.name),
      h('dt', {}, tr('admin.approve.version')), h('dd', {}, i.digest),
      h('dt', {}, tr('admin.approve.scope')), h('dd', {}, covered ? tr('admin.approve.covered', { scopes: scopes.join(', ') }) : tr('admin.approve.notCovered', { scopes: scopes.join(', ') }))),
    h('h2', {}, tr('admin.approve.lifetimeHead')), lifetimeSeg,
    h('h2', {}, tr('admin.approve.reasonHead')), area,
    h('p', { class: 'hint' }, tr('admin.approve.disclaimer')),
    h('div', { class: 'cmd', style: 'margin-top:8px' }, signButton = button(tr('admin.approve.sign'), () => void run(async () => {
      const result = await api.admin.approve(i.instanceId, i.digest, lifetime, reason.trim());
      if (!result.ok) { message = { ok: false, text: result.message }; await fetchStatus(); return; }
      signed = { certificateId: result.certificateId ?? '', certificatePath: result.certificatePath ?? '', expiresAt: result.expiresAt ?? '' };
      reason = '';
      message = { ok: true, text: () => tr('admin.approve.signed') };
      device = 'check';
    }), { primary: true, disabled: !covered || reason.trim() === '', id: 'sign' })));
  // Typing must enable the button without redrawing the pane (a redraw would drop the focus and the caret).
  area.addEventListener('input', () => {
    reason = area.value;
    signButton.disabled = busy || !covered || reason.trim() === '';
  });
}

function checkDetail(pane: HTMLElement): void {
  if (!skillId) { pane.append(h('p', { class: 'hint' }, tr('admin.check.pickSkill'))); return; }
  const name = view.instances.find((i) => i.id === skillId)?.name ?? '';
  pane.append(h('p', { class: 'hint' }, tr('admin.check.hint', { name })),
    h('div', { class: 'cmd' }, button(tr('admin.check.button'), () => void run(async () => { checked = await api.admin.check(skillId!); }), { primary: !checked, id: 'check' })));
  if (checked) pane.append(h('dl', { class: 'kv', style: 'margin-top:12px' },
    h('dt', {}, tr('admin.check.verdict')), h('dd', {}, checked.verdict ?? '—'),
    h('dt', {}, tr('admin.check.reason')), h('dd', {}, checked.reason),
    h('dt', {}, tr('admin.check.trust')), h('dd', {}, checked.trustOk ? tr('admin.check.trustOk') : checked.trustNote ?? tr('admin.check.trustFail'))));
}
