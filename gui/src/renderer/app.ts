// Renderer: draws the rack and views from the service's ServiceView.
// Skill names, paths, file contents and engine reasons are untrusted: they only ever become text nodes.
import type {
  ActionResult, ChangeView, DiffLine, FileChangeView, HistoryEvent, InstanceDetail, InstanceView,
  ObservationState, PkiResultView, Prefs, RendererApi, ServiceView,
} from '../service/types.ts';
import { refreshAdminStatus, renderAdmin, setAdminPolling } from './admin.ts';
import { actionDigest, detailMatches } from './binding.ts';
import { $, h } from './dom.ts';
import { currentLang, locale, noteText, setCurrentLang, tr, type Note } from './lang.ts';
import { LANGS, type Lang, type MessageKey } from '../i18n/messages.ts';

declare global {
  interface Window { magoSki: RendererApi }
}

const api = window.magoSki;

// ------------------------------------------------------------------ vocabulary

const STATE_KEY: Record<ObservationState, MessageKey> = {
  changed: 'state.changed', unchanged: 'state.unchanged', new: 'state.new', reviewed: 'state.reviewed', unreadable: 'state.unreadable', missing: 'state.missing',
};
const HISTORY_KEY: Record<HistoryEvent['kind'], MessageKey> = {
  'first-seen': 'history.first-seen', 'new-skill': 'history.new-skill', changed: 'history.changed', reviewed: 'history.reviewed',
  remembered: 'history.remembered', missing: 'history.missing', returned: 'history.returned', unreadable: 'history.unreadable',
  'history-reset': 'history.history-reset',
};
const NOTIFY_KEY: Record<Prefs['notify'], MessageKey> = { off: 'notify.off', grouped: 'notify.grouped', immediate: 'notify.immediate' };

/** Invisible and bidirectional control characters are shown as code points, never applied to the text. */
function visible(text: string): string {
  return text.replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/gu, (c) => `⟨U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}⟩`);
}
const NOTIFY_STEPS: Array<[Prefs['notify'], number]> = [['off', -120], ['grouped', 0], ['immediate', 120]];
const RETENTION_STEPS: Array<[number, number]> = [[7, -100], [30, -20], [90, 60], [365, 130]];

function short(digest: string | null): string {
  if (!digest) return '—';
  const hex = digest.replace(/^sha256:/u, '');
  return `sha256:${hex.slice(0, 4)}…${hex.slice(-4)}`;
}

function time(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  const sameDay = d.toDateString() === new Date().toDateString();
  return sameDay ? d.toLocaleTimeString(locale()) : d.toLocaleString(locale());
}

function statusLine(i: InstanceView): string {
  switch (i.state) {
    case 'changed':    return tr('status.changed', { n: i.changedFiles });
    case 'reviewed':   return tr('status.reviewed');
    case 'new':        return tr('status.new');
    case 'unchanged':  return tr('status.unchanged');
    case 'missing':    return tr('status.missing');
    case 'unreadable': return tr('status.unreadable');
  }
}

function pkiBadge(pki: PkiResultView | null, view: ServiceView, current = true): HTMLElement {
  if (pki && !current) return h('span', { class: 'pki', title: pki.reason }, tr('pki.previous', { verdict: pki.verdict }));
  if (!pki) return h('span', { class: 'pki' }, view.host.policy.kind === 'none' ? tr('pki.notSet') : 'PKI —');
  if (pki.verdict === 'VERIFIED') return h('span', { class: 'pki verified', title: tr('pki.verifiedTitle') }, 'ORG VERIFIED');
  return h('span', { class: 'pki problem', title: pki.reason }, pki.verdict);
}

// ------------------------------------------------------------------ state

type Device = 'monitor' | 'gate' | 'eq' | 'limiter' | 'clear';
let view: ServiceView | null = null;
let tab: 'skills' | 'activity' | 'settings' | 'admin' = 'skills';
let device: Device = 'monitor';
let selectedId: string | null = null;
let detail: InstanceDetail | null = null;
let detailKey = '';
let selectedFile = 0;
let rememberOnReview = true;
let actionResult: Note | null = null;
let detailError: string | null = null;
let busy = false;

function selected(): InstanceView | undefined {
  return view?.instances.find((i) => i.id === selectedId);
}

// ------------------------------------------------------------------ header and banners

function renderHeader(v: ServiceView): void {
  const s = v.service;
  const [color, text] =
    s.status === 'error'    ? ['var(--problem)', tr('header.error', { error: s.lastError ?? '' })] :
    s.status === 'checking' ? ['var(--accent)', tr('header.checking')] :
    s.status === 'starting' ? ['var(--recorded)', tr('header.starting')] :
                              ['var(--new)', tr('header.observing', { host: v.host.name, time: time(s.lastCheckAt) })];
  $('status').replaceChildren(h('span', { class: 'dot', style: `background:${color}` }), h('span', {}, text));
  $('count').textContent = String(v.instances.filter((i) => i.state !== 'missing').length);

  const pending = v.instances.filter((i) => i.state === 'changed').length;
  const unreadable = v.instances.filter((i) => i.state === 'unreadable').length;
  $('headline').textContent =
    v.instances.length === 0 ? tr('headline.none') :
    pending === 1 ? tr('headline.one') :
    pending > 1 ? tr('headline.many', { n: pending }) :
    unreadable > 0 ? tr('headline.unreadable', { n: unreadable }) :
    tr('headline.clear');

  const banners: HTMLElement[] = [];
  if (s.historyReset) {
    const dismiss = h('button', { class: 'btn', style: 'margin-left:12px' }, tr('banner.dismiss'));
    dismiss.addEventListener('click', () => void api.dismissHistoryReset().then(apply));
    banners.push(h('div', { class: 'banner error' },
      tr('banner.historyReset', { reason: s.historyReset.reason, at: time(s.historyReset.at) })
        + (s.historyReset.backup ? ` ${tr('banner.historyBackup', { backup: s.historyReset.backup })}` : ''), dismiss));
  }
  if (!s.platformSupported) banners.push(h('div', { class: 'banner error' }, tr('banner.platform', { platform: s.platform })));
  if (v.host.policy.kind === 'error') banners.push(h('div', { class: 'banner error' }, tr('banner.policyError', { path: v.host.policy.path, reason: v.host.policy.reason })));
  if (v.host.policy.kind === 'loaded' && !v.host.policy.trustOk) banners.push(h('div', { class: 'banner error' }, tr('banner.trustError', { note: v.host.policy.trustNote ?? '' })));
  for (const root of v.roots) {
    if (root.error) banners.push(h('div', { class: 'banner' }, tr('banner.rootError', { label: root.label, path: root.path, error: root.error })));
    if (root.tooDeep.length) banners.push(h('div', { class: 'banner' }, tr('banner.tooDeep', { label: root.label, n: root.tooDeep.length })));
  }
  $('banners').replaceChildren(...banners);
}

// ------------------------------------------------------------------ rack

function knob(label: string, angle: number, onTurn: (dir: 1 | -1) => void, disabled = false): HTMLButtonElement {
  const k = h('button', { class: 'knob', 'aria-label': label, style: `--angle:${angle}deg`, disabled }) as HTMLButtonElement;
  k.addEventListener('click', (e) => { e.stopPropagation(); onTurn(1); });
  k.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowUp') { e.preventDefault(); e.stopPropagation(); onTurn(1); }
    if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') { e.preventDefault(); e.stopPropagation(); onTurn(-1); }
  });
  return k;
}

function setPrefs(prefs: Partial<Prefs>): void {
  void api.setPrefs(prefs).then(apply);
}

function devHead(name: string, tag: string, live: boolean): HTMLElement {
  return h('div', { class: 'dev-head' },
    h('span', { class: 'power', role: 'img', 'aria-pressed': String(live), 'aria-label': live ? tr('device.on') : tr('device.off') }),
    h('span', { class: 'dev-name' }, name), h('span', { class: 'spacer' }),
    h('span', { class: `dev-tag ${live ? 'live' : 'concept'}` }, tag));
}

function deviceShell(key: Device, width: number, concept: boolean, ...children: HTMLElement[]): HTMLElement {
  const el = h('div', {
    class: `device${concept ? ' concept' : ''}`, tabindex: 0, role: 'button', 'aria-selected': String(device === key),
    'data-device': key, style: `width:${width}px`,
  }, ...children);
  el.addEventListener('click', () => selectDevice(key));
  el.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectDevice(key); } });
  return el;
}

function monitorDevice(v: ServiceView): HTMLElement {
  const notifyIndex = NOTIFY_STEPS.findIndex(([m]) => m === v.prefs.notify);
  const [notifyMode, notifyAngle] = NOTIFY_STEPS[notifyIndex]!;
  const notifyName = tr(NOTIFY_KEY[notifyMode]);
  const turnNotify = (dir: 1 | -1) => setPrefs({ notify: NOTIFY_STEPS[(notifyIndex + dir + 3) % 3]![0] });

  const retIndex = Math.max(0, RETENTION_STEPS.findIndex(([d]) => d === v.prefs.retentionDays));
  const retAngle = RETENTION_STEPS[retIndex]?.[1] ?? 0;
  const turnRetention = (dir: 1 | -1) => setPrefs({ retentionDays: RETENTION_STEPS[(retIndex + dir + RETENTION_STEPS.length) % RETENTION_STEPS.length]![0] });

  const leds = h('div', { class: 'leds', 'aria-label': tr('monitor.ledsAria', { n: v.checks.length }) });
  const slots = Array.from({ length: 12 - v.checks.length }, () => h('div', { class: 'led empty' }));
  const cls = { same: 'ok', new: 'new', changed: 'chg', error: 'err' } as const;
  leds.append(...slots, ...v.checks.map((c) => h('div', { class: `led ${cls[c.outcome]}`, title: tr('monitor.ledTitle', { time: time(c.at), n: c.skills }) })));

  const pending = v.instances.filter((i) => i.state === 'changed').length;
  const retain = h('button', { class: 'toggle', 'aria-pressed': String(v.prefs.retainContent) }, h('span', { class: 'sw' }), tr('monitor.retain'));
  retain.addEventListener('click', (e) => { e.stopPropagation(); setPrefs({ retainContent: !v.prefs.retainContent }); });

  return deviceShell('monitor', 560, false,
    devHead('SKI / CHANGE MONITOR', tr('monitor.tag'), true),
    h('div', { class: 'dev-body' },
      h('div', { class: 'section', style: 'width:130px' },
        h('div', { class: 'sec-label' }, 'NOTIFY'),
        knob(tr('monitor.notifyAria', { mode: notifyName }), notifyAngle, turnNotify),
        h('div', { class: 'sec-value' }, v.prefs.notify === 'off' ? tr('monitor.notifyOff') : tr('monitor.notifyOn', { mode: notifyName })),
        h('div', { class: 'detents' }, ...NOTIFY_STEPS.map(([m]) => h(m === v.prefs.notify ? 'b' : 'span', {}, tr(NOTIFY_KEY[m]))))),
      h('div', { class: 'section', style: 'flex:1' },
        h('div', { class: 'sec-label' }, 'INSPECTION ACTIVITY'),
        leds,
        h('div', { class: 'meter-legend' },
          h('span', {}, h('i', { class: 'same' }), tr('monitor.legendSame')), h('span', {}, h('i', { class: 'new' }), tr('monitor.legendNew')),
          h('span', {}, h('i', { class: 'chg' }), tr('monitor.legendChanged')), h('span', {}, h('i', { class: 'err' }), tr('monitor.legendFailed'))),
        h('div', { class: 'sec-sub' }, tr('monitor.ledNote', { n: v.checks.length }))),
      h('div', { class: 'section', style: 'width:150px' },
        h('div', { class: 'sec-label' }, 'VERSION MEMORY'),
        knob(tr('monitor.retentionAria', { n: v.prefs.retentionDays }), retAngle, turnRetention),
        h('div', { class: 'sec-value' }, tr('monitor.retentionValue', { n: v.prefs.retentionDays })),
        retain)),
    h('div', { class: 'dev-foot' },
      h('span', { class: 'dot', style: `background:${pending ? 'var(--changed)' : 'var(--recorded)'}` }),
      h('span', {}, pending ? tr('monitor.pending', { n: pending }) : tr('monitor.allClear'))));
}

function gateDevice(v: ServiceView): HTMLElement {
  const policy = v.host.policy;
  const results = v.instances.map((i) => i.pki).filter((p): p is PkiResultView => p !== null);
  const verified = results.filter((p) => p.verdict === 'VERIFIED').length;
  const [big, cls, small] =
    policy.kind === 'none'  ? ['NOT CONFIGURED', '', tr('gate.notConfigured')] :
    policy.kind === 'error' ? ['POLICY ERROR', 'problem', tr('gate.policyError')] :
    !policy.trustOk         ? ['TRUST ERROR', 'problem', tr('gate.trustError')] :
    results.length === 0    ? ['NO SKILLS', '', tr('gate.noSkills')] :
    [`VERIFIED ${verified}/${results.length}`, verified === results.length ? 'verified' : 'warn', tr('gate.approvedExact')];
  const mode = policy.kind === 'loaded' ? policy.mode : null;
  const chip = mode === 'enforce' ? tr('gate.chipEnforce') : mode === 'shadow' ? tr('gate.chipShadow') : tr('gate.chipObserve');
  return deviceShell('gate', 300, false,
    devHead('SKI / APPROVAL GATE', tr('gate.tag'), true),
    h('div', { class: 'dev-body' },
      h('div', { class: 'section', style: 'flex:1' },
        h('div', { class: 'sec-label' }, 'ORG APPROVAL (PKI)'),
        h('div', { class: 'screen' }, h('div', { class: `big ${cls}` }, big), h('div', { class: 'small' }, small)),
        h('div', { class: 'sec-label', style: 'margin-top:4px' }, tr('gate.hostMode')),
        h('div', { class: 'detents' }, h(mode === 'enforce' ? 'span' : 'b', {}, tr('gate.modeObserve')), h('span', {}, '·'), h(mode === 'enforce' ? 'b' : 'span', {}, tr('gate.modeRequire'))),
        h('span', { class: 'mode-chip' }, chip))),
    h('div', { class: 'dev-foot' }, tr('gate.foot')));
}

function conceptDevices(): HTMLElement[] {
  const foot = () => h('div', { class: 'dev-foot' }, tr('concept.foot'));
  const band = (label: string, on: number) => h('div', { class: 'band' },
    h('div', { class: 'steps' }, ...[0, 1, 2].map((i) => h('div', { class: `step${i >= on ? ' on' : ''}` }))), h('div', { class: 'bl' }, label));
  const dead = (label: string, angle: number, small = false) => h('div', { class: `knob${small ? ' small' : ''}`, role: 'img', 'aria-label': tr('concept.deadAria', { label }), style: `--angle:${angle}deg` });
  return [
    deviceShell('eq', 270, true, devHead('CAPABILITY EQ', tr('concept.tag'), false),
      h('div', { class: 'dev-body' }, h('div', { class: 'section', style: 'flex:1' },
        h('div', { class: 'sec-label' }, tr('concept.levels')),
        h('div', { class: 'bands' }, band(tr('concept.read'), 1), band(tr('concept.write'), 2), band(tr('concept.network'), 2), band(tr('concept.shell'), 2)),
        h('div', { class: 'sec-sub' }, tr('concept.levelsNote')))), foot()),
    h('div', { class: 'link' }),
    deviceShell('limiter', 250, true, devHead('DYNAMICS LIMITER', tr('concept.tag'), false),
      h('div', { class: 'dev-body' }, h('div', { class: 'section', style: 'flex:1' },
        h('div', { class: 'sec-label' }, 'CALL BUDGET'), dead(tr('concept.callBudget'), 30), h('div', { class: 'sec-value' }, tr('concept.callsPerSession')),
        h('div', { class: 'sec-label' }, 'REDUCTION'), h('div', { class: 'gr' }), h('div', { class: 'sec-sub' }, tr('concept.noInput')))), foot()),
    h('div', { class: 'link' }),
    deviceShell('clear', 270, true, devHead('CLEAR FILTER', tr('concept.tag'), false),
      h('div', { class: 'dev-body' },
        h('div', { class: 'section', style: 'width:50%' }, h('div', { class: 'sec-label' }, 'INTENT'), dead(tr('concept.intent'), 0, true), h('div', { class: 'sec-sub' }, tr('concept.intent'))),
        h('div', { class: 'section', style: 'width:50%' }, h('div', { class: 'sec-label' }, 'RETURN'), dead(tr('concept.responseFilter'), -60, true), h('div', { class: 'sec-sub' }, tr('concept.returnFields')))), foot()),
  ];
}

function renderChain(v: ServiceView): void {
  const present = v.instances.filter((i) => i.state !== 'missing');
  const host = v.host;
  const extension = host.extensionListed === true ? tr('chain.extInstalled') : host.extensionListed === false ? tr('chain.extMissing') : tr('chain.extUnknown');
  const chain = $('chain');
  const scroll = chain.scrollLeft;
  chain.replaceChildren(
    h('div', { class: 'io' }, h('div', { class: 'k' }, 'SKILLS IN'), h('div', { class: 'v' }, String(present.length)),
      h('div', { class: 's' }, ...v.roots.filter((r) => r.exists).flatMap((r, i) => [i ? h('br') : null, r.label]))),
    h('div', { class: 'link live' }),
    monitorDevice(v),
    h('div', { class: 'link live' }),
    gateDevice(v),
    h('div', { class: 'link' }),
    ...conceptDevices(),
    h('div', { class: 'link' }),
    h('div', { class: 'io' }, h('div', { class: 'k' }, 'AGENT'), h('div', { class: 'v', style: 'font-size:16px' }, host.name),
      h('div', { class: 's' }, host.present ? extension : tr('chain.noPiFolder'), h('br'), tr('chain.policyNext'))),
  );
  chain.scrollLeft = scroll;
}

// ------------------------------------------------------------------ monitor detail

function diffTable(file: FileChangeView, change: ChangeView): HTMLElement {
  const head = h('div', { class: 'diff-head' },
    h('span', {}, `${file.path}${file.sections.length ? ` · ${file.sections.slice(0, 3).join(', ')}` : ''}`),
    h('span', {}, tr('diff.compare', { baseline: short(change.baselineDigest), current: short(change.currentDigest) })));
  const box = h('div', { class: 'diff' }, head);
  if (!file.lines) {
    box.append(h('div', { class: 'dl gap' }, h('span', { class: 'n' }), h('span', { class: 't' }, file.note ?? tr('diff.unavailable'))));
    return box;
  }
  const kind = (l: DiffLine) => (l.kind === 'same' ? '' : ` ${l.kind}`);
  const num = (l: DiffLine) => (l.kind === 'add' ? `${l.new} +` : l.kind === 'del' ? `${l.old} −` : l.kind === 'gap' ? '⋯' : String(l.new));
  for (const line of file.lines) box.append(h('div', { class: `dl${kind(line)}` }, h('span', { class: 'n' }, num(line)), h('span', { class: 't' }, visible(line.text))));
  if (file.note) box.append(h('div', { class: 'dl gap' }, h('span', { class: 'n' }), h('span', { class: 't' }, file.note)));
  return box;
}

/** Records `digest`, the version whose change is on screen (from actionDigest), never the latest view's digest. */
async function runAction(kind: 'reviewed' | 'remember', instance: InstanceView, digest: string): Promise<void> {
  if (busy) return;
  busy = true;
  let result: ActionResult;
  try {
    result = kind === 'remember'
      ? await api.rememberVersion(instance.id, digest)
      : await api.markReviewed(instance.id, digest);
  } finally {
    busy = false;
  }
  actionResult = result.ok
    ? { ok: true, text: () => (kind === 'remember' ? tr('action.remembered', { digest: short(digest) }) : tr('action.confirmed')) }
    : { ok: false, text: result.message };
  detailKey = '';
  apply(await api.getView());
}

function renderPane(pane: HTMLElement, v: ServiceView, i: InstanceView): void {
  // A detail for other versions than the view reports is never shown: it would describe bytes that are gone.
  const d = detailMatches(i, detail) ? detail : null;
  const target = actionDigest(i, detail);
  pane.replaceChildren(
    h('h2', {}, i.name, h('span', { class: `state ${i.state}` }, tr(STATE_KEY[i.state])), pkiBadge(i.pki, v, i.pkiCurrent)),
    h('div', { class: 'path' }, `${i.path} · ${i.rootLabel}`));
  if (!i.pkiCurrent) pane.append(h('div', { class: 'result err' }, tr('pane.pkiStale')));

  const summary: Record<ObservationState, string> = {
    new: tr('summary.new'),
    unchanged: tr('summary.unchanged'),
    changed: tr('summary.changed', { time: time(i.baselineAt) }),
    reviewed: tr('summary.reviewed'),
    missing: tr('summary.missing'),
    unreadable: tr('summary.unreadable'),
  };
  pane.append(h('p', { class: 'summary' }, summary[i.state]));
  if (i.error) pane.append(h('div', { class: 'result err' }, i.error));

  const change = d?.change;
  if (change) {
    const execChanges = change.files.filter((f) => f.execBefore !== f.execAfter && f.execAfter === true).length;
    pane.append(h('div', { class: 'facts' },
      h('span', { class: 'fact' }, tr('fact.files', { n: change.files.length })),
      change.addedOrigins.length ? h('span', { class: 'fact evidence' }, tr('fact.addedOrigins', { n: change.addedOrigins.length, list: change.addedOrigins.slice(0, 3).join(', ') })) : null,
      change.removedOrigins.length ? h('span', { class: 'fact' }, tr('fact.removedOrigins', { n: change.removedOrigins.length })) : null,
      execChanges ? h('span', { class: 'fact evidence' }, tr('fact.exec', { n: execChanges })) : null,
      h('span', { class: 'fact' }, tr('fact.versions', { baseline: short(change.baselineDigest), current: short(change.currentDigest) }))));
    if (!change.contentRetained) {
      const why = change.contentNote?.includes('missing or damaged') ? tr('pane.whyMissing')
        : change.contentNote?.includes('does not match') ? tr('pane.whyMismatch')
        : tr('pane.whyNone');
      pane.append(h('div', { class: 'result err' }, tr('pane.metaOnly', { why })));
    }

    if (selectedFile >= change.files.length) selectedFile = 0;
    const tabs = h('div', { class: 'files' });
    change.files.forEach((f, index) => {
      const badge = f.change === 'added' ? 'new' : f.change === 'deleted' ? 'deleted' : f.change === 'mode-changed' ? 'exec' : (() => {
        const adds = f.lines?.filter((l) => l.kind === 'add').length ?? 0;
        const dels = f.lines?.filter((l) => l.kind === 'del').length ?? 0;
        return f.lines ? `+${adds} −${dels}` : 'changed';
      })();
      const b = h('button', { class: 'file', 'aria-selected': String(index === selectedFile) }, `${f.path} `, h('em', {}, badge + (f.execAfter && !f.execBefore ? ' · exec' : '')));
      b.addEventListener('click', () => { selectedFile = index; renderDetail(); });
      tabs.append(b);
    });
    tabs.append(h('span', { class: 'spacer' }), h('span', { class: 'sec-sub' }, tr('pane.textCompare')));
    pane.append(tabs);
    const file = change.files[selectedFile];
    if (file) pane.append(diffTable(file, change));
    pane.append(h('div', { class: 'sec-sub', style: 'text-align:left;margin-top:8px;color:var(--ink-3)' },
      tr('pane.partialEvidence')
        + (change.analysisComplete ? '' : ` ${tr('pane.analysisIncomplete')}`) + (change.truncated ? ` ${tr('pane.truncated')}` : '')));
  } else if (!d && (i.state === 'changed' || i.state === 'reviewed')) {
    pane.append(h('p', { class: 'sec-sub', style: 'text-align:left' }, detailError !== null ? tr('detail.loadFailed', { error: detailError }) : tr('pane.loading')));
    if (detailError) {
      const retry = h('button', { class: 'btn' }, tr('pane.retry'));
      retry.addEventListener('click', () => { detailKey = ''; detailError = null; void loadDetail(); });
      pane.append(retry);
    }
  }

  pane.append(h('div', { class: 'digest-bind' }, target
    ? tr('pane.targetSet', { digest: target })
    : tr('pane.targetWaiting')));

  const waiting = tr('pane.waitTitle');
  if (i.state === 'changed') {
    const cb = h('input', { type: 'checkbox', id: 'remember' }) as HTMLInputElement;
    cb.checked = rememberOnReview;
    cb.addEventListener('change', () => { rememberOnReview = cb.checked; });
    const btn = h('button', { class: 'btn primary', disabled: !target, title: target ? null : waiting }, tr('pane.doneButton'));
    btn.addEventListener('click', () => { if (target) void runAction(rememberOnReview ? 'remember' : 'reviewed', i, target); });
    pane.append(h('label', { class: 'check', for: 'remember' }, cb, tr('pane.rememberCheck')),
      h('div', { class: 'actions' }, h('span', { class: 'note' }, actionNote(v)), btn));
  } else if (i.state === 'reviewed') {
    const btn = h('button', { class: 'btn', disabled: !target, title: target ? null : waiting }, tr('pane.rememberButton'));
    btn.addEventListener('click', () => { if (target) void runAction('remember', i, target); });
    pane.append(h('div', { class: 'actions' }, h('span', { class: 'note' }, actionNote(v)), btn));
  } else if (i.state === 'new') {
    const btn = h('button', { class: 'btn', disabled: !target, title: target ? null : waiting }, tr('pane.confirmNew'));
    btn.addEventListener('click', () => { if (target) void runAction('reviewed', i, target); });
    pane.append(h('div', { class: 'actions' }, h('span', { class: 'note' }, actionNote(v)), btn));
  }
  if (actionResult) pane.append(h('div', { class: `result ${actionResult.ok ? 'ok' : 'err'}` }, noteText(actionResult)));

  if (d?.approveCommand) {
    const copy = h('button', { class: 'btn' }, tr('approve.copy'));
    copy.addEventListener('click', () => { void api.copyText(d.approveCommand!); copy.textContent = tr('approve.copied'); });
    pane.append(h('div', { class: 'approve' },
      h('h3', {}, tr('approve.title')),
      h('p', {}, tr('approve.body')),
      d.approveScope === 'full-diff' ? null : h('div', { class: 'result err' }, d.approveScope === 'no-diff'
        ? tr('approve.noDiff')
        : tr('approve.partialDiff')),
      h('p', {}, tr('approve.baseNote')),
      h('div', { class: 'cmd' }, h('code', {}, d.approveCommand), copy)));
  }

  const meaning = h('details', { class: 'meaning' }, h('summary', {}, tr('meaning.summary')),
    h('p', {}, v.host.policy.kind === 'none'
      ? tr('meaning.noPki')
      : tr('meaning.pki')));
  pane.append(meaning);

  if (d?.previousVersions.length) {
    pane.append(h('h3', { style: 'font-size:13px;margin:18px 0 6px' }, tr('pane.previous', { n: v.prefs.retentionDays })),
      h('table', { class: 'tbl' }, ...d.previousVersions.map((p) => h('tr', {},
        h('td', { class: 'mono' }, short(p.digest)), h('td', {}, tr('pane.recorded', { time: time(p.recordedAt) })),
        h('td', {}, tr('pane.superseded', { time: time(p.supersededAt) })), h('td', {}, p.retained ? tr('pane.retained') : tr('pane.metaOnlyShort'))))));
  }
  if (d?.history.length) {
    pane.append(h('h3', { style: 'font-size:13px;margin:18px 0 6px' }, tr('pane.history')),
      h('table', { class: 'tbl' }, ...d.history.slice(0, 8).map((e) => h('tr', {},
        h('td', {}, time(e.at)), h('td', {}, tr(HISTORY_KEY[e.kind])), h('td', { class: 'mono' }, short(e.digest))))));
  }
}

function actionNote(v: ServiceView): string {
  const p = v.host.policy;
  if (p.kind === 'loaded' && p.mode === 'enforce') return tr('pane.noteEnforce');
  return tr('pane.noteObserve');
}

function renderMonitorDetail(v: ServiceView): void {
  const detailEl = $('detail');
  detailEl.style.gridTemplateColumns = '';
  if (v.instances.length === 0) {
    detailEl.style.gridTemplateColumns = '1fr';
    detailEl.replaceChildren(h('div', { class: 'empty-state' },
      tr('empty.none'), h('br'),
      tr('empty.where'), ...v.roots.flatMap((r, idx) => [idx ? ', ' : '', h('code', {}, r.path)])));
    return;
  }
  if (!selected()) selectedId = v.instances[0]!.id;
  const list = h('div', { class: 'list' },
    h('div', { class: 'list-head' }, h('span', {}, tr('list.found')), h('span', {}, tr('list.unconfirmed', { n: v.instances.filter((i) => i.state === 'changed').length }))));
  for (const i of v.instances) {
    const row = h('button', { class: 'row', 'aria-selected': String(i.id === selectedId) },
      h('div', { class: 'ic' }, i.name.slice(0, 3).toUpperCase()),
      h('div', {}, h('div', { class: 'nm' }, i.name), h('div', { class: 'st' }, statusLine(i))),
      h('div', { class: 'spacer' }),
      h('span', { class: `state ${i.state}` }, tr(STATE_KEY[i.state])));
    row.addEventListener('click', () => { selectedId = i.id; selectedFile = 0; actionResult = null; renderDetail(); });
    list.append(row);
  }
  list.append(h('div', { class: 'roots' }, tr('list.paths'), ...v.roots.flatMap((r) => [h('br'), h('code', {}, r.path)])));
  const pane = h('div', { class: 'pane' });
  renderPane(pane, v, selected()!);
  detailEl.replaceChildren(list, pane);
  void loadDetail();
}

async function loadDetail(): Promise<void> {
  const i = selected();
  if (!i) return;
  const key = `${i.id}:${i.currentDigest}:${i.baselineDigest}:${i.state}`;
  if (key === detailKey) return;
  detailKey = key;
  detailError = null;
  let loaded: InstanceDetail | null;
  try {
    loaded = await api.getDetail(i.id);
  } catch (error) {
    // The key stays set: the same versions are not retried on their own, only by the user or after a new change.
    if (detailKey !== key) return;
    detailError = error instanceof Error ? error.message : String(error);
    if (device === 'monitor' && tab === 'skills' && view) renderMonitorDetail(view);
    return;
  }
  if (detailKey !== key) return;
  detail = loaded;
  if (device === 'monitor' && tab === 'skills' && view) renderMonitorDetail(view);
}

// ------------------------------------------------------------------ other device details

function renderGateDetail(v: ServiceView): void {
  const p = v.host.policy;
  const rows = v.instances.filter((i) => i.state !== 'missing').map((i) => h('tr', {},
    h('td', {}, i.name), h('td', {}, pkiBadge(i.pki, v, i.pkiCurrent)), h('td', {}, i.pki?.reason ?? '—'),
    h('td', { class: 'mono' }, short(i.pki?.approverKeyId ?? null))));
  const decisions = v.host.recentDecisions.slice().reverse().map((d) => h('tr', {},
    h('td', {}, time(d.timestamp)), h('td', {}, d.skill), h('td', {}, d.action), h('td', {}, d.verdict), h('td', {}, d.event)));
  const box = h('div', { class: 'concept-pane', style: 'max-width:none' },
    h('h2', {}, 'SKI / APPROVAL GATE'),
    h('p', {}, tr('gateDetail.lead')),
    h('dl', { class: 'kv' },
      h('dt', {}, tr('gateDetail.policyFile')), h('dd', {}, p.path ?? '—'),
      h('dt', {}, tr('gateDetail.status')), h('dd', {}, p.kind === 'none' ? tr('gateDetail.none') : p.kind === 'error' ? tr('gateDetail.error', { reason: p.reason }) : tr('gateDetail.loaded', { mode: p.mode, trust: p.trustOk ? tr('gateDetail.trustOk') : tr('gateDetail.trustFail', { note: p.trustNote ?? '' }) })),
      h('dt', {}, tr('gateDetail.when')), h('dd', {}, tr('gateDetail.whenText'))),
    h('h2', { style: 'font-size:15px;margin-top:20px' }, tr('gateDetail.perSkill')),
    p.kind === 'none' ? h('p', { class: 'hint' }, tr('gateDetail.noPolicy'))
      : h('table', { class: 'tbl' }, h('tr', {}, h('th', {}, 'Skill'), h('th', {}, tr('gateDetail.verdict')), h('th', {}, tr('gateDetail.reasonEngine')), h('th', {}, tr('gateDetail.approverKey'))), ...rows),
    decisions.length ? h('h2', { style: 'font-size:15px;margin-top:20px' }, tr('gateDetail.recent')) : null,
    decisions.length ? h('table', { class: 'tbl' }, h('tr', {}, h('th', {}, tr('gateDetail.time')), h('th', {}, 'Skill'), h('th', {}, tr('gateDetail.action')), h('th', {}, tr('gateDetail.verdict')), h('th', {}, tr('gateDetail.event'))), ...decisions) : null);
  $('detail').style.gridTemplateColumns = '1fr';
  $('detail').replaceChildren(box);
}

type ConceptKey = 'eq' | 'limiter' | 'clear';
const CONCEPTS: Record<ConceptKey, { title: MessageKey; lead: MessageKey; observe: MessageKey; act: MessageKey }> = {
  eq: { title: 'concept.eq.title', lead: 'concept.eq.lead', observe: 'concept.eq.observe', act: 'concept.eq.act' },
  limiter: { title: 'concept.limiter.title', lead: 'concept.limiter.lead', observe: 'concept.limiter.observe', act: 'concept.limiter.act' },
  clear: { title: 'concept.clear.title', lead: 'concept.clear.lead', observe: 'concept.clear.observe', act: 'concept.clear.act' },
};

function renderConceptDetail(key: ConceptKey): void {
  const c = CONCEPTS[key];
  const rows: Array<[string, string]> = [
    [tr('concept.rowObserve'), tr(c.observe)], [tr('concept.rowAct'), tr(c.act)], [tr('concept.rowStatus'), tr('concept.laterNotConnected')],
  ];
  $('detail').style.gridTemplateColumns = '1fr';
  $('detail').replaceChildren(h('div', { class: 'concept-pane' }, h('h2', {}, tr(c.title)), h('p', {}, tr(c.lead)),
    h('table', {}, ...rows.map(([k, val]) => h('tr', {}, h('td', {}, k), h('td', {}, val))))));
}

function renderDetail(): void {
  if (!view) return;
  if (device === 'monitor') renderMonitorDetail(view);
  else if (device === 'gate') renderGateDetail(view);
  else renderConceptDetail(device);
}

function selectDevice(key: Device): void {
  device = key;
  document.querySelectorAll<HTMLElement>('.device').forEach((d) => d.setAttribute('aria-selected', String(d.dataset.device === key)));
  renderDetail();
}

// ------------------------------------------------------------------ activity and settings tabs

function renderActivity(v: ServiceView): void {
  const page = $('tab-activity');
  page.replaceChildren(h('h2', {}, tr('activity.title')),
    h('p', { class: 'hint' }, tr('activity.hint')),
    v.history.length === 0 ? h('p', {}, tr('activity.empty')) :
      h('table', { class: 'tbl' }, h('tr', {}, h('th', {}, tr('gateDetail.time')), h('th', {}, 'Skill'), h('th', {}, tr('gateDetail.event')), h('th', {}, tr('activity.version')), h('th', {}, tr('activity.content'))),
        ...v.history.map((e) => h('tr', {}, h('td', {}, time(e.at)), h('td', {}, e.name || tr('activity.all')), h('td', {}, tr(HISTORY_KEY[e.kind])),
          h('td', { class: 'mono' }, short(e.digest)), h('td', {}, e.detail ?? '')))));
}

function seg<T extends string | number | boolean>(options: Array<[T, string]>, current: T, onPick: (value: T) => void): HTMLElement {
  return h('div', { class: 'seg' }, ...options.map(([value, label]) => {
    const b = h('button', { 'aria-pressed': String(value === current) }, label);
    b.addEventListener('click', () => onPick(value));
    return b;
  }));
}

function renderSettings(v: ServiceView): void {
  const add = h('button', { class: 'btn' }, tr('settings.add'));
  add.addEventListener('click', () => void api.addRoot().then(apply));
  const rootRows = v.roots.map((r) => {
    const remove = r.origin === 'user' ? h('button', { class: 'btn' }, tr('settings.stop')) : h('span', { class: 'sec-sub' }, tr('settings.default'));
    if (r.origin === 'user') remove.addEventListener('click', () => void api.removeRoot(r.id).then(apply));
    const status = r.error ? tr('settings.error', { error: r.error }) : r.exists ? (r.tooDeep.length ? tr('settings.partial', { n: r.tooDeep.length }) : tr('settings.watching')) : tr('settings.noFolder');
    return h('tr', {}, h('td', {}, r.label), h('td', { class: 'mono' }, r.path), h('td', {}, status), h('td', {}, remove));
  });
  const host = v.host;
  $('tab-settings').replaceChildren(
    h('div', { class: 'section-head' }, h('h2', {}, tr('settings.locations')), h('span', { class: 'spacer' }), add),
    h('p', { class: 'hint' }, tr('settings.locationsHint')),
    h('table', { class: 'tbl' }, h('tr', {}, h('th', {}, tr('settings.name')), h('th', {}, tr('settings.path')), h('th', {}, tr('settings.state')), h('th', {})), ...rootRows),
    h('h2', {}, tr('settings.global')),
    h('dl', { class: 'kv' },
      h('dt', {}, tr('settings.notify')), h('dd', {}, seg<Prefs['notify']>([['off', tr('notify.off')], ['grouped', tr('notify.grouped')], ['immediate', tr('notify.immediate')]], v.prefs.notify, (n) => setPrefs({ notify: n }))),
      h('dt', {}, tr('settings.retainContent')), h('dd', {}, seg<boolean>([[true, tr('settings.retain')], [false, tr('settings.retainNo')]], v.prefs.retainContent, (r) => setPrefs({ retainContent: r }))),
      h('dt', {}, tr('settings.retention')), h('dd', {}, seg<number>(RETENTION_STEPS.map(([d]) => [d, tr('settings.days', { n: d })]), v.prefs.retentionDays, (d) => setPrefs({ retentionDays: d })))),
    h('p', { class: 'hint', style: 'margin-top:10px' }, tr('settings.retainHint')),
    h('h2', {}, tr('settings.hostData')),
    h('dl', { class: 'kv' },
      h('dt', {}, tr('settings.host')), h('dd', {}, tr('settings.hostValue', { name: host.name, dir: host.agentDir || '—', folder: host.present ? tr('settings.folderPresent') : tr('settings.folderAbsent') })),
      h('dt', {}, tr('settings.extension')), h('dd', {}, host.extensionListed === null ? tr('settings.extUnknown') : host.extensionListed ? tr('settings.extRegistered') : tr('settings.extMissing')),
      h('dt', {}, tr('settings.policy')), h('dd', {}, host.policy.path ?? '—'),
      h('dt', {}, tr('settings.dataFolder')), h('dd', {}, v.service.dataDir),
      h('dt', {}, tr('settings.platform')), h('dd', {}, v.service.platformSupported ? v.service.platform : tr('settings.platformUnsupported', { platform: v.service.platform }))));
}

// ------------------------------------------------------------------ wiring

function apply(next: ServiceView): void {
  view = next;
  renderHeader(next);
  if (tab === 'skills') { renderChain(next); renderDetail(); }
  if (tab === 'activity') renderActivity(next);
  if (tab === 'settings') renderSettings(next);
  if (tab === 'admin') renderAdmin($('tab-admin'), next, api);
}

function showTab(next: typeof tab): void {
  tab = next;
  document.querySelectorAll<HTMLElement>('.tab').forEach((t) => t.setAttribute('aria-selected', String(t.dataset.tab === next)));
  for (const name of ['skills', 'activity', 'settings', 'admin'] as const) ($(`tab-${name}`) as HTMLElement).hidden = name !== next;
  // A pin change or a revoked approver must disarm within seconds even if nobody clicks: poll while the tab is visible.
  setAdminPolling(next === 'admin', api);
  if (view) apply(view);
}

/** Fills the texts of index.html that do not change with the data. */
function applyStaticText(): void {
  document.querySelectorAll<HTMLElement>('[data-i18n]').forEach((el) => { el.textContent = tr(el.dataset.i18n as MessageKey); });
  document.querySelectorAll<HTMLElement>('[data-i18n-aria]').forEach((el) => { el.setAttribute('aria-label', tr(el.dataset.i18nAria as MessageKey)); });
  document.querySelectorAll<HTMLElement>('[data-lang]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.lang === currentLang())));
}

/** Changes the language and draws everything again. The renderer's own state (tab, selections, typed text) is kept. */
async function switchLang(next: Lang): Promise<void> {
  if (next === currentLang()) return;
  setCurrentLang(await api.setLang(next));
  applyStaticText();
  if (view) apply(view);
  if (tab === 'admin') refreshAdminStatus();
}

document.querySelectorAll<HTMLElement>('.tab').forEach((t) => t.addEventListener('click', () => showTab(t.dataset.tab as typeof tab)));
document.querySelectorAll<HTMLElement>('[data-lang]').forEach((b) => b.addEventListener('click', () => {
  const next = b.dataset.lang;
  if ((LANGS as readonly string[]).includes(next ?? '')) void switchLang(next as Lang);
}));
$('check-now').addEventListener('click', () => void api.checkNow().then(apply));

async function start(): Promise<void> {
  try {
    setCurrentLang(await api.getLang());
  } catch {
    // keep the default language
  }
  applyStaticText();
  api.onUpdate(apply);
  void api.getView().then(apply);
}
void start();
