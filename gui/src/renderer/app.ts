// Renderer: draws the rack and views from the service's ServiceView.
// Skill names, paths, file contents and engine reasons are untrusted: they only ever become text nodes.
import type {
  ActionResult, ChangeView, DiffLine, FileChangeView, HistoryEvent, InstanceDetail, InstanceView,
  ObservationState, PkiResultView, Prefs, RendererApi, ServiceView,
} from '../service/types.ts';
import { actionDigest, detailMatches } from './binding.ts';

declare global {
  interface Window { magoSki: RendererApi }
}

const api = window.magoSki;

type Child = Node | string | null | undefined | false;
type Props = Record<string, string | number | boolean | null | undefined | ((event: Event) => void)>;

function h<K extends keyof HTMLElementTagNameMap>(tag: K, props: Props = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (typeof value === 'function') el.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === 'class') el.className = String(value);
    else if (key === 'style') el.style.cssText = String(value);
    else el.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    el.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return el;
}

function $(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el;
}

// ------------------------------------------------------------------ vocabulary

const STATE_LABEL: Record<ObservationState, string> = {
  changed: '변경 확인 필요', unchanged: '기록과 같음', new: '새로 발견', reviewed: '확인함', unreadable: '읽기 실패', missing: '찾을 수 없음',
};
const HISTORY_LABEL: Record<HistoryEvent['kind'], string> = {
  'first-seen': '처음 상태 기록', 'new-skill': '새 Skill 발견', changed: '내용 변경', reviewed: '변경 확인',
  remembered: '새 비교 기준 기록', missing: '사라짐', returned: '다시 발견', unreadable: '읽기 실패',
  'history-reset': '이전 기록 초기화',
};

/** Invisible and bidirectional control characters are shown as code points, never applied to the text. */
function visible(text: string): string {
  return text.replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/gu, (c) => `⟨U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}⟩`);
}
const NOTIFY_STEPS: Array<[Prefs['notify'], string, number]> = [['off', '끔', -120], ['grouped', '모아서', 0], ['immediate', '즉시', 120]];
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
  return sameDay ? d.toLocaleTimeString('ko-KR') : d.toLocaleString('ko-KR');
}

function statusLine(i: InstanceView): string {
  switch (i.state) {
    case 'changed':    return `파일 ${i.changedFiles}개 변경 · 미확인`;
    case 'reviewed':   return `확인함 · 비교 기준은 이전 버전`;
    case 'new':        return '새로 발견 · 처음 상태를 기록함';
    case 'unchanged':  return '기록한 상태와 같음';
    case 'missing':    return '설치 위치에서 사라졌어요';
    case 'unreadable': return '검사하지 못했어요';
  }
}

function pkiBadge(pki: PkiResultView | null, view: ServiceView, current = true): HTMLElement {
  if (pki && !current) return h('span', { class: 'pki', title: pki.reason }, `${pki.verdict} · 이전 버전 기준`);
  if (!pki) return h('span', { class: 'pki' }, view.host.policy.kind === 'none' ? 'PKI 미설정' : 'PKI —');
  if (pki.verdict === 'VERIFIED') return h('span', { class: 'pki verified', title: '조직 승인 검증 통과' }, 'ORG VERIFIED');
  return h('span', { class: 'pki problem', title: pki.reason }, pki.verdict);
}

// ------------------------------------------------------------------ state

type Device = 'monitor' | 'gate' | 'eq' | 'limiter' | 'clear';
let view: ServiceView | null = null;
let tab: 'skills' | 'activity' | 'settings' = 'skills';
let device: Device = 'monitor';
let selectedId: string | null = null;
let detail: InstanceDetail | null = null;
let detailKey = '';
let selectedFile = 0;
let rememberOnReview = true;
let actionResult: { ok: boolean; text: string } | null = null;
let detailError: string | null = null;
let busy = false;

function selected(): InstanceView | undefined {
  return view?.instances.find((i) => i.id === selectedId);
}

// ------------------------------------------------------------------ header and banners

function renderHeader(v: ServiceView): void {
  const s = v.service;
  const [color, text] =
    s.status === 'error'    ? ['var(--problem)', `확인 실패 · ${s.lastError ?? ''}`] :
    s.status === 'checking' ? ['var(--accent)', '확인 중…'] :
    s.status === 'starting' ? ['var(--recorded)', '시작하는 중'] :
                              ['var(--new)', `관찰 중 · ${v.host.name} · 마지막 확인 ${time(s.lastCheckAt)}`];
  $('status').replaceChildren(h('span', { class: 'dot', style: `background:${color}` }), h('span', {}, text));
  $('count').textContent = String(v.instances.filter((i) => i.state !== 'missing').length);

  const pending = v.instances.filter((i) => i.state === 'changed').length;
  const unreadable = v.instances.filter((i) => i.state === 'unreadable').length;
  $('headline').textContent =
    v.instances.length === 0 ? '아직 발견한 Skill이 없어요.' :
    pending === 1 ? '확인할 변화가 하나 있어요.' :
    pending > 1 ? `확인할 변화가 ${pending}개 있어요.` :
    unreadable > 0 ? `검사하지 못한 Skill이 ${unreadable}개 있어요.` :
    '확인할 변화가 없어요.';

  const banners: HTMLElement[] = [];
  if (s.historyReset) {
    const dismiss = h('button', { class: 'btn', style: 'margin-left:12px' }, '확인함');
    dismiss.addEventListener('click', () => void api.dismissHistoryReset().then(apply));
    banners.push(h('div', { class: 'banner error' },
      `이전 기록이 사라져서 (${s.historyReset.reason}) ${time(s.historyReset.at)}부터 새로 기록했어요. 그 사이의 변경은 비교할 수 없어서 모든 Skill을 '새로 발견'으로 표시해요.`
        + (s.historyReset.backup ? ` 읽지 못한 파일: ${s.historyReset.backup}` : ''), dismiss));
  }
  if (!s.platformSupported) banners.push(h('div', { class: 'banner error' }, `${s.platform}에서는 실행 비트가 digest에 반영되지 않아 다른 OS에서 만든 승인과 맞지 않을 수 있어요. mago-ski 엔진 0.2는 Linux와 macOS만 지원해요.`));
  if (v.host.policy.kind === 'error') banners.push(h('div', { class: 'banner error' }, `정책 파일을 읽지 못했어요 (${v.host.policy.path}): ${v.host.policy.reason}. Pi는 이 경우 모든 Skill을 차단해요.`));
  if (v.host.policy.kind === 'loaded' && !v.host.policy.trustOk) banners.push(h('div', { class: 'banner error' }, `신뢰 문서를 검증하지 못했어요: ${v.host.policy.trustNote ?? ''}`));
  for (const root of v.roots) {
    if (root.error) banners.push(h('div', { class: 'banner' }, `${root.label} (${root.path})를 확인하지 못했어요: ${root.error}`));
    if (root.tooDeep.length) banners.push(h('div', { class: 'banner' }, `${root.label}: 너무 깊은 폴더 ${root.tooDeep.length}개 아래는 확인하지 않았어요.`));
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
    h('span', { class: 'power', role: 'img', 'aria-pressed': String(live), 'aria-label': live ? '켜짐' : '미연동' }),
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
  const [, notifyName, notifyAngle] = NOTIFY_STEPS[notifyIndex]!;
  const turnNotify = (dir: 1 | -1) => setPrefs({ notify: NOTIFY_STEPS[(notifyIndex + dir + 3) % 3]![0] });

  const retIndex = Math.max(0, RETENTION_STEPS.findIndex(([d]) => d === v.prefs.retentionDays));
  const retAngle = RETENTION_STEPS[retIndex]?.[1] ?? 0;
  const turnRetention = (dir: 1 | -1) => setPrefs({ retentionDays: RETENTION_STEPS[(retIndex + dir + RETENTION_STEPS.length) % RETENTION_STEPS.length]![0] });

  const leds = h('div', { class: 'leds', 'aria-label': `최근 확인 ${v.checks.length}회` });
  const slots = Array.from({ length: 12 - v.checks.length }, () => h('div', { class: 'led empty' }));
  const cls = { same: 'ok', new: 'new', changed: 'chg', error: 'err' } as const;
  leds.append(...slots, ...v.checks.map((c) => h('div', { class: `led ${cls[c.outcome]}`, title: `${time(c.at)} · Skill ${c.skills}개` })));

  const pending = v.instances.filter((i) => i.state === 'changed').length;
  const retain = h('button', { class: 'toggle', 'aria-pressed': String(v.prefs.retainContent) }, h('span', { class: 'sw' }), '비교용 원문 보관');
  retain.addEventListener('click', (e) => { e.stopPropagation(); setPrefs({ retainContent: !v.prefs.retainContent }); });

  return deviceShell('monitor', 560, false,
    devHead('SKI / CHANGE MONITOR', 'PoC · 동작', true),
    h('div', { class: 'dev-body' },
      h('div', { class: 'section', style: 'width:130px' },
        h('div', { class: 'sec-label' }, 'NOTIFY'),
        knob(`알림: ${notifyName}`, notifyAngle, turnNotify),
        h('div', { class: 'sec-value' }, v.prefs.notify === 'off' ? '알림 끔' : `${notifyName} 알림`),
        h('div', { class: 'detents' }, ...NOTIFY_STEPS.map(([m, n]) => h(m === v.prefs.notify ? 'b' : 'span', {}, n)))),
      h('div', { class: 'section', style: 'flex:1' },
        h('div', { class: 'sec-label' }, 'INSPECTION ACTIVITY'),
        leds,
        h('div', { class: 'meter-legend' },
          h('span', {}, h('i', { class: 'same' }), '같음'), h('span', {}, h('i', { class: 'new' }), '새 발견'),
          h('span', {}, h('i', { class: 'chg' }), '변경'), h('span', {}, h('i', { class: 'err' }), '실패')),
        h('div', { class: 'sec-sub' }, `LED 하나 = 전체 확인 1회 · 최근 ${v.checks.length}회`)),
      h('div', { class: 'section', style: 'width:150px' },
        h('div', { class: 'sec-label' }, 'VERSION MEMORY'),
        knob(`이전 버전 보관 ${v.prefs.retentionDays}일`, retAngle, turnRetention),
        h('div', { class: 'sec-value' }, `${v.prefs.retentionDays}일 보관`),
        retain)),
    h('div', { class: 'dev-foot' },
      h('span', { class: 'dot', style: `background:${pending ? 'var(--changed)' : 'var(--recorded)'}` }),
      h('span', {}, pending ? `변경 ${pending}건 · 확인 대기` : '모든 Skill이 기록과 같거나 확인됨')));
}

function gateDevice(v: ServiceView): HTMLElement {
  const policy = v.host.policy;
  const results = v.instances.map((i) => i.pki).filter((p): p is PkiResultView => p !== null);
  const verified = results.filter((p) => p.verdict === 'VERIFIED').length;
  const [big, cls, small] =
    policy.kind === 'none'  ? ['NOT CONFIGURED', '', '조직 승인 검증 미설정'] :
    policy.kind === 'error' ? ['POLICY ERROR', 'problem', '정책 파일을 읽지 못함'] :
    !policy.trustOk         ? ['TRUST ERROR', 'problem', '신뢰 문서 검증 실패'] :
    results.length === 0    ? ['NO SKILLS', '', '검증할 Skill이 없어요'] :
    [`VERIFIED ${verified}/${results.length}`, verified === results.length ? 'verified' : 'warn', '조직이 승인한 정확한 버전'];
  const mode = policy.kind === 'loaded' ? policy.mode : null;
  const chip = mode === 'enforce' ? 'Enforce · 미승인 Skill 차단 (Pi)' : mode === 'shadow' ? 'Shadow · 막지 않고 기록' : '관찰 모드 · 실행을 막지 않음';
  return deviceShell('gate', 300, false,
    devHead('SKI / APPROVAL GATE', '엔진 0.2', true),
    h('div', { class: 'dev-body' },
      h('div', { class: 'section', style: 'flex:1' },
        h('div', { class: 'sec-label' }, 'ORG APPROVAL (PKI)'),
        h('div', { class: 'screen' }, h('div', { class: `big ${cls}` }, big), h('div', { class: 'small' }, small)),
        h('div', { class: 'sec-label', style: 'margin-top:4px' }, 'HOST MODE · 정책 파일이 결정'),
        h('div', { class: 'detents' }, h(mode === 'enforce' ? 'span' : 'b', {}, '관찰'), h('span', {}, '·'), h(mode === 'enforce' ? 'b' : 'span', {}, '승인 필수')),
        h('span', { class: 'mode-chip' }, chip))),
    h('div', { class: 'dev-foot' }, '기록과 확인은 PKI 승인을 발급하지 않아요.'));
}

function conceptDevices(): HTMLElement[] {
  const foot = () => h('div', { class: 'dev-foot' }, '후속 단계 · 아직 동작하지 않음');
  const band = (label: string, on: number) => h('div', { class: 'band' },
    h('div', { class: 'steps' }, ...[0, 1, 2].map((i) => h('div', { class: `step${i >= on ? ' on' : ''}` }))), h('div', { class: 'bl' }, label));
  const dead = (label: string, angle: number, small = false) => h('div', { class: `knob${small ? ' small' : ''}`, role: 'img', 'aria-label': `${label} 미연동`, style: `--angle:${angle}deg` });
  return [
    deviceShell('eq', 270, true, devHead('CAPABILITY EQ', '구상', false),
      h('div', { class: 'dev-body' }, h('div', { class: 'section', style: 'flex:1' },
        h('div', { class: 'sec-label' }, '권한 단계'),
        h('div', { class: 'bands' }, band('읽기', 1), band('쓰기', 2), band('네트워크', 2), band('셸', 2)),
        h('div', { class: 'sec-sub' }, '허용 · 확인 · 차단 단계 (퍼센트 값 없음)'))), foot()),
    h('div', { class: 'link' }),
    deviceShell('limiter', 250, true, devHead('DYNAMICS LIMITER', '구상', false),
      h('div', { class: 'dev-body' }, h('div', { class: 'section', style: 'flex:1' },
        h('div', { class: 'sec-label' }, 'CALL BUDGET'), dead('호출 예산', 30), h('div', { class: 'sec-value' }, '— 회 / 세션'),
        h('div', { class: 'sec-label' }, 'REDUCTION'), h('div', { class: 'gr' }), h('div', { class: 'sec-sub' }, '입력 없음'))), foot()),
    h('div', { class: 'link' }),
    deviceShell('clear', 270, true, devHead('CLEAR FILTER', '구상', false),
      h('div', { class: 'dev-body' },
        h('div', { class: 'section', style: 'width:50%' }, h('div', { class: 'sec-label' }, 'INTENT'), dead('의도 판단', 0, true), h('div', { class: 'sec-sub' }, '의도 판단')),
        h('div', { class: 'section', style: 'width:50%' }, h('div', { class: 'sec-label' }, 'RETURN'), dead('응답 필터', -60, true), h('div', { class: 'sec-sub' }, '업무 필드만 전달'))), foot()),
  ];
}

function renderChain(v: ServiceView): void {
  const present = v.instances.filter((i) => i.state !== 'missing');
  const host = v.host;
  const extension = host.extensionListed === true ? 'mago-ski 확장 설치됨' : host.extensionListed === false ? 'mago-ski 확장 미설치' : '확장 확인 불가';
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
      h('div', { class: 's' }, host.present ? extension : 'Pi 설정 폴더 없음', h('br'), '정책은 다음 세션부터 적용')),
  );
  chain.scrollLeft = scroll;
}

// ------------------------------------------------------------------ monitor detail

function diffTable(file: FileChangeView, change: ChangeView): HTMLElement {
  const head = h('div', { class: 'diff-head' },
    h('span', {}, `${file.path}${file.sections.length ? ` · ${file.sections.slice(0, 3).join(', ')}` : ''}`),
    h('span', {}, `기록한 원문 ${short(change.baselineDigest)} ↔ 현재 원문 ${short(change.currentDigest)}`));
  const box = h('div', { class: 'diff' }, head);
  if (!file.lines) {
    box.append(h('div', { class: 'dl gap' }, h('span', { class: 'n' }), h('span', { class: 't' }, file.note ?? '원문 비교를 표시할 수 없어요.')));
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
    ? { ok: true, text: kind === 'remember' ? `${short(digest)}을 새 비교 기준으로 기록했어요. 조직 승인은 아니에요.` : '이 버전을 확인한 것으로 기록했어요. 조직 승인은 아니에요.' }
    : { ok: false, text: result.message };
  detailKey = '';
  apply(await api.getView());
}

function renderPane(pane: HTMLElement, v: ServiceView, i: InstanceView): void {
  // A detail for other versions than the view reports is never shown: it would describe bytes that are gone.
  const d = detailMatches(i, detail) ? detail : null;
  const target = actionDigest(i, detail);
  pane.replaceChildren(
    h('h2', {}, i.name, h('span', { class: `state ${i.state}` }, STATE_LABEL[i.state]), pkiBadge(i.pki, v, i.pkiCurrent)),
    h('div', { class: 'path' }, `${i.path} · ${i.rootLabel}`));
  if (!i.pkiCurrent) pane.append(h('div', { class: 'result err' }, 'PKI 판정은 직전에 읽은 다른 버전 기준이에요. 다음 확인에서 다시 검증해요.'));

  const summary: Record<ObservationState, string> = {
    new: '새로 발견해서 현재 상태를 비교 기준으로 기록했어요. 안전 검증 결과가 아니라 비교를 위한 출발점이에요.',
    unchanged: '기록한 버전과 내용이 같아요. 확인할 일이 없어요.',
    changed: `기록한 버전(${time(i.baselineAt)})에서 내용이 바뀌었어요.`,
    reviewed: '바뀐 내용을 확인한 것으로 기록했어요. 비교 기준은 아직 이전 버전이에요.',
    missing: '설치 위치에서 이 Skill을 찾을 수 없어요. 이력은 남아 있어요.',
    unreadable: '이 Skill을 검사하지 못했어요. 목록에서 빼지 않고 이유를 보여드려요.',
  };
  pane.append(h('p', { class: 'summary' }, summary[i.state]));
  if (i.error) pane.append(h('div', { class: 'result err' }, i.error));

  const change = d?.change;
  if (change) {
    const execChanges = change.files.filter((f) => f.execBefore !== f.execAfter && f.execAfter === true).length;
    pane.append(h('div', { class: 'facts' },
      h('span', { class: 'fact' }, `파일 ${change.files.length}개 변경`),
      change.addedOrigins.length ? h('span', { class: 'fact evidence' }, `새 HTTP(S) origin ${change.addedOrigins.length}개: ${change.addedOrigins.slice(0, 3).join(', ')}`) : null,
      change.removedOrigins.length ? h('span', { class: 'fact' }, `사라진 origin ${change.removedOrigins.length}개`) : null,
      execChanges ? h('span', { class: 'fact evidence' }, `실행 파일 ${execChanges}개 추가`) : null,
      h('span', { class: 'fact' }, `기록 ${short(change.baselineDigest)} → 현재 ${short(change.currentDigest)}`)));
    if (!change.contentRetained) {
      const why = change.contentNote?.includes('missing or damaged') ? '보관한 사본이 없거나 손상돼서'
        : change.contentNote?.includes('does not match') ? '보관한 사본이 기록과 달라서'
        : '이 버전의 원문을 보관하지 않아서';
      pane.append(h('div', { class: 'result err' }, `${why} 파일 이름, 크기, 실행 비트만 비교했어요.`));
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
    tabs.append(h('span', { class: 'spacer' }), h('span', { class: 'sec-sub' }, '원문 비교'));
    pane.append(tabs);
    const file = change.files[selectedFile];
    if (file) pane.append(diffTable(file, change));
    pane.append(h('div', { class: 'sec-sub', style: 'text-align:left;margin-top:8px;color:var(--ink-3)' },
      '부분 근거: 텍스트 파일의 HTTP(S) origin만 탐지해요. 탐지된 변화가 없어도 안전하다는 뜻은 아니에요.'
        + (change.analysisComplete ? '' : ' 일부 파일은 분석하지 못했어요.') + (change.truncated ? ' 변경 목록이 길어 일부만 보여요.' : '')));
  } else if (!d && (i.state === 'changed' || i.state === 'reviewed')) {
    pane.append(h('p', { class: 'sec-sub', style: 'text-align:left' }, detailError ?? '변경 내용을 불러오는 중…'));
    if (detailError) {
      const retry = h('button', { class: 'btn' }, '다시 시도');
      retry.addEventListener('click', () => { detailKey = ''; detailError = null; void loadDetail(); });
      pane.append(retry);
    }
  }

  pane.append(h('div', { class: 'digest-bind' }, target
    ? `처리 대상: ${target} · 읽는 중 파일이 바뀌면 다시 확인해요`
    : '처리 대상: 화면의 변경 내용이 최신 버전과 맞을 때 정해져요'));

  const waiting = '변경 내용을 불러온 뒤 확인할 수 있어요';
  if (i.state === 'changed') {
    const cb = h('input', { type: 'checkbox', id: 'remember' }) as HTMLInputElement;
    cb.checked = rememberOnReview;
    cb.addEventListener('change', () => { rememberOnReview = cb.checked; });
    const btn = h('button', { class: 'btn primary', disabled: !target, title: target ? null : waiting }, '✓ 변경 확인 완료');
    btn.addEventListener('click', () => { if (target) void runAction(rememberOnReview ? 'remember' : 'reviewed', i, target); });
    pane.append(h('label', { class: 'check', for: 'remember' }, cb, '확인 후 이 버전을 다음 비교 기준으로 기록'),
      h('div', { class: 'actions' }, h('span', { class: 'note' }, actionNote(v)), btn));
  } else if (i.state === 'reviewed') {
    const btn = h('button', { class: 'btn', disabled: !target, title: target ? null : waiting }, '이 버전을 비교 기준으로 기록');
    btn.addEventListener('click', () => { if (target) void runAction('remember', i, target); });
    pane.append(h('div', { class: 'actions' }, h('span', { class: 'note' }, actionNote(v)), btn));
  } else if (i.state === 'new') {
    const btn = h('button', { class: 'btn', disabled: !target, title: target ? null : waiting }, '확인함');
    btn.addEventListener('click', () => { if (target) void runAction('reviewed', i, target); });
    pane.append(h('div', { class: 'actions' }, h('span', { class: 'note' }, actionNote(v)), btn));
  }
  if (actionResult) pane.append(h('div', { class: `result ${actionResult.ok ? 'ok' : 'err'}` }, actionResult.text));

  if (d?.approveCommand) {
    const copy = h('button', { class: 'btn' }, '복사');
    copy.addEventListener('click', () => { void api.copyText(d.approveCommand!); copy.textContent = '복사됨'; });
    pane.append(h('div', { class: 'approve' },
      h('h3', {}, '조직 승인 · 승인자 전용'),
      h('p', {}, '이 명령은 지금 보이는 정확한 버전에만 서명해요. 그 사이 파일이 바뀌면 mago-ski가 서명을 거부해요. 승인자 키는 이 앱에 전달되지 않아요. --reason에는 실제로 검토한 내용을 적으세요.'),
      d.approveScope === 'full-diff' ? null : h('div', { class: 'result err' }, d.approveScope === 'no-diff'
        ? '이 화면은 이 버전의 파일 내용을 보여주지 않았어요. 서명하기 전에 Skill의 모든 파일을 직접 검토하세요.'
        : '이 화면은 바뀐 파일 일부를 텍스트로 보여주지 못했어요. 서명하기 전에 그 파일들을 직접 검토하세요.'),
      h('p', {}, '변경 비교는 이 앱이 기록한 버전 기준이며, 마지막으로 승인된 버전과의 비교가 아니에요.'),
      h('div', { class: 'cmd' }, h('code', {}, d.approveCommand), copy)));
  }

  const meaning = h('details', { class: 'meaning' }, h('summary', {}, '승인 상태와 기록의 의미'),
    h('p', {}, v.host.policy.kind === 'none'
      ? 'PKI가 설정되지 않아 조직 승인 여부는 검사하지 않았어요. 최초 기록과 변경 확인은 비교 이력이며, 안전성 인증이나 PKI 승인이 아닙니다.'
      : '조직 승인은 정책의 Root가 위임한 승인자가 이 정확한 digest에 서명했는지로 판단해요. 최초 기록과 변경 확인은 이 앱의 비교 이력일 뿐 승인을 만들지 않아요.'));
  pane.append(meaning);

  if (d?.previousVersions.length) {
    pane.append(h('h3', { style: 'font-size:13px;margin:18px 0 6px' }, `이전 버전 (${v.prefs.retentionDays}일 보관)`),
      h('table', { class: 'tbl' }, ...d.previousVersions.map((p) => h('tr', {},
        h('td', { class: 'mono' }, short(p.digest)), h('td', {}, `기록 ${time(p.recordedAt)}`),
        h('td', {}, `교체 ${time(p.supersededAt)}`), h('td', {}, p.retained ? '원문 보관됨' : '메타데이터만')))));
  }
  if (d?.history.length) {
    pane.append(h('h3', { style: 'font-size:13px;margin:18px 0 6px' }, '이 Skill의 기록'),
      h('table', { class: 'tbl' }, ...d.history.slice(0, 8).map((e) => h('tr', {},
        h('td', {}, time(e.at)), h('td', {}, HISTORY_LABEL[e.kind]), h('td', { class: 'mono' }, short(e.digest))))));
  }
}

function actionNote(v: ServiceView): string {
  const p = v.host.policy;
  if (p.kind === 'loaded' && p.mode === 'enforce') return 'Enforce 정책: Pi는 조직 승인을 통과한 버전만 사용해요. 여기서 확인해도 승인되지 않아요.';
  return '관찰 중 · 현재 실행은 제한하지 않아요';
}

function renderMonitorDetail(v: ServiceView): void {
  const detailEl = $('detail');
  detailEl.style.gridTemplateColumns = '';
  if (v.instances.length === 0) {
    detailEl.style.gridTemplateColumns = '1fr';
    detailEl.replaceChildren(h('div', { class: 'empty-state' },
      '아직 발견한 Skill이 없어요. 평소처럼 Skill을 설치하면 자동으로 발견해서 처음 상태를 기록해요.', h('br'),
      '찾는 위치: ', ...v.roots.flatMap((r, idx) => [idx ? ', ' : '', h('code', {}, r.path)])));
    return;
  }
  if (!selected()) selectedId = v.instances[0]!.id;
  const list = h('div', { class: 'list' },
    h('div', { class: 'list-head' }, h('span', {}, '발견한 SKILLS'), h('span', {}, `미확인 ${v.instances.filter((i) => i.state === 'changed').length}`)));
  for (const i of v.instances) {
    const row = h('button', { class: 'row', 'aria-selected': String(i.id === selectedId) },
      h('div', { class: 'ic' }, i.name.slice(0, 3).toUpperCase()),
      h('div', {}, h('div', { class: 'nm' }, i.name), h('div', { class: 'st' }, statusLine(i))),
      h('div', { class: 'spacer' }),
      h('span', { class: `state ${i.state}` }, STATE_LABEL[i.state]));
    row.addEventListener('click', () => { selectedId = i.id; selectedFile = 0; actionResult = null; renderDetail(); });
    list.append(row);
  }
  list.append(h('div', { class: 'roots' }, '자동 발견 경로', ...v.roots.flatMap((r) => [h('br'), h('code', {}, r.path)])));
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
    detailError = `변경 내용을 불러오지 못했어요: ${error instanceof Error ? error.message : String(error)}`;
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
    h('p', {}, '조직이 승인한 정확한 버전만 지원 호스트에서 쓰도록 검증해요. 이 화면은 Pi가 읽는 정책을 그대로 읽기만 하고, 정책이나 호스트 상태 파일을 바꾸지 않아요.'),
    h('dl', { class: 'kv' },
      h('dt', {}, '정책 파일'), h('dd', {}, p.path ?? '—'),
      h('dt', {}, '상태'), h('dd', {}, p.kind === 'none' ? '없음 · PKI 미설정' : p.kind === 'error' ? `오류: ${p.reason}` : `${p.mode} · 신뢰 문서 ${p.trustOk ? '검증됨' : `실패 (${p.trustNote ?? ''})`}`),
      h('dt', {}, '적용 시점'), h('dd', {}, 'Pi는 세션을 시작할 때 정책을 읽어요. 바뀐 정책은 다음 세션부터 적용돼요.')),
    h('h2', { style: 'font-size:15px;margin-top:20px' }, 'Skill별 검증 결과'),
    p.kind === 'none' ? h('p', { class: 'hint' }, '정책이 없어서 검증하지 않았어요. 조직 승인을 쓰려면 README의 Quickstart로 정책을 만들고 ~/.mago-ski/policy.json에 두세요.')
      : h('table', { class: 'tbl' }, h('tr', {}, h('th', {}, 'Skill'), h('th', {}, '판정'), h('th', {}, '이유 (엔진)'), h('th', {}, '승인자 키')), ...rows),
    decisions.length ? h('h2', { style: 'font-size:15px;margin-top:20px' }, '호스트가 기록한 최근 결정') : null,
    decisions.length ? h('table', { class: 'tbl' }, h('tr', {}, h('th', {}, '시각'), h('th', {}, 'Skill'), h('th', {}, '처리'), h('th', {}, '판정'), h('th', {}, '사건')), ...decisions) : null);
  $('detail').style.gridTemplateColumns = '1fr';
  $('detail').replaceChildren(box);
}

const CONCEPTS: Record<'eq' | 'limiter' | 'clear', { title: string; lead: string; rows: Array<[string, string]> }> = {
  eq: { title: 'CAPABILITY EQ · 구상', lead: 'Skill이 쓸 수 있는 파일·네트워크·셸 권한을 단계로 조절해요. 실제 격리 계층이 연결되기 전에는 동작하지 않아요.',
    rows: [['관측', '도구 호출의 경로와 대상'], ['개입', '지원되는 실행 경계에서 허용 · 확인 · 차단'], ['상태', '후속 단계 · 미연동']] },
  limiter: { title: 'DYNAMICS LIMITER · 구상', lead: '세션당 도구 호출 예산을 넘으면 추가 실행을 멈춰요.',
    rows: [['관측', '세션별 도구 호출 수'], ['개입', '예산 소진 시 추가 실행 중단'], ['상태', '후속 단계 · 미연동']] },
  clear: { title: 'CLEAR FILTER · 구상', lead: '요청 의도를 판단하고, 반환 데이터에서 업무에 필요한 필드만 전달해요.',
    rows: [['관측', '요청 의도와 도구 반환값'], ['개입', '추가 확인 요청, 응답 필드 투영'], ['상태', '후속 단계 · 미연동']] },
};

function renderConceptDetail(key: 'eq' | 'limiter' | 'clear'): void {
  const c = CONCEPTS[key];
  $('detail').style.gridTemplateColumns = '1fr';
  $('detail').replaceChildren(h('div', { class: 'concept-pane' }, h('h2', {}, c.title), h('p', {}, c.lead),
    h('table', {}, ...c.rows.map(([k, val]) => h('tr', {}, h('td', {}, k), h('td', {}, val))))));
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
  page.replaceChildren(h('h2', {}, '활동 기록'),
    h('p', { class: 'hint' }, '이 컴퓨터에서 관찰한 사건이에요. 기록과 확인은 조직 승인이 아니에요.'),
    v.history.length === 0 ? h('p', {}, '아직 기록이 없어요.') :
      h('table', { class: 'tbl' }, h('tr', {}, h('th', {}, '시각'), h('th', {}, 'Skill'), h('th', {}, '사건'), h('th', {}, '버전'), h('th', {}, '내용')),
        ...v.history.map((e) => h('tr', {}, h('td', {}, time(e.at)), h('td', {}, e.name || '전체'), h('td', {}, HISTORY_LABEL[e.kind]),
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
  const add = h('button', { class: 'btn' }, '+ 폴더 추가');
  add.addEventListener('click', () => void api.addRoot().then(apply));
  const rootRows = v.roots.map((r) => {
    const remove = r.origin === 'user' ? h('button', { class: 'btn' }, '관찰 중지') : h('span', { class: 'sec-sub' }, '기본 위치');
    if (r.origin === 'user') remove.addEventListener('click', () => void api.removeRoot(r.id).then(apply));
    const status = r.error ? `오류: ${r.error}` : r.exists ? (r.tooDeep.length ? `일부 미확인 (깊이 제한 ${r.tooDeep.length}곳)` : '관찰 중') : '폴더 없음 · 설치되면 자동 발견';
    return h('tr', {}, h('td', {}, r.label), h('td', { class: 'mono' }, r.path), h('td', {}, status), h('td', {}, remove));
  });
  const host = v.host;
  $('tab-settings').replaceChildren(
    h('div', { class: 'section-head' }, h('h2', {}, '관찰 위치'), h('span', { class: 'spacer' }), add),
    h('p', { class: 'hint' }, '이 위치 아래에서 SKILL.md가 있는 폴더를 찾아요. 위치를 추가해도 Pi나 조직 정책은 바뀌지 않아요.'),
    h('table', { class: 'tbl' }, h('tr', {}, h('th', {}, '이름'), h('th', {}, '경로'), h('th', {}, '상태'), h('th', {})), ...rootRows),
    h('h2', {}, '전역 설정'),
    h('dl', { class: 'kv' },
      h('dt', {}, '변경 알림'), h('dd', {}, seg<Prefs['notify']>([['off', '끔'], ['grouped', '모아서'], ['immediate', '즉시']], v.prefs.notify, (n) => setPrefs({ notify: n }))),
      h('dt', {}, '비교용 원문 보관'), h('dd', {}, seg<boolean>([[true, '보관'], [false, '보관 안 함']], v.prefs.retainContent, (r) => setPrefs({ retainContent: r }))),
      h('dt', {}, '이전 버전 보관 기간'), h('dd', {}, seg<number>(RETENTION_STEPS.map(([d]) => [d, `${d}일`]), v.prefs.retentionDays, (d) => setPrefs({ retentionDays: d })))),
    h('p', { class: 'hint', style: 'margin-top:10px' }, '원문 보관은 Skill 파일의 복사본을 아래 데이터 폴더에 만들어요. Skill 폴더에는 아무것도 쓰지 않아요. 4 MiB보다 큰 파일은 보관하지 않아요.'),
    h('h2', {}, '호스트와 데이터'),
    h('dl', { class: 'kv' },
      h('dt', {}, '호스트'), h('dd', {}, `${host.name} · ${host.agentDir || '—'} · ${host.present ? '설정 폴더 있음' : '설정 폴더 없음'}`),
      h('dt', {}, 'mago-ski 확장'), h('dd', {}, host.extensionListed === null ? '확인 불가' : host.extensionListed ? 'Pi 설정에 등록됨' : 'Pi 설정에 없음 · pi install npm:@mago-foundation/mago-ski'),
      h('dt', {}, '정책'), h('dd', {}, host.policy.path ?? '—'),
      h('dt', {}, '데이터 폴더'), h('dd', {}, v.service.dataDir),
      h('dt', {}, '플랫폼'), h('dd', {}, `${v.service.platform}${v.service.platformSupported ? '' : ' (엔진 미지원)'}`)));
}

// ------------------------------------------------------------------ wiring

function apply(next: ServiceView): void {
  view = next;
  renderHeader(next);
  if (tab === 'skills') { renderChain(next); renderDetail(); }
  if (tab === 'activity') renderActivity(next);
  if (tab === 'settings') renderSettings(next);
}

function showTab(next: typeof tab): void {
  tab = next;
  document.querySelectorAll<HTMLElement>('.tab').forEach((t) => t.setAttribute('aria-selected', String(t.dataset.tab === next)));
  for (const name of ['skills', 'activity', 'settings'] as const) ($(`tab-${name}`) as HTMLElement).hidden = name !== next;
  if (view) apply(view);
}

document.querySelectorAll<HTMLElement>('.tab').forEach((t) => t.addEventListener('click', () => showTab(t.dataset.tab as typeof tab)));
$('check-now').addEventListener('click', () => void api.checkNow().then(apply));
api.onUpdate(apply);
void api.getView().then(apply);
