// Administration rack (docs/spec/gui-admin-rack-v1.md): the organisation pin, the template picker and the devices of
// the "Approve a Skill version" template. Key material never reaches this page: the main process holds the armed key
// and decides every signature; this module only shows state and sends instance ids, digests and text.
import type {
  AdminCheckView, AdminInspectView, AdminLifetime, AdminPinView, AdminRole, AdminStatusView, ChangeView, RendererApi, ServiceView,
} from '../service/types.ts';
import { h } from './dom.ts';

type TemplateKey = 'approve' | 'approvers' | 'revoke' | 'publish' | 'setup' | 'incident';
type DeviceKey = 'identity' | 'inspect' | 'approve' | 'check';
type DeviceState = 'locked' | 'waiting' | 'ready' | 'done' | 'failed';

const TEMPLATES: Array<{ key: TemplateKey; title: string; chain: string; role: string; phase: 1 | 2 | 3 }> = [
  { key: 'approve',   title: 'Skill 버전 승인',  chain: 'IDENTITY → INSPECT → APPROVE → POLICY CHECK', role: '승인자', phase: 1 },
  { key: 'approvers', title: '승인자 관리',      chain: 'IDENTITY → TRUST ROOT → POLICY CHECK', role: '루트 관리자', phase: 2 },
  { key: 'revoke',    title: '승인 폐기',        chain: 'IDENTITY → INSPECT → REVOKE → POLICY CHECK', role: '루트 관리자', phase: 2 },
  { key: 'publish',   title: '게시',            chain: 'IDENTITY → REVOCATION REFRESH → TIMESTAMP → POLICY CHECK', role: '루트 관리자 · 타임스탬프 키', phase: 2 },
  { key: 'setup',     title: '조직 설정',        chain: 'KEYS → ROOT INIT → RECOVERY SET → POLICY CHECK', role: '없음 (키를 만들어요)', phase: 3 },
  { key: 'incident',  title: '루트 사고 대응',    chain: 'IDENTITY → ROOT EVENT → ADOPT → POLICY CHECK', role: '복구 키 보유자 · 새 루트', phase: 3 },
];

const ROLE_LABEL: Record<AdminRole, string> = { root: 'ROOT', approver: 'APPROVER', recovery: 'RECOVERY', timestamp: 'TIMESTAMP', none: '—' };
const ROLE_NAME: Record<AdminRole, string> = { root: '루트 관리자', approver: '승인자', recovery: '복구 키 보유자', timestamp: '타임스탬프 서명자', none: '역할 없음' };
const STATE_LABEL: Record<DeviceState, string> = { locked: '잠김', waiting: '대기', ready: '준비', done: '완료', failed: '확인 필요' };
const LIFETIMES: Array<[AdminLifetime, string]> = [['30d', '30일'], ['90d', '90일'], ['180d', '180일']];

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
let message: { ok: boolean; text: string } | null = null;
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

/** Polls the status while the 관리 tab is visible, so the main process re-checks the pin and the role on its own. */
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

export function renderAdmin(target: HTMLElement, next: ServiceView, renderer: RendererApi): void {
  api = renderer;
  container = target;
  view = next;
  // A Skill that changed under an inspection voids it, as the main process would.
  const current = skillId ? next.instances.find((i) => i.id === skillId) : undefined;
  if (inspected && (!current || current.currentDigest !== inspected.digest)) {
    resetFrom('inspect');
    message = { ok: false, text: '선택한 Skill이 바뀌었거나 사라졌어요. 다시 검토하세요.' };
  }
  if (!status && !statusLoading) void refreshStatus();
  draw();
}

async function refreshStatus(): Promise<void> {
  statusLoading = true;
  let next: AdminStatusView;
  try {
    next = await api.admin.status();
  } catch {
    return;
  } finally {
    statusLoading = false;
  }
  adoptStatus(next);
}

/** Takes a status from the main process. The page redraws only when something changed, so typing is never interrupted. */
function adoptStatus(next: AdminStatusView): void {
  const previous = status;
  status = next;
  if (previous?.armed && !next.armed) {
    // The main process dropped the key (pin or role change, idle, or a disarm): nothing recorded for it stands.
    resetFrom('inspect');
    message ??= { ok: false, text: '키가 빠졌어요. 다시 불러오세요.' };
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
  const identity: { state: DeviceState; why: string } = !pinOk ? { state: 'locked', why: '조직 고정 정책이 없거나 보호되지 않아요' }
    : armed?.role === 'approver' ? { state: 'done', why: `${armed.name ?? ''} · ${armed.scopes?.join(', ') ?? ''}` }
    : armed ? { state: 'failed', why: `${ROLE_NAME[armed.role]} 키예요. 이 템플릿은 승인자 키가 필요해요` }
    : { state: 'ready', why: '승인자 키를 불러오세요' };
  const inspect: { state: DeviceState; why: string } = identity.state !== 'done' ? { state: 'waiting', why: '먼저 승인자 키를 불러오세요' }
    : inspected?.inspected ? { state: 'done', why: `${inspected.name} · ${short(inspected.digest)}` }
    : { state: 'ready', why: skillId ? '이 버전을 검토했는지 확인하세요' : 'Skill을 고르세요' };
  const approve: { state: DeviceState; why: string } = inspect.state !== 'done' && !signed ? { state: 'waiting', why: '먼저 검토한 버전을 확인하세요' }
    : signed ? { state: 'done', why: `인증서 ${short(signed.certificateId)}` }
    : { state: 'ready', why: '기간과 이유를 정하고 서명하세요' };
  const check: { state: DeviceState; why: string } = !skillId ? { state: 'waiting', why: 'Skill을 고르세요' }
    : checked ? { state: checked.verdict === 'VERIFIED' ? 'done' : 'failed', why: checked.verdict ?? checked.reason }
    : { state: 'ready', why: '정책으로 확인하세요' };
  return { identity, inspect, approve, check };
}

// ------------------------------------------------------------------ drawing

function draw(): void {
  if (!container) return;
  const tpl = TEMPLATES.find((t) => t.key === template)!;
  const parts: Array<HTMLElement | null> = [
    h('div', { class: 'section-head' }, h('h2', {}, '관리 랙'), h('span', { class: 'spacer' }),
      h('span', { class: 'hint', style: 'margin:0' }, '승인자와 관리자용이에요. 역할은 서명 키로 확인해요.')),
    pinPanel(status?.pin ?? null),
    status?.hostPolicyDiffers ? h('div', { class: 'banner', style: 'margin:10px 0' }, '관찰 랙(내 Skills)은 Pi가 읽는 다른 정책을 보여 줘요. 관리 랙은 조직 고정 정책만 기준으로 해요.') : null,
    h('h2', {}, '템플릿'),
    h('div', { class: 'tpl-grid' }, ...TEMPLATES.map(templateCard)),
    tpl.phase === 1 ? approveRack() : h('div', { class: 'empty-state' }, `${tpl.title} 템플릿은 ${tpl.phase}단계에서 만들어요. 그때까지는 CLI를 쓰세요.`),
    tpl.phase === 1 ? deviceDetail() : null,
  ];
  container.replaceChildren(...parts.filter((part): part is HTMLElement => part !== null));
}

function pinPanel(pin: AdminPinView | null): HTMLElement {
  if (!pin) return h('p', { class: 'hint' }, '조직 고정 정책을 읽는 중이에요.');
  const stateText: Record<AdminPinView['kind'], string> = {
    loaded: '보호됨', missing: '설치되지 않음', unprotected: '보호되지 않음 · 쓰지 않아요', invalid: '읽을 수 없음',
  };
  const rows: HTMLElement[] = [
    h('dt', {}, '조직 고정 정책'), h('dd', {}, pin.path),
    h('dt', {}, '상태'), h('dd', {}, `${stateText[pin.kind]}${pin.reason ? ` · ${pin.reason}` : ''}`),
  ];
  if (pin.kind === 'loaded') rows.push(
    h('dt', {}, '루트 키'), h('dd', {}, `${pin.activeRootKeyId ?? '확인할 수 없음'}${pin.activeRootKeyId && pin.activeRootKeyId !== pin.rootKeyId ? ' (루트 이벤트로 교체됨)' : ''}`),
    h('dt', {}, '모드 · 신뢰 문서'), h('dd', {}, `${pin.mode} · ${pin.trustOk ? '검증됨' : `검증 실패: ${pin.trustNote ?? ''}`}`),
  );
  const notices: HTMLElement[] = [];
  if (status?.memoryReset) {
    notices.push(h('div', { class: 'banner', style: 'margin:10px 0' },
      `이 컴퓨터의 관리 기록을 읽을 수 없어서 따로 보관하고 새로 시작했어요 (${status.memoryReset.backup}) `,
      button('닫기', () => void run(async () => { status = await api.admin.dismissMemoryReset(); }), { id: 'dismiss-memory-reset' })));
  }
  if (status?.rollback) {
    notices.push(h('div', { class: 'banner', style: 'margin:10px 0' },
      '이 컴퓨터가 이미 본 것보다 오래된 문서예요. 조직이 문서를 다시 만들었다면 기록을 초기화하세요. ',
      button('기록 초기화', () => void run(async () => {
        status = await api.admin.resetMemory();
        resetFrom('inspect');
      }), { id: 'reset-memory' })));
  }
  const help = pin.kind === 'missing' || pin.kind === 'unprotected'
    ? h('p', { class: 'hint' }, '관리자가 조직의 정책을 이 위치에 설치해야 해요: 파일과 위의 모든 폴더가 root 소유이고, 그룹·다른 사용자가 쓸 수 없어야 해요. 직원이 바꿀 수 있는 정책으로는 역할을 인정하지 않아요.')
    : null;
  return h('div', {}, h('dl', { class: 'kv' }, ...rows), ...notices, help);
}

function templateCard(t: (typeof TEMPLATES)[number]): HTMLElement {
  const disabled = t.phase !== 1;
  const card = h('button', { class: 'tpl', 'aria-pressed': String(t.key === template), 'aria-disabled': String(disabled), 'data-template': t.key },
    h('span', { class: 'tpl-title' }, t.title),
    h('span', { class: 'tpl-chain' }, t.chain),
    h('span', { class: 'tpl-role' }, disabled ? `${t.phase}단계 예정 · ${t.role}` : t.role));
  card.addEventListener('click', () => {
    if (t.key === template) return;
    template = t.key;
    resetFrom('inspect');
    skillId = null;
    // Changing the template drops the armed key (spec: armed key lifetime).
    void run(async () => { if (status?.armed) { status = await api.admin.disarm(); message = { ok: true, text: '템플릿을 바꿔서 키를 메모리에서 뺐어요.' }; } });
  });
  return card;
}

function faceplate(key: DeviceKey, name: string, state: { state: DeviceState; why: string }, ...body: HTMLElement[]): HTMLElement {
  const live = state.state === 'ready' || state.state === 'done';
  const el = h('div', {
    class: `device admin-dev ${state.state}`, tabindex: 0, role: 'button', 'aria-selected': String(device === key), 'data-admin-device': key, style: 'width:250px',
  },
    h('div', { class: 'dev-head' },
      h('span', { class: 'power', role: 'img', 'aria-pressed': String(live), 'aria-label': STATE_LABEL[state.state] }),
      h('span', { class: 'dev-name' }, name), h('span', { class: 'spacer' }),
      h('span', { class: `dev-tag state-${state.state}` }, STATE_LABEL[state.state])),
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
      h('div', { class: 'legend' }, h('span', {}, '고정 순서 · 장치를 옮기거나 건너뛸 수 없어요'))),
    h('div', { class: 'chain' },
      faceplate('identity', 'SKI / IDENTITY', s.identity,
        h('div', { class: 'sec-label' }, 'KEY SLOT'),
        screen(armed ? ROLE_LABEL[armed.role] : 'EMPTY', armed ? short(armed.keyId) : '키 없음', armed?.role === 'approver' ? 'verified' : armed ? 'warn' : '')),
      link(s.identity.state === 'done'),
      faceplate('inspect', 'SKI / INSPECT', s.inspect,
        h('div', { class: 'sec-label' }, 'VERSION'),
        screen(inspected?.name ?? '—', inspected ? short(inspected.digest) : 'Skill 미선택', inspected?.inspected ? 'verified' : '')),
      link(s.inspect.state === 'done'),
      faceplate('approve', 'SKI / APPROVE', s.approve,
        h('div', { class: 'sec-label' }, 'LIFETIME'),
        screen(signed ? 'SIGNED' : LIFETIMES.find(([l]) => l === lifetime)![1], signed ? short(signed.certificateId) : '인증서 기간', signed ? 'verified' : '')),
      link(s.approve.state === 'done'),
      faceplate('check', 'SKI / POLICY CHECK', s.check,
        h('div', { class: 'sec-label' }, 'VERDICT'),
        screen(checked?.verdict ?? '—', checked ? (checked.trustOk ? '신뢰 문서 검증됨' : '신뢰 문서 실패') : '조직 고정 정책 기준', verdictClass))));
}

function deviceDetail(): HTMLElement {
  const pane = h('section', { class: 'admin-detail' });
  const titles: Record<DeviceKey, string> = { identity: 'IDENTITY · 서명 키', inspect: 'INSPECT · 정확한 버전 검토', approve: 'APPROVE · 인증서 서명', check: 'POLICY CHECK · 정책으로 확인' };
  pane.append(h('h2', {}, titles[device]));
  if (device === 'identity') identityDetail(pane);
  if (device === 'inspect') inspectDetail(pane);
  if (device === 'approve') approveDetail(pane);
  if (device === 'check') checkDetail(pane);
  if (message) pane.append(h('div', { class: `result ${message.ok ? 'ok' : 'err'}` }, message.text));
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
    `불러온 개인 키는 이 앱의 메인 프로세스 메모리에만 있어요. 파일·로그·화면에 남지 않고, ${status?.idleMinutes ?? 15}분 동안 쓰지 않거나 템플릿을 바꾸거나 앱을 닫으면 빠져요. 서명할 때마다 역할을 다시 확인해요.`));
  if (armed) {
    pane.append(h('dl', { class: 'kv' },
      h('dt', {}, '역할'), h('dd', {}, ROLE_NAME[armed.role]),
      h('dt', {}, '키'), h('dd', {}, armed.keyId),
      ...(armed.name ? [h('dt', {}, '이름'), h('dd', {}, armed.name)] : []),
      ...(armed.scopes ? [h('dt', {}, '범위'), h('dd', {}, armed.scopes.join(', '))] : []),
      ...(armed.expiresAt ? [h('dt', {}, '키 만료'), h('dd', {}, armed.expiresAt)] : [])));
    if (armed.role === 'root' || armed.role === 'recovery')
      pane.append(h('div', { class: 'banner', style: 'margin:10px 0' }, '루트 키와 복구 키는 오프라인 관리용 컴퓨터에서만 쓰세요. 매일 쓰는 컴퓨터에 불러오면 그 컴퓨터의 다른 프로그램이 볼 수 있어요.'));
  }
  pane.append(h('div', { class: 'cmd', style: 'margin-top:12px' },
    button(armed ? '다른 키 불러오기' : '키 불러오기', () => void run(async () => {
      const result = await api.admin.arm();
      if (!result.ok && result.reason !== 'cancelled') message = { ok: false, text: `키를 쓸 수 없어요: ${result.reason}` };
      if (result.ok) message = { ok: true, text: `${ROLE_NAME[result.role.role]} 키를 확인했어요 (소유 증명 완료).` };
      resetFrom('inspect');
      adoptStatus(await api.admin.status());
    }), { primary: !armed, disabled: status?.pin.kind !== 'loaded', id: 'arm' }),
    armed ? button('키 꺼내기', () => void run(async () => { status = await api.admin.disarm(); resetFrom('inspect'); message = { ok: true, text: '키를 메모리에서 뺐어요.' }; }), { id: 'disarm' }) : null));
}

async function selectSkill(id: string): Promise<void> {
  skillId = id;
  resetFrom('inspect');
  await run(async () => {
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
  pane.append(h('p', { class: 'hint' }, '검토할 Skill을 고르세요. 화면에 보이는 정확한 버전(digest)에만 서명할 수 있고, 그 사이 파일이 바뀌면 서명을 거부해요.'), list);
  if (!inspected) return;
  const i = inspected;
  pane.append(h('dl', { class: 'kv', style: 'margin-top:14px' },
    h('dt', {}, 'Skill'), h('dd', {}, `${i.name} · ${i.path}`),
    h('dt', {}, '버전 (tree digest)'), h('dd', {}, i.digest),
    h('dt', {}, '크기'), h('dd', {}, `파일 ${i.files.length}개 · ${i.totalBytes} bytes`),
    h('dt', {}, '현재 판정'), h('dd', {}, i.verdictStale ? '읽는 동안 바뀌었어요 · 다시 검토하세요' : i.verdict ? `${i.verdict.verdict} · ${i.verdict.reason}` : '조직 고정 정책 없음'),
    ...(i.certificate ? [h('dt', {}, '지금 인증서'), h('dd', {}, `${short(i.certificate.id)} · ${i.certificate.approverKeyId.slice(0, 16)}… · ${i.certificate.issuedAt} ~ ${i.certificate.expiresAt} · "${i.certificate.reason}"`)] : []),
    ...(i.excluded.length ? [h('dt', {}, 'digest에서 제외'), h('dd', {}, i.excluded.join(', '))] : [])));
  if (change) pane.append(h('p', { class: 'hint', style: 'margin-top:10px' },
    `기록한 버전과 달라진 파일: ${change.files.map((f) => `${f.path} (${f.change})`).join(', ')}${change.addedOrigins.length ? ` · 새 HTTP(S) origin: ${change.addedOrigins.join(', ')}` : ''} · 줄 단위 변경은 내 Skills 탭에서 볼 수 있어요.`));
  pane.append(h('table', { class: 'tbl', style: 'margin-top:10px' },
    h('tr', {}, h('th', {}, '파일'), h('th', {}, '크기'), h('th', {}, '실행'), h('th', {}, 'SHA-256')),
    ...i.files.map((f) => h('tr', {}, h('td', { class: 'mono' }, f.path), h('td', {}, String(f.size)), h('td', {}, f.exec ? '예' : ''), h('td', { class: 'mono' }, f.sha256.slice(0, 16) + '…')))));
  const armedApprover = status?.armed?.role === 'approver';
  pane.append(h('div', { class: 'cmd', style: 'margin-top:12px' },
    button(i.inspected ? '✓ 검토 확인됨' : '✓ 이 버전을 검토했어요', () => void run(async () => {
      // The page only asks; a native window owned by the main process shows the exact version and records the answer.
      const result = await api.admin.review(i.instanceId);
      if (!result.ok) { message = { ok: false, text: result.message }; adoptStatus(await api.admin.status()); return; }
      inspected = await api.admin.inspect(i.instanceId);
      if (!inspected.inspected) { message = { ok: false, text: '검토하는 동안 Skill이 바뀌었어요. 다시 검토하세요.' }; return; }
      message = { ok: true, text: `검토한 버전으로 기록했어요: ${i.digest}` };
      device = 'approve';
    }), { primary: !i.inspected, disabled: !armedApprover || i.inspected, id: 'confirm' })));
}

function approveDetail(pane: HTMLElement): void {
  const armed = status?.armed ?? null;
  if (!inspected?.inspected && !signed) { pane.append(h('p', { class: 'hint' }, '먼저 INSPECT에서 정확한 버전을 검토했다고 확인하세요.')); return; }
  if (signed) {
    pane.append(h('dl', { class: 'kv' },
      h('dt', {}, '인증서'), h('dd', {}, signed.certificateId),
      h('dt', {}, '저장 위치'), h('dd', {}, signed.certificatePath),
      h('dt', {}, '만료'), h('dd', {}, signed.expiresAt)));
    return;
  }
  const i = inspected!;
  const scopes = armed?.scopes ?? [];
  const covered = scopes.some((s) => scopeCovers(s, i.name));
  let signButton: HTMLButtonElement;
  const area = h('textarea', { class: 'reason', rows: 3, maxlength: 1024, placeholder: '실제로 검토한 내용을 적으세요 (인증서에 남아요)' }) as HTMLTextAreaElement;
  area.value = reason;
  const lifetimeSeg = h('div', { class: 'seg' }, ...LIFETIMES.map(([value, label]) => {
    const b = h('button', { 'aria-pressed': String(value === lifetime) }, label);
    b.addEventListener('click', () => { lifetime = value; draw(); });
    return b;
  }));
  pane.append(
    h('dl', { class: 'kv' },
      h('dt', {}, 'Skill 이름'), h('dd', {}, i.name),
      h('dt', {}, '서명할 버전'), h('dd', {}, i.digest),
      h('dt', {}, '범위'), h('dd', {}, covered ? `${scopes.join(', ')} · 포함됨` : `${scopes.join(', ')} · 이 이름은 범위 밖이에요`)),
    h('h2', {}, '인증서 기간'), lifetimeSeg,
    h('h2', {}, '검토 내용'), area,
    h('p', { class: 'hint' }, '인증서는 이 버전을 누가 승인했는지 기록할 뿐, Skill이 안전하다는 뜻은 아니에요.'),
    h('div', { class: 'cmd', style: 'margin-top:8px' }, signButton = button('서명', () => void run(async () => {
      const result = await api.admin.approve(i.instanceId, i.digest, lifetime, reason.trim());
      if (!result.ok) { message = { ok: false, text: result.message }; adoptStatus(await api.admin.status()); return; }
      signed = { certificateId: result.certificateId ?? '', certificatePath: result.certificatePath ?? '', expiresAt: result.expiresAt ?? '' };
      reason = '';
      message = { ok: true, text: '인증서에 서명했어요. POLICY CHECK에서 판정을 확인하세요.' };
      device = 'check';
    }), { primary: true, disabled: !covered || reason.trim() === '', id: 'sign' })));
  // Typing must enable the button without redrawing the pane (a redraw would drop the focus and the caret).
  area.addEventListener('input', () => {
    reason = area.value;
    signButton.disabled = busy || !covered || reason.trim() === '';
  });
}

function checkDetail(pane: HTMLElement): void {
  if (!skillId) { pane.append(h('p', { class: 'hint' }, 'INSPECT에서 Skill을 고르세요.')); return; }
  const name = view.instances.find((i) => i.id === skillId)?.name ?? '';
  pane.append(h('p', { class: 'hint' }, `조직 고정 정책으로 ${name}을(를) 확인해요. 호스트 상태 파일은 바꾸지 않아요.`),
    h('div', { class: 'cmd' }, button('정책으로 확인', () => void run(async () => { checked = await api.admin.check(skillId!); }), { primary: !checked, id: 'check' })));
  if (checked) pane.append(h('dl', { class: 'kv', style: 'margin-top:12px' },
    h('dt', {}, '판정'), h('dd', {}, checked.verdict ?? '—'),
    h('dt', {}, '이유'), h('dd', {}, checked.reason),
    h('dt', {}, '신뢰 문서'), h('dd', {}, checked.trustOk ? '검증됨' : checked.trustNote ?? '실패')));
}
