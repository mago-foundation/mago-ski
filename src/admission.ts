// Admission rules (mago.admission/v0): an organisation's short, readable rule file that decides which evidence is
// enough to admit a Skill. A decision is a pure function of (facts, rules, time): no model, no network, no
// probability. Facts are computed beforehand from bytes and verified documents (admission-evidence.ts), so the same
// inputs give the same decision anywhere, and a past decision can be replayed against a new rule file.
// This is the admission language only. It never describes what an agent may do at runtime.
import { createHash } from 'node:crypto';
import { parseDocument } from 'yaml';
import type { ObservedProfile } from './profile.ts';
import type { Publisher } from './published-by.ts';
import type { UsfManifest } from './usf.ts';
import { hostAllowed } from './usf.ts';

export const ADMISSION_VERSION = 'mago.admission/v0';
export const ACTIONS = ['ALLOW', 'LOG_ONLY', 'FLAG', 'REQUIRE_REVIEW', 'BLOCK'] as const;
export type Action = (typeof ACTIONS)[number];
/** Stricter actions win: deny wins over allow. */
const RANK: Readonly<Record<Action, number>> = { ALLOW: 0, LOG_ONLY: 1, FLAG: 2, REQUIRE_REVIEW: 3, BLOCK: 4 };
const ADMITTED: ReadonlySet<Action> = new Set(['ALLOW', 'LOG_ONLY', 'FLAG']);
const MAX_RULES = 200;
const MAX_RULES_BYTES = 256 * 1024;

/* ********************************************  */
/*                    Facts                      */
/* ********************************************  */

export interface Review { approver_key_id: string; certificate_id: string; issued_at: string; expires_at: string }

export interface SkillFacts {
  name: string;
  digest: string;
  profile: ObservedProfile;
  declaration: UsfManifest | null;
  /** Why SKILL.md's declaration could not be read one way only, or null. */
  declaration_error: string | null;
  /** A valid certificate from the organisation's trust root for these exact bytes. */
  reviewed_by: Review | null;
  /** A verified published-by attestation for these exact bytes. */
  published_by: Publisher | null;
}

export interface Facts {
  skill: SkillFacts;
  /** The reviewed version this one updates, when one was supplied (its bytes, its review, its publisher). */
  base: SkillFacts | null;
}

/* ********************************************  */
/*                    Rules                      */
/* ********************************************  */

export interface PublisherCondition { repository_id?: string; owner_id?: string; workflow?: string; branch?: string; trigger?: string[] }
export interface CapabilityCondition { shell?: true; websites?: string[]; any_website?: true; undeclared?: true; no_declaration?: true; incomplete?: true }
export interface UpdateCondition { same_publisher: true; max_days_since_review?: number }

export interface Rule {
  id: string;
  when: { publisher?: PublisherCondition; reviewed?: boolean; capabilities?: CapabilityCondition; update?: UpdateCondition };
  action: Action;
  reason?: string;
}

export interface Rules { admission_version: typeof ADMISSION_VERSION; default: Action; rules: Rule[]; digest: string }

export class AdmissionRulesError extends Error {}

type Plain = Record<string, unknown>;
const isMap = (value: unknown): value is Plain => typeof value === 'object' && value !== null && !Array.isArray(value);

function keys(value: unknown, label: string, allowed: readonly string[], required: readonly string[] = []): Plain {
  if (!isMap(value)) throw new AdmissionRulesError(`${label} must be a block of keys`);
  for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new AdmissionRulesError(`${label}: unknown key "${key}" (allowed: ${allowed.join(', ')})`);
  for (const key of required) if (!Object.hasOwn(value, key)) throw new AdmissionRulesError(`${label}: "${key}" is required`);
  return value;
}

function action(value: unknown, label: string): Action {
  if (typeof value !== 'string' || !(ACTIONS as readonly string[]).includes(value)) throw new AdmissionRulesError(`${label} must be one of ${ACTIONS.join(', ')}`);
  return value as Action;
}

const text = (value: unknown, label: string, pattern: RegExp, hint: string): string => {
  if (typeof value !== 'string' || !pattern.test(value)) throw new AdmissionRulesError(`${label} must be ${hint}`);
  return value;
};
const yes = (value: unknown, label: string): true => {
  if (value !== true) throw new AdmissionRulesError(`${label} can only be true`);
  return true;
};

/**
 * Parses and lints a rule file. Every mistake the closed language can detect is an error here, not a surprise at
 * decision time: unknown keys, duplicate ids, a loosening rule built on self-declared or heuristic facts, a strict
 * action without a reason, an ALLOW that matches every Skill.
 */
export function parseRules(source: string): Rules {
  if (Buffer.byteLength(source) > MAX_RULES_BYTES) throw new AdmissionRulesError(`the rule file is larger than ${MAX_RULES_BYTES} bytes`);
  const doc = parseDocument(source, { version: '1.2', uniqueKeys: true, prettyErrors: false });
  if (doc.errors[0]) throw new AdmissionRulesError(`the rule file is not valid YAML: ${doc.errors[0].message.split('\n')[0]}`);
  let raw: unknown;
  try {
    raw = doc.toJS({ maxAliasCount: 0 });
  } catch (error) {
    throw new AdmissionRulesError(`the rule file uses aliases, which are not accepted: ${(error as Error).message}`);
  }
  const top = keys(raw, 'rule file', ['admission_version', 'default', 'rules'], ['admission_version', 'default', 'rules']);
  if (top.admission_version !== ADMISSION_VERSION) throw new AdmissionRulesError(`admission_version must be ${ADMISSION_VERSION}`);
  const fallback = action(top.default, 'default');
  if (!Array.isArray(top.rules) || top.rules.length > MAX_RULES) throw new AdmissionRulesError(`rules must be a list of at most ${MAX_RULES} rules`);
  const ids = new Set<string>();
  const rules = top.rules.map((item, index): Rule => {
    const r = keys(item, `rule ${index + 1}`, ['id', 'when', 'action', 'reason'], ['id', 'when', 'action']);
    const id = text(r.id, `rule ${index + 1} id`, /^[a-z0-9][a-z0-9-]{0,62}$/u, 'lower-case letters, digits and dashes');
    if (ids.has(id)) throw new AdmissionRulesError(`rule id "${id}" is used twice`);
    ids.add(id);
    const label = `rule "${id}"`;
    const w = keys(r.when, `${label} when`, ['publisher', 'reviewed', 'capabilities', 'update']);
    const when: Rule['when'] = {};
    if (w.publisher !== undefined) {
      const p = keys(w.publisher, `${label} publisher`, ['repository_id', 'owner_id', 'workflow', 'branch', 'trigger']);
      if (Object.keys(p).length === 0) throw new AdmissionRulesError(`${label} publisher must name a repository_id, owner_id or workflow`);
      if (p.workflow !== undefined && p.repository_id === undefined) throw new AdmissionRulesError(`${label}: a workflow path only means something with a repository_id`);
      when.publisher = {};
      if (p.repository_id !== undefined) when.publisher.repository_id = text(p.repository_id, `${label} repository_id`, /^[0-9]{1,20}$/u, 'a numeric repository id, quoted');
      if (p.owner_id !== undefined) when.publisher.owner_id = text(p.owner_id, `${label} owner_id`, /^[0-9]{1,20}$/u, 'a numeric owner id, quoted');
      if (p.workflow !== undefined) when.publisher.workflow = text(p.workflow, `${label} workflow`, /^\.github\/workflows\/[A-Za-z0-9_.\-/]+\.ya?ml$/u, 'a path such as .github/workflows/publish.yml');
      // Branches only: tags move, so no rule can refer to one.
      if (p.branch !== undefined) when.publisher.branch = text(p.branch, `${label} branch`, /^[A-Za-z0-9._\-/]{1,200}$/u, 'a branch name such as main');
      if (p.trigger !== undefined) {
        if (!Array.isArray(p.trigger) || p.trigger.length === 0 || !p.trigger.every((t) => typeof t === 'string' && /^[a-z_]{1,40}$/u.test(t)))
          throw new AdmissionRulesError(`${label} trigger must be a list of GitHub event names such as [release, push]`);
        when.publisher.trigger = p.trigger as string[];
      }
    }
    if (w.reviewed !== undefined) {
      if (typeof w.reviewed !== 'boolean') throw new AdmissionRulesError(`${label} reviewed must be true or false`);
      when.reviewed = w.reviewed;
    }
    if (w.capabilities !== undefined) {
      const c = keys(w.capabilities, `${label} capabilities`, ['shell', 'websites', 'any_website', 'undeclared', 'no_declaration', 'incomplete']);
      if (Object.keys(c).length === 0) throw new AdmissionRulesError(`${label} capabilities must name at least one condition`);
      when.capabilities = {};
      for (const flag of ['shell', 'any_website', 'undeclared', 'no_declaration', 'incomplete'] as const) if (c[flag] !== undefined) when.capabilities[flag] = yes(c[flag], `${label} capabilities.${flag}`);
      if (c.websites !== undefined) {
        if (!Array.isArray(c.websites) || c.websites.length === 0 || !c.websites.every((h) => typeof h === 'string' && /^(?:\*\.)?[a-z0-9.-]+$/u.test(h)))
          throw new AdmissionRulesError(`${label} capabilities.websites must be a list of host names`);
        when.capabilities.websites = c.websites as string[];
      }
    }
    if (w.update !== undefined) {
      const u = keys(w.update, `${label} update`, ['same_publisher', 'max_days_since_review'], ['same_publisher']);
      when.update = { same_publisher: yes(u.same_publisher, `${label} update.same_publisher`) };
      if (u.max_days_since_review !== undefined) {
        if (!Number.isInteger(u.max_days_since_review) || (u.max_days_since_review as number) < 0 || (u.max_days_since_review as number) > 3650)
          throw new AdmissionRulesError(`${label} update.max_days_since_review must be a whole number of days up to 3650`);
        when.update.max_days_since_review = u.max_days_since_review as number;
      }
    }
    const act = action(r.action, `${label} action`);
    const rule: Rule = { id, when, action: act };
    if (r.reason !== undefined) rule.reason = text(r.reason, `${label} reason`, /^[^\u0000-\u001f\u007f]{1,300}$/u, 'one line of up to 300 characters');
    // The linter: what a closed language can check completely.
    if ((act === 'BLOCK' || act === 'REQUIRE_REVIEW') && rule.reason === undefined) throw new AdmissionRulesError(`${label}: a ${act} rule needs a reason, shown to the person it stops`);
    if (when.capabilities && act === 'ALLOW') throw new AdmissionRulesError(`${label}: a rule with capability conditions can only make a decision stricter, so ALLOW would have no effect`);
    // ALLOW, LOG_ONLY and FLAG all admit: a basis rule with one of them must rest on a publisher, a review or an update.
    if (!when.capabilities && (act === 'ALLOW' || act === 'LOG_ONLY' || act === 'FLAG')) {
      if (when.reviewed === false) throw new AdmissionRulesError(`${label}: "reviewed: false" cannot be a reason to admit (${act})`);
      if (!when.publisher && when.reviewed !== true && !when.update) throw new AdmissionRulesError(`${label}: a ${act} rule must require a publisher, a review or a non-escalating update; this one would admit every Skill`);
    }
    return rule;
  });
  return { admission_version: ADMISSION_VERSION, default: fallback, rules, digest: `sha256:${createHash('sha256').update(source).digest('hex')}` };
}

/* ********************************************  */
/*                  Evaluation                   */
/* ********************************************  */

export interface Decision {
  action: Action;
  admitted: boolean;
  /** The rule that set the action, or "default" when none matched. */
  rule_id: string;
  matched: string[];
  reason: string | null;
  /** The smallest evidence that would change a REQUIRE_REVIEW or the default, in words. */
  missing: string | null;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** Everything the Skill may reach: hosts it names or declares, and whether it runs code or declares a shell. */
function reach(facts: SkillFacts): { hosts: Set<string>; shell: boolean } {
  return {
    hosts: new Set([...facts.profile.web_hosts, ...(facts.declaration?.network.allow ?? [])]),
    shell: facts.profile.scripts.length > 0 || facts.declaration?.shell === true,
  };
}

/** Why this version reaches further than its base, or null when it does not. Compares declared and observed together. */
export function escalation(base: SkillFacts, skill: SkillFacts): string | null {
  // A declaration that cannot be read one way only may say anything to some reader.
  // Even when the base's could not be read either: then nobody can say what the new one grants.
  if (skill.declaration_error !== null && skill.declaration === null) return 'its declaration cannot be read reliably';
  if (base.declaration !== null && skill.declaration === null) return 'it no longer has a declaration';
  const before = reach(base);
  const after = reach(skill);
  if (after.shell && !before.shell) return 'it runs code or asks for a shell, and the reviewed version did not';
  const newHosts = [...after.hosts].filter((host) => host !== '*' && !before.hosts.has(host) && !hostAllowed([...before.hosts], host));
  if (after.hosts.has('*') && !before.hosts.has('*')) return 'it declares any website (network.allow: "*")';
  if (newHosts.length > 0) return `it reaches new websites: ${newHosts.slice(0, 10).join(', ')}`;
  if (!skill.profile.complete) return 'its profile is incomplete';
  const added = (before: readonly string[] = [], after: readonly string[] = []) => after.filter((value) => !before.includes(value));
  const d0 = base.declaration;
  const d1 = skill.declaration;
  const checks: Array<[string, string[]]> = [
    ['asks to read new files', added(d0?.files.read, d1?.files.read)],
    ['asks to write new files', added(d0?.files.write, d1?.files.write)],
    ['no longer protects files from writes', added(d1?.files.deny_write, d0?.files.deny_write)],
    ['asks for new tools', added(d0?.tools, d1?.tools)],
    ['needs new programs', added(d0?.requires.binaries, d1?.requires.binaries)],
    ['names new programs in shell code', added(base.profile.programs, skill.profile.programs)],
    ['adds declaration keys this version of mago-ski does not know', added(d0?.unknownKeys, d1?.unknownKeys)],
    ['no longer denies other websites (network.deny)', d0?.network.deny === '*' && d1?.network.deny !== '*' ? ['network.deny'] : []],
  ];
  for (const [what, values] of checks) if (values.length > 0) return `it ${what}: ${values.slice(0, 10).join(', ')}`;
  return null;
}

function samePublisher(a: Publisher | null, b: Publisher | null): boolean {
  return a !== null && b !== null && a.repository_id === b.repository_id && a.workflow === b.workflow;
}

function matches(rule: Rule, facts: Facts, now: Date): boolean {
  const { skill } = facts;
  const { publisher, reviewed, capabilities, update } = rule.when;
  if (publisher) {
    const p = skill.published_by;
    if (!p) return false;
    if (publisher.repository_id !== undefined && p.repository_id !== publisher.repository_id) return false;
    if (publisher.owner_id !== undefined && p.owner_id !== publisher.owner_id) return false;
    if (publisher.workflow !== undefined && p.workflow !== publisher.workflow) return false;
    if (publisher.branch !== undefined && p.ref !== `refs/heads/${publisher.branch}`) return false;
    if (publisher.trigger !== undefined && !publisher.trigger.includes(p.trigger)) return false;
  }
  if (reviewed !== undefined && (skill.reviewed_by !== null) !== reviewed) return false;
  if (capabilities) {
    const r = reach(skill);
    if (capabilities.shell && !r.shell) return false;
    if (capabilities.any_website && r.hosts.size === 0) return false;
    if (capabilities.websites && ![...r.hosts].some((host) => hostAllowed(capabilities.websites!, host) || host === '*')) return false;
    if (capabilities.no_declaration && skill.declaration !== null) return false;
    if (capabilities.incomplete && skill.profile.complete) return false;
    if (capabilities.undeclared) {
      const d = skill.declaration;
      const undeclared = d !== null && (skill.profile.web_hosts.some((host) => !hostAllowed(d.network.allow, host)) || (skill.profile.scripts.length > 0 && d.shell !== true));
      if (!undeclared) return false;
    }
  }
  if (update) {
    const base = facts.base;
    if (!base || base.reviewed_by === null || base.digest === skill.digest || base.name !== skill.name) return false;
    if (!samePublisher(base.published_by, skill.published_by)) return false;
    if (escalation(base, skill) !== null) return false;
    if (update.max_days_since_review !== undefined && now.getTime() - Date.parse(base.reviewed_by.issued_at) > update.max_days_since_review * DAY_MS) return false;
  }
  return true;
}

/** Capability rules only tighten: they come from heuristics and self-declarations, so they can never be why a Skill is admitted. */
const isTightener = (rule: Rule) => rule.when.capabilities !== undefined;

export function evaluate(rules: Rules, facts: Facts, now: Date): Decision {
  const matched = rules.rules.filter((rule) => matches(rule, facts, now));
  // Strictest wins; among equals, the first rule in the file names the decision.
  const strictest = (list: Rule[]) => list.reduce<Rule | null>((best, rule) => (best === null || RANK[rule.action] > RANK[best.action] ? rule : best), null);
  // The base decision comes from publisher, review and update rules (or the default); tighteners can only raise it.
  const basis = strictest(matched.filter((rule) => !isTightener(rule)));
  const tightener = strictest(matched.filter(isTightener));
  const baseAction = basis?.action ?? rules.default;
  const deciding = tightener && RANK[tightener.action] > RANK[baseAction] ? tightener : basis;
  const act = deciding?.action ?? rules.default;
  let missing: string | null = null;
  if (act === 'REQUIRE_REVIEW' || (deciding === null && !ADMITTED.has(act))) {
    if (facts.base && facts.skill.reviewed_by === null) {
      const why = facts.base.name !== facts.skill.name ? `the supplied base is another Skill (${facts.base.name})`
        : facts.base.reviewed_by === null ? 'the supplied base version has no valid review'
        : !samePublisher(facts.base.published_by, facts.skill.published_by) ? 'it was not published by the same repository and workflow as the reviewed version'
          : escalation(facts.base, facts.skill);
      missing = `a review of this exact version (reviewed-by)${why ? `; it is not a plain update because ${why}` : ''}`;
    } else if (facts.skill.reviewed_by === null) missing = 'a review of this exact version (reviewed-by)';
  }
  return { action: act, admitted: ADMITTED.has(act), rule_id: deciding?.id ?? 'default', matched: matched.map((rule) => rule.id), reason: deciding?.reason ?? null, missing };
}

/* ********************************************  */
/*                   Replay                      */
/* ********************************************  */

export interface AdmissionRecord { decided_at: string; rules_digest: string; facts: Facts; decision: Decision }

export interface Flip { decided_at: string; skill: string; digest: string; before: Decision; after: Decision }

const isList = (value: unknown, item: (v: unknown) => boolean) => Array.isArray(value) && value.every(item);
const isText = (value: unknown) => typeof value === 'string';
const nullOr = (value: unknown, check: (v: unknown) => boolean) => value === null || check(value);
const isDate = (value: unknown) => typeof value === 'string' && /^\d{4}-\d\d-\d\dT/u.test(value) && !Number.isNaN(Date.parse(value));
const texts = (value: unknown) => isList(value, isText);

function validDeclaration(d: unknown): boolean {
  return isMap(d) && isMap(d.network) && texts(d.network.allow) && nullOr(d.network.deny, isText)
    && isMap(d.files) && texts(d.files.read) && texts(d.files.write) && texts(d.files.deny_write)
    && nullOr(d.shell, (v) => typeof v === 'boolean') && texts(d.tools) && texts(d.unknownKeys)
    && isMap(d.requires) && texts(d.requires.binaries) && nullOr(d.requires.min_runtime_version, isText);
}

/** Checks a logged skill record field by field: a missing field must never read as present (undefined !== null). */
function validSkillFacts(value: unknown): value is SkillFacts {
  if (!isMap(value)) return false;
  const p = value.profile;
  return isText(value.name) && isText(value.digest) && isMap(p) && isList(p.web_hosts, isText) && isList(p.programs, isText)
    && isList(p.scripts, (s) => isMap(s) && isText(s.path)) && typeof p.complete === 'boolean'
    && nullOr(value.declaration, validDeclaration) && nullOr(value.declaration_error, isText)
    && nullOr(value.reviewed_by, (r) => isMap(r) && isDate(r.issued_at) && isDate(r.expires_at) && isText(r.certificate_id) && isText(r.approver_key_id))
    && nullOr(value.published_by, (b) => isMap(b) && isText(b.repository_id) && isText(b.workflow));
}

export function validRecord(value: unknown): value is AdmissionRecord {
  return isMap(value) && isText(value.decided_at) && isText(value.rules_digest) && isMap(value.facts)
    && validSkillFacts(value.facts.skill) && nullOr(value.facts.base, validSkillFacts);
}

/** Every past decision whose action would change under `next`, each re-evaluated at its own time. */
export function replay(previous: Rules, next: Rules, records: readonly unknown[]): Flip[] {
  const flips: Flip[] = [];
  for (const [index, record] of records.entries()) {
    if (!validRecord(record)) throw new Error(`log record ${index + 1} is not a complete admission record`);
    const at = new Date(record.decided_at);
    if (Number.isNaN(at.getTime())) throw new Error(`log record ${index + 1} has an invalid time`);
    const before = evaluate(previous, record.facts, at);
    const after = evaluate(next, record.facts, at);
    if (before.action !== after.action) flips.push({ decided_at: record.decided_at, skill: record.facts.skill.name, digest: record.facts.skill.digest, before, after });
  }
  return flips;
}
