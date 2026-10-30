// Which version a user action may record. Kept free of the DOM so it can be tested directly.
import type { InstanceDetail, InstanceView } from '../service/types.ts';

/** True when the loaded detail describes exactly the versions the latest view reports for this Skill. */
export function detailMatches(instance: InstanceView, detail: InstanceDetail | null): detail is InstanceDetail {
  if (!detail || detail.instance.id !== instance.id) return false;
  if (detail.instance.currentDigest !== instance.currentDigest || detail.instance.baselineDigest !== instance.baselineDigest) return false;
  if (detail.change && (detail.change.currentDigest !== instance.currentDigest || detail.change.baselineDigest !== instance.baselineDigest)) return false;
  return true;
}

/**
 * The digest an action may record: the one whose change is on screen. Null while the shown detail is
 * missing, loading or stale, so the user can never record a version they were not shown.
 */
export function actionDigest(instance: InstanceView, detail: InstanceDetail | null): string | null {
  if (!detailMatches(instance, detail)) return null;
  if (instance.state === 'changed' || instance.state === 'reviewed') return detail.change?.currentDigest ?? null;
  return detail.instance.currentDigest;
}
