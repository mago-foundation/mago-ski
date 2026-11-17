/** A block requires a completed UserPromptSubmit hook, exit 2 and a nonempty stderr reason. */
export function promptDenied(observations) {
  return observations.some((o) => o?.event === 'UserPromptSubmit' && o.code === 2 && o.signal === null && o.reason === true);
}

export function parseObservations(text) {
  try {
    return text.trim() ? text.trim().split('\n').map((line) => JSON.parse(line)) : [];
  } catch { return []; }
}
