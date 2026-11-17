// Shared by the main process and the renderer: text from outside (names, paths, reasons) never carries control or invisible characters.
/**
 * Text shown in a native dialog: controls, line and bidirectional marks and zero-width characters are replaced by
 * their code point (format characters, surrogates, private-use and unassigned code points included), so a path, name or reason cannot rewrite or hide the lines around it.
 */
export function dialogSafe(text: string): string {
  return text.replace(new RegExp(`[${HIDDEN_CLASS}]`, 'gu'), codePoint);
}

// Controls, format characters (bidirectional marks, zero-width characters, the soft hyphen, the Unicode tag block that can
// carry a hidden instruction), surrogates, private-use and unassigned code points, line and paragraph separators, variation
// selectors, and letters that render as blank (the combining grapheme joiner, the Hangul fillers, the blank Braille pattern).
const HIDDEN_CLASS = '\\p{Cc}\\p{Cf}\\p{Cs}\\p{Co}\\p{Cn}\\p{Zl}\\p{Zp}\\uFE00-\\uFE0F\\u{E0100}-\\u{E01EF}\\u034F\\u115F\\u1160\\u3164\\uFFA0\\u2800';
const codePoint = (c: string): string => `⟨U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}⟩`;

/** True when a line of a file holds a character a reader cannot see (a tab is ordinary in a file and does not count). */
export function hasHidden(line: string): boolean {
  return new RegExp(`(?!\\t)[${HIDDEN_CLASS}]`, 'u').test(line);
}

/**
 * One line of a file as shown in the diff viewer: the same characters as in a dialog are replaced by their code point, except
 * the tab. A Skill's text is what the reviewer approves, so nothing in it may be invisible.
 */
export function lineSafe(line: string): string {
  return line.replace(new RegExp(`(?!\\t)[${HIDDEN_CLASS}]`, 'gu'), codePoint);
}
