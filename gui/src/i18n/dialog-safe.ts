// Shared by the main process and the renderer: text from outside (names, paths, reasons) never carries control or invisible characters.
/**
 * Text shown in a native dialog: controls, line and bidirectional marks and zero-width characters are replaced by
 * their code point (format characters, surrogates, private-use and unassigned code points included), so a path, name or reason cannot rewrite or hide the lines around it.
 */
export function dialogSafe(text: string): string {
  return text.replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\uFE00-\uFE0F\u{E0100}-\u{E01EF}\u034F\u3164\u2800]/gu,
    (c) => `⟨U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}⟩`);
}
