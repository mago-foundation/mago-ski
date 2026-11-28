# Observed profile v1 (`mago.observed-profile/v1`)

Status: draft, part of mago-ski 0.5.0.

An observed profile states what a Skill's own files show: the websites they name, the files that are code, and the programs that shell code calls. It is computed from the bytes alone, deterministically and offline. It never reads the Skill's frontmatter, so what a Skill says about itself cannot change it. A declaration (such as an OWASP Universal Skill Format manifest) can be compared with a profile, and a `published-by` attestation (0.5.0 step 2) records one.

A profile is a list of facts about the content. It does not say a Skill is safe, and it is not complete: instructions written in ordinary words are not extracted.

## Input

The files of the Skill tree as defined by [skill-tree v2](skill-tree-v2.md): the same file set, the same bytes and the same executable bits that the tree digest covers. Files that skill-tree v2 leaves out are not profiled; `.skilldigestignore` entries are listed as `not_searched.ignored`.

## Output

```json
{
  "profile": "mago.observed-profile/v1",
  "digest": "sha256:<tree digest of the same bytes>",
  "web_hosts": ["api.example.com"],
  "scripts": [{ "path": "scripts/run.sh", "reason": ".sh file" }],
  "programs": ["curl", "jq"],
  "not_searched": { "media": [], "unreadable": [], "ignored": [] },
  "complete": true
}
```

Lists are sorted by code point, except `scripts`, which follows the tree's file order.

## Rules

**Searchable file.** A file is searchable when it is at most 2 MiB, contains no NUL byte, and is valid UTF-8. A file that is not searchable goes into `not_searched.media` if its extension is one of `.png .jpg .jpeg .gif .webp .avif .bmp .ico .tif .tiff .heic .woff .woff2 .ttf .otf .eot .mp3 .wav .ogg .flac .m4a .mp4 .webm .mov`, and into `not_searched.unreadable` otherwise. Extensions are compared in lower case.

**web_hosts.** In every searchable file, each match of `https?://[^\s"'`<>()[\]{}]+` (case-insensitive), with trailing `.,;:!?` removed, is parsed as a WHATWG URL. If the scheme is `http` or `https`, the URL's host name is added. A match that does not parse adds nothing. Limits: 128 distinct origins, 100,000 matches per tree, and 262 characters per origin. Reaching a limit sets `complete` to false. These are the same rules as the network-origin scan in `mago-ski diff` (`mago.network-origin-scan/v1`). In addition, each match of `https?://\[[0-9A-Fa-f:.]{2,45}\](?::[0-9]{1,5})?` (a bracketed IPv6 address, which the first pattern does not match) is parsed the same way and its host name added in the URL parser's normal form (for example `[::ffff:a9fe:a9fe]`), up to 128 more hosts. For a match that contains `\`, the host another URL parser reads is added too: the text after `://` up to the first `/`, `?` or `#`, after its last `@`, without a port and percent-decoded, if it is a plain host name or a bracketed IPv6 address (in the URL parser's normal form). Brackets are kept in this candidate. (WHATWG treats `\` as `/`, so `https://a.example\@b.example/` is `a.example` there and `b.example` in Python's `urlparse`.)

**scripts.** A file is listed, with the first reason that applies:

1. `executable file`: its executable bit is set.
2. `starts with #!`: its first two bytes are `#!`.
3. `<ext> file`: its extension is one of `.sh .bash .zsh .fish .ksh .py .js .mjs .cjs .ts .mts .cts .rb .pl .php .lua .ps1 .psm1 .bat .cmd .go .rs .java .kt .kts .swift .c .cc .cpp .cs .vbs .awk .tcl .r .jl .ex .exs .groovy .scala .applescript .scpt .jar .wasm .exe .dll .so .dylib`.
4. `build or task file`: its base name, in lower case, is `makefile`, `gnumakefile`, `justfile`, `rakefile`, `dockerfile` or `containerfile`.
5. `N shell code block(s)`: it is a searchable `.md`, `.markdown` or `.mdx` file, and N ≥ 1 of its lines match `^(?:[ \t>]|[-*+][ \t]|[0-9]{1,9}[.)][ \t])*(`{3,}|~{3,})[ \t]*\{?\.?([A-Za-z0-9_+.:-]*)` (indentation, blockquote and list markers before the fence), where the second group, in lower case and cut at the first `-`, `_`, `+`, `.` or `:`, is one of: `sh bash shell zsh fish ksh csh tcsh dash ash console shellsession shellscript terminal powershell ps1 pwsh cmd bat batch nushell nu`. So `bash-session`, `shell-script` and `sh+x` count.

Rule 5 counts opening lines without pairing fences, on purpose: no arrangement of fences can hide a shell block. A fence that a Markdown reader treats as plain text can still be counted. That errs towards listing.

**programs.** Inside shell code blocks of searchable Markdown files (a fence opens a block; a line with the same fence character, at least as long, and no info string closes it), each line is read as follows. Leading indentation, blockquote and list markers (as in rule 5) and a prompt (`$`, `PS>`, `>`, `%` followed by blanks) are removed. The line is split on blanks. Leading words that are `sudo doas env exec time nohup command builtin then do else !` or `NAME=value` assignments are skipped. Lines whose first remaining word starts with `#` are skipped. The base name of the first remaining word is added if it matches `^[A-Za-z0-9._+-]{1,64}$`. The list holds at most 200 names. It is a hint, not a complete inventory: programs called from scripts are not listed.

**complete.** `false` when `not_searched.unreadable` or `not_searched.ignored` is not empty, or when a web_hosts limit was reached. Media files do not make a profile incomplete.

## Versioning

Any change to which files, hosts, scripts or programs are reported is a new profile version. Verifiers recompute the profile themselves with the version named in the document, and never trust a profile they did not compute.
