# Skill check Action (free, no keys)

A GitHub Action for any repository that publishes Skills. It compares what each Skill declares about itself with what its files contain, and fails the check when a Skill uses something it did not declare. It needs no keys, no accounts and no mago-ski setup.

It reads the [OWASP Universal Skill Format](https://github.com/OWASP/www-project-agentic-skills-top-10/blob/main/universal-skill-format.md) (USF) v1.0 from the YAML frontmatter of each `SKILL.md`. The authors do not have to add a mago-ski file.

The check does not say that a Skill is safe. It says whether the Skill's files match what the Skill declares.

## Set up

```yaml
# .github/workflows/skill-check.yml
name: skill check
on: [pull_request, push]
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
      - uses: mago-foundation/mago-ski/check@v0.5.0
```

Pin the Action to a full commit SHA if your repository pins its Actions. Use `pull_request`, not `pull_request_target`: the check needs no secrets and no write access.

Input: `path` (default `.`): the folder to search for Skills (any folder that holds a `SKILL.md`). `.git` and `node_modules` are skipped.

## Declaring what a Skill needs

Add a `permissions` block to the frontmatter of `SKILL.md`:

```yaml
---
name: release-notes
description: Writes release notes from merged pull requests.
permissions:
  network:
    allow: [api.github.com]
    deny: "*"
  shell: true
  files:
    read: [CHANGELOG.md]
  tools: [web_fetch]
requires:
  binaries: [gh]
---
```

When a check fails, the job summary shows a `permissions` block filled in from what was found. Read it before you paste it in: it lists what the files contain, not what the Skill should be allowed to do.

## What fails the check

| Rule | Fails when |
|---|---|
| Websites | A web address (`http://` or `https://`) in any file of the Skill has a host that `permissions.network.allow` does not cover. |
| Commands | The Skill has scripts or shell commands and `permissions.shell` is not `true`. Scripts are files with the executable bit, files that start with `#!`, files with a script extension (`.sh`, `.py`, `.js`, `.ts`, `.rb`, `.ps1` and others), and shell code blocks (`bash`, `sh`, `console`, `powershell` and others) in Markdown files. |
| No manifest | `SKILL.md` has no `permissions` block. |
| Files it cannot search | A file is binary, not UTF-8 text, or larger than 2 MiB, unless it is an image, font, audio or video file (by extension). A file left out by `.skilldigestignore` fails too: the Skill's own files cannot decide what the check skips. |
| Unreadable manifest | The `permissions` or `requires` block uses YAML this check does not accept (see below), or a value has the wrong type. |

`network.allow` entries are host names: `api.example.com` covers only that host; `*.example.com` covers its subdomains but not `example.com` itself; `"*"` covers every host, and the summary says so.

`files`, `tools` and `requires.binaries` are listed in the summary but not checked against the files: a tool cannot reliably tell them from ordinary text.

Images, fonts and media files are not searched; the summary names them.

## On pull requests

The summary also lists what the change adds compared with the base branch, in plain words: new websites used or declared, a switch to `shell: true`, new scripts, new files to read or write, files no longer protected from writes, new tools and new programs. This list is for the reviewer and does not affect the result: pass or fail depends only on the pull request's own files. The base revision is checked out to the runner's temporary folder, outside the workspace; a repository that contains a `.mago-ski-check-base` path is refused, because the check reserves it.

## Accepted YAML

The whole frontmatter is read with a strict subset of YAML, so that this check and another YAML reader cannot disagree about what a Skill declares: nested `key: value` blocks, lists written as `- item` lines (items may be `key: value` blocks, as in the USF `changelog`) or as `[a, b]` on one line, plain, `'single'` or `"double"` quoted values on one line, `|` and `>` blocks (with an optional `+` or `-`, but no indentation digit), plain values that go on over more-indented lines, `true`/`false`, and `#` comments. Anchors, aliases, tags, quoted or `?` keys, `{…}` maps, quoted or `[…]` values over several lines, tabs (except inside `|` and `>` text), a `?` in an unquoted `[…]` item, the bare values `=` and `<<`, dates that do not exist, duplicate keys, an unquoted value that contains `: `, control characters and Unicode spaces (such as the no-break space) are refused anywhere in the frontmatter, and the Skill then fails with the line number. Only `permissions` and `requires` are used; the other keys are read but not checked. As in YAML 1.1, unquoted `yes`, `no`, `on`, `off`, numbers and dates are not text: write `shell: true`, and quote a host such as `"on"`.

## Limits

- Written instructions cannot be fully checked by a tool. A Skill can tell the model, in ordinary words, to visit a site or run a command, and this check will not see it unless the address or code block is written out. Review by a person stays in the picture.
- USF v1.0 is a proposal and may change; this check follows it.
- `content_hash` and `signature` are not checked yet. USF does not yet define what they cover. Signing comes in a later step of 0.5.0.
- Shell code blocks are found only in Markdown files (`.md`, `.markdown`, `.mdx`); in other text files only scripts by type, `#!` or the executable bit count.
- Web addresses are found only when written with `http://` or `https://`. Skills inside `.git` and `node_modules` folders are not searched.
- Linux and macOS runners only.
