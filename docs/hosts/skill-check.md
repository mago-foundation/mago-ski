# Skill check Action (free, no keys)

A GitHub Action for any repository that publishes Skills. It works on the Skills that exist today: it needs no keys, no accounts, no mago-ski setup and no new file from the author.

For every Skill (a folder with a `SKILL.md`) it does two things:

1. **Shows what the Skill's files contain**: the websites they name, the files that are code (scripts, executables, shell code blocks) and the programs that shell code calls. This is the Skill's [observed profile](../spec/observed-profile-v1.md). It is computed from the bytes alone and never from what the Skill says about itself.
2. **Checks a declaration, if the Skill has one.** A Skill may declare its needs in the `permissions` block of the [OWASP Universal Skill Format](https://github.com/OWASP/www-project-agentic-skills-top-10/blob/main/universal-skill-format.md) (USF) v1.0, in its `SKILL.md` frontmatter. If it does, the check fails when the declaration does not cover what the files contain.

The check does not say that a Skill is safe. It states what the files contain and whether the Skill's own declaration covers it.

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
      - uses: mago-foundation/mago-ski/check@v0.5.0-beta.1
```

Pin the Action to a full commit SHA if your repository pins its Actions. Use `pull_request`, not `pull_request_target`: the check needs no secrets and no write access. The Action installs its single dependency (`yaml`) from mago-ski's lockfile, with install scripts turned off.

Inputs:

- `path` (default `.`): the folder to search for Skills. `.git` and `node_modules` folders are skipped.
- `require-manifest` (default `false`): when `true`, a Skill without a readable USF declaration fails.

Run the same check locally with `mago-ski check SKILL_DIR [--require-manifest]`.

## Results

| Situation | Result |
|---|---|
| No `permissions` block | **Pass**, with the profile shown and a block to paste. Fails only with `require-manifest: true`. |
| The declaration covers the profile | **Pass.** |
| A web address (`http://` or `https://`) in any file has a host that `permissions.network.allow` does not cover | **Fail** |
| Scripts or shell code exist and `permissions.shell` is not `true` | **Fail** |
| A `permissions` block exists but cannot be read one way only (see below) | **Fail** |
| A `permissions` block exists and some files could not be searched (binary, not UTF-8, over 2 MiB, or left out by `.skilldigestignore`; images, fonts and media are fine) | **Fail**: the declaration cannot be checked against them |
| The frontmatter is not valid YAML and declares nothing | **Pass**, with a note that hosts may not read the Skill's name and description |

`network.allow` entries are host names: `api.example.com` covers only that host; `*.example.com` covers its subdomains but not `example.com` itself; `"*"` covers every host, and the summary says so. `files`, `tools` and `requires.binaries` are shown but not checked against the files, because a tool cannot reliably tell them from ordinary text.

## Declaring what a Skill needs

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

The job summary shows a block filled in from the profile. Read it before you paste it: it lists what the files contain, not what the Skill should be allowed to do.

## How the frontmatter is read

The frontmatter is ordinary YAML and is read with a full YAML parser, so anything a YAML reader accepts is accepted: multi-line and quoted descriptions, folded and literal blocks, anchors, Unicode.

YAML readers disagree on some unquoted values. YAML 1.1 (used by PyYAML and others) reads `yes`, `no`, `on`, `off`, some numbers and dates as non-text; YAML 1.2 reads them as text. The declaration is therefore read under both rules. If a declared field reads differently, the check reports it instead of guessing which reader a host uses. Write `shell: true` or `false`, and quote values such as `"on"`.

A few YAML forms make readers disagree, or are accepted by some readers and refused by PyYAML. A frontmatter that uses them cannot carry a declaration: directives and document markers inside it (`%YAML`, `---`, `...`), tags (`!!str`, `!x`), `?` keys, lists or maps used as keys, tabs outside quoted or `|`/`>` text (in unquoted values and keys too), a `:` without a key, control characters and the Unicode line breaks U+0085, U+2028 and U+2029, duplicate keys, more than 2,000 keys or 50 anchors and aliases, or more than 64 KiB. A Skill that uses them and has a `permissions` key fails; one without a `permissions` key passes with a note.

## On pull requests

The summary also lists what the change adds compared with the base branch, in plain words: new websites used or declared, a switch to `shell: true`, new scripts, new programs in shell code, new files to read or write, files no longer protected from writes, and new tools. This list is for the reviewer and does not affect the result: pass or fail depends only on the pull request's own files. The base revision is checked out directly to the runner's temporary folder, outside the workspace, without persisting credentials.

## Limits

- Written instructions cannot be fully checked by a tool. A Skill can tell the model, in ordinary words, to visit a site or run a command. The check sees it only when the address or code is written out. Review by a person stays in the picture.
- Web addresses are found only when written with `http://` or `https://` (not `ws://`, `ftp://`, `ssh://`, `git@…` or a bare host name). Shell code is found in fenced Markdown code blocks only: not in indented code blocks, HTML `<pre><code>`, other languages' code that starts a process (Python's `os.system`, `awk`'s `system()`), or non-Markdown text files; there, scripts count by type, `#!` or the executable bit.
- USF v1.0 is a proposal and may change; this check follows it. `content_hash` and `signature` are not checked: USF does not yet define what they cover. Keyless signing of releases comes in the next step of 0.5.0.
- Linux and macOS runners only.
