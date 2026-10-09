# Skill tree digest: `mago.skill-tree/v2`

Status: draft, implemented by mago-ski 0.1. Test vectors: [`tests/vectors/trees.json`](../../tests/vectors/trees.json).

The tree digest identifies the exact contents of a Skill directory. A certificate approves one tree digest.

## Which files are covered

Start at the Skill root (the directory that holds `SKILL.md`) and walk it recursively.

- Every regular file is covered, except:
  - the entry named `.git` at the root (file or directory);
  - the file `.mago-ski-cert.json` at the root (the in-tree certificate);
  - paths listed in `.skilldigestignore` at the root (below).
- `.skilldigestignore` itself is covered when present.
- `SKILL.md` at the root is required and always covered. A tree without it is not a Skill and has no digest.
- These make the whole tree **unverifiable** (the digest is not computed):
  - symbolic links, sockets, FIFOs, devices;
  - a path component that is not valid UTF-8, is not in Unicode NFC, is empty, `.` or `..`, contains `/`, `\`, `:` or a control character, ends with a dot or space, or is a reserved Windows device name;
  - two paths that are equal after NFKC normalization and lowercasing (they would collide on case-insensitive file systems);
  - more than 20,000 files, 50,000 entries, depth 64, 64 MiB per file, 256 MiB total, or 4,096 bytes per relative path;
  - a file that changes while it is being read.
- Empty directories and other metadata (owner, timestamps, permissions other than the executable bit) are not covered.

## `.skilldigestignore`

UTF-8 text, at most 64 KiB and 256 patterns. Blank lines and lines starting with `#` are skipped. Each other line is one relative POSIX path:

- `name/` excludes the directory `name` and everything under it;
- `name` excludes a file or directory with that exact relative path.

Globs (`* ? [ ] !`), absolute paths, `.` or `..` segments, backslashes, the ignore file itself and `SKILL.md` are rejected.

Excluded files are not approved. Hosts must not serve them as Skill content: the Pi host refuses to read any file inside a verified Skill that is not in the certificate's file list.

## Per-file record

For each covered file:

| Field | Value |
|---|---|
| `path` | Relative path, `/`-separated, UTF-8, NFC |
| `size` | Byte length |
| `sha256` | Lowercase hex SHA-256 of the raw bytes (no line-ending normalization) |
| `exec` | `true` if any POSIX execute bit (`0o111`) is set. Always `false` on Windows, which has no mode bits |

## Digest

1. Sort records by the UTF-8 bytes of `path` (byte order, not locale order).
2. Build `{"files": [...records], "profile": "mago.skill-tree/v2"}`.
3. Serialize as canonical JSON: object keys sorted, no whitespace, integers only, one trailing LF.
4. The digest is `sha256:` followed by the lowercase hex SHA-256 of those bytes.

Because the digest is computed from the record list, anyone holding a certificate's file list can recompute and check its digest, and a host can verify a single file by comparing its hash with one record.

## Known limitations

- On Windows the executable bit is always `false`, so a Skill approved on Linux or macOS with an executable script will not verify on Windows. mago-ski 0.1 does not support Windows for this reason.
- Some file systems report every file as executable (for example WSL's DrvFs mounts of Windows drives). Digest Skills on a native Linux or macOS file system.
