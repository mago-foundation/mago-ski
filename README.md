# mago-ski (preview)

`mago-ski` (Skills PKI) is Mago's open-source tool for organizations that approve exact Skill versions and enforce those approvals on the agent host. Licensed under Apache-2.0. TypeScript is the single planned implementation; the current sources are JavaScript ES modules seeded from the earlier `skill-pki` preview and are pending conversion.

This is a standalone local package for measuring Skill-directory bytes, creating signed manifests, verifying trust and exact-digest approval, and producing a bounded content diff. It requires Node.js 22 or newer and has no npm runtime dependencies. It does not call the Mago Registry or any Mago API; the existing registry backend is optional and unchanged.

This implementation, its website, and code access remain preview-only. This document is not a public release, general-availability, safety, benign-behavior, OWASP, or USF claim. No OWASP/USF conformance or affiliation is asserted.

## Local quickstart: Ed25519

From the repository root, this creates a temporary Skill and a **local demonstration-only** key, trust file, and approval. It does not publish anything or contact a service. Use an independently controlled trust policy and an authorized approval process outside candidate-controlled content for real use.

```sh
node --version # 22 or newer
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/skills/demo" "$work/policy"
printf '# Demo Skill\nRead-only example instructions.\n' > "$work/skills/demo/SKILL.md"

keygen="$(node bin/mago-ski.mjs keygen \
  --private-key "$work/policy/demo-private.pem" \
  --public-key "$work/policy/demo-public.pem")"
node bin/mago-ski.mjs init \
  --skill "$work/skills/demo" \
  --manifest "$work/policy/demo.manifest.json" \
  --name demo

# Build canonical example trust and approval sidecars from the demo key/digest.
node --input-type=module - "$work" "$keygen" <<'NODE'
import path from 'node:path';
import {
  APPROVAL_VERSION,
  TRUST_VERSION,
  makeEd25519TrustEntry,
  readManifest,
  writeNewCanonicalFile,
} from './src/index.mjs';

const root = process.argv[2];
const key = JSON.parse(process.argv[3]);
const policy = path.join(root, 'policy');
await writeNewCanonicalFile(path.join(policy, 'trust.json'), {
  trust_version: TRUST_VERSION,
  ed25519: [makeEd25519TrustEntry(
    key.key_id, Buffer.from(key.public_key_spki_base64, 'base64'),
  )],
  sigstore: [],
});
const manifest = await readManifest(path.join(policy, 'demo.manifest.json'));
await writeNewCanonicalFile(path.join(policy, 'approvals.json'), {
  approval_version: APPROVAL_VERSION,
  approvals: [{ skill_name: manifest.skill_name, digest: manifest.tree_digest }],
});
NODE

node bin/mago-ski.mjs sign \
  --skill "$work/skills/demo" \
  --manifest "$work/policy/demo.manifest.json" \
  --profile ed25519 \
  --signature "$work/policy/demo.signature.json" \
  --private-key "$work/policy/demo-private.pem"
node bin/mago-ski.mjs verify \
  --skill "$work/skills/demo" \
  --manifest "$work/policy/demo.manifest.json" \
  --profile ed25519 \
  --signature "$work/policy/demo.signature.json" \
  --trust "$work/policy/trust.json" \
  --approvals "$work/policy/approvals.json"
```

The final command prints `VERIFIED_APPROVED`. The example intentionally creates its own trust and approval only to demonstrate CLI wiring; it is not an organizational approval workflow. Keep private keys outside Skill roots and do not commit them. On POSIX, keygen creates the private-key file with mode `0600`; Windows ACLs are the caller's responsibility. Manifests, signatures/bundles, trust, approvals, and trusted roots are sidecars and must remain outside the Skill directory.

## Profiles, trust, and approval

### Offline Ed25519

`init`, `keygen`, Ed25519 `sign`, `verify`, and `diff` use Node's built-in modules and need no network. Configure the trusted public key explicitly in `mago.skill-trust/v1`; a key ID declared by a manifest or signature is not itself a trust anchor. Keep trust and approval files in a policy-controlled location outside candidate content. Signing requires the corresponding external private key, which must remain secret.

### Sigstore keyless (kept, not on the Phase 1 critical path)

The Sigstore profile is retained and tested, but Phase 1 acceptance does not depend on it.


Keyless signing delegates to the official Cosign **v3.1.3** binary, whose platform-specific checksum and version are checked by the package. It creates a bundle with the equivalent of:

```sh
cosign sign-blob --yes --bundle <bundle> <payload>
```

Signing requires an OIDC identity/token and network access to the Sigstore signing and transparency services (including Fulcio and Rekor). Mago does not log in, acquire identity, or implement Sigstore cryptography.

Verification requires the exact certificate identity and OIDC issuer to be supplied and to match an entry in the explicit trusted config, plus that entry's adjacent trusted-root file. The verifier checks the bundle against the payload with Cosign's `verify-blob --bundle ... --trusted-root ... --certificate-identity ... --certificate-oidc-issuer ...` flow. The pinned public-good bundle and explicit trusted root have been verified with networking blocked; no deprecated `--offline` flag is used. A local verifier needs the pinned binary, bundle, trust config, trusted root, identity, and issuer, but no network for this tested bundled-material path. Keyless signing remains online and identity-dependent.

For either profile, `verify` separates three results: current Skill bytes match the manifest, the signature is valid under an explicitly configured signer, and the exact `(skill_name, tree_digest)` has an external approval. A valid signature is not approval. A changed digest requires a new explicit approval even if the diff finds no change in its partial capability evidence. Verification does not create or update approvals.

## Digest and diff semantics

The `mago.skill-tree/v1` SHA-256 profile covers every regular file's normalized relative UTF-8 path, byte length, and raw bytes in stable path order, with a versioned framing header. It rejects symlinks, special files, ambiguous/colliding paths, and resource-limit violations. Empty directories and filesystem metadata are not covered. Keep the manifest, detached signature or bundle, policy, and approval files outside the tree.

`diff` compares two directory snapshots and their manifests against an approval file; it does not verify signatures and does not modify policy. It reports added, deleted, and modified files, with bounded Markdown section labels. Its capability evidence is deliberately partial: it looks only for HTTP(S) origins in bounded UTF-8 text (up to 2 MiB per file and 128 distinct origins); unsupported, oversized, binary, or incomplete inputs may make analysis inconclusive. Output is capped at 200 changed files and 32 changed section labels per file.

- `VERIFIED_UNCHANGED` is limited to identical covered bytes whose exact digest is approved.
- For changed bytes, a detected origin delta is `CAPABILITY_CHANGED`; no detected delta is `INCONCLUSIVE`, not unchanged or safe. Incomplete evidence is also inconclusive.
- A candidate digest is never approved by diffing. Changed content needs a separate explicit approval for that exact digest, even when extracted capability evidence is unchanged.

These outputs are integrity/provenance and review evidence only. They do not establish safety or benign behavior.

## Pi host

The earlier Bubblewrap-sealed offline Pi launcher was dropped. Phase 1 targets a Pi extension that gates Skills inside a normal Pi session; it is not implemented yet.

## Checks

```sh
npm test
```

The Sigstore public-fixture test requires `MAGO_COSIGN_BIN` pointing to the checksum-pinned Cosign v3.1.3 binary; to establish offline verification, run that test with network access blocked (for example, in Bubblewrap with `--unshare-net`). Mocked Cosign tests cover process arguments and failure handling, not cryptographic verification.
