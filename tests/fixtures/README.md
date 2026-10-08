# Public Sigstore keyless verification fixture

These files are unmodified public verification material from the Sigstore Cosign `v3.1.3` GitHub release and Sigstore public-good TUF repository:

- `cosign_checksums.txt` — the release checksum document.
- `cosign_checksums.txt.sigstore.json` — the release's Sigstore bundle authenticating that checksum document.
- `cosign-trusted-root.json` — Sigstore public-good trusted root downloaded from the TUF target `trusted_root.json` (SHA-256 `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`).

Sources:

- https://github.com/sigstore/cosign/releases/tag/v3.1.3
- https://github.com/sigstore/cosign/blob/v3.1.3/LICENSE
- https://tuf-repo-cdn.sigstore.dev/ (TUF repository state at fixture capture)

The bundle's certificate identity is `keyless@projectsigstore.iam.gserviceaccount.com`; its OIDC issuer is `https://accounts.google.com`. The fixture contains only public release data and trust material; it contains no credentials or private key. Set `MAGO_COSIGN_BIN` to the official Cosign `v3.1.3` binary to run the real fixture test. To prove verification is offline, run that test inside a network-isolated sandbox (the acceptance run used Bubblewrap `--unshare-net`) with this explicit trusted root. The test performs no OIDC login or signing.
