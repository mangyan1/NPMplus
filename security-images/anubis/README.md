# Patched Anubis build

This build retains Techaro's Anubis v1.28.1 application and runtime layout while
rebuilding its executable with Go 1.26.9, gRPC 1.84.0, x/text 0.42.0, x/net 0.60.0,
and cel.dev/cel-go 0.32.0. Source and runtime image are pinned to immutable
revisions. The upstream MIT license is included in the final image.

The generated JavaScript, CSS, localization, templates, WASM and JavaScript
fallback assets are rebuilt using the upstream lockfiles and a digest-pinned Rust
1.99.0 build stage. Rust tests, upstream Go unit tests and Go vet run before the
executable is copied into the final image. The runtime retains user 1000,
`/ko-app/anubis`, the trust store, and upstream data. No challenge, honeypot, or
policy rule is removed.

The Security Images workflow tests and scans both AMD64 and ARM64 candidates
before promoting their exact digests to `ghcr.io/mangyan1/npmplus:anubis`.
Candidate and commit tags do not move the upstream Anubis tags. Installer adoption
is a separate change, with explicit policy-version compatibility and recovery
checks.

Local verification:

```sh
docker build -t npmplus-anubis:check security-images/anubis
python3 security-images/anubis/smoke.py npmplus-anubis:check
```

The fork owns updates to these dependency pins and the base image. Reassess the
build whenever upstream releases a newer stable version; do not silently combine
a new policy document with an older binary.

Anubis 1.28.1 checks for a 64-byte signing key at startup, including when
`HS512_SECRET` is supplied. Manual deployments using that variable must provide
exactly 64 bytes. The synthetic smoke fixture uses a 64-byte key; the installer
does not set `HS512_SECRET` and keeps upstream's Ed25519 default.
