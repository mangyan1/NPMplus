# Patched Anubis build

This build retains Techaro's Anubis v1.27.0 application and runtime layout while
rebuilding its executable with Go 1.26.8, gRPC 1.83.2, x/text 0.41.0, and CEL
0.29.2. Source and runtime image are pinned to immutable revisions. The upstream
MIT license is included in the final image.

The generated JavaScript, CSS, localization, and templates are rebuilt using the
upstream lockfile. Upstream unit tests and Go vet run before the executable is
copied into the final image. The runtime retains user 1000, `/ko-app/anubis`, the
trust store, and upstream data. No challenge, honeypot, or policy rule is removed.

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
