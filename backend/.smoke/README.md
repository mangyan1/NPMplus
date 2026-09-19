# Docker security and browser checks

Run from the repository root with Docker available:

```sh
pnpm --dir backend install --frozen-lockfile
pnpm --dir backend exec playwright install chromium
docker build -t npmplus:security-ci .
node backend/.smoke/docker-security.mjs
```

On Linux, install browser system dependencies with `pnpm --dir backend exec playwright install --with-deps chromium`.
Playwright and its browser revision are pinned by the backend development lockfile. They are not production dependencies.
Set `NPMPLUS_TEST_IMAGE` to exercise another locally available image.

The runner creates randomly named containers and data volumes, publishes only on loopback with dynamically assigned ports,
waits for Docker health, and removes its containers and volumes in a `finally` block. Credentials are synthetic.
It runs the API privilege/replay checks, modal interactions, and first-admin setup/MFA browser walkthrough.
The `security-browser` GitHub workflow builds the checked-out source and runs the same command on pushes and pull requests.

Modal coverage includes user and permission saves, password setting, invalid forms, cancellation, deletion, certificate
forms, and audit details. Only a synthetic certificate and its failed renewal response are intercepted: renewal starts as
soon as its dialog opens, so this fixture avoids contacting an ACME service. Certificate issuance remains covered separately
by the backend certificate tests. Other API requests use the actual container backend.

Screenshots contain synthetic data, remain ignored locally, and are retained for seven days in CI. The runner does not
upload browser traces, cookies, enrollment secrets, or container logs.

The older SQLite upgrade fixture is `backend/test/sqlite-upgrade.test.js`, included in the normal backend test suite.
It reconstructs the pre-replay schema, seeds an existing MFA account and proxy, then invokes the production migration path
and verifies login, replay rejection, repeat startup, and preserved configuration.
