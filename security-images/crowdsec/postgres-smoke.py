"""Run upstream's real PostgreSQL race regression with the maintained driver."""

import subprocess
import sys
import time
import uuid


def main():
    name = "npmplus-pg-smoke-" + uuid.uuid4().hex[:12]
    started = False
    try:
        subprocess.run(["docker", "run", "--rm", "-d", "--name", name,
                        "-e", "POSTGRES_PASSWORD=secret",
                        "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24"], check=True)
        started = True
        deadline = time.monotonic() + 60
        while subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            if time.monotonic() >= deadline:
                raise AssertionError("isolated PostgreSQL fixture failed to start")
            time.sleep(1)
        # No published database port. The test builder shares only this fixture's
        # network namespace; 'secret' is the upstream synthetic fixture password.
        subprocess.run(["docker", "run", "--rm", "--network", "container:" + name,
                        "-e", "CROWDSEC_PG_RACE_TEST=1", "-e", "TEST_LOCAL_ONLY=1",
                        sys.argv[1], "go", "test", "-timeout", "3m",
                        "-tags", "netgo,osusergo,expr_debug,nomsgpack,sqlite_omit_load_extension,re2_cgo",
                        "-run", "TestAlertCreateVsFlushOrphansRace", "./pkg/database"], check=True)
    finally:
        if started:
            subprocess.run(["docker", "rm", "-f", name], check=True)


if __name__ == "__main__":
    main()
