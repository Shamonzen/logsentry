"""The attacker guard is the code enforcing the lab-only hard rule, so it gets a unit test.

The refusal path (a host that is not `target`) needs no network, so it runs in normal CI.
The accept path needs DNS resolution inside the lab, so it lives in the e2e suite instead.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

GUARD = Path(__file__).resolve().parents[1] / "lab" / "attacker" / "lib.sh"
bash = shutil.which("bash")


@pytest.mark.skipif(bash is None, reason="needs bash")
def test_guard_refuses_a_non_target_host():
    result = subprocess.run(  # noqa: S603
        [bash, "-c", f". '{GUARD.as_posix()}'; guard_target"],
        env={"TARGET": "example.com", "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "refusing" in result.stderr.lower()
