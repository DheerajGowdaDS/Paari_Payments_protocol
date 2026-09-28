"""Test-environment isolation must be provable, not merely present.

The Blueprint asked for one specific guarantee: an operator shell carrying
`PAARI_REQUIRE_USER_MANDATE=1` cannot silently switch the suite into autonomous
posture. The first version of this file asserted that by running a test which
checks `decision == "deny"` for an over-cap payment - and that assertion is
produced by the delegated-limit check, which runs about twenty lines before the
mandate posture is consulted at all. It therefore passed identically whether
isolation was working or deleted, which is the worst kind of green: a suite that
claims to guard a property it cannot observe.

So this file tests two directions.

  1. POSITIVE - with the polluting environment set, a test that only passes in
     STANDARD posture still passes. Isolation held.
  2. CANARY - with that same polluting environment, a process that does NOT get
     the isolation fixture resolves to AUTONOMOUS. This is what makes (1)
     meaningful: it proves the pollution was live, so (1) passing is evidence
     about the fixture rather than evidence that the leak was inert.

Delete `isolate_test_environment` from conftest and the positive test goes red.
Delete the canary and the positive test silently loses its teeth again.
"""
import os
import pathlib
import re
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]

POLLUTION = {
    "PAARI_REQUIRE_USER_MANDATE": "1",
    "PAARI_MODE": "autonomous",
    "PAARI_REQUIRE_SIGNED_MANDATE": "1",
}

# A test that asserts an ALLOW with no mandate in play. In autonomous posture the
# same request is denied ("no active user payment mandate"), so this target is
# only green while the baseline posture is standard.
POSTURE_SENSITIVE_TARGET = "tests/test_audit.py::test_audit_chain_answers_eleven_questions"


def _polluted_env() -> dict:
    env = os.environ.copy()
    env.update(POLLUTION)
    return env


def test_pollution_is_live_without_the_fixture():
    """Canary: the same environment, absent conftest isolation, really does
    resolve to autonomous. If this stops being true, the positive test below is
    proving nothing and both must be retargeted."""
    probe = (
        "import os,sys;"
        "sys.path.insert(0, {root!r});"
        "from app.config import mandate_policy;"
        "p = mandate_policy();"
        "print(p.mode.value, p.mandate_required, p.require_signed_mandate)"
    ).format(root=str(REPO))
    res = subprocess.run([sys.executable, "-c", probe], env=_polluted_env(),
                         capture_output=True, text=True, cwd=str(REPO))
    assert res.returncode == 0, res.stderr
    mode, required, signed = res.stdout.strip().split()
    assert (mode, required, signed) == ("autonomous", "True", "True"), (
        f"pollution no longer flips posture ({res.stdout.strip()}); "
        "the isolation test is vacuous until this canary passes")


def test_ambient_shell_mandate_env_does_not_pollute_the_suite():
    """Positive: under the identical pollution, the suite stays in standard
    posture and a posture-sensitive test still passes."""
    res = subprocess.run(
        [sys.executable, "-m", "pytest", POSTURE_SENSITIVE_TARGET, "-q", "--no-header", "-x"],
        env=_polluted_env(), capture_output=True, text=True, cwd=str(REPO),
    )
    assert res.returncode == 0, (
        f"posture-sensitive test failed under ambient mandate env:\n"
        f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
    assert "1 passed" in res.stdout, res.stdout


def test_ambient_deployment_database_url_does_not_reach_the_app():
    """`DATABASE_URL` names the deployment's database. A test run must not
    inherit it, and must not point the app under test at anything it could
    write to or drop. See tests/conftest.py's module docstring."""
    res = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_health.py", "-q", "--no-header"],
        env={**_polluted_env(),
             "DATABASE_URL": "postgresql://user:pw@127.0.0.1:1/definitely_not_a_real_db",
             "ALEMBIC_URL": "postgresql://user:pw@127.0.0.1:1/definitely_not_a_real_db",
             "PAARI_LIVE": "1"},
        capture_output=True, text=True, cwd=str(REPO),
    )
    assert res.returncode == 0, (
        "an ambient deployment DATABASE_URL / PAARI_LIVE leaked into the suite:\n"
        f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")


def test_harness_labels_are_read_from_the_server_not_the_process():
    """Every E2E harness prints mode/provider/llm. Those labels are only worth
    anything if the server supplied them, so the derivation is pinned here
    rather than left to a reviewer reading a banner."""
    reads_posture_from_health = re.compile(r"health\w*\.(?:get\(\s*|__getitem__)['\"]mandate_mode")
    for name in ("foreign_agent_proof.py", "llm_agent_e2e.py", "autonomous_payment_e2e.py"):
        source = (REPO / "scripts" / name).read_text(encoding="utf-8")
        assert '"autonomous" if REQUIRE_MANDATE' not in source, (
            f"{name} derives governance posture from its own CLI flag")
        assert 'provider_str = "real-razorpay" if os.environ' not in source, (
            f"{name} derives provider mode from its own process environment")
        assert reads_posture_from_health.search(source), (
            f"{name} never reads mandate_mode from the server's /health response")
