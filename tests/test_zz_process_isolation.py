"""
Process-global state must not leak between tests.
================================================
Rounds 20-21 introduced three process-globals, and each is a way for one test to weaken a
security check for every test that runs after it:

    SENTINEL_PROMOTION_GATE_WITNESSED   (env)   INV-OPS-7 — a leak DISABLES the promotion
                                                gate process-wide, which is the exact
                                                failure the witness exists to prevent
    the sentinel_harness.metric log handler     INV-METRIC-1 — a stacking bug duplicates
                                                every emitted metric line
    logger.propagate = False                    pre-existing; it silently broke a `caplog`
                                                assertion in round 20 depending on whether
                                                an earlier test had called
                                                configure_logging()

The file name starts with `zz_` so pytest collects it LAST in the default alphabetical
order: these assertions are about the state the rest of the suite leaves behind, so running
them first would prove nothing.

Under `pytest-randomly` (this repo's default) collection order is shuffled, so these become
a sample rather than a guarantee — still useful, and the `-p no:randomly` CI leg gives the
ordered run. Recorded rather than worked around: an ordering-dependent check that pretends
to be absolute is worse than one that says what it covers.

A NOTE ON THE SECOND ASSERTION, which was wrong first
-----------------------------------------------------
The behavioural check originally read `assert out["ok"] is False`. With the witness
deliberately leaked, that PASSED — for the wrong reason. The gate had correctly opened, the
call proceeded to AWS, and it failed on `NoCredentialsError`, so `ok` was False with
`error == "upstream_error"`. The environment assertion caught the planted leak; the
behavioural one did not.

So it now asserts the error KIND. Two assertions that look like they test the same thing
can differ in strength, and the weaker one passing is how a real leak would ship.
"""
from __future__ import annotations

import logging
import os

WITNESS_ENV = "SENTINEL_PROMOTION_GATE_WITNESSED"


def test_the_promotion_witness_did_not_leak():
    """A leaked witness means every later caller in this process can promote unattended."""
    value = os.environ.get(WITNESS_ENV)
    assert value is None, (
        f"{WITNESS_ENV} leaked into the process environment as {value!r}. Some test set "
        "it without cleanup, and INV-OPS-7's tool-side promotion gate is now open for "
        "everything that runs afterwards. Use the `gate_witnessed` fixture (monkeypatch, "
        "auto-reverted) or `agent_loop._with_promotion_witness`, which restores the prior "
        "value in a `finally`."
    )


def test_the_promotion_gate_still_refuses_at_the_end_of_the_suite(monkeypatch):
    """The behavioural half: ask the real tool after everything else has run.

    Asserts the error KIND, not merely `ok is False`. With a leaked witness the gate opens,
    the call reaches the control plane and returns `ok: False` with `upstream_error` — so
    the loose version of this assertion passed while the gate was disabled.

    The control plane is stubbed, deliberately. Positive-controlling this test surfaced a
    real hazard in an earlier draft: with a leaked witness the gate opens and the handler
    issues a genuine `CreateHarnessEndpoint`. It was rejected
    (`UnrecognizedClientException`) only because the ambient credentials were invalid — on
    a machine with working credentials, a test in a suite that advertises ZERO AWS would
    have created a production endpoint. Stubbing makes that impossible rather than
    unlikely.
    """
    import importlib.util
    import pathlib

    handler_path = (pathlib.Path(__file__).resolve().parent.parent
                    / "tools" / "harness_ops" / "handler.py")
    spec = importlib.util.spec_from_file_location("_isolation_harness_ops", handler_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class _RefuseToCall:
        """Any control-plane call is a test failure, not a network round trip."""

        def __getattr__(self, name):
            def _boom(**_kwargs):
                raise AssertionError(
                    f"the promotion gate let a real control-plane call through: "
                    f"{name}(...). The witness leaked."
                )
            return _boom

    from sentinel_harness import core
    monkeypatch.setattr(core, "_control", _RefuseToCall())

    out = module.handler(
        {"action": "promote_endpoint",
         "params": {"harness_id": "h-isolation", "endpoint_name": "prod"}},
        None,
    )
    assert out["ok"] is False, f"promotion was ALLOWED at end of suite: {out}"
    assert out.get("error") == "validation_error", (
        f"the promotion was refused, but not BY THE GATE — error={out.get('error')!r}, "
        f"message={str(out.get('message'))[:160]!r}. An `upstream_error` here means the "
        "gate OPENED and the call reached the control plane, i.e. the witness leaked and "
        "only the absence of credentials stopped it."
    )
    assert "human-approval gate" in str(out.get("message")), out.get("message")


def test_the_metric_handler_did_not_stack():
    """`logutil.get_metric_sink` is idempotent by design (one tagged handler). A stacking
    regression would duplicate every metric line, which reads as double the token spend."""
    logger = logging.getLogger("sentinel_harness.metric")
    tagged = [h for h in logger.handlers
              if getattr(h, "_sentinel_metric_handler", False)]
    assert len(tagged) <= 1, (
        f"{len(tagged)} tagged metric handlers are attached: {tagged}. "
        "get_metric_sink must reuse the one handler, not append another."
    )


def test_no_test_left_the_repo_registry_path_redirected():
    """`SENTINEL_REGISTRY_PATH` overrides the governance registry. Left set, it points every
    later caller — including the MCP server's approved-set load — at whatever file the last
    test used."""
    value = os.environ.get("SENTINEL_REGISTRY_PATH")
    assert value is None, (
        f"SENTINEL_REGISTRY_PATH leaked as {value!r}; the registry every later test reads "
        "is whatever that path holds. Set it with monkeypatch.setenv, never os.environ."
    )
