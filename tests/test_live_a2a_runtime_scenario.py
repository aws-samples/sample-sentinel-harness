"""
Offline tests for the LIVE A2A on AgentCore **Runtime** scenario
================================================================
Exercises ``scenarios/scenario_live_a2a_runtime.py`` with ZERO AWS / ZERO network:

1. The DEFAULT (mock) run yields ``closed=True`` + a ``teardown_called`` flag, is
   import-safe, and touches ZERO real AWS (fake control+data clients only). We
   assert the fake clients received ``create -> get(READY) -> invoke -> delete`` in
   order, and that a ``delete`` still happens even when the invoke RAISES.
2. The account id in the written evidence is scrubbed to the ``000000000000``
   placeholder; the walk is deterministic.

The scenario is loaded by explicit file path under a UNIQUE module name (never a
name a sibling test could collide with). Importing it must make ZERO AWS/network
calls — asserted implicitly by these tests running offline with only the
``000000000000`` placeholder role in the environment. The live path
(``SENTINEL_A2A_LIVE=1`` / ``--live``) is documented in the scenario but NEVER
invoked here.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys

import pytest

# --- Hermetic import: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault(
    "SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role"
)
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
# The live path must NEVER be reached by the suite.
os.environ.pop("SENTINEL_A2A_LIVE", None)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

SCENARIO_PATH = os.path.join(
    REPO_ROOT, "scenarios", "scenario_live_a2a_runtime.py"
)


def _load_scenario():
    """Load the scenario module under a unique name (import-safe, offline)."""
    unique = "scenario_live_a2a_runtime__test"
    spec = importlib.util.spec_from_file_location(unique, SCENARIO_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod
    spec.loader.exec_module(mod)  # must not touch AWS/network
    return mod


sc = _load_scenario()


@pytest.fixture(autouse=True)
def _fresh_result():
    """Reset the module-level RESULT so each test walk starts clean."""
    sc.RESULT.clear()
    sc.RESULT.update({"scenario": "live_a2a_runtime", "steps": []})
    yield


# --------------------------------------------------------------------------
# 1. The default (mock) run closes true, tears down, is import-safe & zero-AWS.
# --------------------------------------------------------------------------
def test_offline_run_closes_true_and_tears_down():
    result = sc.run_offline()
    verdict = result["verdict"]
    assert verdict["closed"] is True
    assert verdict["invoke_http_200"] is True
    assert verdict["a2a_jsonrpc_ok"] is True
    assert verdict["teardown_called"] is True
    # Top-level convenience flags mirror the verdict.
    assert result["teardown_called"] is True
    assert result["invoke_http_status"] == 200


def test_offline_run_is_clearly_labeled_mock():
    result = sc.run_offline()
    assert result["mock"] is True
    assert "MOCK RUN" in result["mock_note"]
    # No live note on the offline path.
    assert "live_note" not in result


def test_fake_clients_get_calls_in_order():
    """create -> (poll) get(READY) -> invoke -> delete, in that order."""
    control = sc.FakeControlClient()
    data = sc.FakeDataClient()
    sc.run(control, data)

    assert control.calls[0] == "create_agent_runtime"
    assert "get_agent_runtime" in control.calls
    # delete is the LAST control-plane call (teardown after everything else).
    assert control.calls[-1] == "delete_agent_runtime"
    # get(s) happen after create and before delete.
    first_get = control.calls.index("get_agent_runtime")
    assert 0 < first_get < len(control.calls) - 1
    # The data plane was invoked exactly once, after the runtime went READY.
    assert data.calls == ["invoke_agent_runtime"]


def test_create_wires_a2a_public_and_ecr_image():
    """The create call carries protocol=A2A, network=PUBLIC, and an ECR image."""
    control = sc.FakeControlClient()
    data = sc.FakeDataClient()
    sc.run(control, data, image="000000000000.dkr.ecr.us-east-1.amazonaws.com/x:tag")
    rt = next(iter(control._runtimes.values()))
    assert rt["protocol"] == "A2A"
    assert rt["networkMode"] == "PUBLIC"
    assert rt["image"].endswith("/x:tag")


def test_invoke_sends_a2a_message_send_payload():
    """The data plane receives a JSON-RPC message/send envelope."""
    control = sc.FakeControlClient()
    data = sc.FakeDataClient()
    sc.run(control, data)
    assert data.last_payload["method"] == "message/send"
    assert data.last_payload["jsonrpc"] == "2.0"
    text = data.last_payload["params"]["message"]["parts"][0]["text"]
    assert "CVE-2021-44228" in text


# --------------------------------------------------------------------------
# 2. Teardown ALWAYS runs — even when the invoke raises (never leak compute).
# --------------------------------------------------------------------------
def test_delete_happens_even_when_invoke_raises():
    control = sc.FakeControlClient()
    data = sc.FakeDataClient(raise_on_invoke=True)
    result = sc.run(control, data)

    # The invoke failed, so the walk did NOT close...
    assert result["verdict"]["closed"] is False
    assert "walk_error" in result
    # ...but the runtime was STILL torn down.
    assert result["teardown_called"] is True
    assert control.calls[-1] == "delete_agent_runtime"
    # And the created runtime is in a deleting state (never left running).
    rt = next(iter(control._runtimes.values()))
    assert rt["status"] == "DELETING"


def test_no_delete_when_create_never_ran():
    """If create fails outright, there is no runtime to (and no attempt to) delete."""
    class _FailCreate(sc.FakeControlClient):
        def create_agent_runtime(self, **kwargs):
            self.calls.append("create_agent_runtime")
            raise RuntimeError("create boom")

    control = _FailCreate()
    data = sc.FakeDataClient()
    result = sc.run(control, data)
    assert result["verdict"]["closed"] is False
    assert result["teardown_called"] is False
    assert "delete_agent_runtime" not in control.calls


# --------------------------------------------------------------------------
# 3. Zero real AWS: the fakes are strict; an unmapped op raises loudly.
# --------------------------------------------------------------------------
def test_fake_control_is_strict():
    fake = sc.FakeControlClient()
    with pytest.raises(AssertionError):
        fake.some_unmapped_operation()


def test_fake_data_is_strict():
    fake = sc.FakeDataClient()
    with pytest.raises(AssertionError):
        fake.some_unmapped_operation()


def test_scenario_does_not_build_boto3_clients_on_import():
    """The scenario must not import core (which builds boto3 clients) at module load."""
    # It is loaded above with only placeholder creds; importing again is a no-op cost.
    # The live-only ``run_live`` imports core lazily, so a fresh import stays offline.
    assert not hasattr(sc, "boto3")


# --------------------------------------------------------------------------
# 4. Determinism + evidence scrubbing.
# --------------------------------------------------------------------------
def test_offline_run_is_deterministic():
    v1 = sc.run(sc.FakeControlClient(), sc.FakeDataClient())["verdict"]
    # Reset RESULT between runs (autouse fixture only fires per-test).
    sc.RESULT.clear()
    sc.RESULT.update({"scenario": "live_a2a_runtime", "steps": []})
    v2 = sc.run(sc.FakeControlClient(), sc.FakeDataClient())["verdict"]
    assert v1 == v2


def test_scrub_masks_account_id():
    arn = "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1"
    scrubbed = sc._scrub(arn)
    assert "123456789012" not in scrubbed
    assert "000000000000" in scrubbed


def test_scrub_masks_ecr_account_id():
    ref = "123456789012.dkr.ecr.us-east-1.amazonaws.com/sentinel/cve-intel:tag"
    scrubbed = sc._scrub(ref)
    assert "123456789012" not in scrubbed
    assert scrubbed.startswith("000000000000.dkr.ecr.")


def test_evidence_has_no_foreign_account_id():
    """No 12-digit id other than the 000000000000 placeholder leaks into evidence."""
    import re

    result = sc.run(
        sc.FakeControlClient(), sc.FakeDataClient(),
        image="555555555555.dkr.ecr.us-east-1.amazonaws.com/x:tag",
    )
    blob = json.dumps(sc._scrub(result))
    foreign = [m for m in re.findall(r"\d{12}", blob) if m != "000000000000"]
    assert foreign == [], f"leaked account id(s): {foreign}"


def test_wait_ready_polls_until_ready():
    """The scenario polls get_agent_runtime until READY before invoking."""
    control = sc.FakeControlClient(ready_after=3)  # needs 3 polls to go READY
    data = sc.FakeDataClient()
    result = sc.run(control, data)
    assert result["verdict"]["closed"] is True
    wait_step = next(s for s in result["steps"] if s["step"] == "wait_ready")
    assert wait_step["data"]["status"] == "READY"
    assert wait_step["data"]["polls"] >= 3
