"""
Importing the library must be cheap and side-effect free.
========================================================
A fifth test sweep read the suite's own timing data — `--durations` — and found every
subprocess test paying a flat ~4.5s that was not work:

    import sentinel_harness      4.50s at 7% CPU     (not computing, waiting)
    python -c "pass"             0.03s

`-X importtime` put 4.15s of self time in `sentinel_harness.core`, and the cause was two
module-level statements:

    _control = boto3.client("bedrock-agentcore-control", ...)   # 2.15s
    _data    = boto3.client("bedrock-agentcore", ...)           # 2.01s

The cost is NOT service-model parsing, which was my first assumption and is wrong — those
models are gzipped JSON on disk and load in milliseconds. Measured in matched environments:

    no credentials                   4.46s    the full chain, ending at IMDS
    fake credentials                 0.31s    first provider hits
    AWS_EC2_METADATA_DISABLED=true   0.32s

It is the **instance-metadata probe timing out**. So importing this library made it reach
for ``169.254.169.254`` — the exact address its own INV-EGRESS family exists to refuse.
Three consequences, the third mattering most:

1. **Cost.** 26 subprocess tests x 4.5s ~ 115s of a 202s suite — more than half the
   runtime spent building clients nothing used.
2. **Importing had SIDE EFFECTS.** `import sentinel_harness` read ``~/.aws/``, and on an
   EC2 host the credential chain can reach the instance metadata service. A library must
   not touch the network or a user's credential store merely to be imported. That is a
   correctness and least-surprise property, not a performance one.
3. **It shaped the tests.** Because real clients existed before any test ran, the only way
   to substitute a fake was to patch the module global afterwards — which ~48 files do.

`core._LazyClient` defers construction to first attribute access. Import dropped
4.50s -> 0.26s (17x) and the suite 202s -> 105s (1.9x), with no call-site or test changes.

This file pins both properties. The performance bound is deliberately loose (a CI runner is
slower and noisier than a laptop) — it is set to catch a REGRESSION to eager construction,
which costs seconds, not to police tenths.
"""
from __future__ import annotations

import subprocess
import textwrap

import pytest

import child_pytest

# Eager construction cost ~4.5s; lazy is ~0.3s. A 2.0s ceiling cannot be tripped by
# ordinary noise and cannot be satisfied by the eager version even on a fast machine.
_IMPORT_BUDGET_SECONDS = 2.0


def _run_snippet(code: str, timeout: float = 120) -> subprocess.CompletedProcess:
    """Run `code` in a clean child interpreter through the shared launcher.

    Uses `child_pytest.resolve_python_launcher()` rather than a hardcoded `uv`/`python`:
    that mistake has been made five times in this repo (see tests/child_pytest.py).
    """
    launcher = child_pytest.resolve_python_launcher()
    return subprocess.run(
        [*launcher, "-c", textwrap.dedent(code)],
        cwd=child_pytest.REPO_ROOT, capture_output=True, text=True, timeout=timeout,
    )


# --------------------------------------------------------------------------- #
# Importing is cheap                                                          #
# --------------------------------------------------------------------------- #
def test_importing_the_package_is_fast():
    """Measured in a FRESH interpreter: an in-process timer would see boto3's warm caches
    and report a fast import even if construction were eager again."""
    result = _run_snippet(
        """
        import time
        t = time.perf_counter()
        import sentinel_harness  # noqa: F401
        print(f"{time.perf_counter() - t:.3f}")
        """
    )
    assert result.returncode == 0, (result.stdout + result.stderr)[-600:]
    elapsed = float(result.stdout.strip().splitlines()[-1])
    assert elapsed < _IMPORT_BUDGET_SECONDS, (
        f"importing sentinel_harness took {elapsed:.2f}s, over the "
        f"{_IMPORT_BUDGET_SECONDS}s budget. Something is doing real work at import time — "
        "most likely a boto3 client built at module level again. Use core._LazyClient."
    )


def test_importing_core_does_not_build_a_client():
    """The structural version of the same property, immune to timing noise."""
    result = _run_snippet(
        """
        from sentinel_harness import core
        print(repr(core._control))
        print(repr(core._data))
        """
    )
    assert result.returncode == 0, (result.stdout + result.stderr)[-600:]
    for line in result.stdout.strip().splitlines()[-2:]:
        assert "not yet built" in line, (
            f"a client was constructed at import time: {line}. Import must stay free of "
            "AWS work — the credential chain can reach the instance metadata service."
        )


def test_importing_makes_no_aws_call():
    """Property 2, enforced rather than described: fail the import if boto3 is asked to
    build ANY client while `sentinel_harness` is being imported."""
    result = _run_snippet(
        """
        import boto3
        real = boto3.client

        def _forbidden(*a, **k):
            raise AssertionError(f"import built a boto3 client: {a[:1]}")

        boto3.client = _forbidden
        import sentinel_harness           # must not construct anything
        from sentinel_harness import gateway, registry_live, mcp_server  # noqa: F401
        boto3.client = real
        print("OK")
        """
    )
    assert result.returncode == 0, (
        "importing the package (or gateway / registry_live / mcp_server) constructed a "
        f"boto3 client:\n{(result.stdout + result.stderr)[-700:]}"
    )
    assert "OK" in result.stdout


# --------------------------------------------------------------------------- #
# The proxy is transparent — every contract its callers already relied on      #
# --------------------------------------------------------------------------- #
class TestTheProxyIsTransparent:
    """~48 test files patch these objects. The proxy has to keep all of it working."""

    def test_replacing_the_whole_client_still_works(self, monkeypatch):
        """The dominant pattern: `monkeypatch.setattr(core, "_control", fake)`."""
        from sentinel_harness import core

        class _Fake:
            def list_harnesses(self, **_kw):
                return {"harnesses": ["fake"]}

        monkeypatch.setattr(core, "_control", _Fake())
        assert core._control.list_harnesses()["harnesses"] == ["fake"]

    def test_patching_a_method_on_the_client_still_works(self):
        """`test_gateway.py::test_scenario_named_supervisor_imports_without_aws` patches a
        method ON the client. The first version of the proxy used `__slots__` and broke it —
        recorded because it is exactly the kind of caller a "transparent" proxy must not
        surprise."""
        from sentinel_harness.core import _LazyClient, _CONTROL_CONFIG

        proxy = _LazyClient("bedrock-agentcore-control", _CONTROL_CONFIG)
        proxy.create_gateway = lambda **_kw: "patched"
        assert proxy.create_gateway() == "patched"
        assert "not yet built" in repr(proxy), (
            "patching a method triggered construction — the patch should shadow the "
            "forwarded attribute without resolving the client"
        )

    def test_internal_fields_are_not_forwarded(self):
        """`_service` / `_config` / `_client` must resolve on the proxy itself. Forwarding
        them would recurse or silently build a client to answer a bookkeeping question."""
        from sentinel_harness.core import _LazyClient, _DATA_CONFIG

        proxy = _LazyClient("bedrock-agentcore", _DATA_CONFIG)
        assert proxy._service == "bedrock-agentcore"
        assert proxy._client is None
        assert "not yet built" in repr(proxy)

    def test_set_region_stays_lazy(self, monkeypatch):
        """`set_region` is called by the CLI's --region flag before any AWS work — including
        for the offline detection commands, which never touch AWS. Building clients there
        would put the ~4.2s cost back on every command's startup path."""
        from sentinel_harness import core

        monkeypatch.setattr(core, "_control", core._LazyClient("x", core._CONTROL_CONFIG))
        monkeypatch.setattr(core, "_data", core._LazyClient("y", core._DATA_CONFIG))
        monkeypatch.setenv("SENTINEL_REGION", "us-east-1")
        core.set_region("eu-west-1")
        try:
            assert core.REGION == "eu-west-1"
            assert "not yet built" in repr(core._control)
            assert "not yet built" in repr(core._data)
        finally:
            core.set_region("us-east-1")

    def test_the_deferred_client_uses_the_current_region(self, monkeypatch):
        """Laziness must not mean staleness: a client built AFTER `set_region` has to use
        the new region, not the one that was current at import."""
        from sentinel_harness import core

        built = {}

        def _fake_boto_client(service, region_name=None, config=None):
            built["service"] = service
            built["region"] = region_name
            return object()

        monkeypatch.setattr(core.boto3, "client", _fake_boto_client)
        monkeypatch.setattr(core, "REGION", "ap-southeast-2")
        proxy = core._LazyClient("bedrock-agentcore-control", core._CONTROL_CONFIG)
        proxy._resolve()
        assert built["region"] == "ap-southeast-2", (
            f"the deferred client was built for {built['region']!r}; it must read the "
            "module-global REGION at resolve time"
        )

    def test_the_client_is_built_once_and_cached(self, monkeypatch):
        from sentinel_harness import core

        calls = []
        monkeypatch.setattr(
            core.boto3, "client",
            lambda service, **_kw: calls.append(service) or object(),
        )
        proxy = core._LazyClient("bedrock-agentcore", core._DATA_CONFIG)
        proxy._resolve()
        proxy._resolve()
        proxy._resolve()
        assert len(calls) == 1, f"the client was rebuilt {len(calls)} times: {calls}"


# --------------------------------------------------------------------------- #
# The guard's own control                                                     #
# --------------------------------------------------------------------------- #
def test_construction_reaches_for_instance_metadata():
    """What the 4.1s actually WAS — and why this is a correctness finding, not a tuning one.

    My first version of this control asserted "eager construction costs > 2s" and FAILED,
    reporting 0.09s. The premise was wrong, not the measurement: inside pytest the
    credential chain is already satisfied (fake keys in the environment), so it short-
    circuits. Measured properly, in matched environments:

        no credentials       4.46s     the full chain, ending at IMDS
        fake credentials     0.31s     first provider hits
        AWS_EC2_METADATA_DISABLED=true 0.32s

    So the cost is the **instance-metadata probe timing out** — `boto3.client()` at import
    time made this library reach for ``169.254.169.254``, the exact address its own
    INV-EGRESS family exists to refuse. Deferring construction means an import no longer
    touches the credential store or the network at all.

    Asserts the RATIO between matched runs rather than an absolute, so it stays meaningful
    on a fast CI runner and on a laptop.
    """
    def _timed(env_extra: dict) -> float:
        code = """
            import time, os
            import boto3
            t = time.perf_counter()
            boto3.client("bedrock-agentcore-control", region_name="us-east-1")
            boto3.client("bedrock-agentcore", region_name="us-east-1")
            print(f"{time.perf_counter() - t:.3f}")
        """
        import os as _os
        env = {k: v for k, v in _os.environ.items()
               if not k.startswith(("AWS_", "SENTINEL_"))}
        env["AWS_DEFAULT_REGION"] = "us-east-1"
        env.update(env_extra)
        launcher = child_pytest.resolve_python_launcher()
        r = subprocess.run(
            [*launcher, "-c", textwrap.dedent(code)],
            cwd=child_pytest.REPO_ROOT, capture_output=True, text=True,
            timeout=180, env=env,
        )
        if r.returncode != 0:
            pytest.skip(f"could not construct clients here: {r.stderr[-200:]}")
        return float(r.stdout.strip().splitlines()[-1])

    without_imds = _timed({"AWS_EC2_METADATA_DISABLED": "true",
                           "AWS_ACCESS_KEY_ID": "t", "AWS_SECRET_ACCESS_KEY": "t"})
    with_chain = _timed({})  # no credentials at all -> the chain walks to IMDS

    if with_chain < 1.0:
        pytest.skip(
            f"the credential chain resolved in {with_chain:.2f}s — this host answers or "
            "refuses IMDS instantly, so the cost this guard describes is not reproducible "
            "here. The laziness itself is still asserted by the tests above."
        )
    assert with_chain > without_imds * 3, (
        f"constructing clients took {with_chain:.2f}s with the full credential chain vs "
        f"{without_imds:.2f}s with IMDS disabled. The gap is the metadata probe, and it is "
        "why client construction must not happen at import time."
    )
