"""
Property-based tests for the CVE-vs-asset blast-radius core (``triage()``)
==========================================================================
``scenarios/scenario_cve_asset_triage.py::triage`` is the deterministic,
LLM-free join that turns a CVE + the asset surface into a blast-radius verdict.
It is one of the three "gate" cores the project markets. Example tests pin the
Log4Shell story; these Hypothesis tests attack the *structural invariants* that
must hold for any synthetic fleet + CVE.

Invariants exercised (all real, none tautological):
  * Determinism: ``triage(x) == triage(x)`` for arbitrary inputs.
  * ``blast_radius.affected_count == len(affected_hosts)``.
  * ``reachable_hosts`` is DISJOINT from ``affected_hosts`` (a pivot target is
    never itself an affected host) and every reachable host is a real trust-edge
    destination out of an affected host.
  * A CVE that affects NO host => empty ``affected_hosts`` + empty
    ``reachable_hosts`` + ``no_action_not_exposed`` (no crash).
  * ``affected_hosts`` is sorted + de-duplicated.
  * The recommendation policy matches the documented exposure/exploit quadrant.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS. Pure function, fully offline.
"""
from __future__ import annotations

import importlib.util
import os
import sys

from hypothesis import given, settings
from hypothesis import strategies as st

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

_SCENARIO_PATH = os.path.join(REPO_ROOT, "scenarios", "scenario_cve_asset_triage.py")


def _load_scenario():
    """Load the scenario under a UNIQUE module name (import-safe, offline)."""
    unique = "scenario_cve_asset_triage__prop"
    spec = importlib.util.spec_from_file_location(unique, _SCENARIO_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod
    spec.loader.exec_module(mod)  # must not touch AWS/network
    return mod


cat = _load_scenario()

_SETTINGS = settings(max_examples=200, deadline=None)

_CVE = "CVE-2021-44228"
_OTHER_CVE = "CVE-2000-0001"
_host_ids = st.sampled_from(["web-01", "app-01", "db-01", "bastion-01", "edge-01", "svc-02"])


def _mk_service(draw):
    carries = draw(st.booleans())
    if carries:
        return {"port": 443, "known_vuln": True, "cve_id": _CVE}
    return {
        "port": draw(st.sampled_from([22, 80, 8080])),
        "known_vuln": draw(st.booleans()),
        "cve_id": draw(st.sampled_from([_OTHER_CVE, None])),
    }


@st.composite
def _surface(draw):
    ids = draw(st.lists(_host_ids, min_size=0, max_size=6, unique=True))
    hosts = []
    for hid in ids:
        n_svc = draw(st.integers(min_value=0, max_value=3))
        services = [_mk_service(draw) for _ in range(n_svc)]
        hosts.append(
            {"id": hid, "internet_exposed": draw(st.booleans()), "services": services}
        )
    edges = []
    if ids:
        n_edges = draw(st.integers(min_value=0, max_value=6))
        for _ in range(n_edges):
            edges.append(
                {
                    "src": draw(st.sampled_from(ids)),
                    "dst": draw(st.sampled_from(ids)),
                    "kind": "test_edge",
                }
            )
    return {"hosts": hosts, "trust_edges": edges}


_nvd = st.one_of(
    st.none(),
    st.fixed_dictionaries(
        {
            "cvss_v3_score": st.sampled_from([None, 5.0, 7.5, 9.8, 10.0]),
            "cvss_v3_severity": st.sampled_from([None, "LOW", "MEDIUM", "HIGH", "CRITICAL"]),
        }
    ),
)
_epss = st.one_of(
    st.none(),
    st.fixed_dictionaries(
        {"epss": st.sampled_from([None, 0.01, 0.5, 0.97]), "in_kev": st.booleans()}
    ),
)


# --------------------------------------------------------------------------- #
# 1. Determinism.                                                              #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(nvd=_nvd, epss=_epss, surface=_surface())
def test_determinism(nvd, epss, surface):
    v1 = cat.triage(_CVE, nvd, epss, surface)
    v2 = cat.triage(_CVE, nvd, epss, surface)
    assert v1 == v2


# --------------------------------------------------------------------------- #
# 2. affected_count == len(affected_hosts); sorted + unique.                   #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(nvd=_nvd, epss=_epss, surface=_surface())
def test_affected_count_equals_len(nvd, epss, surface):
    v = cat.triage(_CVE, nvd, epss, surface)
    affected = v["affected_hosts"]
    assert v["blast_radius"]["affected_count"] == len(affected)
    # Sorted + de-duplicated.
    assert affected == sorted(set(affected))


# --------------------------------------------------------------------------- #
# 3. reachable_hosts disjoint from affected_hosts + are true edge targets.     #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(nvd=_nvd, epss=_epss, surface=_surface())
def test_reachable_disjoint_from_affected(nvd, epss, surface):
    v = cat.triage(_CVE, nvd, epss, surface)
    affected = set(v["affected_hosts"])
    reachable = set(v["blast_radius"]["reachable_hosts"])
    assert affected.isdisjoint(reachable)
    # Every reachable host is the dst of a trust edge whose src is affected.
    valid_targets = {
        e["dst"]
        for e in surface["trust_edges"]
        if e.get("src") in affected and e.get("dst") and e.get("dst") not in affected
    }
    assert reachable == valid_targets


# --------------------------------------------------------------------------- #
# 4. A CVE affecting no host => empty everything + no_action (no crash).       #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(nvd=_nvd, epss=_epss, surface=_surface())
def test_unmatched_cve_is_empty(nvd, epss, surface):
    """A CVE id no service carries yields empty affected/reachable + benign rec."""
    v = cat.triage("CVE-9999-99999", nvd, epss, surface)
    assert v["affected_hosts"] == []
    assert v["blast_radius"]["affected_count"] == 0
    assert v["blast_radius"]["reachable_hosts"] == []
    assert v["recommended_action"] == "no_action_not_exposed"


@_SETTINGS
@given(nvd=_nvd, epss=_epss)
def test_none_surface_never_crashes(nvd, epss):
    """A None asset surface (asset_lookup unavailable) yields an empty, benign
    verdict rather than raising."""
    v = cat.triage(_CVE, nvd, epss, None)
    assert v["affected_hosts"] == []
    assert v["blast_radius"]["affected_count"] == 0
    assert v["recommended_action"] == "no_action_not_exposed"


# --------------------------------------------------------------------------- #
# 5. The recommendation policy matches the documented quadrant.               #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(nvd=_nvd, epss=_epss, surface=_surface())
def test_recommendation_policy_matches_quadrant(nvd, epss, surface):
    v = cat.triage(_CVE, nvd, epss, surface)
    affected = v["affected_hosts"]
    exposed = v["blast_radius"]["internet_exposed_hit"]
    exploited = v["exploited_in_wild"]
    action = v["recommended_action"]
    if not affected:
        assert action == "no_action_not_exposed"
    elif exposed and exploited:
        assert action == "patch_now_exposed_and_exploited"
    elif exposed or exploited:
        assert action == "prioritize_patch"
    else:
        assert action == "schedule_patch"


# --------------------------------------------------------------------------- #
# 6. cve_id is normalized (stripped + uppercased); non-empty required.         #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(
    prefix=st.sampled_from(["", " ", "  "]),
    suffix=st.sampled_from(["", " ", "\t"]),
    lower=st.booleans(),
)
def test_cve_id_normalized(prefix, suffix, lower):
    raw = "cve-2021-44228" if lower else "CVE-2021-44228"
    v = cat.triage(prefix + raw + suffix, None, None, None)
    assert v["cve_id"] == "CVE-2021-44228"


def test_empty_cve_id_raises():
    import pytest

    for bad in ("", "   ", "\t"):
        with pytest.raises(ValueError):
            cat.triage(bad, None, None, None)
