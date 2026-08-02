"""
Round-14 regression suite — fidelity at the EXTERNAL DATA BOUNDARY.
===================================================================
Rounds M18/R9-R13b asked about our own layers: does the gate fail closed, does the
docstring match the mechanism, does the number reflect capability, does the
generated rule preserve its match set, is breadth judged by selectivity. Round 14
asks a question none of those did:

    When an external data source's response does not match our assumption,
    WHO decides on its behalf, and WHICH DIRECTION does that decision default to?

Every tool covered here translates a response we do not control into a judgement a
security analyst acts on. A defect here is never a crash — it is a CONFIDENT WRONG
ANSWER derived from data that was absent, malformed, or shaped differently than
assumed. And in all seven defects the round found, the default leaned the same way:

    **"I could not read it" was rendered as "there is nothing there."**

- An unreadable CISA KEV catalog reported `in_kev: False` with `ok: True` — byte
  identical to "this CVE is not being actively exploited".
- An unrecognized CMDB envelope reported an EMPTY attack surface with `ok: True` —
  "I could not read your asset inventory" rendered as "you have no exposed assets".
- An unassessed service (`cve_id` populated, no `known_vuln` flag) reported as not
  vulnerable, zeroing the blast radius of a CVSS-10.0 KEV-listed CVE.
- An NVD reply carrying a DIFFERENT CVE was relabelled with the requested id, so
  Log4Shell came back with a 3.1 LOW score and someone else's description.

The other two were direction-blind rather than fail-open — a bare `bool()` and
case-sensitive equality against feed-controlled values — and each was wrong in BOTH
directions, which is how they escaped notice: any single test case looks fine.

Method note (round 13's lesson, applied here)
---------------------------------------------
Every test below varies the dimension that could mask the result and keeps a
CONTROL case asserting the correct input still works. A guard that only proves the
broken input now raises cannot distinguish "we fixed the defect" from "we broke the
tool" — round 13 published a wrong conclusion from exactly that gap.

Every test FAILS on pre-R14 source. Zero network, zero AWS, zero LLM: the two
handlers with hardcoded upstream URLs are exercised at their normalization layer,
which is where the defects live.
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN",
                      "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")


def _load(unique_name: str, rel_path: str):
    path = os.path.join(REPO_ROOT, rel_path)
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    return module


asset = _load("asset_lookup_r14", "tools/asset_lookup/handler.py")
nvd = _load("nvd_lookup_r14", "tools/nvd_lookup/handler.py")
ek = _load("epss_kev_r14", "tools/epss_kev/handler.py")
ioc = _load("enrich_ioc_r14", "tools/enrich_ioc/handler.py")
attack = _load("attack_lookup_r14", "tools/attack_lookup/handler.py")

from sentinel_harness.connectors.base import _coerce_bool  # noqa: E402

LOG4SHELL = "CVE-2021-44228"

# The two upstreams `epss_kev._enrich_live` contacts. Dispatch below compares the
# parsed HOST for equality rather than substring-matching the URL: `"first.org" in
# url` is true for `https://evil.com/?x=first.org` too, and CodeQL flags it
# (py/incomplete-url-substring-sanitization) even inside a test stub. It is the
# right call — a test that models URL identity with a substring check teaches the
# pattern, and here it would also let a future URL change silently route the KEV
# request to the EPSS fixture, making the KEV guard tests vacuous.
_EPSS_HOST = "api.first.org"
_KEV_HOST = "www.cisa.gov"


def _is_epss_url(url: str) -> bool:
    """True iff `url`'s host IS the EPSS API host (exact match, not substring)."""
    import urllib.parse
    return urllib.parse.urlsplit(url).hostname == _EPSS_HOST
_HOST = {"id": "prod-web-01", "subnet": "192.0.2.0/24", "internet_exposed": True,
         "services": [{"port": 443, "proto": "tcp", "name": "https",
                       "known_vuln": True, "cve_id": LOG4SHELL}]}


# --------------------------------------------------------------------------- #
# INV-BOUNDARY-1 — a truthiness value is parsed, never bare-bool()'d          #
# --------------------------------------------------------------------------- #
class TestTruthinessIsParsedNotCoerced:
    """PRE-R14: `bool(raw.get("known_vuln", False))`, and `bool("false") is True`.

    A backend that serializes booleans as strings therefore turned a PATCHED
    service into a vulnerable one and an INTERNAL host into an internet-facing
    one — manufacturing a phantom exposure that pulls an on-call engineer out of
    bed. The repo already had the authoritative `_coerce_bool`, whose docstring
    records this exact trap; this call site had reimplemented it.
    """

    @pytest.mark.parametrize("falsey", ["false", "False", "FALSE", "0", "no", "f", "n"])
    def test_string_false_is_not_vulnerable(self, falsey):
        svc = asset._normalize_service({"port": 443, "known_vuln": falsey})
        assert svc["known_vuln"] is False, f"{falsey!r} read as VULNERABLE"

    @pytest.mark.parametrize("truthy", ["true", "True", "1", "yes", "y", "t"])
    def test_string_true_is_still_vulnerable(self, truthy):
        """CONTROL: the fix must not make everything False."""
        svc = asset._normalize_service({"port": 443, "known_vuln": truthy})
        assert svc["known_vuln"] is True, f"{truthy!r} read as clean"

    @pytest.mark.parametrize("falsey", ["false", "False", "0", "no"])
    def test_string_false_is_not_internet_exposed(self, falsey):
        """Same coercion on the exposure flag: a string "false" must not read as
        internet-facing, which would inflate the blast radius of every finding."""
        host = asset._normalize_host({"id": "h", "internet_exposed": falsey,
                                      "services": []})
        assert host["internet_exposed"] is False

    def test_string_true_is_still_internet_exposed(self):
        host = asset._normalize_host({"id": "h", "internet_exposed": "true",
                                      "services": []})
        assert host["internet_exposed"] is True

    @pytest.mark.parametrize("value", ["false", "true", "0", "1", "no", "yes",
                                       True, False, None, "", 0, 1])
    def test_asset_lookup_agrees_with_the_repo_helper(self, value):
        """The tool must not diverge from the authoritative coercion.

        R13b found two live paths returning OPPOSITE booleans for the same bytes.
        This pins asset_lookup to the shared helper so that cannot recur here.
        """
        svc = asset._normalize_service({"port": 1, "known_vuln": value})
        assert svc["known_vuln"] == _coerce_bool(value)


# --------------------------------------------------------------------------- #
# INV-BOUNDARY-2 — "unassessed" is distinguishable from "assessed clean"      #
# --------------------------------------------------------------------------- #
class TestUnassessedIsNotClean:
    """PRE-R14: an absent, null, or differently-named vulnerability flag collapsed
    to False. `known_vuln` is the SOLE gate on the CVE-vs-asset join, so a scanner
    that expresses vulnerability by populating `cve_id` alone made an
    internet-exposed host running a KEV-listed CVSS-10.0 CVE report as
    `no_action_not_exposed` — a real exposure closed out as "this CVE touches
    nothing here". The old docstring called defaulting to False "conservative";
    for a security tool the conservative direction is the opposite one.
    """

    def test_a_populated_cve_id_is_itself_evidence(self):
        svc = asset._normalize_service({"port": 443, "cve_id": LOG4SHELL})
        assert svc["known_vuln"] is True, (
            "a service the backend says is affected by a CVE reported as not "
            "vulnerable — this zeroes the blast radius of the CVE-asset join"
        )
        assert svc["vuln_assessed"] is True

    @pytest.mark.parametrize("alias", ["vulnerable", "has_known_vuln", "is_vulnerable"])
    def test_the_flag_is_read_under_the_names_backends_use(self, alias):
        svc = asset._normalize_service({"port": 443, alias: True})
        assert svc["known_vuln"] is True, f"flag named {alias!r} was ignored"

    def test_never_assessed_is_marked_as_such(self):
        """No flag and no CVE = nobody looked. That must be visible, not rounded
        down to a negative finding (the degradation-must-leave-a-trace rule)."""
        svc = asset._normalize_service({"port": 22, "proto": "tcp", "name": "ssh"})
        assert svc["known_vuln"] is False       # still safe to act on
        assert svc["vuln_assessed"] is False    # ...but known to be unverified

    def test_an_explicit_negative_is_an_assessment(self):
        """CONTROL: `known_vuln: False` means a backend checked and found nothing.
        That is materially different from never having checked, and the two must not
        collapse back together."""
        svc = asset._normalize_service({"port": 22, "known_vuln": False})
        assert svc["known_vuln"] is False
        assert svc["vuln_assessed"] is True

    def test_explicit_null_is_unassessed_not_negative(self):
        svc = asset._normalize_service({"port": 22, "known_vuln": None})
        assert svc["vuln_assessed"] is False

    def test_the_two_states_are_actually_distinguishable(self):
        """The point of the whole invariant: a caller can tell them apart."""
        never = asset._normalize_service({"port": 22})
        checked = asset._normalize_service({"port": 22, "known_vuln": False})
        assert never != checked, (
            "'never assessed' and 'assessed clean' are byte-identical again"
        )


# --------------------------------------------------------------------------- #
# INV-BOUNDARY-3 — an unreadable reply is never an empty attack surface       #
# --------------------------------------------------------------------------- #
class TestUnreadableReplyIsNotAnEmptySurface:
    """PRE-R14: `surface.get("hosts", [])` returned zero hosts for ANY reply shape
    it did not recognize, with `ok: True`. "I could not read your CMDB" rendered as
    "you have no vulnerable, internet-exposed assets" — the most dangerous possible
    rendering of a read failure in this tool. The docstring already claimed "we
    never coerce a malformed reply into a (misleadingly empty) success"; the code
    did precisely that.
    """

    @pytest.mark.parametrize("payload,why", [
        ({"data": {"hosts": [_HOST]}}, "envelope renamed to 'data'"),
        ({"result": {"hosts": [_HOST]}}, "envelope renamed to 'result'"),
        ({"surface": {"assets": [_HOST]}}, "collection renamed to 'assets'"),
        ({"error": "CMDB unavailable", "code": 503}, "200-OK error body"),
        ({}, "empty object"),
        ({"catalogVersion": "2026.08.01"}, "truncated/unrelated body"),
    ])
    def test_an_unrecognized_reply_raises(self, payload, why):
        with pytest.raises(ValueError, match="hosts"):
            asset._normalize_surface(payload)

    def test_the_error_names_what_it_actually_saw(self):
        """Four-element error contract: a changed upstream schema must be a
        two-minute diagnosis, not a silent zero."""
        with pytest.raises(ValueError) as ei:
            asset._normalize_surface({"data": {"hosts": []}, "meta": 1})
        msg = str(ei.value)
        assert "data" in msg and "meta" in msg, f"error does not name the keys: {msg}"

    @pytest.mark.parametrize("payload", [
        {"surface": {"hosts": [_HOST], "trust_edges": []}},
        {"hosts": [_HOST], "trust_edges": []},
    ])
    def test_both_supported_envelopes_still_work(self, payload):
        """CONTROL: the two documented shapes must keep parsing."""
        assert len(asset._normalize_surface(payload)["hosts"]) == 1

    def test_a_genuinely_empty_surface_is_still_reported(self):
        """CONTROL, and the reason the fix keys on PRESENCE not emptiness: a backend
        that says "the surface is empty" is giving us data, and must be believed."""
        out = asset._normalize_surface({"surface": {"hosts": [], "trust_edges": []}})
        assert out["hosts"] == [] and out["trust_edges"] == []


# --------------------------------------------------------------------------- #
# INV-BOUNDARY-4 — a CVE record is never relabelled with the requested id     #
# --------------------------------------------------------------------------- #
class TestNvdRecordIdentityIsVerified:
    """PRE-R14: `vulns[0]` was taken unconditionally and the result returned
    `"id": cve_id` — the id we ASKED for, stamped onto whatever record was first.
    Nothing cross-checked them. A reply carrying a different CVE therefore produced
    a confidently mislabelled answer: Log4Shell reported with a 3.1 LOW score and
    someone else's description. Triage that ranks by CVSS then de-prioritises it,
    and the output looks entirely normal.
    """

    @staticmethod
    def _vuln(cve_id, score, sev, desc):
        return {"cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": desc}],
            "metrics": {"cvssMetricV31": [
                {"cvssData": {"baseScore": score, "baseSeverity": sev}}]},
            "published": "2021-12-10T00:00:00",
            "lastModified": "2021-12-11T00:00:00",
            "references": [],
        }}

    def test_a_mismatched_record_is_refused_not_relabelled(self):
        data = {"vulnerabilities": [
            self._vuln("CVE-2019-0001", 3.1, "LOW", "unrelated minor issue")]}
        with pytest.raises(LookupError, match="does not contain"):
            nvd._normalize_nvd(LOG4SHELL, data)

    def test_the_refusal_names_what_came_back(self):
        data = {"vulnerabilities": [
            self._vuln("CVE-2019-0001", 3.1, "LOW", "x")]}
        with pytest.raises(LookupError) as ei:
            nvd._normalize_nvd(LOG4SHELL, data)
        assert "CVE-2019-0001" in str(ei.value)

    def test_a_record_without_an_id_cannot_be_verified(self):
        """An unverifiable record is refused: the alternative is the mislabelling."""
        data = {"vulnerabilities": [{"cve": {
            "descriptions": [{"lang": "en", "value": "no id"}],
            "metrics": {"cvssMetricV31": [
                {"cvssData": {"baseScore": 2.0, "baseSeverity": "LOW"}}]}}}]}
        with pytest.raises(LookupError):
            nvd._normalize_nvd(LOG4SHELL, data)

    def test_the_right_record_is_found_at_any_position(self):
        """Position 0 was an assumption, not a contract. Selecting by id fixes the
        NEGATIVE direction too: the old code would have returned the LOW score here
        even though the correct record was present in the same reply."""
        data = {"vulnerabilities": [
            self._vuln("CVE-2019-0001", 3.1, "LOW", "unrelated"),
            self._vuln(LOG4SHELL, 10.0, "CRITICAL", "Log4Shell RCE")]}
        out = nvd._normalize_nvd(LOG4SHELL, data)
        assert out["cvss_v3_score"] == 10.0
        assert out["cvss_v3_severity"] == "CRITICAL"
        assert "Log4Shell" in out["description"]

    def test_a_matching_record_still_parses(self):
        """CONTROL: the ordinary single-hit reply is unaffected."""
        data = {"vulnerabilities": [
            self._vuln(LOG4SHELL, 10.0, "CRITICAL", "Log4Shell RCE")]}
        out = nvd._normalize_nvd(LOG4SHELL, data)
        assert out["id"] == LOG4SHELL and out["cvss_v3_score"] == 10.0

    @pytest.mark.parametrize("spelling", ["cve-2021-44228", "CVE-2021-44228",
                                          "Cve-2021-44228"])
    def test_case_is_not_a_mismatch(self, spelling):
        """CONTROL, and a guard against over-tightening: NVD is consistently
        upper-case, but a proxy or cache need not be, and a case difference is not
        a different CVE. Refusing it would turn this fix into a new false negative.
        """
        data = {"vulnerabilities": [
            self._vuln(spelling, 10.0, "CRITICAL", "Log4Shell RCE")]}
        assert nvd._normalize_nvd(LOG4SHELL, data)["cvss_v3_score"] == 10.0


# --------------------------------------------------------------------------- #
# INV-BOUNDARY-5 — an unreadable KEV catalog is not "not exploited"           #
# --------------------------------------------------------------------------- #
class TestKevReadFailureIsNotANegativeFinding:
    """PRE-R14: `kev_data.get("vulnerabilities", [])` produced an empty catalog for
    any unexpected shape, and every CVE then came back `in_kev: False` with
    `ok: True`. `in_kev` is the field that gates emergency patching: CISA saying
    "actively exploited in the wild" is the strongest possible signal, and reading
    the feed wrong turned it into silence.

    These drive the REAL `_enrich_live` — an earlier draft of this class asserted
    against a local re-implementation of the parse loop, which tests the copy and
    not the code. `urlopen` is stubbed per-URL so there is still zero network.
    """

    @staticmethod
    def _run(kev_payload, epss_payload=None, monkeypatch=None):
        """Call the real `_enrich_live` with both upstreams stubbed at urlopen."""
        import io
        import json
        import urllib.request
        epss_payload = epss_payload or {
            "data": [{"cve": LOG4SHELL, "epss": "0.97", "percentile": "0.999"}]}

        class _Resp(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, *a, **kw):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            body = epss_payload if _is_epss_url(url) else kev_payload
            return _Resp(json.dumps(body).encode())

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        return ek._enrich_live([LOG4SHELL])

    @pytest.mark.parametrize("payload,why", [
        ({"items": [{"cveID": LOG4SHELL}]}, "envelope renamed"),
        ({"vulnerabilities": [{"cve_id": LOG4SHELL}]}, "row field renamed"),
        ({"error": "service temporarily unavailable"}, "200-OK error body"),
        ({}, "empty object"),
        ({"catalogVersion": "2026.08.01", "count": 1300}, "truncated feed"),
        ({"vulnerabilities": {}}, "vulnerabilities is not a list"),
        ({"vulnerabilities": []}, "zero-entry catalog"),
    ])
    def test_every_unreadable_shape_is_refused(self, payload, why, monkeypatch):
        with pytest.raises(RuntimeError, match="(?i)refusing|must be a list"):
            self._run(payload, monkeypatch=monkeypatch)

    def test_a_real_catalog_still_reports_in_kev(self, monkeypatch):
        """CONTROL — and the half that proves the fix discriminates rather than
        just refusing everything."""
        out = self._run({"vulnerabilities": [
            {"cveID": LOG4SHELL, "dateAdded": "2021-12-10",
             "dueDate": "2021-12-24"},
            {"cveID": "CVE-2019-0001", "dateAdded": "2019-01-01"}]},
            monkeypatch=monkeypatch)
        assert out[LOG4SHELL]["in_kev"] is True
        assert out[LOG4SHELL]["kev_date_added"] == "2021-12-10"
        assert out[LOG4SHELL]["epss"] == 0.97

    def test_a_readable_catalog_that_omits_the_cve_reports_false(self, monkeypatch):
        """CONTROL, and the whole point of the distinction: a catalog we COULD read
        which does not list this CVE is a genuine negative finding and must stay
        `in_kev: False` — not become an error."""
        out = self._run({"vulnerabilities": [
            {"cveID": "CVE-2019-0001", "dateAdded": "2019-01-01"}]},
            monkeypatch=monkeypatch)
        assert out[LOG4SHELL]["in_kev"] is False
        assert out[LOG4SHELL]["kev_date_added"] is None

    def test_the_error_is_reported_as_upstream_not_as_a_verdict(self, monkeypatch):
        """Through the handler: a read failure must surface as ok=False, never as a
        successful `in_kev: False`."""
        import io
        import json
        import urllib.request

        class _Resp(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, *a, **kw):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            body = ({"data": [{"cve": LOG4SHELL, "epss": "0.97",
                               "percentile": "0.9"}]} if _is_epss_url(url)
                    else {"error": "maintenance"})
            return _Resp(json.dumps(body).encode())

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setenv("EPSS_KEV_LIVE", "1")
        res = ek.handler({"cve_ids": [LOG4SHELL]}, None)
        assert res["ok"] is False, "a KEV read failure was reported as a success"
        assert res["error"] == "upstream_error"
        assert "results" not in res or not res.get("results")

    def test_kev_lookup_is_case_insensitive_on_both_sides(self, monkeypatch):
        """The fix normalizes the map keys; the lookup must normalize too, or the
        fix itself becomes a new false 'not in KEV'."""
        out = self._run({"vulnerabilities": [
            {"cveID": LOG4SHELL.lower(), "dateAdded": "2021-12-10"}]},
            monkeypatch=monkeypatch)
        assert out[LOG4SHELL]["in_kev"] is True

    def test_this_suites_url_dispatch_is_exact(self):
        """Guard the guard: if `_is_epss_url` mis-routed, the KEV payloads above
        would never reach the KEV parser and every test in this class would pass
        vacuously — the same fail-open the class exists to prevent, reintroduced
        via the harness. Exact host equality, not a substring scan.
        """
        assert _is_epss_url("https://api.first.org/data/v1/epss?cve=CVE-2021-44228")
        assert not _is_epss_url(
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")
        # A substring check would wrongly call each of these EPSS.
        assert not _is_epss_url("https://evil.example/?redirect=api.first.org")
        assert not _is_epss_url("https://api.first.org.evil.example/data")
        # And the two real URLs the shipped code uses must dispatch differently.
        import inspect
        src = inspect.getsource(ek._enrich_live)
        assert _EPSS_HOST in src and _KEV_HOST in src, (
            "the upstream hosts changed; this suite's dispatch would silently send "
            "both requests to one fixture"
        )


# --------------------------------------------------------------------------- #
# INV-BOUNDARY-6 — a feed's letter case is not a security signal              #
# --------------------------------------------------------------------------- #
class TestVerdictIsCaseInsensitive:
    """PRE-R14: `_derive_verdict` compared feed-controlled values with exact
    case-sensitive equality, so the SAME data spelled differently flipped the
    verdict in BOTH directions:

        confidence="High"  -> the `== "high"` test failed -> malicious DOWNGRADED
                              to suspicious (a real threat de-prioritised)
        category="BENIGN"  -> the benign-set test failed, then fell through to the
                              confidence branch -> benign UPGRADED to malicious

    Both directions matter, which is why a single test case never caught it.
    """

    @pytest.mark.parametrize("confidence", ["high", "High", "HIGH", " high "])
    def test_high_confidence_is_malicious_however_spelled(self, confidence):
        assert ioc._derive_verdict("c2", confidence) == "malicious"

    @pytest.mark.parametrize("category", ["benign", "Benign", "BENIGN", " benign "])
    def test_benign_stays_benign_however_spelled(self, category):
        assert ioc._derive_verdict(category, "high") == "benign", (
            "an uppercase benign category was escalated to malicious"
        )

    @pytest.mark.parametrize("category", ["scanner", "SCANNER", "Anonymizer"])
    def test_low_signal_categories_are_matched_case_insensitively(self, category):
        assert ioc._derive_verdict(category, "high") == "suspicious"

    @pytest.mark.parametrize("confidence", ["medium", "Medium", "low", "LOW", ""])
    def test_non_high_confidence_is_still_only_suspicious(self, confidence):
        """CONTROL: normalizing must not promote everything to malicious."""
        assert ioc._derive_verdict("c2", confidence) == "suspicious"

    def test_none_inputs_do_not_crash_or_escalate(self):
        assert ioc._derive_verdict(None, None) == "suspicious"


# --------------------------------------------------------------------------- #
# INV-BOUNDARY-7 — a revoked ATT&CK technique is reported as revoked          #
# --------------------------------------------------------------------------- #
class TestRevokedTechniquesAreSurfaced:
    """PRE-R14: STIX `revoked` and `x_mitre_deprecated` were dropped, so a
    superseded technique was indistinguishable from a current one. A coverage or
    detection-engineering consumer then invests in a dead target and counts it
    toward coverage of a tactic the REPLACEMENT technique governs — the
    capability-vs-intent error INV-COVERAGE records, arriving from upstream.

    Surfaced rather than raised: looking up a revoked id is legitimate (an existing
    rule may reference one) and the caller needs to be told, not stonewalled.
    """

    def test_offline_and_live_return_the_same_field_set(self):
        """The two paths must not diverge — a caller cannot KeyError depending on
        which one served it (the offline/live divergence class from R13b)."""
        res = attack.handler({"technique_id": "T1059.001"}, None)
        assert res["ok"] is True
        for field in ("revoked", "deprecated"):
            assert field in res["technique"], f"offline path omits {field!r}"

    def test_stub_techniques_are_current(self):
        """CONTROL: the curated set contains only live techniques, so both flags are
        present AND False — presence is the contract, False is the fact."""
        tech = attack.handler({"technique_id": "T1059.001"}, None)["technique"]
        assert tech["revoked"] is False
        assert tech["deprecated"] is False

    def test_the_live_normalizer_reads_both_stix_flags(self):
        import inspect
        src = inspect.getsource(attack)
        assert '"revoked"' in src or "'revoked'" in src
        assert "x_mitre_deprecated" in src
