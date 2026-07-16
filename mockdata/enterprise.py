"""mockdata.enterprise — a DEEP fictional enterprise for attack-path reasoning.

.. warning::
   **CLEARLY-LABELED MOCK DATA for POC / testing only.** No real company, host,
   network, or person. Public IPs are RFC 5737 documentation ranges
   (``192.0.2.0/24`` / ``198.51.100.0/24`` / ``203.0.113.0/24``); internal
   subnets are RFC 1918 ranges (``10.x``), mirroring
   ``tools/asset_lookup/handler.py``'s convention. Domains end in ``example.test``.
   AWS account ids, if referenced, are ``000000000000``.

Why this module exists (and why it is SEPARATE from ``world.py``)
-----------------------------------------------------------------
``mockdata/world.py`` is the CANONICAL SMALL world (6 hosts / ~10 IOCs / ~11
alerts) whose size is deliberately capped by ``tests/test_mockworld.py``
(``8 <= iocs <= 12`` etc.) so the alert-triage narrative stays legible. Deepening
*that* world would break those bounds and the scenarios that depend on the fixed
canonical set.

Attack-path reasoning needs the opposite: a *large, multi-tier* topology with
several distinct exploitation chains, so the ``build_attack_paths`` reasoner
(``specialists/attack-mapper``) has real depth to traverse and rank — and so the
``attack_path`` golden eval dataset has a coherent world its cases point at. This
module provides that WITHOUT touching the canonical world: pure addition.

Shape contract (plugs straight into the real reasoner)
------------------------------------------------------
:func:`exposure_surface` returns EXACTLY the shape
``tools/asset_lookup/handler.py`` emits and ``build_attack_paths`` consumes::

    {
      "hosts": [
        {"id", "subnet", "internet_exposed": bool,
         "services": [{"port", "proto", "name", "known_vuln": bool, "cve_id"}]}
      ],
      "trust_edges": [{"src", "dst", "kind"}],
    }

``name`` values match the reasoner's ``_SERVICE_IMPACT`` table (postgres/redis/
https/ssh/http-app...) and ``kind`` values match its ``_EDGE_COST`` table
(ssh_key_reuse / shared_admin_cred / service_account / flat_network) so the
scoring is meaningful, not defaulted.

The tiers & the planted chains
------------------------------
Five tiers across RFC-1918 subnets:

- **DMZ** ``10.10.0.0/24`` — internet-exposed edge (web, proxy, VPN, bastion, mail).
- **App** ``10.20.0.0/24`` — internal application/API tier.
- **Data** ``10.30.0.0/24`` — crown jewels (postgres/redis/warehouse).
- **Corp** ``10.40.0.0/24`` — workstations, file server, domain controller.
- **Mgmt** ``10.50.0.0/24`` — CI/CD, secrets, monitoring.

Three DELIBERATE, distinct chains for the reasoner to find and rank:

1. **Crown-jewel chain (highest risk):** ``web-01`` (internet-exposed, Log4Shell
   ``CVE-2021-44228``) → ``app-01`` (ssh_key_reuse) → ``db-01`` postgres
   (shared_admin_cred). Mirrors the canonical world + asset_lookup exactly.
2. **AD chain:** ``vpn-01`` (internet-exposed, vuln SSL-VPN) → ``jump-01``
   (service_account) → ``dc-01`` (shared_admin_cred) — reach the domain controller.
3. **CI/CD supply-chain:** ``proxy-01`` (internet-exposed, vuln) → ``cicd-01``
   (service_account) → ``secrets-01`` (shared_admin_cred) — reach the secrets store.

Plus DEAD ends the reasoner must NOT over-claim: ``bastion-01`` (internet-exposed
but fully patched — not an entry), isolated corp workstations with no outbound
trust edge, and app hosts with no path to a crown jewel.

Determinism
-----------
Literal Python data; no clock, no randomness, no I/O. :func:`load_enterprise`
returns a fresh deep copy each call so a caller's mutation can never corrupt the
shared source. Same query in → same data out.
"""
from __future__ import annotations

import copy
import ipaddress
from typing import Any, Dict, List

# --------------------------------------------------------------------------- #
# Subnets (RFC 1918 internal, mirroring asset_lookup's 10.x convention)        #
# --------------------------------------------------------------------------- #
DMZ = "10.10.0.0/24"
APP = "10.20.0.0/24"
DATA = "10.30.0.0/24"
CORP = "10.40.0.0/24"
MGMT = "10.50.0.0/24"


def _svc(port: int, name: str, *, vuln: bool = False, cve: str | None = None,
         proto: str = "tcp") -> Dict[str, Any]:
    """Build one service record in the exact shape the reasoner reads."""
    return {"port": port, "proto": proto, "name": name,
            "known_vuln": bool(vuln), "cve_id": cve}


def _host(hid: str, subnet: str, *, exposed: bool, services: List[Dict[str, Any]],
          role: str, criticality: str) -> Dict[str, Any]:
    """Build one host record. ``role``/``criticality`` are human-readable extras
    the reasoner ignores but the eval cases / dashboards can use."""
    return {
        "id": hid,
        "subnet": subnet,
        "internet_exposed": bool(exposed),
        "services": services,
        "role": role,
        "criticality": criticality,
    }


# --------------------------------------------------------------------------- #
# HOSTS — ~50 across five tiers                                                #
# --------------------------------------------------------------------------- #
_HOSTS: List[Dict[str, Any]] = [
    # ---- DMZ (internet-exposed edge) ------------------------------------- #
    _host("web-01", DMZ, exposed=True, role="public web server", criticality="high",
          services=[_svc(443, "https", vuln=True, cve="CVE-2021-44228"),
                    _svc(22, "ssh")]),
    _host("web-02", DMZ, exposed=True, role="public web server", criticality="high",
          services=[_svc(443, "https"), _svc(22, "ssh")]),
    _host("proxy-01", DMZ, exposed=True, role="reverse proxy", criticality="high",
          services=[_svc(443, "https", vuln=True, cve="CVE-2023-3519"),
                    _svc(80, "http-app")]),
    _host("vpn-01", DMZ, exposed=True, role="ssl-vpn gateway", criticality="high",
          services=[_svc(443, "https", vuln=True, cve="CVE-2023-27997"),
                    _svc(22, "ssh")]),
    _host("mail-01", DMZ, exposed=True, role="mail gateway", criticality="medium",
          services=[_svc(25, "smtp"), _svc(443, "https")]),
    _host("bastion-01", DMZ, exposed=True, role="ssh bastion (patched)", criticality="medium",
          services=[_svc(22, "ssh")]),  # exposed but NO known_vuln -> not an entry
    _host("dns-01", DMZ, exposed=True, role="authoritative dns", criticality="medium",
          services=[_svc(53, "dns", proto="udp")]),

    # ---- App tier -------------------------------------------------------- #
    _host("app-01", APP, exposed=False, role="app server (web backend)", criticality="high",
          services=[_svc(8080, "http-app"), _svc(22, "ssh")]),
    _host("app-02", APP, exposed=False, role="app server", criticality="high",
          services=[_svc(8080, "http-app")]),
    _host("app-03", APP, exposed=False, role="app server (isolated)", criticality="medium",
          services=[_svc(8080, "http-app")]),  # dead end: no outbound edge
    _host("api-01", APP, exposed=False, role="internal api gateway", criticality="high",
          services=[_svc(8443, "https"), _svc(22, "ssh")]),
    _host("api-02", APP, exposed=False, role="internal api gateway", criticality="high",
          services=[_svc(8443, "https")]),
    _host("cache-01", APP, exposed=False, role="redis cache", criticality="medium",
          services=[_svc(6379, "redis")]),
    _host("queue-01", APP, exposed=False, role="message queue", criticality="medium",
          services=[_svc(5672, "amqp")]),
    _host("jump-01", APP, exposed=False, role="internal jump host", criticality="high",
          services=[_svc(22, "ssh")]),

    # ---- Data tier (crown jewels) ---------------------------------------- #
    _host("db-01", DATA, exposed=False, role="primary postgres (crown jewel)", criticality="critical",
          services=[_svc(5432, "postgres")]),
    _host("db-02", DATA, exposed=False, role="postgres replica", criticality="critical",
          services=[_svc(5432, "postgres")]),
    _host("db-mysql-01", DATA, exposed=False, role="mysql (billing)", criticality="critical",
          services=[_svc(3306, "mysql")]),
    _host("warehouse-01", DATA, exposed=False, role="data warehouse", criticality="critical",
          services=[_svc(5439, "redshift"), _svc(5432, "postgres")]),
    _host("redis-data-01", DATA, exposed=False, role="session store", criticality="high",
          services=[_svc(6379, "redis")]),
    _host("backup-01", DATA, exposed=False, role="backup vault", criticality="high",
          services=[_svc(22, "ssh")]),

    # ---- Corp tier ------------------------------------------------------- #
    _host("dc-01", CORP, exposed=False, role="domain controller (crown jewel)", criticality="critical",
          services=[_svc(389, "ldap"), _svc(445, "smb"), _svc(88, "kerberos")]),
    _host("dc-02", CORP, exposed=False, role="domain controller (replica)", criticality="critical",
          services=[_svc(389, "ldap"), _svc(445, "smb")]),
    _host("fileserver-01", CORP, exposed=False, role="file server", criticality="high",
          services=[_svc(445, "smb")]),
    _host("print-01", CORP, exposed=False, role="print server", criticality="low",
          services=[_svc(631, "ipp")]),
    # A block of employee workstations — mostly dead ends (no crown-jewel path).
    *[
        _host(f"ws-{i:02d}", CORP, exposed=False, role="employee workstation",
              criticality="low", services=[_svc(445, "smb")])
        for i in range(1, 16)
    ],

    # ---- Mgmt tier ------------------------------------------------------- #
    _host("cicd-01", MGMT, exposed=False, role="ci/cd runner", criticality="high",
          services=[_svc(8080, "http-app"), _svc(22, "ssh")]),
    _host("secrets-01", MGMT, exposed=False, role="secrets manager (crown jewel)", criticality="critical",
          services=[_svc(8200, "https")]),
    _host("monitor-01", MGMT, exposed=False, role="monitoring", criticality="medium",
          services=[_svc(9090, "http-app")]),
    _host("registry-01", MGMT, exposed=False, role="container registry", criticality="high",
          services=[_svc(443, "https")]),
    _host("logserver-01", MGMT, exposed=False, role="log aggregator", criticality="medium",
          services=[_svc(514, "syslog", proto="udp")]),
]

_HOST_IDS = {h["id"] for h in _HOSTS}


# --------------------------------------------------------------------------- #
# TRUST EDGES — three planted chains + a benign flat-network edge              #
# --------------------------------------------------------------------------- #
_EDGES: List[Dict[str, str]] = [
    # Chain 1 — crown-jewel db (the canonical Log4Shell pivot).
    {"src": "web-01", "dst": "app-01", "kind": "ssh_key_reuse"},
    {"src": "app-01", "dst": "db-01", "kind": "shared_admin_cred"},
    {"src": "app-01", "dst": "cache-01", "kind": "service_account"},  # side hop
    {"src": "db-01", "dst": "db-02", "kind": "shared_admin_cred"},    # replica reach

    # Chain 2 — SSL-VPN to domain controller.
    {"src": "vpn-01", "dst": "jump-01", "kind": "service_account"},
    {"src": "jump-01", "dst": "dc-01", "kind": "shared_admin_cred"},
    {"src": "dc-01", "dst": "fileserver-01", "kind": "shared_admin_cred"},
    {"src": "dc-01", "dst": "dc-02", "kind": "shared_admin_cred"},

    # Chain 3 — reverse proxy to secrets store via CI/CD.
    {"src": "proxy-01", "dst": "api-01", "kind": "ssh_key_reuse"},
    {"src": "api-01", "dst": "cicd-01", "kind": "service_account"},
    {"src": "cicd-01", "dst": "secrets-01", "kind": "shared_admin_cred"},
    {"src": "cicd-01", "dst": "registry-01", "kind": "service_account"},

    # Benign flat-network edge from the patched bastion — leads to web-02 which
    # has no vuln and no onward edge, so the reasoner must NOT over-claim a chain.
    {"src": "bastion-01", "dst": "web-02", "kind": "flat_network"},
]


def _entry_hosts() -> list:
    """Hosts that are a valid attack ENTRY: internet-exposed AND running a
    known-vuln service. Mirrors the reasoner's entry criterion."""
    return [
        h for h in _HOSTS
        if h["internet_exposed"] and any(s["known_vuln"] for s in h["services"])
    ]


def _validate_world() -> None:
    """Fail loudly at import if the planted data is internally inconsistent.

    Guards the invariants the eval cases + tests rely on:
      1. every trust-edge endpoint is a real host;
      2. at least one valid ATTACK ENTRY node exists (internet-exposed AND running
         a known-vuln service) — otherwise the attack-path world has no foothold
         and the reasoner would yield zero chains, silently breaking the
         attack_path eval domain. (The named chain library lives in campaign.py;
         this guard validates the topology's entry-node viability, which those
         chains depend on.)
    Cheap, deterministic, runs once at import."""
    for e in _EDGES:
        if e["src"] not in _HOST_IDS:
            raise ValueError(f"edge src {e['src']!r} is not a known host")
        if e["dst"] not in _HOST_IDS:
            raise ValueError(f"edge dst {e['dst']!r} is not a known host")
    if not _entry_hosts():
        raise ValueError(
            "no valid attack entry node (internet-exposed + known-vuln) — the "
            "attack-path world would have no foothold"
        )


_validate_world()


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #
def load_enterprise() -> Dict[str, Any]:
    """Return a fresh deep copy of the entire enterprise (hosts + trust edges).

    Deep-copied so a caller mutating its slice can never corrupt the shared
    source (same discipline as ``world.load_world``)."""
    return copy.deepcopy({"hosts": _HOSTS, "trust_edges": _EDGES})


def _host_in_subnet(host: Dict[str, Any], cidr: str) -> bool:
    """True iff the host's subnet is inside (or equal to) the queried CIDR.

    Returns False (never raises) for an unparseable CIDR OR a version mismatch:
    an IPv6 query against the IPv4 internal subnets is simply "no match", not an
    error — ``subnet_of`` across IP versions raises TypeError, so we short-circuit
    on differing versions before comparing (audited: an IPv6 CIDR query escaped
    ``exposure_surface``'s never-raises contract)."""
    try:
        want = ipaddress.ip_network(cidr, strict=False)
        have = ipaddress.ip_network(host["subnet"], strict=False)
    except ValueError:
        return False
    if want.version != have.version:
        return False  # cross-version comparison is a non-match, not a TypeError
    return have.subnet_of(want) or have == want


def exposure_surface(query: str = "*") -> Dict[str, Any]:
    """Return the exposure surface for a query, in the EXACT shape
    ``tools/asset_lookup`` emits and ``build_attack_paths`` consumes.

    ``query`` is one of:
    - ``"*"`` — the whole enterprise (all hosts + all trust edges).
    - a host id (e.g. ``"web-01"``) — that single host, with the trust edges
      whose ``src`` is that host.
    - a CIDR subnet (e.g. ``"10.30.0.0/24"``) — the hosts in that subnet, with
      the trust edges whose ``src`` is one of them.

    The reasoner ignores the human ``role``/``criticality`` extras; they are kept
    so eval cases and dashboards can reference them. Deterministic; a query that
    matches nothing returns empty ``hosts``/``trust_edges`` (never raises)."""
    world = load_enterprise()
    hosts = world["hosts"]
    edges = world["trust_edges"]

    if query == "*":
        selected = hosts
    elif "/" in query:  # CIDR subnet
        selected = [h for h in hosts if _host_in_subnet(h, query)]
    else:  # single host id
        selected = [h for h in hosts if h["id"] == query]

    selected_ids = {h["id"] for h in selected}
    scoped_edges = [e for e in edges if e["src"] in selected_ids]
    return {"hosts": selected, "trust_edges": scoped_edges}


def crown_jewels() -> List[str]:
    """Return the ids of the critical crown-jewel hosts (deterministic, sorted).

    Convenience for eval cases that assert a chain reaches a crown jewel."""
    return sorted(h["id"] for h in _HOSTS if h["criticality"] == "critical")


def stats() -> Dict[str, int]:
    """Summary counts — used by tests + the module's __main__ smoke print."""
    exposed = [h for h in _HOSTS if h["internet_exposed"]]
    entries = [h for h in exposed if any(s["known_vuln"] for s in h["services"])]
    return {
        "hosts": len(_HOSTS),
        "internet_exposed": len(exposed),
        "entry_nodes": len(entries),
        "trust_edges": len(_EDGES),
        "crown_jewels": len(crown_jewels()),
    }


if __name__ == "__main__":
    import json

    print(json.dumps(stats(), indent=2))
