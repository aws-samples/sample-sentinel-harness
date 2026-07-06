# `mockdata/` — the fictional SecOps world (MOCK DATA, POC/testing only)

> **This is CLEARLY-LABELED MOCK DATA for proof-of-concept and testing.**
> It is **not** real threat intelligence, **not** a real SIEM export, and
> describes **no** real company, person, host, network, or threat-actor
> infrastructure. It exists so the alert-triage POC can run end-to-end on
> realistic, internally-consistent, cross-linked data **before** any real
> customer SIEM / asset / ticketing plane is wired in.

## What this is

`mockdata` is the **single source of truth** for one small fictional
enterprise. All four alert-triage data-plane tools read from it, so they all
agree on the same hosts, indicators, alerts, and tickets.

Everything is deterministic literal Python data (`world.py`) — no clock, no
randomness, no network, no secrets. Same query in, same data out.

## Absolutely fictional by construction

| Artifact | Range used | Why it is obviously fake |
|---|---|---|
| IP addresses | RFC 5737 doc ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | Reserved by IANA purely for documentation; never routes |
| Domains | `example.test`, `example.com` | RFC 6761 reserved names; never resolve to real infra |
| File hashes | 64-hex (valid SHA-256 *length*) but fabricated | Correct shape, meaningless value |
| AWS account ids | `000000000000` placeholder only | Not a real account |

No real threat-actor infrastructure is referenced. IOCs are fictional but
well-formed so tools can parse/validate them realistically.

## The world

- **Hosts** — `web-01`, `app-01`, `db-01`, `bastion-01` reuse the exact ids and
  facts from `tools/asset_lookup/handler.py` (notably **`web-01` carries
  `CVE-2021-44228` / Log4Shell**), plus `win-ws-07` (workstation) and `dc-01`
  (domain controller). Each has an OS, owner team, criticality, and a
  `known_vuln`/`cve` flag where relevant.
- **IOCs** — ~10 indicators (IPs, domains, SHA-256 hashes), each with `type`,
  `first_seen`, `threat_category`, `confidence`, and the `relates_to` host(s).
  Includes a **C2 IP `203.0.113.66`** and a benign allowlisted CDN so triage
  has both a true positive and a clear false positive.
- **Alerts/events** — ~11 SIEM-style events over several days, each with
  `alert_id`, `ts`, `severity`, `rule_name`, `src_ip`, `dst_ip`/`host`,
  `technique` (MITRE ATT&CK id), and `raw_summary`. A mix of
  true-positive-looking and benign/false-positive (`false_positive: true`).
- **Seed tickets** — two tickets (`SEC-1001`, `SEC-1002`) so `create_ticket`
  can show a monotonic id sequence (next issued id: `SEC-1003`).

## The cross-link story (Log4Shell)

The world is stitched together so alert triage correlates cleanly across all
four planes:

```
SIEM alert  alert-1001  "Log4Shell JNDI Exploit Attempt"
    │  src_ip = 203.0.113.66
    ▼
IOC enrich  ioc-c2-01   (203.0.113.66, category "c2", confidence high)
    │  relates_to = web-01
    ▼
Asset       web-01      (internet-exposed https, known_vuln CVE-2021-44228)
    │
    ▼
Ticket      SEC-1002 (seed) — or a new SEC-1003 created from the finding
```

`alert-1002` (outbound LDAP callback from `web-01` to the same C2 IP) confirms
the exploit succeeded, reinforcing the chain.

## How the four data-plane tools consume it

All tools import the package and read via the typed accessors — none invent
their own fixtures:

```python
import mockdata

mockdata.load_world()     # -> full world dict (fresh deep copy each call)
mockdata.hosts()          # -> host inventory  (asset_lookup)
mockdata.alerts()         # -> SIEM events     (siem_query)
mockdata.iocs()           # -> indicators      (enrich_ioc)
mockdata.tickets_seed()   # -> seed tickets    (create_ticket id sequence)
```

- **`siem_query`** reads `alerts()` to answer alert/event queries.
- **`asset_lookup`** reads `hosts()` (kept in sync with its own embedded
  fixture — same host ids + the Log4Shell fact).
- **`enrich_ioc`** reads `iocs()` to score/enrich an indicator and pivot to the
  related host(s).
- **`create_ticket`** reads `tickets_seed()` (and `load_world()["ticket_sequence"]`)
  to continue the id sequence from `SEC-1003`.

Each accessor returns a fresh deep copy, so a tool mutating its slice can never
corrupt the shared source or another tool's read.
