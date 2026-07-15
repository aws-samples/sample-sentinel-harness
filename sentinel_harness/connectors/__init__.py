"""
sentinel-harness · connectors — plug-and-play backend adapters
==============================================================
Turns the generic ``*_LIVE`` HTTP seams into real, named integrations. Instead of
hand-writing a translation shim, an adopter sets an env var
(``SIEM_QUERY_CONNECTOR=splunk`` / ``CREATE_TICKET_CONNECTOR=servicenow``) and the
tool's live path routes native requests/responses through the matching connector.

.. warning::
   Connectors do **pure translation, no network** — the HTTP round-trip stays in
   the tool's SSRF-guarded ``*_LIVE`` path. That is what makes every connector
   deterministic and contract-testable with a native-response fixture (no server,
   no clock, no credentials). See ``connectors/base.py``.

Registries
----------
- :func:`get_siem_connector` — name → SIEM/search connector (splunk / elastic /
  opensearch).
- :func:`get_ticketing_connector` — name → ticketing connector (servicenow / jira).

Both raise ``KeyError`` (with the known names) on an unknown connector, so a
mis-set env var fails loudly rather than silently degrading. Nothing here carries
an endpoint, index/table, token, or tenant — only vendor API shapes.
"""
from __future__ import annotations

from typing import Dict

from .base import (
    NEUTRAL_EVENT_FIELDS,
    ConnectorError,
    SiemConnector,
    neutral_event,
)
from .siem import ElasticConnector, OpenSearchConnector, SplunkConnector
from .ticketing import JiraConnector, ServiceNowConnector

# name -> singleton connector instance (connectors are stateless/pure).
_SIEM_CONNECTORS: Dict[str, object] = {
    c.name: c for c in (SplunkConnector(), ElasticConnector(), OpenSearchConnector())
}
_TICKETING_CONNECTORS: Dict[str, object] = {
    c.name: c for c in (ServiceNowConnector(), JiraConnector())
}

__all__ = [
    "get_siem_connector",
    "get_ticketing_connector",
    "available_siem_connectors",
    "available_ticketing_connectors",
    "NEUTRAL_EVENT_FIELDS",
    "ConnectorError",
    "SiemConnector",
    "neutral_event",
    "SplunkConnector",
    "ElasticConnector",
    "OpenSearchConnector",
    "ServiceNowConnector",
    "JiraConnector",
]


def get_siem_connector(name: str):
    """Return the SIEM/search connector registered under ``name``.

    Raises ``KeyError`` listing the known names on an unknown connector — a
    mis-set ``SIEM_QUERY_CONNECTOR`` fails loudly, never silently degrades."""
    try:
        return _SIEM_CONNECTORS[name]
    except KeyError:
        raise KeyError(
            f"unknown SIEM connector {name!r}; known: {sorted(_SIEM_CONNECTORS)}"
        ) from None


def get_ticketing_connector(name: str):
    """Return the ticketing connector registered under ``name`` (KeyError if unknown)."""
    try:
        return _TICKETING_CONNECTORS[name]
    except KeyError:
        raise KeyError(
            f"unknown ticketing connector {name!r}; known: {sorted(_TICKETING_CONNECTORS)}"
        ) from None


def available_siem_connectors() -> list:
    """Sorted names of the registered SIEM/search connectors."""
    return sorted(_SIEM_CONNECTORS)


def available_ticketing_connectors() -> list:
    """Sorted names of the registered ticketing connectors."""
    return sorted(_TICKETING_CONNECTORS)
