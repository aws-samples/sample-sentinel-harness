"""
sentinel-harness · ticketing connectors (ServiceNow · Jira)
===========================================================
Translators between sentinel's neutral ticket shape and the two most common
ticketing backends. Pure translation — NO network (see ``connectors/base.py``).
An adopter picks one via ``CREATE_TICKET_CONNECTOR``.

Neutral ticket (what sentinel's create_ticket works in)::

    request : {title, severity, related_alert_ids: [...], assigned_team, body}
    result  : {ticket_id, status, url}

Each connector maps that request to the backend's create-payload, and maps the
backend's create-response back to the neutral result. Field mapping is permissive
on the READ side (a backend may return ``number``/``key``/``sys_id`` as the id).

Nothing here carries an endpoint, table name, token, or tenant.
"""
from __future__ import annotations

from typing import Any, Dict

from .base import ConnectorError

# ServiceNow incident urgency/impact scale (1=high … 3=low) mapped from sentinel
# severities. Kept explicit so the mapping is auditable, not magic.
_SN_URGENCY = {"critical": "1", "high": "1", "medium": "2", "low": "3", "info": "3"}
# Jira priority names by sentinel severity.
_JIRA_PRIORITY = {"critical": "Highest", "high": "High", "medium": "Medium",
                  "low": "Low", "info": "Lowest"}


def _require_title(request: Dict[str, Any]) -> str:
    title = request.get("title")
    if not isinstance(title, str) or not title.strip():
        raise ConnectorError("ticket request must carry a non-empty 'title'")
    return title


class ServiceNowConnector:
    """ServiceNow connector — creates an incident on the ``incident`` table.

    build_request maps the neutral ticket to SN incident fields
    (``short_description``/``urgency``/``impact``/``description``/
    ``assignment_group``/``correlation_id``); parse_response reads the SN create
    reply's ``result`` object, taking ``number`` as the neutral ``ticket_id`` and
    ``state`` as ``status``."""

    name = "servicenow"

    def build_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        title = _require_title(request)
        sev = str(request.get("severity", "medium")).lower()
        urgency = _SN_URGENCY.get(sev, "2")
        related = request.get("related_alert_ids") or []
        body = {
            "short_description": title,
            "urgency": urgency,
            "impact": urgency,
            "description": request.get("body", ""),
            "assignment_group": request.get("assigned_team", ""),
            # SN de-dupes on correlation_id — join related alert ids so a re-run
            # updates rather than duplicates.
            "correlation_id": ",".join(str(a) for a in related),
        }
        return {"body": body, "path": "/api/now/table/incident"}

    def parse_response(self, payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict) or not isinstance(payload.get("result"), dict):
            raise ConnectorError("ServiceNow reply missing 'result' object")
        result = payload["result"]
        ticket_id = result.get("number") or result.get("sys_id")
        if not ticket_id:
            raise ConnectorError("ServiceNow result missing a ticket number/sys_id")
        return {
            "ticket_id": str(ticket_id),
            "status": str(result.get("state", "new")),
            "url": str(result.get("url", "")),
        }


class JiraConnector:
    """Jira connector — creates an issue via the create-issue API.

    build_request maps the neutral ticket to Jira ``fields`` (``summary``/
    ``priority``/``description``/``labels``); parse_response reads the create
    reply's ``key`` as the neutral ``ticket_id``."""

    name = "jira"

    def build_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        title = _require_title(request)
        sev = str(request.get("severity", "medium")).lower()
        related = request.get("related_alert_ids") or []
        fields = {
            "summary": title,
            "priority": {"name": _JIRA_PRIORITY.get(sev, "Medium")},
            "description": request.get("body", ""),
            "labels": [str(a) for a in related],
        }
        team = request.get("assigned_team")
        if team:
            fields["labels"].append(f"team:{team}")
        return {"body": {"fields": fields}, "path": "/rest/api/2/issue"}

    def parse_response(self, payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise ConnectorError("Jira reply must be an object")
        key = payload.get("key")
        if not key:
            raise ConnectorError("Jira reply missing issue 'key'")
        return {
            "ticket_id": str(key),
            "status": "open",
            "url": str(payload.get("self", "")),
        }
