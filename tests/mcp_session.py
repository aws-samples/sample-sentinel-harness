"""One import point for the in-memory MCP client/server session used by the protocol E2Es.

`test_mcp_protocol.py` and `test_mcp_error_redaction.py` between them imported
`mcp.shared.memory.create_connected_server_and_client_session` at **eight separate call
sites**, each with its own inline `from mcp.shared.memory import ...`. mcp 2.0.0 removed that
helper, so the CI run that first installed the SDK failed nine tests with

    ImportError: cannot import name 'create_connected_server_and_client_session'
                 from 'mcp.shared.memory'

Eight inline imports of an SDK symbol is eight places the next SDK break has to be fixed —
the shape this repo has recorded more than any other. They now all route through here.

Why this is a thin wrapper and not a compatibility shim
-------------------------------------------------------
My first version of this module carried a fallback that rebuilt the removed helper from
`create_client_server_memory_streams` + `ClientSession` (both of which survive in 2.x), on
the premise that production code was 2.0-compatible and only the test helper had moved. That
premise was **wrong**, and the fallback did not fix the failures.

mcp 2.0.0 also removed `Server.list_tools()` and `Server.call_tool()` — the two decorators
`sentinel_harness/mcp_server.py` registers its handlers with — so `create_server()` raises
`AttributeError: 'Server' object has no attribute 'list_tools'` on 2.0. The break is in
production code, not in the test transport. `pyproject.toml` therefore pins `mcp>=1.0,<2`
(see the comment there and `tests/test_mcp_version_bound.py`), which means the SDK helper is
always present and a 2.x fallback here would be unreachable dead code. Removed rather than
kept: code excluded from ever running is code nobody maintains and everybody trusts.

I had concluded 2.0-compatibility from `from mcp.server import Server` still resolving. It
does resolve — and the API behind it is gone. An import check is not a compatibility check.
"""
from __future__ import annotations

from typing import Any


def connected_session(server: Any) -> Any:
    """An initialised in-memory MCP `ClientSession` connected to `server`.

    Returns the SDK's own async context manager. Imported here rather than at module scope so
    a suite run without the `test` extra fails at the (skip-guarded) call site instead of at
    collection time.
    """
    from mcp.shared.memory import create_connected_server_and_client_session

    return create_connected_server_and_client_session(server)
